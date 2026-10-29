"""Contextual multi-armed bandit over attack_tree.py's technique choices.

The problem this solves: attack_tree.py ranks techniques (SQLi, IDOR, XSS, ...) by a
fixed, hand-set `priority` constant, globally, forever — the same order against every
target regardless of what has actually been working. That's a single prior with no
learning, repeated across every engagement.

A bandit is the right fit specifically because this is a repeated choice among discrete
options (techniques) with an unknown, noisy payoff (does this technique confirm on THIS
KIND of endpoint), where we want to learn the best option while still paying some cost to
explore untested ones. Thompson sampling (draw from each arm's Beta(alpha, beta) belief,
play the highest draw) is used because it naturally balances that explore/exploit
trade-off without a separate tuning schedule, and degrades gracefully with few samples —
important since any single engagement sees only a handful of trials per bucket.

CONTEXT (the "bucket"): an endpoint's shape, not its identity — numeric sequential IDs,
an auth wall, API-schema-shaped, workflow-shaped — the same shape categories
memory_backend/app_patterns.py already derives for cross-run pattern recall. Buckets are
deliberately coarse: enough trials per bucket to learn from requires NOT having one bucket
per unique endpoint.

REWARD: 1.0 when a technique attempted on a bucket's endpoint reaches a `confirmed`
finding (see tools/independent_verify.py — the only place that promotes to confirmed),
0.0 when attack_tree.py's swarm worker marks that (technique, target) FAILED having found
nothing. This reward signal already exists in the swarm's control flow; this module just
tallies it per (technique, bucket) instead of discarding it.

PERSISTENCE: pluggable, same Backend protocol shape as memory.py, so the learned
win-rates compound ACROSS engagements (this only pays off with a track record — a single
run gives a bandit almost nothing to learn from). LocalJSONBackend is the always-available
default; a HelixDB-backed store is a natural later upgrade but not required here since this
is plain tabular (technique, bucket) -> (alpha, beta), not something needing vector recall.

MULTI-GAMBIT EXTENSIONS (see docs/multi-gambit.md for the full research mapping):
 - DISCOUNTING (`discount`): targets get patched and defenders adapt mid-engagement;
   a fixed Beta posterior weights a win from round 1 equally with one from round 100,
   forever. Exponential decay on (alpha, beta) at each record() makes stale evidence
   fade, so the sampler tracks regime changes. 1.0 (the default) = exact legacy
   behavior; anything smaller trades memory for adaptivity.
 - FEDERATION (`export_state` / `merge_state`): each swarm worker keeps its own store;
   posteriors are sufficient statistics (two floats per arm), so peers sync through the
   event bus by pooling EVIDENCE counts (alpha-1, beta-1), never raw draws — one
   agent's confirmed exploit instantly raises every other agent's belief about that arm.
 - SUSPICION CAP (`suspicion_cap`): an arm that confirms on every early trial is not
   skill, it's a signature — that's what a honeypot (or a reward-hacking strategist)
   looks like. While an arm has never failed within its first few trials, its draws
   are capped, so the too-perfect arm can't starve genuinely strong-but-imperfect ones.
 - COST-AWARE SELECTION (`select`): techniques differ in OPSEC price — a quiet probe
   costs noise-budget 1, a loud exploit 5+. select() ranks one Thompson draw per
   candidate by yield-per-cost, which is the budgeted-MAB objective: maximize confirmed
   findings per unit of detectable noise, not per request.
 - PRIOR INJECTION (`seed` / `prior_provider`): a new arm starts at Beta(1,1) — maximum
   ignorance — so every engagement re-derives public knowledge ("Log4Shell-class bugs
   pop unpatched targets, exotic deserialization rarely does") at the price of failed,
   detectable probes. See priors.py: EPSS/KEV exploit intelligence becomes informative
   pseudo-counts, Beta(1 + s·p, 1 + s·(1−p)). Three contracts keep this honest:
   (1) LOCAL-ONLY — the prior is this store's starting knowledge, never broadcast;
     export_state() ships OBSERVED evidence only, so peers that seeded the same public
     intel never double-count it through federation;
   (2) DATA WINS — a prior never overrides evidence: seed() refuses arms with any
     observed or merged outcome, and record() washes the prior out within ~2·strength
     real trials;
   (3) NO CERTAINTY — 0 < p < 1 is enforced; intel that claims certainty is a bug,
     not knowledge.
"""

from __future__ import annotations

import json
import random
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

# -- bucket (context) derivation ---------------------------------------------------

# Coarse, reusable shape tags — intentionally the same vocabulary app_patterns.py uses,
# so a human reading both already knows what they mean. Order is deterministic (sorted)
# so the same shape always produces the same bucket string.
_NUMERIC_ID = "numeric-id"
_UUID_ID = "uuid-id"
_AUTH_WALL = "auth-wall"
_API_SCHEMA = "api-schema"
_WORKFLOW = "workflow-shaped"
_GENERIC = "generic"

_UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def bucket_for_endpoint(endpoint_key: str, node=None) -> str:
    """Derive a coarse, reusable shape signature for one endpoint — the bandit's
    "context". `node` is the KnowledgeGraph Node for this endpoint if available (gives
    attrs/coverage); falls back to URL-shape regex alone when not (e.g. a technique
    seeded before the graph observed this endpoint yet)."""
    import re

    path = urlsplit(endpoint_key).path
    tags = []

    if re.search(r"/\d{1,8}(/|$)", path):
        tags.append(_NUMERIC_ID)
    elif re.search(_UUID_RE, path, re.IGNORECASE):
        tags.append(_UUID_ID)

    attrs = getattr(node, "attrs", None) or {}
    if attrs.get("requires_auth") or re.search(r"/(login|auth|session|account)s?(/|$)", path):
        tags.append(_AUTH_WALL)
    if attrs.get("source") == "passive_recon" and ("schema" in endpoint_key or "openapi" in endpoint_key
                                                    or "swagger" in endpoint_key):
        tags.append(_API_SCHEMA)
    if re.search(r"/(checkout|cart|order|payment|workflow|transfer|approve)s?(/|$)", path):
        tags.append(_WORKFLOW)

    return ",".join(sorted(set(tags))) or _GENERIC


# -- storage -------------------------------------------------------------------------

@dataclass
class ArmState:
    technique: str
    bucket: str
    alpha: float = 1.0   # Beta prior: alpha=beta=1 is uniform (no information yet)
    beta: float = 1.0
    # Prior bookkeeping (see seed()/priors.py): pseudo-counts injected from public
    # exploit intel. belief = 1 + prior + observed. Priors are LOCAL starting
    # knowledge — never broadcast (export_state strips them), never applied over
    # evidence (seed refuses arms with observations).
    prior_alpha: float = 0.0
    prior_beta: float = 0.0
    prior_source: str = ""
    # Raw observed outcomes (real records + pooled peer evidence), tracked separately
    # from alpha/beta because discounting and priors mix multiplicatively into the
    # belief and cannot be unmixed afterwards. Authoritative for prior-bearing arms.
    obs_wins: float = 0.0
    obs_losses: float = 0.0

    @property
    def id(self) -> str:
        return f"{self.technique}@{self.bucket}"

    @property
    def trials(self) -> int:
        return int(self.alpha + self.beta - 2)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def observed(self) -> float:
        """Real outcomes seen (own records + merged peer evidence), prior excluded."""
        return self.obs_wins + self.obs_losses

    @property
    def has_prior(self) -> bool:
        return bool(self.prior_alpha or self.prior_beta)


class BanditBackend(Protocol):
    def load(self) -> list[dict]: ...
    def save(self, rows: list[dict]) -> None: ...


class LocalJSONBanditBackend:
    def __init__(self, path: str | Path):
        self._path = Path(path)

    def load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def save(self, rows: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def make_sync_handler(bandit: "BanditStore", own_source: str = ""):
    """Event-bus federation handler (docs/multi-gambit.md §4.1).

    Subscribe this to an EventBus; every FOREIGN `bandit.state` event it sees is
    merged into `bandit` — evidence-pooled posteriors, so one engine's confirmed
    exploits raise every other engine's beliefs with no coordinator. Own-source
    events are skipped (a store merging back its own broadcast would double-count
    its evidence every round), and malformed payloads are skipped: a bad peer can
    no more corrupt the shared belief than a bad sink can corrupt a proof. The
    handler itself never raises — the same contract events.py runs under."""

    def _handler(event: object) -> None:
        try:
            if not isinstance(event, dict) or event.get("type") != "bandit.state":
                return
            source = event.get("source")
            if not source or source == own_source:
                return
            arms = event.get("arms")
            if isinstance(arms, list):
                bandit.merge_state(arms, source=str(source))
        except Exception:
            pass

    return _handler


class BanditStore:
    """Thompson-sampling store over (technique, bucket) arms, persisted across runs.

    Usage from attack_tree.py's actionable(): call `sample(technique, bucket)` to get a
    score in [0, 1] reflecting the learned win-rate (centered at 0.5 with no data, so it
    never dominates the static priority table before there's evidence); call
    `record(technique, bucket, won)` whenever a swarm worker confirms or fails a node.
    """

    def __init__(self, path: str | Path | None = None, backend: BanditBackend | None = None,
                 discount: float = 1.0, suspicion_cap: float = 0.0,
                 suspicion_window: int = 6, prior_provider=None):
        if not 0.0 < discount <= 1.0:
            raise ValueError(f"discount must be in (0, 1], got {discount!r}")
        if suspicion_cap and not 0.5 <= suspicion_cap < 1.0:
            raise ValueError(f"suspicion_cap must be in [0.5, 1) or 0 to disable, "
                             f"got {suspicion_cap!r}")
        self._discount = discount
        self._suspicion_cap = suspicion_cap
        self._suspicion_window = max(int(suspicion_window), 1)
        self._backend = backend or (LocalJSONBanditBackend(path) if path else None)
        self._arms: dict[str, ArmState] = {}
        self._lock = threading.Lock()   # swarm workers record() concurrently
        self._prior_provider = prior_provider
        if self._backend:
            for row in self._backend.load():
                arm = ArmState(**row)
                self._arms[arm.id] = arm

    def _get(self, technique: str, bucket: str) -> ArmState:
        key = f"{technique}@{bucket}"
        arm = self._arms.get(key)
        if arm is None:
            arm = ArmState(technique=technique, bucket=bucket)
            self._arms[key] = arm
            self._apply_prior_provider(arm)
        return arm

    def set_prior_provider(self, provider) -> None:
        """Install a warm-start source: provider(technique) -> (p, strength, source) or
        None, consulted once when a VIRGIN arm is first created (any bucket — class
        intel is bucket-agnostic; local evidence then per-bucketizes the belief).
        Built from public exploit intel by priors.make_provider(). Never fatal: a
        raising provider is treated as "no prior for this technique"."""
        self._prior_provider = provider

    def _apply_prior_provider(self, arm: ArmState) -> None:
        if self._prior_provider is None:
            return
        try:
            provided = self._prior_provider(arm.technique)
            if not provided:
                return
            p, strength, source = provided
            p, strength = float(p), float(strength)
            if not 0.0 < p < 1.0 or strength < 1.0:
                return
        except Exception:
            return
        arm.prior_alpha = p * strength
        arm.prior_beta = (1.0 - p) * strength
        arm.prior_source = str(source)
        arm.alpha = 1.0 + arm.prior_alpha
        arm.beta = 1.0 + arm.prior_beta
        self._flush()

    def sample(self, technique: str, bucket: str) -> float:
        """A Thompson-sampled draw from this arm's current belief — higher means
        "try this technique on this bucket sooner." With no data (alpha=beta=1), this
        draws uniformly around 0.5, so it nudges the static priority order rather than
        overriding it outright until real evidence accumulates."""
        with self._lock:
            arm = self._get(technique, bucket)
            return self._suspicion_adjust(arm, random.betavariate(arm.alpha, arm.beta))

    def _suspicion_adjust(self, arm: ArmState, draw: float) -> float:
        """Anti-honeypot gate: while an arm is young AND has never failed, cap its
        draw. A 100% early win-rate is a signature, not skill — honeypots confirm
        cheap exploits on purpose, and a reward-hacking loop can manufacture the
        same shape. The cap keeps the too-perfect arm competitive but stops it
        starving arms with realistic (intermediate) failure rates. Disabled entirely
        when suspicion_cap is 0 (the default)."""
        if not self._suspicion_cap:
            return draw
        young = 0 < arm.trials <= self._suspicion_window
        never_failed = arm.beta <= 1.0
        if young and never_failed:
            return min(draw, self._suspicion_cap)
        return draw

    # Posterior floor: discounting alone would eventually decay both counts toward 0,
    # where Beta(alpha, 0) is degenerate and betavariate would raise. The floor keeps
    # every posterior a legal Beta no matter how long an arm goes unpulled.
    _DISCOUNT_FLOOR = 0.05

    def record(self, technique: str, bucket: str, won: bool) -> None:
        """Update one arm's belief after a technique was actually tried on a bucket.
        won=True means it reached a CONFIRMED finding; won=False means the swarm marked
        it FAILED having found nothing (see attack_tree.py's worker loop).

        With discount < 1, existing evidence decays by `discount` before the new
        outcome is added — a win from ten rounds ago counts for progressively less,
        so the belief tracks a target whose behavior changes under us (patched,
        redeployed, or turned into a trap)."""
        with self._lock:
            arm = self._get(technique, bucket)
            if self._discount < 1.0:
                arm.alpha = max(self._DISCOUNT_FLOOR, arm.alpha * self._discount)
                arm.beta = max(self._DISCOUNT_FLOOR, arm.beta * self._discount)
            if won:
                arm.alpha += 1
                arm.obs_wins += 1
            else:
                arm.beta += 1
                arm.obs_losses += 1
            self._flush()

    # -- priors: public exploit intel as informative Beta pseudo-counts -------------

    def seed(self, technique: str, bucket: str, p: float, strength: float = 12.0,
             source: str = "epss") -> bool:
        """Warm-start one arm with `strength` pseudo-observations at success rate p:
        Beta(1 + s·p, 1 + s·(1−p)) instead of Beta(1,1). Thompson then probes where
        public exploitability says yield is, before any local evidence exists — and
        local evidence overrides within ~2·strength real trials (data wins).

        Returns True if seeded. Refuses (False) arms that already carry observed or
        merged outcomes — a prior may shape WHERE we probe first, never WHAT we
        conclude. Re-seeding a still-virgin arm replaces its prior wholesale, so
        re-importing a refreshed intel snapshot is idempotent. 0 < p < 1 enforced:
        a prior claiming certainty is a bug, not knowledge."""
        p, strength = float(p), float(strength)
        if not 0.0 < p < 1.0:
            raise ValueError(f"prior p must be in (0, 1), got {p!r}")
        if strength < 1.0:
            raise ValueError(f"prior strength must be >= 1, got {strength!r}")
        with self._lock:
            arm = self._get(technique, bucket)
            if arm.observed > 0:
                return False
            arm.prior_alpha = p * strength
            arm.prior_beta = (1.0 - p) * strength
            arm.prior_source = str(source)
            arm.alpha = 1.0 + arm.prior_alpha
            arm.beta = 1.0 + arm.prior_beta
            self._flush()
            return True

    # -- federation: multi-agent posterior sync -----------------------------------

    def export_state(self, min_trials: int = 0) -> list[dict]:
        """This store's sufficient statistics, ready for the event bus. Two floats per
        arm — the whole learned state of an engagement compresses to a few hundred
        bytes, so peers can sync every round without a coordinator.

        EVIDENCE-ONLY contract: arms carrying an injected prior broadcast their
        OBSERVED evidence (1 + obs_wins, 1 + obs_losses), never the belief — public
        intel is local starting knowledge, and peers that seeded the same snapshot
        would double-count it if we broadcast pseudo-counts. Prior-free arms broadcast
        the raw (alpha, beta) exactly as before (their belief IS their evidence).
        Discounting likewise stays local: it is this store's belief policy, applied
        again by each peer on its own future records.

        `min_trials` drops arms with fewer completed trials — sampling alone creates
        zero-trial arms (every live node gets sampled by actionable()), and arms with
        no evidence carry nothing worth broadcasting."""
        with self._lock:
            out = []
            for a in self._arms.values():
                evidence = a.observed if a.has_prior else a.trials
                if evidence < min_trials:
                    continue
                row = asdict(a)
                if a.has_prior:
                    row["alpha"] = 1.0 + a.obs_wins
                    row["beta"] = 1.0 + a.obs_losses
                out.append(row)
            return out

    def merge_state(self, rows: list[dict], source: str = "peer") -> int:
        """Pool a peer's evidence into ours and return how many arms merged.

        Beta posteriors ADD under independent evidence, but only the evidence — not the
        Beta(1,1) prior each peer started from. So we add (alpha-1, beta-1) and keep our
        own prior: one merge is a proper pooled posterior. (Merging the SAME peer blob
        twice double-counts its evidence — re-broadcast dedupe is the caller's problem,
        and peer_traces already tracks what each peer has seen.)

        Malformed or hostile rows are skipped, never raised: a bad peer can no more
        corrupt the shared belief than a bad sink can corrupt a proof (same isolation
        contract traffic.py runs under)."""
        merged = 0
        with self._lock:
            for row in (rows or []):
                if not isinstance(row, dict):
                    continue
                try:
                    technique = str(row["technique"])
                    bucket = str(row["bucket"])
                    if not technique or not bucket:
                        continue
                    peer_a = max(1.0, float(row["alpha"]))
                    peer_b = max(1.0, float(row["beta"]))
                except (KeyError, TypeError, ValueError):
                    continue
                arm = self._get(technique, bucket)
                arm.alpha = max(1.0, arm.alpha + (peer_a - 1.0))
                arm.beta = max(1.0, arm.beta + (peer_b - 1.0))
                # Pooled peer evidence is OBSERVED evidence too — tracked so an arm that
                # only ever merged still exports what it pooled (relay topology), and
                # so a later seed() correctly refuses it.
                arm.obs_wins += (peer_a - 1.0)
                arm.obs_losses += (peer_b - 1.0)
                merged += 1
            if merged:
                self._flush()
        return merged

    # -- cost-aware selection (budgeted multi-armed bandit) -----------------------

    def select(self, candidates: list[tuple[str, str, float]],
               k: int = 1) -> list[dict]:
        """One Thompson draw per candidate, ranked by yield-per-cost.

        `candidates` is a list of (technique, bucket, cost) tuples where cost is the
        arm's OPSEC price — noise budget, rate-limit weight, SOC attention (quiet
        probe = 1, loud exploit = 5+). Ranking by draw/cost optimizes confirmed
        findings per unit of detectable noise (the budgeted-MAB objective), not per
        request: under a tight noise budget the selector buys cheap gambits first and
        pays an expensive arm's price only when its evidence is strong enough to
        clear it. Suspicion caps and discounting apply exactly as in sample().
        Returns at most k dicts: {technique, bucket, cost, draw, score}.

        Candidates may be (technique, bucket, cost) 3-tuples or
        (technique, bucket, cost, meta) 4-tuples when the caller needs ranked items
        mapped back to its own objects (the orchestrator maps each candidate back to
        its attack-tree node); a 4-tuple's meta is returned verbatim on the item."""
        scored: list[dict] = []
        with self._lock:
            for item in candidates:
                if len(item) == 4:
                    technique, bucket, cost, meta = item
                    has_meta = True
                else:
                    technique, bucket, cost = item
                    meta, has_meta = None, False
                cost = max(float(cost), 1e-6)
                arm = self._get(technique, bucket)
                draw = self._suspicion_adjust(arm, random.betavariate(arm.alpha, arm.beta))
                entry = {"technique": technique, "bucket": bucket, "cost": cost,
                         "draw": draw, "score": draw / cost}
                if has_meta:
                    entry["meta"] = meta
                scored.append(entry)
        scored.sort(key=lambda s: s["score"], reverse=True)
        return scored[:k]

    def summary(self) -> dict:
        with self._lock:
            out = {}
            for arm in sorted(self._arms.values(), key=lambda a: a.trials, reverse=True):
                entry = {"trials": arm.trials, "mean": round(arm.mean, 3),
                         "observed": int(arm.observed)}
                if arm.has_prior:
                    entry["prior"] = {"source": arm.prior_source,
                                      "strength": arm.prior_alpha + arm.prior_beta}
                out[arm.id] = entry
            return out

    def _flush(self) -> None:
        if self._backend:
            self._backend.save([asdict(a) for a in self._arms.values()])

"""Multi-agent orchestrator — the "army of ants".

One agent with all tools and one giant context is the bottleneck. This splits the work
across focused specialist agents, each with a small tool set, a focused prompt, and its
own model tier, all sharing ONE brain (knowledge graph), ONE attack tree, ONE memory, and
ONE budget:

  - Recon specialist   — maps the attack surface (breadth). Runs on a cheaper model.
  - Exploit specialist — probes and PROVES/chains vulnerabilities (depth). Runs on the
    strongest available model.
  - Verify specialist  — independently re-checks every pending finding before anything
    may count (see tools/independent_verify.py). Runs in a FRESH context, never the
    context that proposed the finding.
  - Access specialist  — once a confirmed foothold exists, PRESSES it: harvest secrets,
    try credentials, prove privilege boundaries. Mechanical, procedural work, separated
    out so the exploit specialist's context stays focused on proving new bugs instead of
    also reasoning about what a foothold unlocks.
  - Logic specialist   — hunts BUSINESS-LOGIC bugs (price tampering, race conditions,
    skipped workflow steps) on endpoints that look workflow-shaped. This is the class of
    bug pattern-matched vuln scanning misses entirely: it requires reasoning about the
    app's domain, not a payload library, and its proof (tools/logic.py) is structurally
    different (ordered multi-step sequences, single-run + control) from the single/
    differential-request proofs everything else uses.

The orchestrator is deterministic (a disciplined commander, not another LLM to go astray):
recon populates the graph; then each round is EXPLOIT -> VERIFY -> (ACCESS -> VERIFY)* ->
LOGIC -> VERIFY, where the ACCESS loop runs only as long as the KILL CHAIN says there is a
foothold worth pressing, and the LOGIC round only runs when recon turned up endpoints that
look workflow-shaped (cart/checkout/coupon/payment/...) — no point spending a round hunting
business logic on an app that's just a static content site. Specialists share state, so
what recon finds, exploit attacks; what exploit confirms, access presses; what any
specialist proves, memory learns.

EXPLOIT itself is a SWARM, not one thread of reasoning: AttackTree.actionable() is a
prioritized (technique, target) worklist, and when it's non-empty each round fans out
up to max_swarm_workers separate EXPLOIT contexts running CONCURRENTLY (ThreadPoolExecutor),
each pulling and atomically claiming the next untried pair via AttackTree.claim() so no
two workers burn turns on the same hypothesis. Findings land in the shared, now
thread-safe FindingStore exactly as a single EXPLOIT would write them; VERIFY still runs
once per round over everything the whole swarm left pending. Falls back to a single
EXPLOIT context (the pre-swarm behavior) whenever there's nothing actionable yet (e.g.
right after recon, before the attack tree has anything seeded) — this is a strict
addition, not a replacement of the serial path.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import json
from pathlib import Path
import threading

from .agent import RedTeamAgent
from .attack_tree import FAILED, TECHNIQUES, TODO, technique_cost
from .sandbox.detection_belief import BeliefFilter
from .config import Engagement
from .events import coerce_payload
from .killchain import (CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT,
                        PRIVILEGE_ESCALATION)
from .llm.openrouter import OpenRouterClient
from .llm.routing import PARSE, PLAN
from .reflection import coach_note, reflect
from .strategy import EngagementStrategy, reset_tree_nudges
from .tools import ToolContext, Tool


def profile_for(technique: str | None):
    """Module-level alias so callers (and tests) can reach the router without the
    specialists import — kept as a function attribute to avoid a circular import
    at module load time (specialists.py imports SpecialistProfile from here)."""
    from .specialists import profile_for as _pf
    return _pf(technique)

# Kill-chain stages that mean "there is a foothold worth pressing further" — if
# KillChain.recommend() names any of these, an ACCESS round (not another EXPLOIT round)
# is the next useful move.
_ACCESS_STAGES = {CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, DISCOVERY}

# Endpoint URL/key fragments that suggest a multi-step, stateful workflow — the shape of
# thing business-logic bugs live in. Heuristic, not exhaustive: a miss here just means the
# LOGIC round doesn't run (cheap to skip), a false match just means it runs and finds
# nothing (cheap to waste a round on) — asymmetric cost, so a loose heuristic is fine.
_WORKFLOW_HINTS = ("cart", "checkout", "coupon", "voucher", "discount", "order", "payment",
                   "pay", "redeem", "transfer", "withdraw", "booking", "reserve", "apply",
                   "submit", "vote", "like", "quantity", "balance", "wallet")


def _looks_workflow_shaped(graph) -> bool:
    if graph is None:
        return False
    from .knowledge import ENDPOINT
    return any(hint in ep.key.lower() for ep in graph.nodes(ENDPOINT) for hint in _WORKFLOW_HINTS)


@dataclass
class SpecialistProfile:
    name: str
    addon: str                       # role-specific system instructions
    tool_names: list[str]            # subset of the registry this specialist may use
    role: str = PLAN                 # model tier (cheap for recon, strong for exploit)
    max_steps: int = 20


RECON = SpecialistProfile(
    name="recon",
    addon=("You are the RECON specialist. Map the attack surface only: browse the app, "
           "discover endpoints, parameters, and technologies, and let them register in the "
           "knowledge graph. Do NOT try to exploit or confirm vulnerabilities — that is the "
           "exploit specialist's job. You MAY authenticate (log in as a basic/seeded user) "
           "purely to get past a login wall and see what's behind it — logging in is "
           "mapping, not exploiting. If the app has a multi-step login (e.g. submit a "
           "username, then a password at a second URL), use authenticate's "
           "second_url_template rather than guessing follow-up URLs by hand. If the "
           "engagement brief hands you a ready-made token/cookie, register it with "
           "set_session instead of inventing a login. START with surface_scan (one call, "
           "no arguments): it knocks on every host/port the RoE allows and fills the asset "
           "inventory, so you know which in-scope services are actually alive before you "
           "spend a single step on a dead one. Use http_probe for raw API surfaces "
           "the browser cannot reach (JSON endpoints, API roots, robots.txt, versioned "
           "APIs) and for anything behind a session — it is a cheap fetch, not a proof. "
           "Be broad and fast."),
    tool_names=["browser_navigate", "browser_content", "browser_click", "kali_exec",
                "authenticate", "set_session", "http_probe", "surface_scan",
                "search_peer_traces"],
    role=PARSE,          # breadth work -> cheaper model
    max_steps=15,
)

EXPLOIT = SpecialistProfile(
    name="exploit",
    addon=("You are the EXPLOIT specialist. The surface is already mapped in the knowledge "
           "graph and the attack tree lists prioritized untested checks. For each, PROVE the "
           "vulnerability with a reproducing check (confirm_finding / verify_vulnerability), "
           "authenticate when needed, and chain confirmed footholds. Separate LOOKING from "
           "PROVING: use http_probe to inspect responses, validate a session, or walk an ID "
           "space — it never records anything — and only fire confirm_finding once you have "
           "a hypothesis worth proving; confirm_finding costs verification trials, probes "
           "do not. If the engagement brief hands you a ready-made token/cookie, register it "
           "with set_session instead of hand-writing headers everywhere. Bias hard toward "
           "confirming findings; do not re-map the surface. NOTE: your checks only reach "
           "pending_verification — a separate pass independently re-checks them before "
           "anything counts. That is by design; keep proving, don't try to self-promote."),
    tool_names=["confirm_finding", "verify_vulnerability", "authenticate", "set_session",
                "http_probe", "kali_exec", "search_peer_traces",
                "browser_navigate", "browser_content", "browser_fill"],
    role=PLAN,           # depth/reasoning work -> strongest model
    max_steps=40,
)

ACCESS = SpecialistProfile(
    name="access",
    addon=("You are the ACCESS specialist. A confirmed foothold already exists — the kill "
           "chain briefing tells you which stage to press (credential access, privilege "
           "escalation, discovery, or lateral movement). Your job is mechanical, not "
           "exploratory: harvest secrets from material you already hold (extract_secrets), "
           "try candidates against in-scope probes (try_credential), and prove privilege "
           "boundaries differentially (prove_privilege) — never label access yourself; "
           "prove_privilege's own check still only reaches pending_verification, same as "
           "every other proof tool. Use http_probe with as_session to exercise a held "
           "session against endpoints the brief names (e.g. the objective's target) — its "
           "response tells you whether the session reaches further before you spend a "
           "proving step. Use record_access only to note leads/edges you discover, not to "
           "self-grant held access. Do NOT hunt new vulnerability "
           "classes — that is the exploit specialist's job; if nothing presses further, "
           "say so and stop."),
    tool_names=["extract_secrets", "try_credential", "prove_privilege", "record_access",
                "authenticate", "set_session", "http_probe", "kali_exec",
                "browser_navigate", "browser_content"],
    role=PARSE,          # procedural/mechanical work once a path is already known -> cheaper model
    max_steps=20,
)

LOGIC = SpecialistProfile(
    name="logic",
    addon=("You are the LOGIC specialist. Endpoints that look workflow-shaped (cart, "
           "checkout, coupon, payment, voucher, order, transfer, booking, ...) are in the "
           "knowledge graph. Reason about what the APP'S DOMAIN assumes should be true — a "
           "coupon used once, a price computed server-side, a step that can't be skipped, "
           "an action that can't be repeated — and try to break that assumption. Use "
           "verify_workflow_abuse: give an ordered attack_steps sequence (e.g. redeem the "
           "same coupon twice, or submit a negative quantity, or call the 'confirm order' "
           "step without first calling 'add payment'), an ordered control_steps sequence "
           "doing the SAME workflow honestly (ideally with a fresh identifier — a "
           "different coupon/order), and the invariant that proves the attack sequence "
           "broke something the control didn't. This is NOT re-run k-of-n like the other "
           "proof tools — business logic is usually one-shot, so get the sequence right "
           "the first time rather than spraying payloads. Authenticate first if the "
           "workflow needs a session. Do NOT hunt injection/XSS/access-control here — "
           "that's the exploit specialist's job; only pursue bugs where the vulnerability "
           "IS the business rule being violated, not a technical injection flaw."),
    tool_names=["verify_workflow_abuse", "authenticate", "browser_navigate", "browser_content",
                "browser_fill", "browser_click"],
    role=PLAN,           # requires reasoning about the specific app's domain, not pattern-matching
    max_steps=25,
)

VERIFY = SpecialistProfile(
    name="verify",
    addon=("You are the VERIFY specialist — the adversary inside the team. You did not "
           "propose any of these findings and you owe them no loyalty. For each pending "
           "finding, call verify_finding_independently(finding_id) and accept whatever "
           "verdict comes back: it reproduces the check fresh and forces a negative "
           "control, so your job is just to run it for every pending finding, not to "
           "argue with the result. Work through ALL pending findings before stopping."),
    tool_names=["verify_finding_independently"],
    role=PLAN,           # independence matters more than cost here; use the strong pool
    max_steps=15,
)


def run_verify_pass(engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                    client: OpenRouterClient, objective: str, budget=None, on_text=None) -> int:
    """Run an independent VERIFY specialist over every pending finding, in a FRESH context.

    Shared by both run modes: the orchestrator calls this between exploit rounds, and
    single-agent mode (cli.py) calls it after the main run — a single continuous context
    must never be allowed to grade its own pending findings, even outside multi-agent mode.
    Returns the number of findings still pending afterward (0 = fully cleared).
    """
    pending = ctx.findings.pending()
    if not pending:
        # Live-fire regression (run 20261022-1239): in single-agent mode the model may
        # legitimately call verify_finding_independently MID-RUN, so by the time the
        # post-run pass arrives there is nothing pending — and the early return below
        # used to skip collection entirely, leaving a confirmed finding on the
        # objective's target uncollected. Crediting runs even when verification is
        # already clear; the sweep is idempotent and only ever acts on confirmed work.
        from .credit import credit_confirmed_findings
        try:
            credit_confirmed_findings(ctx)
        except Exception as exc:
            ctx.audit.record("credit.failed", error=str(exc))
        return 0
    ctx.audit.record("verify_pass.start", pending=len(pending))
    subset = {n: tools[n] for n in VERIFY.tool_names if n in tools}
    verifier = RedTeamAgent(engagement, subset, ctx, client, max_steps=VERIFY.max_steps,
                            system_addon=VERIFY.addon, role=VERIFY.role,
                            agent_name="verify")
    if budget is not None:
        verifier.with_runtime(budget=budget)
    ids = ", ".join(f.id for f in pending)
    verifier.run(
        f"{objective}\n\nThis run: VERIFY — independently re-check these pending findings "
        f"(finding_id values): {ids}. Call verify_finding_independently once per id. Do not "
        f"skip any.", on_text=on_text)
    remaining = len(ctx.findings.pending())
    ctx.audit.record("verify_pass.finish", remaining=remaining)
    # Creditor: collection is nobody's implicit job. A confirmed finding on the
    # objective's target must convert into access hold + criterion credit WITHOUT
    # depending on the model remembering to call record_access/claim_objective —
    # live-fire showed a fully-proven, independently-confirmed IDOR sitting there
    # uncollected because the final linkage never left the model's head. The sweep is
    # deterministic, gated by the same REQUIRED_SOURCE rules as everything else, and
    # idempotent (see credit.py).
    from .credit import credit_confirmed_findings
    try:
        credit_confirmed_findings(ctx)
    except Exception as exc:   # collection must never crash the pipeline
        ctx.audit.record("credit.failed", error=str(exc))
    return remaining


# -- Phase B3 scheduler constants (the mu/V/SCALE rationale lives here on purpose:
#    next to the class the numbers feed, where a reviewer will look first) ----------
#
# These calibrate the drift-plus-penalty controller against ONE fixed ruler: the
# OPSEC price table attack_tree.TECHNIQUE_COST, whose entire domain is [1.0, 5.0]
# (quiet probes 1.0, mid techniques ~2.0, bulk exfil 5.0, mean 2.46 over 13
# techniques). Every constant below is anchored in that domain — nothing is magic.
#
# DEFAULT_MU = 2.0 — the sustainable per-claim loudness: the swarm's AVERAGE claim
#   may cost as much as access.control/idor (2.0) without detection pressure
#   accumulating. Claims quieter than mu repay pressure (a cost-1 probe drains the
#   queue by 1), claims louder accrue it (an exfil adds 3). This is the conservative
#   choice by construction: mu sits BELOW the table's mean (2.46), so an ordinary
#   mixed basket stays near-stable while any loud-heavy streak drifts Q up — slow to
#   forgive, quick to throttle.
#
# DEFAULT_V = 1.0 — the weight of progress (learned yield-per-cost, a Thompson draw
#   divided by cost, so bounded in [0, 1]) against the pressure term Q*cost. At V=1
#   the progress pull is at most 1 credit while any Q >= 1 makes the pressure term
#   dominate — i.e. under ANY real detection pressure the scheduler prefers stealth
#   over yield (conservative default), and at Q=0 the order is exactly the legacy
#   yield-per-cost ranking regardless of V. Overt engagements raise V toward SCALE
#   (yield competes with a fully-alerted detector); assumed-breach stealth lowers it.
#
# DEFAULT_SCALE = 4.0 — converts the belief filter's risk in [0,1] into noise-credit
#   pressure on the SAME ruler: risk=1.0 (detector effectively certain) presses as
#   hard as the loudest single technique minus one quiet probe (5 - 1 = 4); risk=0.5
#   presses like one access.control (2.0) over the sustainable rate. With the default
#   round budget of 12, a fully-alerted belief withholds a third of a round — a real
#   throttle that never paralyzes the swarm.
DEFAULT_MU = 2.0
DEFAULT_V = 1.0
DEFAULT_SCALE = 4.0


class DriftPlusPenaltyScheduler:
    """Per-round OPSEC spend controller for the exploit swarm (Phase B3; supersedes
    NoiseBudget's flat one-shot greedy knapsack, docs/multi-gambit.md §3.4).

    THE MODEL: every claim spends the technique's OPSEC price (attack_tree.
    technique_cost) from a per-round allowance, AND accrues detection pressure in a
    virtual queue — the Lyapunov drift-plus-penalty recursion

        Q(t+1) = max(Q(t) + noise_cost(a) - mu, 0)

    applied per action on try_spend() (and unwound on refund(): a lost claim race
    means no request was ever sent, so its pressure never happened). Q is a DEBT in
    noise credits: spending louder than mu borrows against the future.

    THE BLEND (where the POMDP plugs in): the pressure the controller actually acts
    on is

        Q(t) = max(raw_accumulator(t), belief_filter.risk_score(t) * SCALE)

    The raw accumulator alone would only rise after the noise was already spent; the
    belief term is the immediate override — a challenge burst observed by tools/
    http.py's hook raises risk_score within one round and the scheduler throttles
    NOW, without waiting for the queue to drift up. The raw term keeps the pressure
    honest in the other direction: a noisy-but-unnoticed streak still owes its debt.

    THE DECISION: each claim cycle, candidates from the tree's actionable frontier
    are ranked by

        score(a) = Q(t) * noise_cost(a) - V * progress_value(a)

    and the swarm walks them cheapest-score-first (min score, ascending), skipping
    candidates that don't fit the remaining allowance — the same greedy fill shape
    NoiseBudget always had, with a pressure-aware order instead of a flat one.
    progress_value is the existing yield estimate: the bandit's Thompson draw
    divided by the technique's cost (exactly BanditStore.select's score), so at
    Q=0 the ranking degenerates to the legacy yield-per-cost order — the old
    behavior is the Q=0 special case, not a lost sibling. Ties keep the tree's
    priority order (stable sort — the same equal-split tie-breaking the knapsack
    relied on). Without a bandit, progress is a constant and the order degenerates
    to the tree's order at Q=0, cheap-first under pressure.

    THE THROTTLE: the round allowance restored by reset() is
    max(mu, total - Q(t)) — pressure withholds budget one-for-one (the debt is
    denominated in the same credits), floored at mu so the swarm can always afford
    one sustainable claim and never deadlocks against its own queue.

    Thread-safe — swarm workers spend concurrently. The public interface is
    NoiseBudget's exactly (remaining / can_afford / try_spend / refund / reset);
    `NoiseBudget` remains as an alias below so every existing caller and test
    keeps working unchanged."""

    def __init__(self, total: float, *, mu: float = DEFAULT_MU, V: float = DEFAULT_V,
                 scale: float = DEFAULT_SCALE, bandit=None, belief=None):
        self._total = max(float(total), 0.0)
        self._remaining = self._total
        self._lock = threading.Lock()
        self._mu = max(float(mu), 1e-6)
        self._V = max(float(V), 0.0)
        self._scale = max(float(scale), 0.0)
        self._bandit = bandit     # BanditStore | None — progress_value's source
        self._belief = belief     # BeliefFilter | None — the POMDP side of the blend
        self._q_raw = 0.0         # raw_accumulator: the cross-round virtual queue

    # -- pressure state ------------------------------------------------------------

    def q_effective(self) -> float:
        """Q(t) = max(raw_accumulator, belief risk * SCALE) — read live so a
        challenge burst throttles the very next claim, not the next round."""
        with self._lock:
            raw = self._q_raw
        risk = 0.0
        if self._belief is not None:
            try:
                risk = float(self._belief.risk_score())
            except Exception:
                risk = 0.0   # a broken POMDP degrades to raw-queue-only, never blocks
        return max(raw, risk * self._scale)

    def _risk_snapshot(self) -> float:
        if self._belief is None:
            return 0.0
        try:
            return float(self._belief.risk_score())
        except Exception:
            return 0.0

    # -- NoiseBudget-compatible accounting -------------------------------------------

    @property
    def remaining(self) -> float:
        with self._lock:
            return self._remaining

    def can_afford(self, cost: float) -> bool:
        with self._lock:
            return self._remaining >= cost - 1e-9

    def try_spend(self, cost: float) -> bool:
        """Atomically reserve `cost` from the remaining allowance AND advance the
        pressure queue one action (Q <- max(Q + cost - mu, 0)); False if it doesn't
        fit (the caller moves on to a cheaper candidate — nothing was spent)."""
        with self._lock:
            if self._remaining >= cost - 1e-9:
                self._remaining -= cost
                self._q_raw = max(self._q_raw + cost - self._mu, 0.0)
                return True
            return False

    def refund(self, cost: float) -> None:
        """Return a reservation (capped at the total — refunds can never mint
        budget that was never there) and unwind the claim's pressure step."""
        with self._lock:
            self._remaining = min(self._total, self._remaining + cost)
            self._q_raw = max(self._q_raw - cost + self._mu, 0.0)

    def reset(self) -> None:
        """Start a new round: restore the allowance, throttled by current pressure
        (max(mu, total - Q(t))) — called ONCE per exploit round. 'Per-round' is the
        documented contract (RunOptions.round_noise_budget); without the reset,
        round 0's spend starves every later round and the swarm stops exploring
        after its first claims (caught by the product E2E run of 2026-10-30: 12
        rounds started, only round 0 ever claimed). The PRESSURE QUEUE is
        deliberately NOT reset — cross-round memory is the entire point; only the
        round's bookkeeping allowance starts whole."""
        with self._lock:
            # Hard cap first (the round budget is a CONTRACT — spend must never
            # exceed total), then the pressure throttle, then the mu floor so the
            # swarm can always afford one sustainable claim (only meaningful when
            # total > mu; the cap always wins).
            self._remaining = min(self._total, max(self._mu, self._total
                                                   - max(self._q_raw, self._risk_snapshot() * self._scale)))

    # -- candidate ranking (replaces the flat greedy knapsack order) ------------------

    def rank(self, candidates: list[tuple]) -> list[dict]:
        """Score candidates by drift-plus-penalty and return them cheapest-score
        first. `candidates` are (technique, bucket, cost) or (technique, bucket,
        cost, meta) tuples exactly like BanditStore.select takes; a meta is
        returned verbatim on the item. score(a) = Q*cost - V*progress with
        progress = Thompson draw / cost when a bandit is attached (one draw per
        candidate, input order — so a fixed seed reproduces BanditStore.select's
        draws and, at Q=0, its exact order), else a constant (order = tree order
        at Q=0, cheap-first under pressure). Stable sort: equal scores keep the
        tree's priority order — the knapsack's equal-split tie-breaking."""
        q = self.q_effective()
        scored: list[dict] = []
        for item in candidates:
            if len(item) == 4:
                technique, bucket, cost, meta = item
                has_meta = True
            else:
                technique, bucket, cost = item
                meta, has_meta = None, False
            cost = max(float(cost), 1e-6)
            draw = None
            if self._bandit is not None:
                try:
                    draw = float(self._bandit.sample(technique, bucket))
                except Exception:
                    draw = None
            progress = (draw / cost) if draw is not None else 1.0
            entry = {"technique": technique, "bucket": bucket, "cost": cost,
                     "progress": progress, "score": q * cost - self._V * progress}
            if draw is not None:
                entry["draw"] = draw
            if has_meta:
                entry["meta"] = meta
            scored.append(entry)
        scored.sort(key=lambda s: s["score"])   # stable — ties keep tree order
        return scored


# Backward-compatibility alias: NoiseBudget's public interface is the scheduler's
# accounting subset, and every existing caller/test imports this name. The class
# above IS the replacement; this alias IS the contract that nothing else had to move.
NoiseBudget = DriftPlusPenaltyScheduler


class Orchestrator:
    def __init__(self, engagement: Engagement, tools: dict[str, Tool], ctx: ToolContext,
                 client: OpenRouterClient, graph=None, attack_tree=None, memory=None,
                 max_exploit_rounds: int = 12, max_access_rounds: int = 4,
                 max_swarm_workers: int = 3, noise_budget: float | None = None,
                 detection=None, noise_mu: float | None = None,
                 noise_V: float | None = None):
        self._eng = engagement
        self._tools = tools
        self._ctx = ctx
        self._client = client
        self._graph = graph
        self._attack_tree = attack_tree
        self._memory = memory
        # These are SAFETY CEILINGS, not targets — the loop stops far earlier whenever
        # there's no untested work left, the objective is achieved, or the budget runs
        # out (see run()/_run_access_loop()). The old default of 2 was an arbitrary
        # constant that could cut a run off mid-chain even with budget and untested work
        # remaining; the ceiling now exists only to bound a pathological worst case
        # (e.g. an attack tree that keeps unlocking new chained work indefinitely),
        # not to cap a normal engagement.
        self._max_exploit_rounds = max_exploit_rounds
        self._max_access_rounds = max_access_rounds   # ceiling on the press-the-foothold loop
        # Small on purpose: every worker is a full free-model context (its own system
        # prompt + briefing overhead), so more workers is more TOKENS per round, not just
        # more wall-clock parallelism — under a tight daily free-model request quota (see
        # Phase 5/6 notes), 3 concurrent is the realistic ceiling, not a target to raise
        # without also raising the token budget.
        self._max_swarm_workers = max_swarm_workers
        # Phase B3 — the detection belief (POMDP over the defender's state): adopt one
        # wired by the caller (run.py / tests) or create our own, and expose it on the
        # shared ToolContext so tools/http.py's observation hook feeds THE SAME filter
        # the scheduler reads. Every multi-agent run gets the filter (the hook is
        # best-effort and costs nothing); only the scheduler CONSUMES it.
        self._detection = detection or getattr(ctx, "detection", None) or BeliefFilter()
        try:
            if getattr(ctx, "detection", None) is not self._detection:
                ctx.detection = self._detection
        except Exception:
            pass   # a frozen/odd ctx must never block construction — the hook just no-ops
        # Per-round OPSEC budget (docs/multi-gambit.md §3.4): None/0 = unlimited
        # spend (exact legacy behavior); a positive value drives the
        # DriftPlusPenaltyScheduler — per-round allowance, drift-plus-penalty claim
        # ordering (Q*cost - V*progress), and the POMDP blend that throttles the
        # swarm when the belief filter sees the defender reacting. mu/V default to
        # the calibrated module constants; run.py exposes both as per-run knobs
        # (RunOptions.noise_mu / noise_V) for per-engagement tuning.
        self._noise = None
        if noise_budget and noise_budget > 0:
            self._noise = DriftPlusPenaltyScheduler(
                noise_budget,
                mu=DEFAULT_MU if noise_mu is None else max(float(noise_mu), 1e-6),
                V=DEFAULT_V if noise_V is None else max(float(noise_V), 0.0),
                bandit=getattr(attack_tree, "bandit", None),
                belief=self._detection)
        self._budget = None
        self._manifest = None
        # Reflection state defaults (re-created fresh per run() — a new engagement
        # starts with clean reflections; these exist so direct method use never
        # hits an attribute error).
        self._reflections: list[dict] = []
        self._reflection_notes: list[str] = []
        # Phase B5 defaults (re-created fresh per run() — a new engagement starts
        # with a clean strategy state; these exist so direct method use in tests
        # never hits an attribute error).
        self._strategy = EngagementStrategy()
        self._round_claims: list[str] = []
        self._confirmed_seen: set = set()   # tree node ids already fed to the ledger

    def with_runtime(self, budget=None, manifest=None, manifest_path=None):
        self._budget = budget
        if manifest is not None and manifest_path is not None:
            self._manifest = (manifest, manifest_path)
        return self

    def _make_specialist(self, profile: SpecialistProfile, addon_suffix: str = "",
                         agent_name: str | None = None) -> RedTeamAgent:
        # Give the specialist only its allowed tools that actually exist in the registry.
        subset = {n: self._tools[n] for n in profile.tool_names if n in self._tools}
        addon = profile.addon + addon_suffix
        # agent_name override: the swarm gives each concurrent worker a UNIQUE telemetry
        # identity (exploit-w0, exploit-w1, ...) so peer-trace search can attribute
        # observations to a specific sibling hypothesis. Without it every worker shows
        # up as the same "exploit" role and "peer" means nobody in particular.
        agent = RedTeamAgent(self._eng, subset, self._ctx, self._client,
                             max_steps=profile.max_steps, graph=self._graph,
                             attack_tree=self._attack_tree, memory=self._memory,
                             system_addon=addon, role=profile.role,
                             agent_name=agent_name or profile.name)
        if self._budget is not None:
            mpath = self._manifest[1] if self._manifest else None
            manifest = self._manifest[0] if self._manifest else None
            agent.with_runtime(budget=self._budget, manifest=manifest, manifest_path=mpath)
        return agent

    # -- telemetry --------------------------------------------------------------

    def _emit(self, etype: str, **fields) -> None:
        bus = getattr(self._ctx, "events", None)
        if bus is not None:
            try:
                bus.emit(etype, role="orchestrator", **fields)
            except Exception:
                pass

    def _phase(self, phase: str, **extra) -> None:
        self._ctx.audit.record("orchestrator.phase", phase=phase, **extra)
        self._emit("phase.change", phase=phase, **extra)

    def _run_exploit_swarm(self, objective: str, round_no: int, on_text=None) -> str:
        """Fan out EXPLOIT across up to max_swarm_workers CONCURRENT contexts, each
        claiming and working a distinct (technique, target) pair from AttackTree's
        prioritized worklist, instead of one context working the list serially. Falls
        back to a single EXPLOIT context (the old behavior) when there's nothing
        actionable yet — this never regresses a run with no attack tree seeded."""
        if self._attack_tree is None:
            exploit = self._make_specialist(EXPLOIT)
            return exploit.run(
                f"{objective}\n\nThis run: EXPLOIT round {round_no + 1} — confirm and "
                f"chain vulnerabilities from the mapped surface.", on_text=on_text) or ""

        actionable = self._attack_tree.actionable(limit=self._max_swarm_workers * 4)
        if not actionable:
            exploit = self._make_specialist(EXPLOIT)
            return exploit.run(
                f"{objective}\n\nThis run: EXPLOIT round {round_no + 1} — confirm and "
                f"chain vulnerabilities from the mapped surface.", on_text=on_text) or ""

        n_workers = min(self._max_swarm_workers, len(actionable))
        self._ctx.audit.record("orchestrator.swarm_start", round=round_no,
                               workers=n_workers, actionable=len(actionable))
        if self._noise is not None:
            self._noise.reset()   # per-ROUND allowance: throttled by current pressure
            self._emit("scheduler.state", round=round_no,
                       q=round(self._noise.q_effective(), 4),
                       risk=round(self._detection.risk_score(), 4),
                       allowance=round(self._noise.remaining, 4))

        def worker(worker_id: int) -> str:
            summary = ""
            # Each worker claims its OWN next item each time through the loop (not a
            # fixed slice assigned upfront) so a fast worker that finishes its hypothesis
            # quickly picks up the next untried one instead of sitting idle while a
            # slower sibling is still on its first.
            while True:
                claimed = None
                nodes = self._attack_tree.actionable(limit=self._max_swarm_workers * 4)
                if not nodes:
                    break
                if self._noise is not None:
                    # Drift-plus-penalty claim order (Phase B3, docs/multi-gambit.md
                    # §3.4): the tree's frontier is re-sorted by Q*cost - V*progress,
                    # so at zero pressure the swarm buys the highest learned yield-
                    # per-cost first (the legacy bandit order), and under detection
                    # pressure (raw queue or the belief filter's POMDP) it pivots to
                    # quiet gambits. Candidates still come ONLY from the tree's
                    # actionable frontier — the scheduler reorders in-scope work,
                    # it never creates, authorizes, or widens anything.
                    ranked = self._noise.rank(
                        [(n.technique, n.bucket, technique_cost(n.technique), n)
                         for n in nodes])
                    for item in ranked:
                        node, cost = item["meta"], item["cost"]
                        if not self._noise.try_spend(cost):
                            continue   # doesn't fit the remaining allowance — a cheaper one may
                        if self._attack_tree.claim(node.technique, node.target):
                            claimed = node
                            break
                        self._noise.refund(cost)   # lost the claim race — allowance and pressure back
                else:
                    for node in nodes:
                        if self._attack_tree.claim(node.technique, node.target):
                            claimed = node
                            break
                if claimed is None:
                    break   # nothing left unclaimed/affordable — this worker is done
                # Phase B5: the strategy ledger's claim evidence comes straight from
                # the claim loop (list.append is atomic under the GIL — swarm workers
                # race here, and a torn count is impossible).
                self._round_claims.append(claimed.technique)
                self._emit("swarm.claim", worker=worker_id, round=round_no,
                           technique=claimed.technique, target=claimed.target)
                if self._budget is not None:
                    try:
                        self._budget.check()
                    except Exception:
                        break
                technique = TECHNIQUES.get(claimed.technique)
                desc = technique.description if technique else claimed.technique
                findings_before = len(self._ctx.findings.all())
                # Gen-3 class routing: every claimed hypothesis goes to the OWASP class
                # expert that owns the technique (see specialists.py) — claim/noise/
                # verify machinery unchanged. Unowned techniques still run the generic
                # EXPLOIT profile, and RED_CLASS_SPECIALISTS=0 disables routing outright
                # (the specialists-vs-generalist A/B switch).
                profile = profile_for(claimed.technique)
                exploit = self._make_specialist(
                    profile, agent_name=f"{profile.name}-w{worker_id}",
                    addon_suffix=f"\n\nYOUR ASSIGNED TARGET THIS TURN: "
                    f"{claimed.technique} on {claimed.target} — {desc}. Work ONLY this "
                    f"hypothesis; other workers are covering the rest of the attack tree "
                    f"in parallel. You are {profile.name}-w{worker_id}: if you need context "
                    f"you don't have (an error body, a token shape, whether a sibling already "
                    f"looked here), search_peer_traces shows what the OTHER workers' raw "
                    f"tool activity actually saw — hits are leads, prove them yourself.")
                summary = exploit.run(
                    f"{objective}\n\nThis run: EXPLOIT swarm worker {worker_id} round "
                    f"{round_no + 1} — prove {claimed.technique} on {claimed.target}.",
                    on_text=on_text) or summary
                # A landed finding (pending or already confirmed) means this hypothesis is
                # under its normal lifecycle now — sync() (called every turn inside
                # RedTeamAgent.run()) will promote the node to COMPLETED once VERIFY
                # confirms it, same self-grading-free path every other finding takes.
                #
                # If NOTHING landed, mark it FAILED rather than freeing it back to TODO:
                # claim() only claims a TODO node, so FAILED makes it unclaimable for the
                # REST OF THIS ROUND — freeing back to TODO instead causes an infinite
                # loop (this same worker, or another, immediately re-claims and re-tries
                # the identical empty hypothesis forever, since nothing else changed).
                # FAILED is not terminal across rounds: the next exploit round can still
                # reset stale FAILED nodes back to TODO via attack_tree.sync() picking up
                # new graph/finding state, so a hypothesis that failed with a thin surface
                # can still be retried once more context exists.
                if len(self._ctx.findings.all()) == findings_before:
                    self._attack_tree.mark(claimed.technique, claimed.target, FAILED)
            return summary

        summary = ""
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(worker, i) for i in range(n_workers)]
            for fut in as_completed(futures):
                try:
                    summary = fut.result() or summary
                except Exception as exc:
                    self._ctx.audit.record("orchestrator.swarm_worker_error", error=str(exc))
        return summary

    def _run_access_loop(self, objective: str, on_text=None) -> str:
        """Press a confirmed foothold as far as the kill chain says it goes.

        Runs ACCESS -> VERIFY (prove_privilege also only reaches pending_verification)
        repeatedly while KillChain.recommend() still names a pressing stage, stopping as
        soon as the achieved-stage set stops growing (no more progress from pressing) or
        the round ceiling / budget is hit — never a fixed number of rounds regardless of
        whether there's anything left to press.
        """
        access, killchain = getattr(self._ctx, "access", None), getattr(self._ctx, "killchain", None)
        if access is None or killchain is None:
            return ""
        summary = ""
        last_achieved = set(killchain.achieved())
        for rnd in range(self._max_access_rounds):
            if self._budget is not None:
                try:
                    self._budget.check()
                except Exception as exc:   # Halt
                    self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                    break
            objective_obj = getattr(self._ctx, "objective", None)
            recs = killchain.recommend(access, objective_obj)
            if not (_ACCESS_STAGES & set(recs)):
                break   # kill chain says the next move is new exploitation, not pressing
            self._ctx.audit.record("orchestrator.phase", phase="access", round=rnd,
                                   recommend=recs)
            specialist = self._make_specialist(ACCESS)
            summary = specialist.run(
                f"{objective}\n\nThis run: ACCESS round {rnd + 1} — press the confirmed "
                f"foothold toward: {', '.join(recs)}.", on_text=on_text) or summary

            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)

            achieved_now = set(killchain.achieved())
            if achieved_now == last_achieved:
                break   # stalled — pressing isn't advancing the kill chain further
            last_achieved = achieved_now
        return summary

    def _untested_remaining(self) -> int:
        if self._attack_tree is not None:
            return len(self._attack_tree.actionable(limit=999))
        if self._graph is not None:
            return len(self._graph.untested())
        return 1

    def run(self, objective: str, on_text=None) -> str:
        self._ctx.audit.record("orchestrator.start", objective=objective)
        # Reflection state: accumulated strategist notes steer later rounds and land in
        # the run directory (reflections.json) for the report/dashboard.
        self._reflections: list[dict] = []
        self._reflection_notes: list[str] = []
        # Phase B5 — the cross-round strategy state (redteam/strategy.py): directives
        # with TTLs, released on evidence or expiry, carried through reflection
        # failures; the strategist amends it instead of restarting every round.
        self._strategy = EngagementStrategy()
        self._round_claims: list[str] = []   # this round's claimed techniques (evidence)
        self._confirmed_seen: set = set()

        # Phase 0 — deterministic recon runs once, before either driver starts (see
        # cli.py's call to run_deterministic_recon) so single-agent and multi-agent runs
        # get identical treatment instead of duplicating this per-driver.

        # Phase 1 — recon (breadth, cheap model).
        self._phase("recon")
        recon = self._make_specialist(RECON)
        recon.run(f"{objective}\n\nThis run: RECON only — map the attack surface.", on_text=on_text)

        # Phase 2 — exploit rounds (depth, strong model) while there is untested work + budget.
        # Each round is followed by a VERIFY round in a FRESH, separate context: the
        # exploit specialist's checks only ever reach pending_verification, and nothing
        # downstream (objective credit, access-graph holds, the skill library) may act on
        # a finding until an independent context has tried to kill it and failed to.
        summary = ""
        for rnd in range(self._max_exploit_rounds):
            if self._budget is not None:
                try:
                    self._budget.check()
                except Exception as exc:   # Halt
                    self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                    break
            if self._untested_remaining() == 0 and rnd > 0:
                break
            objective_obj = getattr(self._ctx, "objective", None)
            if objective_obj is not None and objective_obj.achieved:
                self._ctx.audit.record("orchestrator.objective_achieved", round=rnd)
                break
            if self._attack_tree is not None and rnd > 0:
                # Give nodes that failed in an EARLIER round another chance now that this
                # round may have more graph/finding context — never reset within the same
                # round that set FAILED (see retry_failed()'s own docstring).
                self._attack_tree.retry_failed()
            self._phase("exploit", round=rnd)
            # Coach's notes from the last reflection steer this round's specialists.
            round_objective = objective
            if self._reflection_notes:
                round_objective = objective + "\n\n" + self._reflection_notes[-1]
            summary = self._run_exploit_swarm(round_objective, rnd, on_text) or summary

            # Learned-state broadcast (docs/multi-gambit.md §4.1): the store's
            # sufficient statistics go on the bus every round. Dashboards get "what
            # has the swarm learned"; peers subscribed via bandit.make_sync_handler
            # merge foreign payloads (this run's own source is skipped by the
            # handler — merging it back would double-count evidence). Evidence
            # only: min_trials=1 drops sampling-created zero-trial arms.
            tree_bandit = getattr(self._attack_tree, "bandit", None) \
                if self._attack_tree is not None else None
            if tree_bandit is not None:
                bus = getattr(self._ctx, "events", None)
                if bus is not None:
                    self._emit("bandit.state", arms=tree_bandit.export_state(min_trials=1),
                               source=getattr(bus, "run_id", "orchestrator"))

            self._phase("verify", round=rnd)
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)
            if self._attack_tree is not None:
                # Promote nodes this pass just confirmed NOW: only worker agents sync
                # (on their own turns), so a confirmation landing in the final verify
                # pass would otherwise never promote — no COMPLETED, no unlock, and
                # the bandit never sees its win. sync is idempotent (mark() refuses
                # same-status re-marks), so mid-run confirmations are not re-fed.
                self._attack_tree.sync(graph=self._graph, findings=self._ctx.findings.all())

            summary = self._run_access_loop(objective, on_text) or summary

            # Strategy reflection (Gen-2): a strong model reads this round's factual
            # digest and redirects the swarm — attack-tree boosts + coach's notes. The
            # run never depends on it succeeding (see reflection.py's failure policy).
            self._reflect_on_round(objective, rnd)

        # Phase 3 — logic round: business-logic bugs don't chain off exploit findings the
        # way access-pressing does, so one round after the surface is mapped and exploited
        # is enough — gated on the surface actually looking workflow-shaped, so an app
        # that's just static content doesn't burn a round and steps on nothing.
        budget_remains = True
        if self._budget is not None:
            try:
                self._budget.check()
            except Exception as exc:   # Halt
                self._ctx.audit.record("orchestrator.halt", reason=str(exc))
                budget_remains = False
        if budget_remains and _looks_workflow_shaped(self._graph):
            self._phase("logic")
            logic = self._make_specialist(LOGIC)
            summary = logic.run(
                f"{objective}\n\nThis run: LOGIC — find and prove business-logic bugs "
                f"on the workflow-shaped endpoints already mapped.", on_text=on_text) or summary

            self._phase("verify", phase_end="logic")
            still_pending = run_verify_pass(self._eng, self._tools, self._ctx, self._client,
                                            objective, budget=self._budget, on_text=on_text)
            if still_pending:
                self._ctx.audit.record("orchestrator.verify_incomplete", remaining=still_pending)
            if self._attack_tree is not None:
                self._attack_tree.sync(graph=self._graph, findings=self._ctx.findings.all())

        # Final creditor sweep (idempotent — see run_verify_pass note): catches a
        # confirmation that landed after the last verify pass funneled through.
        from .credit import credit_confirmed_findings
        try:
            credit_confirmed_findings(self._ctx)
        except Exception as exc:
            self._ctx.audit.record("credit.failed", error=str(exc))

        confirmed_count = len([f for f in self._ctx.findings.all()
                               if f.confidence == "confirmed"])
        self._ctx.audit.record("orchestrator.finish",
                               findings=len(self._ctx.findings.all()),
                               confirmed=confirmed_count)
        self._emit("run.summary", findings=len(self._ctx.findings.all()),
                   confirmed=confirmed_count, reflections=len(self._reflections))
        return summary

    def _reflect_on_round(self, objective: str, round_no: int) -> None:
        """One strategist call per completed round; folds the round's evidence into
        the cross-round strategy state (Phase B5, redteam/strategy.py), lets the
        strategist AMEND that state instead of restarting, and re-applies exactly
        the surviving directives to the tree. Never raises."""
        if not getattr(self._eng, "enable_reflection", True):
            return
        if self._budget is not None:
            try:
                self._budget.check()
            except Exception:
                return   # out of budget — skip the strategist, reflection is optional
        tail = []
        try:
            tail = self._ctx.audit.read_all()[-120:]
        except Exception:
            pass
        # Phase B5 — evidence in, deterministic decay out: what the swarm claimed
        # this round (its own claim loop) and what the tree confirmed (only NEWLY
        # completed nodes — confirmed_chain() repeats, the ledger must not), then
        # tick() expires TTLs and releases directives on evidence — whether or not
        # the strategist answers (forgetting is never LLM-dependent).
        confirmed: list[str] = []
        if self._attack_tree is not None:
            try:
                for n in self._attack_tree.confirmed_chain():
                    if n.id not in self._confirmed_seen:
                        self._confirmed_seen.add(n.id)
                        confirmed.append(n.technique)
            except Exception:
                confirmed = []
        self._strategy.observe_round(round_no + 1, self._round_claims, confirmed)
        self._round_claims = []
        released = self._strategy.tick(round_no + 1)
        objective_obj = getattr(self._ctx, "objective", None)
        reflection = reflect(
            self._client,
            objective_text=objective,
            round_no=round_no + 1,
            objective=objective_obj,
            findings=self._ctx.findings.all(),
            attack_tree=self._attack_tree,
            killchain=getattr(self._ctx, "killchain", None),
            audit_tail=tail,
            notes_so_far=self._reflection_notes,
            strategy_brief=self._strategy.brief() or None,
        )
        amended = None
        if reflection is not None:
            amended = self._strategy.amend(reflection, round_no + 1)
        applied = self._apply_strategy_state()
        if reflection is None:
            # The amplifier failed. The state still decayed above and the surviving
            # directives remain applied for the next round — the run continues
            # exactly as Gen-1 did, with a strategy that still forgets on schedule.
            if released:
                self._ctx.audit.record("orchestrator.strategy_released",
                                       round=round_no + 1, released=released)
                self._emit("strategy.state", round=round_no + 1, released=released,
                           **self._strategy.state())
            return
        reflection["round"] = round_no + 1
        reflection["boosts_applied"] = applied
        reflection["strategy_amended"] = amended
        reflection["strategy_released"] = released
        self._reflections.append(reflection)
        self._reflection_notes.append(coach_note(reflection))
        self._ctx.audit.record("orchestrator.reflection", round=round_no + 1,
                               boosts=applied)
        if released:
            self._ctx.audit.record("orchestrator.strategy_released",
                                   round=round_no + 1, released=released)
        self._emit("reflection", round=round_no + 1, boosts_applied=applied,
                   assessment=reflection["assessment"],
                   focus_next=reflection.get("focus_next") or [])
        self._emit("strategy.state", round=round_no + 1, released=released,
                   **self._strategy.state())
        # Persist for the report/dashboard even if the process dies mid-run.
        if self._manifest is not None:
            try:
                out_dir = Path(self._manifest[1]).parent
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "reflections.json").write_text(
                    json.dumps(self._reflections, indent=2, ensure_ascii=False),
                    encoding="utf-8")
                (out_dir / "strategy.json").write_text(
                    json.dumps(self._strategy.to_dict(), indent=2,
                               ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass

    def _apply_strategy_state(self) -> int:
        """Phase B5 — the strategy object is the ONLY writer of tree nudges: restore
        the nudge layer to neutral, then apply exactly the live directives. A
        released directive genuinely releases (the old apply-once-forever behavior
        is gone), and a live directive survives a failed reflection. Returns how
        many boosts landed on real nodes — the audit event's shape is unchanged."""
        if self._attack_tree is None:
            return 0
        reset_tree_nudges(self._attack_tree)
        press, avoid = self._strategy.directives_for_tree()
        try:
            return self._attack_tree.apply_strategy(prioritize=press,
                                                    deprioritize=avoid)
        except Exception:
            return 0

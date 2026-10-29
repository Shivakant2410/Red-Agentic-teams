"""Adversarial reasoning engine — a deterministic attack tree that thinks in chains.

A scanner runs checks. An attacker reasons: form a hypothesis, test it, and when it
lands, *chain* the foothold into the next attack. This module encodes that as a
deterministic tree of techniques (grounded in a MITRE ATT&CK-style TTP graph), which —
per Nakano et al. 2025 (arXiv:2509.07939) — constrains the model, kills the circular/
hallucinated reasoning self-guided agents fall into, and cuts query count sharply
(their result: -56%), with the biggest gains on small models (our free-model case).

The TAP idea (arXiv:2312.02119) supplies the loop: propose candidate attacks, let an
evaluator (our verification engine) score them, and prune refuted or low-value branches.

The adversarial edge is the `unlocks` graph: confirming a technique doesn't end the
branch — it spawns the follow-on attacks a real operator would pursue next
(SQLi -> auth bypass -> admin -> data exfil).
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

TODO, IN_PROGRESS, COMPLETED, FAILED = "todo", "in_progress", "completed", "failed"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    description: str            # what the operator does, and how to prove it
    unlocks: tuple[str, ...] = ()   # techniques this one chains into once confirmed
    priority: int = 50          # higher = pursue sooner
    chained: bool = False       # True = only appears after being unlocked, not seeded


# A compact, web-focused TTP graph. Entry techniques are seeded per discovered endpoint;
# chained techniques appear only when an upstream technique is confirmed.
TECHNIQUES: dict[str, Technique] = {t.id: t for t in [
    # -- entry techniques (seeded on every endpoint) --
    Technique("auth.test", "Authentication testing", "credential-access",
              "Log in with the `authenticate` tool (store a session); probe weak auth/session handling.",
              unlocks=("auth.bypass",), priority=90),
    Technique("access.control", "Broken access control", "privilege-escalation",
              "Use `verify_vulnerability`: one request to a protected URL with NO auth; "
              "conditions = status==200 AND body_regex for protected content. If it holds, broken.",
              unlocks=("privesc.admin",), priority=88),
    Technique("access.idor", "IDOR", "privilege-escalation",
              "Use `authenticate`, then `verify_vulnerability` with two requests (your own object "
              "as baseline, another id as payload) and conditions status==200 on payload AND "
              "json_differs on the id/owner path — proves you reached another principal's object.",
              unlocks=("data.exfil",), priority=85),
    Technique("injection.sqli", "SQL injection", "initial-access",
              "Send safe injection probes; CONFIRM via differential/time-based signal, "
              "not error text alone (error text can be planted — see ATOBench).",
              unlocks=("auth.bypass", "data.exfil"), priority=84),
    Technique("injection.cmd", "Command injection", "execution",
              "Test parameters reaching a shell; confirm via out-of-band or timing signal.",
              unlocks=("data.exfil",), priority=80),
    Technique("ssrf", "Server-side request forgery", "discovery",
              "Test URL/host params for SSRF to IN-SCOPE internal targets only.",
              unlocks=("internal.access",), priority=70),
    Technique("xss.reflected", "Reflected XSS", "initial-access",
              "Use `verify_vulnerability`: request with a unique token like <rtx931> in a "
              "reflected param; condition reflected_unescaped on that token proves the XSS.",
              unlocks=("session.steal",), priority=65),
    Technique("info.sensitive", "Sensitive data exposure", "collection",
              "Look for tokens, keys, PII, verbose errors, debug or backup endpoints.",
              priority=60),
    # -- chained follow-ups (only appear once unlocked) --
    Technique("auth.bypass", "Authentication bypass", "initial-access",
              "Use the confirmed weakness (e.g. SQLi) to `authenticate` as another user, then "
              "chain into test_access_control / test_idor as that principal.",
              unlocks=("privesc.admin", "data.exfil"), priority=95, chained=True),
    Technique("privesc.admin", "Privilege escalation to admin", "privilege-escalation",
              "From a foothold, reach administrative functionality.",
              unlocks=("data.exfil",), priority=93, chained=True),
    Technique("data.exfil", "Data exfiltration", "exfiltration",
              "Demonstrate access to sensitive data the account should not reach.",
              priority=92, chained=True),
    Technique("session.steal", "Session hijack via XSS", "credential-access",
              "Show the XSS can capture a session token.", priority=75, chained=True),
    Technique("internal.access", "Internal resource access via SSRF", "discovery",
              "Reach an in-scope internal service through the SSRF.", priority=72, chained=True),
]}

ENTRY_TECHNIQUES = tuple(t.id for t in TECHNIQUES.values() if not t.chained)

# OPSEC price of ONE attempt per technique (docs/multi-gambit.md §3.4) — what the
# bandit's cost-aware selection (BanditStore.select) divides the Thompson draw by,
# which is the budgeted-MAB objective: maximize confirmed findings per unit of
# DETECTABLE noise, not per request. Calibrated by loudness: quiet single-request
# checks cost 1-2, multi-probe injections 3-4, and anything that moves data off the
# target 5 — bulk reads are the loudest thing a web engagement does.
TECHNIQUE_COST: dict[str, float] = {
    "auth.test": 1.0, "xss.reflected": 1.0, "info.sensitive": 1.0,
    "access.control": 2.0, "access.idor": 2.0, "ssrf": 2.0,
    "session.steal": 2.0, "internal.access": 2.0,
    "injection.sqli": 3.0, "auth.bypass": 3.0,
    "injection.cmd": 4.0, "privesc.admin": 4.0,
    "data.exfil": 5.0,
}
_DEFAULT_TECHNIQUE_COST = 1.0


def technique_cost(technique_id: str) -> float:
    """OPSEC price of one attempt of this technique. Unknown ids default to quiet
    (1.0) — a missing cost must never make the selector over-spend the budget."""
    return TECHNIQUE_COST.get(technique_id, _DEFAULT_TECHNIQUE_COST)

# Map a finding's CWE to the technique it confirms, so results drive the tree.
_CWE_TO_TECHNIQUE = {
    "CWE-89": "injection.sqli", "CWE-78": "injection.cmd", "CWE-79": "xss.reflected",
    "CWE-918": "ssrf", "CWE-639": "access.idor", "CWE-284": "access.control",
    "CWE-287": "auth.test", "CWE-200": "info.sensitive",
    "CWE-22": "info.sensitive", "CWE-98": "info.sensitive",  # path traversal / file inclusion
}


@dataclass
class AttackNode:
    technique: str
    target: str
    status: str = TODO
    findings: str = ""
    bucket: str = ""   # endpoint-shape context for the bandit (see bandit.py); "" = unknown

    @property
    def id(self) -> str:
        return f"{self.technique}@{self.target}"


class AttackTree:
    def __init__(self, path: str | Path | None = None, bandit=None):
        self._nodes: dict[str, AttackNode] = {}
        self._path = Path(path) if path else None
        # Optional BanditStore (see bandit.py): when given, actionable()'s ranking blends
        # the static priority table with a learned per-(technique, bucket) win rate, and
        # mark()/claim() feed outcomes back into it. None (the default) preserves the old
        # fixed-priority-only behavior exactly — this is additive, never required.
        self._bandit = bandit
        # Per-run strategy nudges from the LLM strategist (see reflection.py), applied in
        # actionable()'s ranking. Node-level boosts come from prioritize[] (technique@target
        # pairs the strategist wants attacked next); technique-level penalties from
        # deprioritize[]. These can only REORDER already-in-scope work — never create,
        # authorize, or unlock anything — which keeps the strategist's influence safe.
        self._strategy_boost: dict[str, float] = {}
        self._technique_penalty: dict[str, float] = {}
        # RLock: sync()/mark()/briefing() all call other locked methods on self from the
        # SAME thread (sync -> seed_endpoint -> _add, mark -> _unlock -> _add, briefing ->
        # confirmed_chain/actionable) — a plain Lock would deadlock. Needed once a parallel
        # exploit swarm (orchestrator.py) has multiple specialist threads syncing/reading
        # this ONE shared tree concurrently; there was no synchronization here before.
        self._lock = threading.RLock()
        if self._path and self._path.exists():
            for row in json.loads(self._path.read_text(encoding="utf-8")):
                n = AttackNode(**row)
                self._nodes[n.id] = n

    @property
    def bandit(self):
        """The attached BanditStore (or None). Read-only on purpose: reward recording
        stays inside mark(), the single write path; the orchestrator only ever reads
        this for ranked selection (select) and learned-state export (export_state)."""
        return self._bandit

    # -- construction ----------------------------------------------------------

    def _add(self, technique: str, target: str, status: str = TODO, bucket: str = "") -> AttackNode:
        with self._lock:
            node = self._nodes.get(f"{technique}@{target}")
            if node is None:
                node = AttackNode(technique=technique, target=target, status=status, bucket=bucket)
                self._nodes[node.id] = node
            elif bucket and not node.bucket:
                node.bucket = bucket   # sync() learning the bucket after the node already existed
            return node

    def seed_endpoint(self, target: str, bucket: str = "") -> None:
        """Seed the entry techniques for a newly discovered endpoint. `bucket` (see
        bandit.py's bucket_for_endpoint) is optional: passive_recon/static_source seed
        endpoints before a KnowledgeGraph node exists for them, so they seed with "" and
        pick up a real bucket later via sync()."""
        with self._lock:
            for tid in ENTRY_TECHNIQUES:
                self._add(tid, target, bucket=bucket)

    def sync(self, graph=None, findings: list | None = None) -> None:
        """Grow the tree from current knowledge: seed new endpoints, and mark techniques
        confirmed by findings (which unlocks their chained follow-ups)."""
        with self._lock:
            if graph is not None:
                from .bandit import bucket_for_endpoint
                from .knowledge import ENDPOINT
                for ep in graph.nodes(ENDPOINT):
                    self.seed_endpoint(ep.key, bucket=bucket_for_endpoint(ep.key, ep))
            for f in (findings or []):
                confidence = getattr(f, "confidence", None) or (f.get("confidence") if isinstance(f, dict) else None)
                if confidence != "confirmed":
                    continue
                cwe = getattr(f, "cwe", None) or (f.get("cwe") if isinstance(f, dict) else "")
                target = getattr(f, "target", None) or (f.get("target") if isinstance(f, dict) else "")
                tid = _CWE_TO_TECHNIQUE.get((cwe or "").upper())
                if tid and target:
                    self.confirm(tid, target)

    # -- state transitions -----------------------------------------------------

    def mark(self, technique: str, target: str, status: str, findings: str = "") -> None:
        with self._lock:
            node = self._add(technique, target)
            node.status = status
            if findings:
                node.findings = findings
            if status == COMPLETED:
                self._unlock(technique, target)
            if self._bandit is not None and status in (COMPLETED, FAILED):
                self._bandit.record(technique, node.bucket, won=(status == COMPLETED))
            self._flush()

    def confirm(self, technique: str, target: str, findings: str = "") -> None:
        self.mark(technique, target, COMPLETED, findings)

    def retry_failed(self) -> int:
        """Give every FAILED node (a swarm worker tried it this round and nothing
        landed — see orchestrator._run_exploit_swarm) another chance, by resetting it to
        TODO so it's claimable again. Call this ONCE per orchestrator round, never
        inside sync() (which runs every agent turn) — resetting more often than once a
        round would undo the FAILED status within the same round it was set, which is
        exactly the infinite empty-retry loop FAILED exists to prevent. Returns how many
        nodes were reset."""
        with self._lock:
            reset = 0
            for node in self._nodes.values():
                if node.status == FAILED:
                    node.status = TODO
                    reset += 1
            if reset:
                self._flush()
            return reset

    def _unlock(self, technique: str, target: str) -> None:
        """A confirmed technique spawns its chained follow-ups — the adversarial chain."""
        with self._lock:
            for child in TECHNIQUES.get(technique, Technique("", "", "", "")).unlocks:
                self._add(child, target, status=TODO)

    # -- reasoning output ------------------------------------------------------

    def actionable(self, limit: int = 6) -> list[AttackNode]:
        """The prioritized frontier: what to attack next. Chained (unlocked) follow-ups
        outrank fresh entry techniques — press the foothold, don't wander.

        When a BanditStore is attached (see bandit.py), the static priority is nudged by
        a Thompson-sampled per-(technique, bucket) win-rate learned across past
        engagements — e.g. IDOR sampling higher than SQLi specifically on endpoints
        shaped like /resource/<numeric-id>, because that's what has actually confirmed
        on that shape before. With no bandit attached (the default), ranking is exactly
        the old fixed-priority behavior — this is a pure addition, never a requirement."""
        with self._lock:
            live = [n for n in self._nodes.values() if n.status in (TODO, IN_PROGRESS)]

            def key(n: AttackNode):
                t = TECHNIQUES.get(n.technique)
                base = t.priority if t else 0
                boost = 100 if (t and t.chained) else 0   # pursue the chain first
                if self._bandit is not None:
                    # Centered scaling: a sample of 0.5 (no evidence yet) adds nothing;
                    # evidence shifts the technique up or down within its priority tier,
                    # it never lets a low-priority technique leapfrog the chain boost.
                    learned = (self._bandit.sample(n.technique, n.bucket) - 0.5) * 40
                    base_shift = base + learned
                else:
                    base_shift = base
                strategy = (self._strategy_boost.get(n.id, 0.0)
                            + self._technique_penalty.get(n.technique, 0.0))
                return base_shift + boost + strategy
            return sorted(live, key=key, reverse=True)[:limit]

    def confirmed_chain(self) -> list[AttackNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.status == COMPLETED]

    def apply_strategy(self, prioritize: list[dict] | None = None,
                       deprioritize: list[str] | None = None) -> int:
        """Apply the LLM strategist's per-round nudges (see reflection.py).

        prioritize: [{"technique", "target"}] — those tree nodes jump the frontier queue
        (a +25 shift is enough to outrank everything in their priority tier without
        letting a non-chained node leapfrog the +100 chain boost).
        deprioritize: [technique ids] — pushed down this run (-25), never removed.

        Boosts only apply to nodes that actually exist; unknown technique@target pairs
        from a hallucinating strategist are counted and ignored. Returns how many
        boosts landed on real nodes (useful for the reflection audit event)."""
        applied = 0
        with self._lock:
            for item in (prioritize or []):
                nid = f"{item.get('technique', '')}@{item.get('target', '')}"
                if nid in self._nodes:
                    self._strategy_boost[nid] = 25.0
                    applied += 1
            for tid in (deprioritize or []):
                if tid in TECHNIQUES:
                    self._technique_penalty[tid] = -25.0
                    applied += 1
            self._flush()
        return applied

    def claim(self, technique: str, target: str) -> bool:
        """Atomically claim an actionable node for one swarm worker: set it to
        IN_PROGRESS only if it is currently TODO. Returns True if this call won the
        claim. Without this, two swarm workers could both read the same TODO node from
        actionable() and both work it — not incorrect (duplicate proof attempts just
        dedupe in FindingStore), but wasted turns/tokens, which matters under a tight
        free-model budget."""
        with self._lock:
            node = self._nodes.get(f"{technique}@{target}")
            if node is None or node.status != TODO:
                return False
            node.status = IN_PROGRESS
            self._flush()
            return True

    def briefing(self, limit: int = 6) -> str:
        with self._lock:
            lines = ["[ADVERSARIAL PLAN]"]
            chain = self.confirmed_chain()
            if chain:
                lines.append("Footholds confirmed (press these into their follow-ups):")
                for n in chain:
                    t = TECHNIQUES.get(n.technique)
                    nxt = ", ".join(t.unlocks) if t and t.unlocks else "(terminal)"
                    lines.append(f"  [done] {t.name if t else n.technique} on {n.target} -> unlocks: {nxt}")
            nxt = self.actionable(limit)
            if nxt:
                lines.append("Next attacks (highest-value first):")
                for n in nxt:
                    t = TECHNIQUES.get(n.technique)
                    tag = "[CHAIN]" if (t and t.chained) else ""
                    lines.append(f"  -> {tag} {t.name if t else n.technique} on {n.target}: "
                                 f"{t.description if t else ''}")
            else:
                lines.append("No open attack paths — map more surface or deepen tested endpoints.")
            return "\n".join(lines)

    def summary(self) -> dict:
        with self._lock:
            by_status: dict[str, int] = {}
            for n in self._nodes.values():
                by_status[n.status] = by_status.get(n.status, 0) + 1
            return {"nodes": len(self._nodes), "by_status": by_status,
                    "confirmed": len(self.confirmed_chain())}

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps([asdict(n) for n in self._nodes.values()], indent=2),
                              encoding="utf-8")

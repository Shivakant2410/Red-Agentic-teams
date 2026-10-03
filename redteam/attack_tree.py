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

    @property
    def id(self) -> str:
        return f"{self.technique}@{self.target}"


class AttackTree:
    def __init__(self, path: str | Path | None = None):
        self._nodes: dict[str, AttackNode] = {}
        self._path = Path(path) if path else None
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

    # -- construction ----------------------------------------------------------

    def _add(self, technique: str, target: str, status: str = TODO) -> AttackNode:
        with self._lock:
            node = AttackNode(technique=technique, target=target, status=status)
            self._nodes.setdefault(node.id, node)
            return self._nodes[node.id]

    def seed_endpoint(self, target: str) -> None:
        """Seed the entry techniques for a newly discovered endpoint."""
        with self._lock:
            for tid in ENTRY_TECHNIQUES:
                self._add(tid, target)

    def sync(self, graph=None, findings: list | None = None) -> None:
        """Grow the tree from current knowledge: seed new endpoints, and mark techniques
        confirmed by findings (which unlocks their chained follow-ups)."""
        with self._lock:
            if graph is not None:
                from .knowledge import ENDPOINT
                for ep in graph.nodes(ENDPOINT):
                    self.seed_endpoint(ep.key)
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
        outrank fresh entry techniques — press the foothold, don't wander."""
        with self._lock:
            live = [n for n in self._nodes.values() if n.status in (TODO, IN_PROGRESS)]

            def key(n: AttackNode):
                t = TECHNIQUES.get(n.technique)
                base = t.priority if t else 0
                boost = 100 if (t and t.chained) else 0   # pursue the chain first
                return base + boost
            return sorted(live, key=key, reverse=True)[:limit]

    def confirmed_chain(self) -> list[AttackNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.status == COMPLETED]

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

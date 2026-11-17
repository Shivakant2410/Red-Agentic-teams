"""The ACCESS GRAPH — what the operator currently holds, and what it unlocks.

Our knowledge graph models the *target's surface* (hosts, endpoints, parameters). That is
a scanner's view. An adversary reasons over a different structure entirely: **what do I
possess right now, and what does it get me?**

Nodes are things you can hold or reach:
    principal   an identity you can act as (user, service account, role)
    credential  a secret that authenticates as some principal (token, password, key)
    host        a machine/service you can reach or execute on
    resource    something of value (a datastore, a file, an admin function)
    privilege   a capability held over something

Edges are how one thing yields another — `holds`, `authenticates_as`, `can_access`,
`escalates_to`, `pivots_to`, `reveals`. A node is `held` only when access has actually
been demonstrated, so the graph never flatters us about what we control.

The two questions it answers are the ones that drive every adversary decision:
    - Am I there yet?          -> reached(target)
    - What gets me closer?     -> paths_to(target) / frontier()
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

# One evidence vocabulary, one identity rule (redteam.knowledge): access
# provenance dedupes by the same stable evidence_id the swarm registry and the
# KnowledgeGraph use, so repeated holds/synchronizations never grow it.
from .knowledge import merge_evidence_refs

# Phase E2: hold-lifecycle vocabulary lives in states.py (the one lifecycle
# registry). REVOKED is a currency state, not deletion — the historical hold,
# its evidence and its revocation record all stay on file.
from .states import HOLD_REVOKED

PRINCIPAL, CREDENTIAL, HOST, RESOURCE, PRIVILEGE = (
    "principal", "credential", "host", "resource", "privilege")
KINDS = (PRINCIPAL, CREDENTIAL, HOST, RESOURCE, PRIVILEGE)

# How one asset yields another.
HOLDS, AUTHENTICATES_AS, CAN_ACCESS = "holds", "authenticates_as", "can_access"
ESCALATES_TO, PIVOTS_TO, REVEALS = "escalates_to", "pivots_to", "reveals"

# Phase E2: bounded provenance strings (same discipline as the swarm — shared
# text is stored, never executed, never allowed to bloat the file).
_MAX_REASON = 200
_MAX_RAW = 300
_INVALIDATION_HISTORY_CAP = 32


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _clip(text: str, limit: int) -> str:
    text = str(text or "")
    return text[:limit]


@dataclass
class AccessNode:
    kind: str
    key: str
    attrs: dict = field(default_factory=dict)
    held: bool = False            # demonstrated, not assumed
    evidence: str = ""
    source: str = ""
    first_seen: str = field(default_factory=_now)
    # Phase E2 (additive — every field defaults, so pre-E2 access.json rows
    # load unchanged via the existing AccessNode(**row) path):
    last_seen: str = ""           # refreshed whenever the holding is re-demonstrated
    evidence_refs: list[dict] = field(default_factory=list)  # EvidenceRef-shaped dicts (swarm vocabulary)
    invalidated_at: str = ""      # when the hold stopped being current (HOLD_REVOKED)
    invalidation_reason: str = ""

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"

    @property
    def revoked(self) -> bool:
        return self.held is False and bool(self.invalidated_at)


class AccessGraph:
    def __init__(self, path: str | Path | None = None):
        self._nodes: dict[str, AccessNode] = {}
        self._edges: set[tuple[str, str, str]] = set()
        self._path = Path(path) if path else None
        # RLock (not Lock): hold()/briefing()/summary()/paths_to() call other locked
        # methods on self (e.g. hold() -> observe(), briefing() -> held()/frontier()) from
        # the SAME thread, which would deadlock a plain Lock. Needed once a parallel
        # exploit swarm (see orchestrator.py) has multiple specialist threads hitting one
        # shared AccessGraph concurrently — this was pure in-memory dict/set mutation with
        # no synchronization at all before.
        self._lock = threading.RLock()
        if self._path and self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                for row in data.get("nodes", []):
                    n = AccessNode(**row)
                    self._nodes[n.id] = n
                for e in data.get("edges", []):
                    self._edges.add(tuple(e))
            except (json.JSONDecodeError, TypeError):
                pass

    # -- building --------------------------------------------------------------

    def observe(self, kind: str, key: str, attrs: dict | None = None,
                source: str = "", evidence_refs: list[dict] | None = None) -> AccessNode:
        """Record that something EXISTS (not that we hold it).

        A node is commonly observed first (discovery) and held later (proof) — e.g. a
        resource is noticed, then a verified finding proves it's reachable. `source`
        therefore upgrades on re-observation when a new one is given: without this, a bare
        `source=""`/"agent" first-touch would permanently stick, and no later proving
        mechanism could ever satisfy a REQUIRED_SOURCE gate in objective.py (this silently
        defeated the DATA_ACCESS/HOST_ACCESS gating the first time it was exercised).

        Phase E2: `evidence_refs` (optional, EvidenceRef-shaped dicts from the swarm
        vocabulary) records provenance for this observation — idempotently: a
        reference whose stable identity (evidence_id) is already recorded is not
        duplicated. Existing callers are unaffected."""
        with self._lock:
            node = AccessNode(kind=kind, key=key, attrs=dict(attrs or {}), source=source)
            existing = self._nodes.get(node.id)
            if existing:
                existing.attrs.update(attrs or {})
                if source:
                    existing.source = source
                if evidence_refs:
                    existing.evidence_refs = merge_evidence_refs(
                        existing.evidence_refs, evidence_refs)
                # the update path persists like new-node insertion — a memory-only
                # update would be silently lost on restart
                self._flush()
                return existing
            if evidence_refs:
                node.evidence_refs = merge_evidence_refs(node.evidence_refs,
                                                         evidence_refs)
            self._nodes[node.id] = node
            self._flush()
            return node

    def hold(self, kind: str, key: str, evidence: str = "", attrs: dict | None = None,
             source: str = "", evidence_refs: list[dict] | None = None) -> AccessNode:
        """Record that we DEMONSTRABLY hold this (a session, a credential, a foothold).

        Phase E2: re-demonstration refreshes last_seen; re-holding a REVOKED node
        re-activates it (states.py access_hold: revoked -> held) — which is legal
        ONLY through this demonstration path, never through observe(). Whether the
        (re-)hold can satisfy an objective criterion is still decided solely by the
        objective.REQUIRED_SOURCE gate on `source`, so an agent's unsupported
        assertion remains unable to credit anything, resurrected or not. The
        revocation record survives the re-hold (append-only history in attrs).
        Supplied evidence_refs are recorded exactly once — observe() records them
        (idempotently), and this method must not append them again."""
        with self._lock:
            node = self.observe(kind, key, attrs, source, evidence_refs=evidence_refs)
            if node.revoked:
                history = list(node.attrs.get("invalidation_history") or [])
                history.append({"invalidated_at": node.invalidated_at,
                                "reason": node.invalidation_reason,
                                "re_held_at": _now(),
                                "re_hold_source": _clip(source, 80)})
                node.attrs["invalidation_history"] = history[-_INVALIDATION_HISTORY_CAP:]
                node.invalidated_at = ""
                node.invalidation_reason = ""
            node.held = True
            node.last_seen = _now()
            if evidence:
                node.evidence = _clip(evidence, _MAX_RAW)
            self._flush()
            return node

    def revoke(self, kind: str, key: str, reason: str = "") -> bool:
        """Record that a demonstrated holding is NO LONGER current (Phase E2,
        states.py access_hold: held -> revoked). Written by the retest-fixed
        bridge; nothing here deletes nodes or edges, and the historical evidence
        (evidence, source, evidence_refs, when/why it was revoked) stays on file
        — an auditor can always see that the access WAS demonstrated. Revoked
        nodes drop out of held()/reached()/frontier(), so no downstream consumer
        (objective crediting, kill-chain recommendation, projections) treats a
        revoked holding as current. Returns whether a held node was revoked;
        revoking an unknown or already-revoked node is a safe no-op."""
        with self._lock:
            node = self._nodes.get(f"{kind}:{key}")
            if node is None or not node.held:
                return False
            node.held = False
            node.invalidated_at = _now()
            node.invalidation_reason = _clip(reason, _MAX_REASON)
            history = list(node.attrs.get("invalidation_history") or [])
            history.append({"invalidated_at": node.invalidated_at,
                            "reason": _clip(reason, _MAX_REASON)})
            node.attrs["invalidation_history"] = history[-_INVALIDATION_HISTORY_CAP:]
            self._flush()
            return True

    def revoked_nodes(self) -> list[AccessNode]:
        """Historical holdings that were demonstrated once and are no longer
        current — the honesty view (projections and reports render these with
        their status instead of hiding them)."""
        with self._lock:
            return [n for n in self._nodes.values() if n.revoked]

    def link(self, src_id: str, relation: str, dst_id: str,
             evidence_refs: list[dict] | None = None) -> None:
        """Phase E2: `evidence_refs` (optional) records provenance for this
        relationship as node-adjacent metadata in attrs of the source node
        (edges stay bare tuples — see ADR-002 §Edge metadata)."""
        with self._lock:
            self._edges.add((src_id, relation, dst_id))
            if evidence_refs:
                src = self._nodes.get(src_id)
                if src is not None:
                    out = list(src.attrs.get("edge_evidence") or [])
                    out.append({"edge": [src_id, relation, dst_id],
                                "evidence_refs": evidence_refs})
                    src.attrs["edge_evidence"] = out[-_INVALIDATION_HISTORY_CAP:]
            self._flush()

    # -- questions an adversary asks -------------------------------------------

    def held(self) -> list[AccessNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.held]

    def release(self, kind: str, key: str) -> AccessNode | None:
        """The inverse of hold(): the demonstrated holding is no longer active
        (e.g. a retest verdict of FIXED — the weakness that proved it is gone).
        The node and its evidence REMAIN: held=False plus retained evidence is
        the graph's own invalidation record (invalidated_holdings()), so any
        consumer can tell a stale milestone from a live holding. Idempotent."""
        with self._lock:
            node = self._nodes.get(f"{kind}:{key}")
            if node is not None and node.held:
                node.held = False
                self._flush()
            return node

    def invalidated_holdings(self) -> list[AccessNode]:
        """Demonstrated-then-invalidated holdings: nodes that carry evidence
        (evidence is only written on hold()) but are no longer active.
        observe()-only nodes never appear here. This is the record the
        orchestrator's ACCESS prerequisite gate trusts over a possibly-stale
        KillChain INITIAL_ACCESS stage."""
        with self._lock:
            return [n for n in self._nodes.values() if not n.held and n.evidence]

    def reached(self, target_key: str) -> bool:
        """Do we hold the objective's target (by key, any kind)?"""
        with self._lock:
            return any(n.held and n.key == target_key for n in self._nodes.values())

    def _neighbors(self, node_id: str) -> list[tuple[str, str]]:
        with self._lock:
            return [(rel, dst) for (src, rel, dst) in self._edges if src == node_id]

    def paths_to(self, target_key: str, max_depth: int = 6) -> list[list[str]]:
        """Shortest known routes from something we hold to the target."""
        with self._lock:
            targets = {n.id for n in self._nodes.values() if n.key == target_key}
            if not targets:
                return []
            results: list[list[str]] = []
            for start in self.held():
                queue = deque([(start.id, [start.id])])
                seen = {start.id}
                while queue:
                    current, path = queue.popleft()
                    if current in targets and len(path) > 1:
                        results.append(path)
                        break
                    if len(path) > max_depth:
                        continue
                    for _, dst in self._neighbors(current):
                        if dst not in seen:
                            seen.add(dst)
                            queue.append((dst, path + [dst]))
            return sorted(results, key=len)

    def distance_to(self, target_key: str) -> int | None:
        with self._lock:
            if self.reached(target_key):
                return 0
            paths = self.paths_to(target_key)
            return (len(paths[0]) - 1) if paths else None

    def frontier(self) -> list[AccessNode]:
        """Things we hold that have known unexploited edges — where to push next."""
        with self._lock:
            out = []
            for node in self.held():
                for _, dst in self._neighbors(node.id):
                    target = self._nodes.get(dst)
                    if target is not None and not target.held:
                        out.append(target)
            return out

    # -- reporting -------------------------------------------------------------

    def briefing(self, objective=None) -> str:
        lines = ["[ACCESS HELD]"]
        holdings = self.held()
        if not holdings:
            lines.append("  nothing yet — you have no foothold. Getting ANY authenticated "
                         "principal or host access is the priority.")
        for n in holdings:
            lines.append(f"  {n.kind}: {n.key}" + (f"  ({n.attrs.get('note')})" if n.attrs.get("note") else ""))

        # Phase E2: previously-held access that is no longer current (retest
        # proved the fix, credential revoked, ...). Honest surface, not history
        # rewriting — the agent must not keep leaning on a dead foothold, and
        # must not pretend it never existed.
        revoked = self.revoked_nodes()
        if revoked:
            lines.append("[NO LONGER HELD — re-demonstrate before relying on these]")
            for n in revoked[-6:]:
                why = n.invalidation_reason or "invalidated"
                lines.append(f"  x {n.kind}: {n.key}  ({why[:120]})")

        frontier = self.frontier()
        if frontier:
            lines.append("[REACHABLE NEXT — press these]")
            for n in frontier[:6]:
                lines.append(f"  -> {n.kind}: {n.key}")

        if objective is not None:
            for c in objective.outstanding():
                if not c.target:
                    continue
                d = self.distance_to(c.target)
                if d == 0:
                    lines.append(f"[OBJECTIVE TARGET REACHED] {c.target} — prove it and mark the criterion.")
                elif d is None:
                    lines.append(f"[NO KNOWN PATH] to {c.target} — find one (discovery, "
                                 f"credential access, lateral movement).")
                else:
                    lines.append(f"[DISTANCE] {d} hop(s) from what you hold to {c.target}.")
        return "\n".join(lines)

    def summary(self) -> dict:
        with self._lock:
            by_kind: dict[str, int] = {}
            for n in self._nodes.values():
                by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
            return {"nodes": len(self._nodes), "held": len(self.held()),
                    "revoked": len(self.revoked_nodes()),
                    "edges": len(self._edges), "by_kind": by_kind}

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(
            {"nodes": [asdict(n) for n in self._nodes.values()],
             "edges": sorted(list(self._edges))}, indent=2, ensure_ascii=False),
            encoding="utf-8")

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
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

PRINCIPAL, CREDENTIAL, HOST, RESOURCE, PRIVILEGE = (
    "principal", "credential", "host", "resource", "privilege")
KINDS = (PRINCIPAL, CREDENTIAL, HOST, RESOURCE, PRIVILEGE)

# How one asset yields another.
HOLDS, AUTHENTICATES_AS, CAN_ACCESS = "holds", "authenticates_as", "can_access"
ESCALATES_TO, PIVOTS_TO, REVEALS = "escalates_to", "pivots_to", "reveals"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class AccessNode:
    kind: str
    key: str
    attrs: dict = field(default_factory=dict)
    held: bool = False            # demonstrated, not assumed
    evidence: str = ""
    source: str = ""
    first_seen: str = field(default_factory=_now)

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"


class AccessGraph:
    def __init__(self, path: str | Path | None = None):
        self._nodes: dict[str, AccessNode] = {}
        self._edges: set[tuple[str, str, str]] = set()
        self._path = Path(path) if path else None
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
                source: str = "") -> AccessNode:
        """Record that something EXISTS (not that we hold it)."""
        node = AccessNode(kind=kind, key=key, attrs=dict(attrs or {}), source=source)
        existing = self._nodes.get(node.id)
        if existing:
            existing.attrs.update(attrs or {})
            return existing
        self._nodes[node.id] = node
        self._flush()
        return node

    def hold(self, kind: str, key: str, evidence: str = "", attrs: dict | None = None,
             source: str = "") -> AccessNode:
        """Record that we DEMONSTRABLY hold this (a session, a credential, a foothold)."""
        node = self.observe(kind, key, attrs, source)
        node.held = True
        if evidence:
            node.evidence = evidence
        self._flush()
        return node

    def link(self, src_id: str, relation: str, dst_id: str) -> None:
        self._edges.add((src_id, relation, dst_id))
        self._flush()

    # -- questions an adversary asks -------------------------------------------

    def held(self) -> list[AccessNode]:
        return [n for n in self._nodes.values() if n.held]

    def reached(self, target_key: str) -> bool:
        """Do we hold the objective's target (by key, any kind)?"""
        return any(n.held and n.key == target_key for n in self._nodes.values())

    def _neighbors(self, node_id: str) -> list[tuple[str, str]]:
        return [(rel, dst) for (src, rel, dst) in self._edges if src == node_id]

    def paths_to(self, target_key: str, max_depth: int = 6) -> list[list[str]]:
        """Shortest known routes from something we hold to the target."""
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
        if self.reached(target_key):
            return 0
        paths = self.paths_to(target_key)
        return (len(paths[0]) - 1) if paths else None

    def frontier(self) -> list[AccessNode]:
        """Things we hold that have known unexploited edges — where to push next."""
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
        by_kind: dict[str, int] = {}
        for n in self._nodes.values():
            by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
        return {"nodes": len(self._nodes), "held": len(self.held()),
                "edges": len(self._edges), "by_kind": by_kind}

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(
            {"nodes": [asdict(n) for n in self._nodes.values()],
             "edges": sorted(list(self._edges))}, indent=2, ensure_ascii=False),
            encoding="utf-8")

"""Target knowledge graph — the agent's memory of the engagement.

This is what separates a coherent long-horizon agent from a stateless chat loop. Every
observation the agent makes (a live host, an open service, a discovered endpoint, a
parameter, a credential, a technology fingerprint) becomes a typed node, deduplicated
and correlated with what's already known, with edges expressing structure
(host -> service -> endpoint -> parameter). The planner reasons over THIS, not over a
transcript, so step 300 still knows what step 3 found.

It also tracks methodology coverage per asset, so testing is systematic (did we test
auth on this endpoint? injection? access control?) rather than ad hoc.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Node kinds in the graph.
HOST = "host"
SERVICE = "service"          # e.g. 203.0.113.5:443 https
ENDPOINT = "endpoint"        # e.g. https://api.acme.example/v1/users
PARAMETER = "parameter"      # a query/body/header parameter on an endpoint
TECHNOLOGY = "technology"    # nginx, Django, WordPress 6.2, ...
CREDENTIAL = "credential"    # a discovered/used credential (store references, not secrets in the report)

# Methodology checklist applied per endpoint (subset of OWASP WSTG, extend freely).
WSTG_CHECKS = (
    "auth", "access_control", "injection", "xss", "ssrf",
    "idor", "misconfig", "sensitive_data", "business_logic",
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Node:
    kind: str
    key: str                                  # unique within kind (e.g. the URL, host:port)
    attrs: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)   # which tool/step observed it
    confidence: str = "observed"              # observed | corroborated
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    coverage: dict = field(default_factory=dict)  # check -> status (untested|tested|finding)

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"


class KnowledgeGraph:
    def __init__(self, path: str | Path | None = None):
        self._nodes: dict[str, Node] = {}
        self._edges: set[tuple[str, str, str]] = set()  # (src_id, relation, dst_id)
        self._path = Path(path) if path else None
        # A parallel exploit swarm (multiple specialist contexts fanned out over
        # AttackTree.actionable() targets, run concurrently) calls observe()/
        # mark_coverage() from different threads against this ONE shared graph. Without
        # a lock, concurrent dict/set mutation here is a real data race (lost updates at
        # best, a corrupted _nodes dict at worst) — not a theoretical concern once
        # anything calls this from more than one thread.
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            self._load()

    # -- mutation --------------------------------------------------------------

    def observe(self, kind: str, key: str, attrs: dict | None = None,
                source: str = "", relate_to: str | None = None,
                relation: str = "has") -> Node:
        """Add or merge a node. Re-observing an existing node corroborates it and merges
        attributes rather than duplicating — this is the dedup/correlation core."""
        with self._lock:
            node_id = f"{kind}:{key}"
            node = self._nodes.get(node_id)
            if node is None:
                node = Node(kind=kind, key=key, attrs=dict(attrs or {}))
                if kind == ENDPOINT:
                    node.coverage = {c: "untested" for c in WSTG_CHECKS}
                self._nodes[node_id] = node
            else:
                for k, v in (attrs or {}).items():
                    node.attrs[k] = v
                node.last_seen = _now()
                if source and source not in node.sources:
                    # a second independent source corroborates the observation
                    node.confidence = "corroborated"
            if source and source not in node.sources:
                node.sources.append(source)
            if relate_to and relate_to in self._nodes:
                self._edges.add((relate_to, relation, node_id))
            self._flush()
            return node

    def mark_coverage(self, endpoint_key: str, check: str, status: str) -> None:
        """Record that a methodology check was performed on an endpoint."""
        with self._lock:
            node = self._nodes.get(f"{ENDPOINT}:{endpoint_key}")
            if node is not None and check in node.coverage:
                node.coverage[check] = status
                self._flush()

    # -- queries ---------------------------------------------------------------
    # Reads take the lock too: a concurrent writer resizing self._nodes mid-iteration
    # (from another swarm thread) can raise "dictionary changed size during iteration"
    # even on a pure read, not just corrupt data — the lock makes every read a consistent
    # snapshot, same guarantee the mutation methods above give writers.

    def nodes(self, kind: str | None = None) -> list[Node]:
        with self._lock:
            return [n for n in self._nodes.values() if kind is None or n.kind == kind]

    def neighbors(self, node_id: str, relation: str | None = None) -> list[Node]:
        with self._lock:
            out = []
            for src, rel, dst in self._edges:
                if src == node_id and (relation is None or rel == relation):
                    if dst in self._nodes:
                        out.append(self._nodes[dst])
            return out

    def untested(self) -> list[tuple[str, str]]:
        """(endpoint_key, check) pairs not yet tested — the planner's to-do list.

        This is how the agent stays systematic: it can always ask 'what haven't I tested?'
        instead of wandering."""
        with self._lock:
            pending = []
            for n in self._nodes.values():
                if n.kind != ENDPOINT:
                    continue
                for check, status in n.coverage.items():
                    if status == "untested":
                        pending.append((n.key, check))
            return pending

    def summary(self) -> dict:
        with self._lock:
            counts: dict[str, int] = {}
            tested = total = 0
            for n in self._nodes.values():
                counts[n.kind] = counts.get(n.kind, 0) + 1
                if n.kind == ENDPOINT:
                    tested += sum(1 for s in n.coverage.values() if s != "untested")
                    total += len(n.coverage)
            return {
                "counts": counts,
                "edges": len(self._edges),
                "coverage_tested": tested,
                "coverage_total": total,
                "coverage_pct": round(100 * tested / total, 1) if total else 0.0,
            }

    # -- persistence -----------------------------------------------------------

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": sorted(list(self._edges)),
        }
        self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _load(self) -> None:
        data = json.loads(self._path.read_text(encoding="utf-8"))
        for row in data.get("nodes", []):
            n = Node(**row)
            self._nodes[n.id] = n
        for e in data.get("edges", []):
            self._edges.add(tuple(e))

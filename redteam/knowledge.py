"""Target knowledge graph — the agent's memory of the engagement.

This is what separates a coherent long-horizon agent from a stateless chat loop. Every
observation the agent makes (a live host, an open service, a discovered endpoint, a
parameter, a credential, a technology fingerprint) becomes a typed node, deduplicated
and correlated with what's already known, with edges expressing structure
(host -> service -> endpoint -> parameter). The planner reasons over THIS, not over a
transcript, so step 300 still knows what step 3 found.

It also tracks methodology coverage per asset, so testing is systematic (did we test
auth on this endpoint? injection? access control?) rather than ad hoc.

Phase E2 additions (docs/adr-002-unified-intelligence-graph.md), all additive:

  - CANONICAL IDENTITY — canonical_url()/canonical_host() give every store one
    join key so cross-store matching (inventory bridge, attack-path projection,
    falsified-finding sync) can be exact instead of best-effort string equality.
    Existing node keys are NEVER re-keyed: canonicalization is used for lookups
    and for the new inventory-sourced observations only.
  - EVIDENCE REFERENCES — Node.evidence_refs and the parallel edge_attrs map
    reuse the swarm's EvidenceRef vocabulary (origin/source/artifact_ref/kind/ts)
    so a relationship can answer "who recorded this, when, and where is the
    full material". Provenance is optional-but-captured-when-available; old
    files load with empty refs.
  - LIFECYCLE — Node.lifecycle carries the states.py "kg_node_lifecycle"
    machine (active / stale / remediated) as a currency decoration. History is
    append-only; nothing is ever deleted; marking cannot authorize or execute
    anything.
  - ATOMIC PERSISTENCE — _flush() writes tmp+replace (the inventory.py pattern)
    and _load() tolerates a torn/corrupt file by reporting a warning instead of
    crashing the run.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# Node kinds in the graph.
HOST = "host"
SERVICE = "service"          # e.g. 203.0.113.5:443 https
ENDPOINT = "endpoint"        # e.g. https://api.acme.example/v1/users
PARAMETER = "parameter"      # a query/body/header parameter on an endpoint
TECHNOLOGY = "technology"    # nginx, Django, WordPress 6.2, ...
CREDENTIAL = "credential"    # a discovered/used credential (store references, not secrets in the report)
DOMAIN = "domain"            # a registered name observed on the surface (Phase E2)

# Methodology checklist applied per endpoint (subset of OWASP WSTG, extend freely).
WSTG_CHECKS = (
    "auth", "access_control", "injection", "xss", "ssrf",
    "idor", "misconfig", "sensitive_data", "business_logic",
)

# Lifecycle vocabulary lives in states.py (the one lifecycle registry) — same
# pattern attack_tree/findings/killchain already follow.
from .states import (KG_ACTIVE, KG_LIFECYCLE_INITIAL, KG_LIFECYCLE_STATES,
                     KG_REMEDIATED, KG_STALE)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
# How much of the raw (pre-canonicalization) URL we keep as provenance on a
# node whose key was canonicalized. Bounded like every other stored surface
# string (see swarm/hypotheses._clip and recon/passive._MAX_DOC).
_MAX_RAW = 300
_LIFECYCLE_HISTORY_CAP = 32


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _clip(text: str, limit: int) -> str:
    """Bounded storage for caller-supplied strings (same discipline as the
    swarm: shared text is stored, never executed, and never allowed to bloat)."""
    text = str(text or "")
    return text[:limit]


# -- canonical identity (Phase E2, ADR-002 §Canonicalization policy) ---------------
#
# The join layer for cross-store matching. Policy, in one place:
#
#   HOST: trim + lowercase + strip one trailing dot. IP literals are validated
#   but otherwise untouched (no DNS resolution here — the ScopeGuard owns name
#   resolution, and a resolver call in an identity function would turn graph
#   maintenance into network activity). `www.` is NOT stripped: www.example.com
#   and example.com frequently serve different content, and conflating them
#   would invent a relationship the records don't contain.
#
#   URL: lowercase scheme and host; drop the fragment; drop the port when it is
#   the default for the scheme; keep the path EXACTLY (path distinctions are
#   real resources — no trailing-slash folding); DROP the query string.
#
#   QUERY POLICY (the deliberate trade-off, ADR-002): canonical endpoint
#   identity is scheme://host[:port]/path — query strings are excluded because
#   they are behavior, not resource identity, and keeping them is what produced
#   the duplicate-endpoint problem the audit measured (spa_recon strips queries,
#   passive recon keeps them, ffuf keeps them). Parameter NAMES and observed
#   values stay available through the existing PARAMETER nodes (browser.py
#   already records them as "{action}#{param}") and through attrs["url_raw"]
#   (bounded) on first canonical observation. What this merges: the same path
#   reached with different/absent query strings. What it never merges: two
#   different paths.
#
#   These functions are PURE string work — no I/O, no network, no scope logic.
#   They can never widen or authorize anything; they only decide when two
#   recorded spellings denote the same recorded entity.

def canonical_host(host: str) -> str:
    """One spelling of a host: trimmed, lowercased, trailing dot dropped.
    IP literals pass through validated-but-unchanged (v4/v6 zone info kept —
    the zone identifies the interface, which is real distinction, not noise)."""
    h = str(host or "").strip().rstrip(".")
    if not h:
        return ""
    h = h.lower()
    try:
        import ipaddress as _ip
        _ip.ip_address(h)  # validation only; the literal itself is canonical
    except ValueError:
        pass
    return h


def canonical_url(url: str) -> str:
    """One spelling of a URL: lowercased scheme+host, no fragment, no default
    port, exact path, no query (see the QUERY POLICY above). Unparseable or
    empty input returns the trimmed input unchanged — canonicalization must
    never lose a record it does not understand."""
    raw = str(url or "").strip()
    if not raw:
        return raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.netloc:  # not scheme://host[/...] shaped — leave it alone
        return raw
    scheme = (parts.scheme or "").lower()
    host = canonical_host(parts.hostname or "")
    if not host:
        return raw
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    if port is not None and scheme in _DEFAULT_PORTS and port == _DEFAULT_PORTS[scheme]:
        netloc = host
    path = parts.path or "/"
    return f"{scheme}://{netloc}{path}"


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
    # Phase E2 (additive — every field defaults, so pre-E2 graph.json rows load
    # unchanged via the existing Node(**row) path):
    evidence_refs: list[dict] = field(default_factory=list)  # EvidenceRef-shaped dicts (swarm vocabulary)
    lifecycle: dict = field(default_factory=dict)  # states.py "kg_node_lifecycle": {status, marked_at, reason, history}

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"

    def lifecycle_status(self) -> str:
        return str((self.lifecycle or {}).get("status") or KG_ACTIVE)


class KnowledgeGraph:
    def __init__(self, path: str | Path | None = None):
        self._nodes: dict[str, Node] = {}
        self._edges: set[tuple[str, str, str]] = set()  # (src_id, relation, dst_id)
        # Phase E2: parallel edge metadata keyed by the SAME triple — the tuple
        # representation is preserved (every existing consumer, serializer and
        # test keeps working); evidence/timestamps/status ride alongside.
        self._edge_attrs: dict[tuple[str, str, str], dict] = {}
        self._path = Path(path) if path else None
        # A parallel exploit swarm (multiple specialist contexts fanned out over
        # AttackTree.actionable() targets, run concurrently) calls observe()/
        # mark_coverage() from different threads against this ONE shared graph. Without
        # a lock, concurrent dict/set mutation here is a real data race (lost updates at
        # best, a corrupted _nodes dict at worst) — not a theoretical concern once
        # anything calls this from more than one thread.
        self._lock = threading.Lock()
        # Phase E1A: a torn/corrupt graph file must not crash the run. The
        # warning is REPORTED, not swallowed — callers and tests can read it.
        self.last_load_warning: str = ""
        if self._path and self._path.exists():
            self._load()

    # -- mutation --------------------------------------------------------------

    def observe(self, kind: str, key: str, attrs: dict | None = None,
                source: str = "", relate_to: str | None = None,
                relation: str = "has",
                evidence_refs: list[dict] | None = None,
                edge_evidence: list[dict] | None = None) -> Node:
        """Add or merge a node. Re-observing an existing node corroborates it and merges
        attributes rather than duplicating — this is the dedup/correlation core.

        Phase E2 optional parameters (existing callers are unaffected):
          evidence_refs — EvidenceRef-shaped provenance for the NODE observation
                          (see swarm/hypotheses.EvidenceRef; stored as dicts).
          edge_evidence — provenance for the relate_to EDGE created by THIS call.
        Lifecycle policy: a fresh observation clears a STALE status (the entity
        answered again — stronger evidence than aging) but deliberately does NOT
        clear REMEDIATED (an endpoint answering says nothing about whether the
        vulnerability is back; only the finding pipeline could re-establish that).
        """
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
                if node.lifecycle.get("status") == KG_STALE:
                    self._set_lifecycle_locked(node, KG_ACTIVE,
                                               reason="re-observed", event="reobserved")
            if source and source not in node.sources:
                node.sources.append(source)
            if evidence_refs:
                node.evidence_refs.extend(evidence_refs)
            if relate_to and relate_to in self._nodes:
                edge = (relate_to, relation, node_id)
                self._edges.add(edge)
                if edge_evidence:
                    ea = self._edge_attrs.setdefault(edge, {})
                    refs = list(ea.get("evidence_refs") or [])
                    refs.extend(edge_evidence)
                    ea["evidence_refs"] = refs
                    ea["first_seen"] = ea.get("first_seen") or _now()
                    ea["last_seen"] = _now()
            self._flush()
            return node

    def observe_canonical(self, kind: str, key: str, attrs: dict | None = None,
                          **kwargs) -> Node:
        """Observe through the canonical identity layer (Phase E2).

        For ENDPOINT-kind keys the canonical spelling becomes the node key and
        the raw spelling is preserved (once, bounded) as attrs["url_raw"] when
        it differs. Other kinds keep their key verbatim — hosts from the
        inventory bridge already arrive canonically, and service/technology
        keys are composite strings with no query grammar."""
        if kind == ENDPOINT:
            raw = str(key or "").strip()
            canon = canonical_url(raw)
            if canon != raw:
                attrs = dict(attrs or {})
                attrs.setdefault("url_raw", _clip(raw, _MAX_RAW))
            key = canon
        return self.observe(kind, key, attrs, **kwargs)

    def mark_coverage(self, endpoint_key: str, check: str, status: str) -> None:
        """Record that a methodology check was performed on an endpoint."""
        with self._lock:
            node = self._nodes.get(f"{ENDPOINT}:{endpoint_key}")
            if node is not None and check in node.coverage:
                node.coverage[check] = status
                self._flush()

    # -- lifecycle (Phase E2) ---------------------------------------------------

    def _set_lifecycle_locked(self, node: Node, status: str, reason: str = "",
                              event: str = "marked") -> None:
        """Apply one lifecycle transition. History is append-only (capped so a
        flapping entity cannot bloat the file); the observation itself is NEVER
        touched. Idempotent in state: re-marking the same status refreshes the
        stamp without duplicating history."""
        now = _now()
        lc = node.lifecycle if isinstance(node.lifecycle, dict) else {}
        history = list(lc.get("history") or [])
        previous = lc.get("status") or KG_ACTIVE
        if previous != status:
            history.append({"event": event, "from": previous, "to": status,
                            "at": now, "reason": _clip(reason, 200)})
        node.lifecycle = {"status": status, "marked_at": now,
                          "reason": _clip(reason, 200),
                          "history": history[-_LIFECYCLE_HISTORY_CAP:]}

    def mark_stale(self, key: str, reason: str = "", kind: str | None = None) -> bool:
        """Mark an observation no longer trusted as current (states.py
        KG_STALE). Pure state decoration: nothing is deleted, nothing is
        executed, nothing is authorized. Safe to call repeatedly. Returns
        whether a node was found."""
        with self._lock:
            node = self._find_locked(key, kind)
            if node is None or node.lifecycle_status() == KG_STALE:
                return node is not None and node.lifecycle_status() == KG_STALE
            self._set_lifecycle_locked(node, KG_STALE, reason=reason, event="mark_stale")
            self._flush()
            return True

    def mark_remediated(self, key: str, reason: str = "", kind: str | None = None) -> bool:
        """Mark an entity whose finding-backed relationship was independently
        proven fixed (states.py KG_REMEDIATED — written by the retest-fixed
        bridge only). Same append-only, no-delete discipline as mark_stale."""
        with self._lock:
            node = self._find_locked(key, kind)
            if node is None or node.lifecycle_status() == KG_REMEDIATED:
                return node is not None and node.lifecycle_status() == KG_REMEDIATED
            self._set_lifecycle_locked(node, KG_REMEDIATED, reason=reason,
                                       event="mark_remediated")
            self._flush()
            return True

    def _find_locked(self, key: str, kind: str | None) -> Node | None:
        """Node lookup by exact id first, then canonical join (the same URL
        recorded under a different spelling must still be findable)."""
        if kind is not None:
            node = self._nodes.get(f"{kind}:{key}")
            if node is not None:
                return node
        node = self._nodes.get(str(key))
        if node is not None:
            return node
        canon = canonical_url(str(key or ""))
        if canon:
            # a bare URL key matches its ENDPOINT node even when the caller
            # passed the already-canonical spelling
            node = self._nodes.get(f"{ENDPOINT}:{canon}")
            if node is not None:
                return node
            if canon != str(key or ""):
                for n in self._nodes.values():
                    if n.kind == ENDPOINT and canonical_url(n.key) == canon:
                        return n
        return None

    def stale_nodes(self) -> list[Node]:
        """Every node whose lifecycle says its observation is no longer
        trusted-as-current (stale OR remediated) — the honesty view."""
        with self._lock:
            return [n for n in self._nodes.values()
                    if n.lifecycle_status() in (KG_STALE, KG_REMEDIATED)]

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

    def edge_attrs(self, src_id: str, relation: str, dst_id: str) -> dict:
        """Metadata for one edge (evidence refs, first/last seen). Empty dict
        when the edge predates Phase E2 or carries no metadata — consumers must
        treat that as 'no provenance recorded', never as 'provenance disproven'."""
        with self._lock:
            return dict(self._edge_attrs.get((src_id, relation, dst_id)) or {})

    def untested(self) -> list[tuple[str, str]]:
        """(endpoint_key, check) pairs not yet tested — the planner's to-do list.

        This is how the agent stays systematic: it can always ask 'what haven't I tested?'
        instead of wandering. Stale/remediated endpoints stay listed (selection is the
        AttackTree's authority and a quiet endpoint may return); staleness is surfaced
        in summaries and projections instead of silently descopeing work here."""
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
            lifecycle: dict[str, int] = {}
            for n in self._nodes.values():
                counts[n.kind] = counts.get(n.kind, 0) + 1
                st = n.lifecycle_status()
                lifecycle[st] = lifecycle.get(st, 0) + 1
                if n.kind == ENDPOINT:
                    tested += sum(1 for s in n.coverage.values() if s != "untested")
                    total += len(n.coverage)
            return {
                "counts": counts,
                "edges": len(self._edges),
                "coverage_tested": tested,
                "coverage_total": total,
                "coverage_pct": round(100 * tested / total, 1) if total else 0.0,
                # Phase E2 (additive): lifecycle rollup so briefings/reports can
                # surface currency honestly without any consumer change.
                "lifecycle": lifecycle,
            }

    # -- persistence -----------------------------------------------------------
    # Phase E2: atomic tmp+replace (the inventory.py pattern — a concurrent API
    # reader never sees a torn file and a failed write never leaves a partial
    # graph), plus corrupt-file-tolerant load that REPORTS instead of crashing.

    def _flush(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "nodes": [asdict(n) for n in self._nodes.values()],
                "edges": sorted(list(self._edges)),
                # rows, not separator-joined keys: URLs/relations can contain
                # almost anything, and rows stay self-describing.
                "edge_attrs": [
                    {"src": src, "rel": rel, "dst": dst, **meta}
                    for (src, rel, dst), meta in sorted(
                        self._edge_attrs.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]))
                ],
            }
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            # Persistence is best-effort here (same policy as inventory.py:
            # never break the run over a save) — but a FAILED write must never
            # look like success, so the in-memory graph remains the authority
            # and the next mutation retries the write.
            pass

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            self.last_load_warning = (
                f"graph file {self._path.name} unreadable ({exc.__class__.__name__}); "
                f"starting from an empty graph — the previous file is kept on disk "
                f"for inspection and the next mutation rewrites it")
            return
        if not isinstance(data, dict):
            self.last_load_warning = f"graph file {self._path.name} has unexpected top-level type; ignored"
            return
        loaded = 0
        for row in data.get("nodes", []) or []:
            try:
                n = Node(**row)
            except TypeError:
                self.last_load_warning = (
                    f"graph file {self._path.name}: a node row failed to load and "
                    f"was skipped (pre-E2 forward-compat gate); "
                    f"{loaded} nodes loaded before it")
                continue
            self._nodes[n.id] = n
            loaded += 1
        for e in data.get("edges", []) or []:
            try:
                self._edges.add(tuple(e))
            except TypeError:
                continue
        for row in data.get("edge_attrs", []) or []:
            try:
                key = (str(row["src"]), str(row["rel"]), str(row["dst"]))
            except (KeyError, TypeError):
                continue
            meta = {k: v for k, v in row.items() if k not in ("src", "rel", "dst")}
            self._edge_attrs[key] = meta

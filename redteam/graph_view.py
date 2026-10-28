"""build_exploration_graph — the exploration path (ARTEX 探索链路) from run artifacts.

ARTEX's dashboard answers the operator's most important question with a picture:
HOW did the agent get from "nothing" to "this finding"? Which asset was touched,
which endpoints were discovered on it, what access was claimed through them, and
which finding proved impact. Our event bus records all of it chronologically, but
a timeline is the wrong shape for a chain question — you want the GRAPH.

This module is a pure adapter over the per-run artifact files the engine already
writes (server stays decoupled from the engine, same as /traffic and /inventory):

    graph.json      knowledge nodes (host/endpoint/parameter...) + edges
    access.json     what identities/material the agent HOLDS (demonstrated only)
    findings.json   recorded findings + verification state
    killchain.json  MITRE-style stage progression
    inventory.json  services seen per host (passive fingerprints)
    attack_tree.json  planned branches and their status

Output is a layered graph — assets → endpoints → access → findings — sized for a
dashboard render: every node carries its layer, every edge its relation, and
nothing is included that did not come out of a store. Missing files yield empty
layers (a run in round one still renders, honestly partial).
"""

from __future__ import annotations

import json
from pathlib import Path

LAYERS = ("asset", "endpoint", "access", "finding")

# knowledge-graph node kinds that are attack-surface objects (everything else —
# e.g. credential material stored as nodes — routes to the access layer instead).
_ASSET_KINDS = {"host", "service", "domain"}
_ENDPOINT_KINDS = {"endpoint", "parameter", "route"}


def _read_json(path: Path, default):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if data is not None else default
    except (OSError, json.JSONDecodeError, TypeError):
        return default


def _node(node_id: str, layer: str, label: str, status: str = "",
          detail: str = "") -> dict:
    return {"id": node_id, "layer": layer, "label": label,
            "status": status, "detail": detail}


def build_exploration_graph(run_dir: str | Path) -> dict:
    """Assemble the layered exploration graph for one run directory. Tolerant of
    absent/partial artifacts by design — it must render for ANY run state."""
    run_dir = Path(run_dir)
    nodes: list[dict] = []
    edges: list[dict] = []
    ids: set[str] = set()

    def add(n: dict) -> str:
        if n["id"] in ids:
            return n["id"]
        ids.add(n["id"])
        nodes.append(n)
        return n["id"]

    def link(src: str, dst: str, rel: str) -> None:
        if src in ids and dst in ids and src != dst:
            e = {"src": src, "dst": dst, "rel": rel}
            if e not in edges:
                edges.append(e)

    # -- knowledge graph: surface objects --------------------------------------
    kg = _read_json(run_dir / "graph.json", {}) or {}
    kg_nodes = {}
    for n in kg.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        nid = n.get("id") or f"{n.get('kind')}:{n.get('key')}"
        kind = str(n.get("kind", ""))
        key = str(n.get("key", ""))
        if kind in _ASSET_KINDS:
            kg_nodes[nid] = add(_node(nid, "asset", key))
        elif kind in _ENDPOINT_KINDS:
            kg_nodes[nid] = add(_node(nid, "endpoint", key))
    # asset --has--> endpoint edges straight out of the knowledge graph
    for e in kg.get("edges", []) or []:
        try:
            src, rel, dst = e[0], e[1], e[2]
        except (TypeError, ValueError, IndexError):
            continue
        if src in kg_nodes and dst in kg_nodes:
            link(src, dst, str(rel or "related"))

    # -- inventory: services seen per host (passive evidence, may precede graph) --
    inv = _read_json(run_dir / "inventory.json", {}) or {}
    for host, rec in (inv.get("hosts", {}) or {}).items():
        if not isinstance(rec, dict):
            continue
        hid = add(_node(f"asset:{host}", "asset", host))
        for svc in (rec.get("services", {}) or {}).values():
            if not isinstance(svc, dict):
                continue
            scheme = svc.get("scheme", "tcp")
            port = svc.get("port", "?")
            sid = add(_node(f"asset:{host}/{scheme}/{port}", "asset",
                            f"{scheme}://{host}:{port}",
                            status=str(svc.get("status_last") or ""),
                            detail=str(svc.get("title") or "")))
            link(hid, sid, "serves")

    # -- access: only what is HELD (demonstrated), never what was merely observed --
    acc = _read_json(run_dir / "access.json", {}) or {}
    for n in acc.get("nodes", []) or []:
        if not isinstance(n, dict) or not n.get("held"):
            continue
        nid = n.get("id") or f"{n.get('kind')}:{n.get('key')}"
        aid = add(_node(nid, "access", str(n.get("key", "")),
                        status="held", detail=str(n.get("evidence", ""))[:160]))
        # access reached THROUGH an endpoint: the holder's own edges say how
    for e in acc.get("edges", []) or []:
        try:
            src, rel, dst = e[0], e[1], e[2]
        except (TypeError, ValueError, IndexError):
            continue
        # normalize: access ids may not exist as nodes if not held — link() guards
        link(src, dst, str(rel or "leads-to"))

    # -- findings: the impact layer ---------------------------------------------
    # Finding fields: id/title/severity/target/confidence/... (see findings.py).
    # `confidence` is the honest status: only "confirmed" survived independent
    # verification — the graph must NOT paint pending work as impact.
    for f in _read_json(run_dir / "findings.json", []) or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        if not fid:
            continue
        nid = add(_node(f"finding:{fid}", "finding",
                        str(f.get("title") or fid),
                        status=str(f.get("confidence") or "tentative"),
                        detail=str(f.get("severity") or "")))
        # a finding sits on the target it proved, when the target is an endpoint
        # we discovered (full URL or query-stripped — endpoint keys are URLs)
        target = str(f.get("target") or "")
        for cand in (target, target.split("?")[0]):
            if cand and f"endpoint:{cand}" in ids:
                link(f"endpoint:{cand}", nid, "proved-by")
                break

    # -- kill chain: stage progression as status metadata (not graph nodes) ------
    killchain = [{"stage": s.get("stage", ""), "status": s.get("status", ""),
                  "achieved_at": s.get("achieved_at", "")}
                 for s in _read_json(run_dir / "killchain.json", []) or []
                 if isinstance(s, dict)]

    # -- attack tree: branch pressure, as aggregate metadata ----------------------
    tree = _read_json(run_dir / "attack_tree.json", []) or []
    tree_stats = {"todo": 0, "in_progress": 0, "failed": 0, "completed": 0}
    for n in tree:
        if isinstance(n, dict) and n.get("status") in tree_stats:
            tree_stats[n["status"]] += 1

    counts = {layer: sum(1 for n in nodes if n["layer"] == layer)
              for layer in LAYERS}
    return {"nodes": nodes, "edges": edges, "layer_counts": counts,
            "killchain": killchain, "attack_tree": tree_stats}

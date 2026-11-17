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

from .knowledge import canonical_url

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
    result = {"nodes": nodes, "edges": edges, "layer_counts": counts,
              "killchain": killchain, "attack_tree": tree_stats}

    # -- Phase E2: attack paths (read-time projection, ADR-002) ------------------
    # Chains assembled ONLY from records that actually join: every hop cites a
    # real row in one of the persisted stores (no invented edges, no inferred
    # demonstrations, no authority behavior). Revoked holdings and
    # stale/remediated assets are represented with their status — never hidden,
    # never presented as current. This section changes nothing upstream: it
    # reads files and returns dicts.
    result["attack_paths"] = _build_attack_paths(run_dir)
    return result


def _canonical_key_match(candidate: str, node_keys: list[str]) -> str | None:
    """First node key that canonically denotes the same URL as `candidate`
    (exact first, then canonical form). Pure read-time string work."""
    if not candidate:
        return None
    if candidate in node_keys:
        return candidate
    canon = canonical_url(candidate)
    for k in node_keys:
        if k == canon or canonical_url(k) == canon:
            return k
    return None


def _build_attack_paths(run_dir: Path) -> list[dict]:
    """Dashboard projection: the attack-path join over the PERSISTED artifacts.
    The join itself lives in join_attack_paths() — the planner computes the SAME
    projection read-time over the live authorities (planner.authority_projection),
    so both consumers share one join and one record shape."""
    kg = _read_json(run_dir / "graph.json", {}) or {}
    tree_nodes = [n for n in _read_json(run_dir / "attack_tree.json", []) or []
                  if isinstance(n, dict) and n.get("technique")]
    findings_raw = [f for f in _read_json(run_dir / "findings.json", []) or []
                    if isinstance(f, dict) and f.get("id")]
    access_nodes = []
    for n in (_read_json(run_dir / "access.json", {}) or {}).get("nodes", []):
        if not isinstance(n, dict):
            continue
        if not n.get("id") and n.get("kind") and n.get("key") is not None:
            n = dict(n, id=f"{n.get('kind')}:{n.get('key')}")
        if n.get("id"):
            access_nodes.append(n)
    objective_raw = _read_json(run_dir / "objective.json", {}) or {}
    criteria = [c for c in (objective_raw.get("criteria") or []) if isinstance(c, dict)]
    inv = _read_json(run_dir / "inventory.json", {}) or {}
    return join_attack_paths(kg_nodes=kg.get("nodes", []) or [],
                             kg_edges=kg.get("edges", []) or [],
                             tree_nodes=tree_nodes, findings=findings_raw,
                             access_nodes=access_nodes, criteria=criteria,
                             inv_hosts=inv.get("hosts", {}) or {})


def join_attack_paths(*, kg_nodes, kg_edges, tree_nodes, findings,
                      access_nodes, criteria, inv_hosts) -> list[dict]:
    """One attack-path record per endpoint that actually participates in a
    chain (has a tree technique, a finding, or a holding attached). The PURE
    join behind the Phase E2 projection — both the dashboard (persisted
    artifacts) and the planner (live authorities, read-time) feed it the same
    normalized rows:

      AssetInventory host/service -> KG endpoint -> AttackTree technique
        -> FindingStore finding (+ verification + retest state)
        -> AccessGraph holding (held or revoked, with its finding reference)
        -> Objective criterion (target match with the holding)
    """
    endpoints: dict[str, dict] = {}
    host_of_service: dict[str, str] = {}
    service_of_endpoint: dict[str, str] = {}
    for n in kg_nodes or []:
        if not isinstance(n, dict):
            continue
        nid = n.get("id") or f"{n.get('kind')}:{n.get('key')}"
        kind = str(n.get("kind", ""))
        if kind in ("host", "service", "domain", "endpoint"):
            endpoints[nid] = n
    for e in kg_edges or []:
        try:
            src, rel, dst = str(e[0]), str(e[1]), str(e[2])
        except (TypeError, ValueError, IndexError):
            continue
        if src.startswith("host:") and dst.startswith("service:"):
            host_of_service[dst] = src
        elif src.startswith("service:") and dst.startswith("endpoint:"):
            service_of_endpoint[dst] = src

    holds_by_finding: dict[str, list[dict]] = {}
    for n in access_nodes or []:
        fid = (n.get("attrs") or {}).get("finding_id") if isinstance(n.get("attrs"), dict) else None
        if fid:
            holds_by_finding.setdefault(str(fid), []).append(n)

    endpoint_keys = sorted(str(n.get("key") or "") for n in endpoints.values()
                           if str(n.get("kind")) == "endpoint")
    paths: list[dict] = []
    unmatched_findings: list[dict] = []
    for f in findings or []:
        target = str(f.get("target") or "")
        matched = _canonical_key_match(target, endpoint_keys)
        if matched is None:
            # fall back to the raw query-stripped spelling the dashboard has
            # always used — still a real-record join, just one level looser
            matched = _canonical_key_match(target.split("?")[0], endpoint_keys)
        fid = str(f.get("id"))
        endpoint_id = f"endpoint:{matched}" if matched else None
        if endpoint_id is None:
            unmatched_findings.append({"finding_id": fid, "target": target,
                                       "reason": "no matching endpoint record"})
            continue
        retest_hist = f.get("retest_history") or []
        last_retest = retest_hist[-1] if retest_hist else None
        path = _path_entry(endpoint_id, endpoints.get(endpoint_id, {}),
                           host_of_service, service_of_endpoint, inv_hosts)
        techniques = [n for n in tree_nodes or []
                      if _canonical_key_match(str(n.get("target") or ""), [matched])
                      or str(n.get("target") or "") == matched]
        path["techniques"] = [{"id": f"{n.get('technique')}@{n.get('target')}",
                               "technique": n.get("technique"), "status": n.get("status"),
                               "findings": n.get("findings", "")} for n in techniques]
        path["findings"] = [{
            "id": fid, "title": f.get("title"), "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "independent_verdict": f.get("independent_verdict", ""),
            "retest_last": ({"verdict": last_retest.get("verdict"),
                             "when": last_retest.get("when")}
                            if last_retest else None),
        }]
        # holdings that THIS finding demonstrated (structured finding_id marker)
        holds = holds_by_finding.get(fid, [])
        path["access"] = [{"id": n.get("id"), "kind": n.get("kind"), "key": n.get("key"),
                           "status": "held" if n.get("held") else "revoked",
                           "source": n.get("source", ""),
                           "invalidated_at": n.get("invalidated_at", "")}
                          for n in holds]
        # objective criteria reached through those holdings (target match)
        hold_keys = {str(h.get("key") or "") for h in holds}
        path["objective"] = [{"criterion": c.get("id"), "kind": c.get("kind"),
                              "achieved": c.get("achieved", False),
                              "target": c.get("target", "")}
                             for c in criteria or [] if c.get("target") in hold_keys]
        paths.append(path)

    # endpoints with techniques but no findings still form honest partial paths
    path_endpoints = {p["endpoint"]["id"] for p in paths if p.get("endpoint")}
    for n in tree_nodes or []:
        matched = _canonical_key_match(str(n.get("target") or ""), endpoint_keys)
        if matched is None:
            continue
        endpoint_id = f"endpoint:{matched}"
        if endpoint_id in path_endpoints:
            continue
        path = _path_entry(endpoint_id, endpoints.get(endpoint_id, {}),
                           host_of_service, service_of_endpoint, inv_hosts)
        path["techniques"] = [{"id": f"{n.get('technique')}@{n.get('target')}",
                               "technique": n.get("technique"), "status": n.get("status"),
                               "findings": n.get("findings", "")}]
        path["findings"] = []
        path["access"] = []
        path["objective"] = []
        paths.append(path)
        path_endpoints.add(endpoint_id)

    for p in paths:
        if p.get("unmatched_reason"):
            p.pop("unmatched_reason")
    if unmatched_findings:
        paths.append({"unresolved": unmatched_findings})
    return paths


def _path_entry(endpoint_id: str, ep: dict, host_of_service: dict,
                service_of_endpoint: dict, inv_hosts: dict) -> dict:
    """Build the asset-side prefix of one attack path from REAL records only:
    the KG host->service->endpoint edges and the inventory row for the same
    canonical host. Anything missing stays None — never guessed."""
    svc_id = service_of_endpoint.get(endpoint_id)
    host_id = host_of_service.get(svc_id or "")
    entry: dict = {
        "endpoint": {"id": endpoint_id, "key": ep.get("key", ""),
                     "lifecycle": ((ep.get("lifecycle") or {}).get("status") or "active")
                     if isinstance(ep.get("lifecycle"), dict) else "active",
                     "url_raw": (ep.get("attrs") or {}).get("url_raw", "")
                     if isinstance(ep.get("attrs"), dict) else ""},
        "service": {"id": svc_id, "key": (endpoints_key(svc_id))} if svc_id else None,
        "host": {"id": host_id, "key": (endpoints_key(host_id))} if host_id else None,
    }
    # inventory join on the canonical host spelled in the endpoint URL
    try:
        from urllib.parse import urlsplit
        host = canonical_host_of(str(ep.get("key") or ""))
        if host and host in inv_hosts:
            services = inv_hosts[host].get("services", {}) or {}
            entry["inventory"] = {"host": host, "services": sorted(services.keys()),
                                  "status_last": [s.get("status_last") for s in services.values()]}
    except Exception:
        entry["inventory"] = None
    return entry


def endpoints_key(node_id: str | None) -> str | None:
    """The `kind:key` node id's key part (None-safe helper for path entries)."""
    if not node_id or ":" not in node_id:
        return None
    return node_id.split(":", 1)[1]


def canonical_host_of(url: str) -> str | None:
    """Canonical host out of a URL, or None for non-URL keys. Thin wrapper so
    the projection's only canonicalization comes from the shared layer."""
    try:
        from urllib.parse import urlsplit
        from .knowledge import canonical_host
        parts = urlsplit(url)
        if not parts.netloc:
            return None
        return canonical_host(parts.hostname or "")
    except Exception:
        return None

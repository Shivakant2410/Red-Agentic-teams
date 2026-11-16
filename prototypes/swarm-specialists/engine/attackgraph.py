"""engine/attackgraph.py — M3: the attack-surface map and the attack graph
that guides exploit agents.

Two artifacts, ONE builder (they can never disagree), both induced from the
run's own evidence — never from a template:

  surface map  — resources/actions/read-backs with a documented|discovered
                 layer and an evidence state (probed / refuted / verified /
                 ambient-paid). This is M2's surface truth promoted to a
                 first-class artifact (OWASP: map what is exposed before
                 testing it; the map must be continuous, not recon-once).

  attack graph — capability/state nodes ("acct:any" -> "obj:res:state" ->
                 "goal:wallet-credit") and edges that carry {requests cost,
                 evidence state, technique suggestion}. Unlike a static TTP
                 tree (redteam/attack_tree.py — the strategic layer), every
                 edge here was OBSERVED this run or is ranked as the next
                 untested step toward money (Chen et al. 2024: the planner
                 over the graph, not the scanner, is the differentiator).

next_actions() is the guidance contract: cheapest untested edges to the
money goal, each mapped to the technique tag that tests it. The swarm's
ATTACKGRAPH specialist converts the top ranks into HYPOTHESIS facts — the
existing router dispatch loop is the bridge, no new machinery.

Layering: spine module — must not import the swarm, and never issues a
request. Pure dict-in, artifact-out.
"""
import json
import os
import time

# technique suggestion per edge shape — the static map from edge evidence
# to the arm that tests it (M5's LLM seam may rewrite priors, never this).
EDGE_TECHNIQUE = {
    "terminal-transition": "h_state_skip",
    "credit-verb": "h_value_replay",
    "credit-verb-unguarded": "h_credit_race",
    "cross-user-read": "h_cross_tenant",
    "price-field": "h_mass_assign",
    "async-seam": "h_async_seam",
    "cycle-pricing": "h_arith_cycle",
    "cancel-family": "h_state_guard",
}

GOAL = "goal:wallet-credit"
SOURCE = "acct:any"


# --------------------------------------------------------------- builder --
def build(facts, ambient_events=(), tested_tags=()):
    """facts: blackboard facts (list of dict-likes). ambient_events:
    WalletWatcher.events. tested_tags: technique tags already hypothesized
    on the board (next_actions skips them). Returns the artifact doc."""
    surfaces = [f for f in facts if f.get("kind") == "SURFACE"]
    surface = surfaces[-1]["payload"] if surfaces else {}
    findings = [f["payload"].get("finding", {}) for f in facts
                if f.get("kind") == "FINDING"]
    statuses = {f["payload"].get("finding", {}).get("id"):
                f["payload"].get("status", "candidate")
                for f in facts if f.get("kind") == "FINDING"}
    disc = surface.get("discoveries") or {}
    undoc_verbs = {(v.get("resource"), v.get("verb"))
                   for v in disc.get("undocumented_verbs", [])}
    credited = {(v.get("resource"), v.get("verb")) for v in
                disc.get("verb_facts", []) if v.get("credited")}
    # verified / ambient evidence per (resource, verb)
    verified, endpoints = set(), {}
    for fd in findings:
        ep = str(fd.get("endpoint", ""))
        ev_text = json.dumps(fd.get("evidence", []), default=str).lower()
        status = statuses.get(fd.get("id"), "candidate")
        for res in _resources(surface):
            if res in ep:
                for a in (surface.get("resource_actions", {})
                          .get(res, {}).get("actions", [])):
                    if a.get("verb") in ep:
                        key = (res, a["verb"])
                        endpoints[key] = ep
                        if status.startswith("verified"):
                            verified.add(key)
    ambient_paid = {(e.get("tag"), ): e for e in ambient_events
                    if e.get("delta", 0) > 0}

    # ---- surface map -----------------------------------------------------
    map_nodes, map_edges = [], []
    for res, g in (surface.get("resource_actions") or {}).items():
        documented = not any(v.get("resource") == res
                             for v in disc.get("undocumented_verbs", [])) \
            and not any(r.get("noun") == res
                        for r in disc.get("undocumented_resources", []))
        undoc_res = any(r.get("noun") == res
                        for r in disc.get("undocumented_resources", []))
        map_nodes.append({
            "id": "res:%s" % res, "kind": "resource",
            "layer": "discovered" if (undoc_res or not documented and
                                      bool(g.get("discovered"))) else
                     ("documented" if documented else "mixed"),
            "money": bool(g.get("mined_fields")) or
                     any((res, a.get("verb")) in credited
                         for a in g.get("actions", [])),
            "create": g.get("create")})
        for a in g.get("actions", []):
            key = (res, a.get("verb"))
            ev = ("verified" if key in verified else
                  "discovered" if key in undoc_verbs else "documented")
            if any(k[0] == res for k in ambient_paid) and \
                    (res, a.get("verb")) in credited:
                ev = "ambient-paid"
            map_edges.append({
                "from": "res:%s" % res, "verb": a.get("verb"),
                "path": a.get("path"), "method": a.get("method", "POST"),
                "layer": "discovered" if a.get("discovered") else
                         "documented",
                "evidence": ev})
    for rb in surface.get("readback", []) or []:
        map_nodes.append({"id": "read:%s" % rb, "kind": "readback",
                          "layer": "documented"})
    doc_suspect = surface.get("doc_suspect") or {}

    # ---- attack graph ----------------------------------------------------
    nodes = [{ "id": SOURCE, "kind": "capability",
               "label": "any registered account"},
             { "id": GOAL, "kind": "goal",
               "label": "wallet credit (attacker-controlled value)"}]
    edges = []
    # 1) credit edges: credited verbs pay the CALLER -> money goal
    for (res, verb) in sorted(credited):
        g = (surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        key = (res, verb)
        edges.append({
            "id": "e-credit-%s-%s" % (res, verb),
            "from": SOURCE, "to": GOAL, "kind": "credit-verb",
            "resource": res, "verb": verb,
            "requests": _edge_cost(g, verb),
            "evidence": ("verified" if key in verified else
                         "ambient-paid" if any(k[0] == res
                                               for k in ambient_paid)
                         else "probed"),
            "technique": "h_value_replay",
            "path": endpoints.get(key) or
                    "/api/%s/{id}/%s" % (res, verb)})
    # 2) untested terminal transitions: ranked next actions (GV-8 shape)
    for (res, verb) in sorted(undoc_verbs - credited):
        g = (surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        edges.append({
            "id": "e-term-%s-%s" % (res, verb),
            "from": SOURCE, "to": GOAL, "kind": "terminal-transition",
            "resource": res, "verb": verb,
            "requests": _edge_cost(g, verb), "evidence": "untested",
            "technique": "h_state_skip",
            "path": "/api/%s/{id}/%s" % (res, verb)})
    # 2b) credited TERMINAL verbs: the probe saw the credit but nothing
    # tested the state machine behind it — the GV-8 follow-through the
    # graph must push agents toward (Freightlane's settle-from-booked).
    for (res, verb) in sorted(credited):
        if verb not in ("settle", "complete", "confirm", "fulfill",
                        "approve", "capture", "close", "terminate"):
            continue
        g = (surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        edges.append({
            "id": "e-follow-%s-%s" % (res, verb),
            "from": SOURCE, "to": GOAL, "kind": "terminal-followup",
            "resource": res, "verb": verb,
            "requests": _edge_cost(g, verb) + 18, "evidence": "credit-only",
            "technique": "h_state_skip",
            "path": "/api/%s/{id}/%s" % (res, verb)})
    # 3) async seams -> window driver
    markers = [f for f in facts if f.get("kind") == "OBSERVATION" and
               "async-opened" in (f.get("tags") or [])]
    for m in markers:
        shape = (m.get("payload") or {}).get("async_opened") or {}
        if not shape.get("create_path"):
            continue
        edges.append({
            "id": "e-seam-%s" % shape.get("resource", "x"),
            "from": SOURCE, "to": GOAL, "kind": "async-seam",
            "resource": shape.get("resource"), "verb": "settle/async",
            "requests": 18, "evidence": "probed", "technique":
                "h_async_seam", "path": shape["create_path"]})
    # 4) cross-user reads with leaked foreign ids -> deputy credit path
    if any("recent" in str(rb) or "audit" in str(rb)
           for rb in disc.get("readback_added", [])):
        edges.append({
            "id": "e-xu-readbacks", "from": SOURCE, "to": GOAL,
            "kind": "cross-user-read", "resource": "readbacks",
            "verb": "GET", "requests": 8,
            "evidence": "verified" if any(fd.get("id") == "FW-AUDIT-LEAK"
                                          and statuses.get(fd.get("id"), "")
                                          .startswith("verified")
                                          for fd in findings)
            else "probed",
            "technique": "h_cross_tenant", "path": "readback scan"})

    doc = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "attack-graph", "version": "1.0.0-m3",
        "surface_map": {"nodes": map_nodes, "edges": map_edges,
                        "doc_suspect": doc_suspect},
        "attack_graph": {"source": SOURCE, "goal": GOAL,
                         "nodes": nodes, "edges": edges},
        "money_paths": _money_paths(edges),
        "next_actions": next_actions(edges, tested_tags=tested_tags)}
    return doc


def _resources(surface):
    return sorted((surface.get("resource_actions") or {}).keys())


def _edge_cost(g, verb):
    """Request cost estimate for one edge: bootstrap + create + invoke +
    wallet attribution (the number next_actions ranks by)."""
    schema_ints = any(isinstance(s, dict) and s.get("type") == "integer"
                      for s in (g.get("create_schema") or {}).values())
    return 4 + (2 if schema_ints else 3)


def _money_paths(edges):
    """Edge ids on any source->goal path (this graph is flat: every money
    edge IS a path; kept as an explicit field for consumers)."""
    return [e["id"] for e in edges if e["to"] == GOAL]


# --------------------------------------------------------------- guidance --
def next_actions(edges, limit=5, tested_tags=()):
    """Ranked cheapest edges to the money goal that still need an agent:
    evidence 'untested' (never probed) or 'credit-only' (the probe saw the
    credit but no arm tested the guard behind it — the GV-8 follow-through),
    technique not already hypothesized. Verified/ambient-paid edges are the
    graph's memory, not its future."""
    pending = [e for e in edges
               if e.get("evidence") in ("untested", "credit-only") and
               e.get("technique") not in tested_tags]
    pending.sort(key=lambda e: (e.get("requests", 9), e.get("id", "")))
    return [{"edge": e["id"], "resource": e.get("resource"),
             "verb": e.get("verb"), "path": e.get("path"),
             "requests": e.get("requests"), "technique": e.get("technique")}
            for e in pending[:limit]]


# ------------------------------------------------------------------ io ----
def save(doc, out_dir, name="attack_surface.json"):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path

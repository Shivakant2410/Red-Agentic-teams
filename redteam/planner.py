"""Planner / methodology engine — drives systematic testing over the knowledge graph.

The difference between an agent that *performs* and one that wanders is whether it works
from state and a method. Each turn the planner produces:
  - a compact briefing of what's known (so the model reasons over structured state, not
    a re-read of raw output), and
  - a prioritized list of concrete next actions derived from coverage gaps.

Priorities encode a real methodology order: map the surface first (recon), then test the
high-signal classes (auth, access control, injection) on discovered endpoints, then the
rest. The model still decides *how* to test; the planner keeps it *systematic and
exhaustive* instead of forgetful and random.
"""

from __future__ import annotations

from .knowledge import ENDPOINT, HOST, SERVICE, TECHNOLOGY, KnowledgeGraph

# Methodology weighting: higher = test sooner. Tune from real engagement data.
_CHECK_PRIORITY = {
    "auth": 100, "access_control": 95, "idor": 90, "injection": 85,
    "ssrf": 70, "xss": 65, "sensitive_data": 60, "misconfig": 55,
    "business_logic": 40,
}

# Suggested tooling per check — a hint to the model, not a hard script.
_CHECK_HINT = {
    "auth": "probe for missing/weak authentication and session handling",
    "access_control": "test whether the endpoint enforces authorization (try without/with lower-priv token)",
    "idor": "vary object identifiers to reach another principal's data",
    "injection": "send safe injection probes; confirm via differential/time-based signal, not error text alone",
    "ssrf": "test URL/host parameters for server-side request forgery to in-scope internal targets only",
    "xss": "reflect a benign unique marker and check for unescaped output",
    "sensitive_data": "look for tokens, keys, PII, verbose errors, debug endpoints",
    "misconfig": "check headers, methods (OPTIONS/PUT), directory listing, default creds",
    "business_logic": "test workflow assumptions (quantity, price, state transitions)",
}


def surface_doc_notes(graph: KnowledgeGraph, limit: int = 5, note_chars: int = 200) -> list[tuple[str, str]]:
    """(node_key, doc) pairs for nodes that carry a `doc` attr from passive recon —
    openapi operation/level summary+description prose. API docs are where targets leak
    service-account tokens, internal hostnames and auth requirements in plain text, and
    the recon layer now stores them; but nothing else renders node attrs into agent
    context, so state_briefing surfaces them here, capped (target-controlled text —
    bound the injection/bloat surface)."""
    notes: list[tuple[str, str]] = []
    for n in graph.nodes(TECHNOLOGY):
        doc = n.attrs.get("doc")
        if doc:
            notes.append((f"api {n.attrs.get('title') or n.key}", str(doc)[:note_chars]))
    for n in graph.nodes(ENDPOINT):
        doc = n.attrs.get("doc")
        if doc:
            notes.append((n.key, str(doc)[:note_chars]))
    return notes[:limit]


def state_briefing(graph: KnowledgeGraph, max_targets: int = 6) -> str:
    s = graph.summary()
    counts = s["counts"]
    lines = ["[KNOWN STATE]"]
    lines.append(
        f"hosts={counts.get(HOST, 0)} services={counts.get(SERVICE, 0)} "
        f"endpoints={counts.get(ENDPOINT, 0)} | coverage {s['coverage_pct']}% "
        f"({s['coverage_tested']}/{s['coverage_total']} checks)"
    )
    doc_notes = surface_doc_notes(graph)
    if doc_notes:
        lines.append("[API DOC NOTES — verbatim from the target's published schema docs; "
                     "docs regularly leak auth schemes, service tokens and internal hosts]")
        lines.extend(f"  - {key}: {note}" for key, note in doc_notes)
    actions = next_actions(graph, limit=max_targets)
    if actions:
        lines.append("[NEXT — prioritized untested checks]")
        lines.extend(f"  - {a}" for a in actions)
    else:
        eps = graph.nodes(ENDPOINT)
        if not eps:
            lines.append("[NEXT] No endpoints mapped yet — run recon "
                         "(port scan, then directory/content discovery) to build the surface.")
        else:
            lines.append("[NEXT] All tracked checks covered — review findings and consider "
                         "deeper business-logic testing.")
    return "\n".join(lines)


def next_actions(graph: KnowledgeGraph, limit: int = 6) -> list[str]:
    """Prioritized (endpoint, check) work items as human/agent-readable actions."""
    pending = graph.untested()  # list of (endpoint_key, check)
    pending.sort(key=lambda pc: _CHECK_PRIORITY.get(pc[1], 0), reverse=True)
    out = []
    for endpoint_key, check in pending[:limit]:
        hint = _CHECK_HINT.get(check, "")
        out.append(f"{check} on {endpoint_key} — {hint}")
    return out


# -- Phase F1: intelligence-driven offensive planning (Issue #15, WS1) --------
#
# The functions below connect the unified attack-path projection (graph_view)
# to planning: the SAME join the dashboard renders is computed READ-TIME over
# the LIVE authorities (KnowledgeGraph, AttackTree, FindingStore, AccessGraph,
# Objective), and its records ground the ranking of attack opportunities.
# Authority rules are preserved unchanged:
#   - the AttackTree remains the work-selection authority: opportunities are
#     ranked from tree.actionable() — the planner NEVER invents work, adds
#     nodes, or authorizes techniques;
#   - findings count only through their verification state (confirmed /
#     falsified / retest-remediated), never an agent claim;
#   - a remediated surface (latest retest verdict FIXED) is excluded from
#     re-attack — the same currency rule the creditor enforces (credit.py),
#     generalized to planning.


def _targets_align(a: str, b: str) -> bool:
    """The containment rule claim_objective / the creditor apply — either
    direction, so a node on the full URL matches a criterion targeting the
    symbolic key and vice versa."""
    if not a or not b:
        return False
    return a in b or b in a


def authority_projection(*, graph=None, tree=None, findings=(),
                         access=None, objective=None,
                         inv_hosts=None) -> list[dict]:
    """The unified attack-path projection computed over the LIVE authorities.

    Same join, same record shape as graph_view.build_exploration_graph's
    attack_paths (the dashboard renders the persisted artifacts; this renders
    the current in-memory state). Live dataclass objects are normalized to the
    exact dict shapes the artifacts persist, then handed to the shared pure
    join — one join implementation, two consumers, zero duplication."""
    from dataclasses import asdict
    from .graph_view import join_attack_paths
    kg_nodes = [asdict(n) for n in graph.nodes(None)] if graph is not None else []
    kg_edges = graph.edges() if graph is not None else []
    tree_nodes = [asdict(n) for n in tree.nodes_all()] if tree is not None else []
    finding_rows = [asdict(f) for f in (findings or [])]
    access_nodes = [asdict(n) for n in access.nodes()] if access is not None else []
    criteria = ([asdict(c) for c in objective.criteria]
                if objective is not None else [])
    return join_attack_paths(kg_nodes=kg_nodes, kg_edges=kg_edges,
                             tree_nodes=tree_nodes, findings=finding_rows,
                             access_nodes=access_nodes, criteria=criteria,
                             inv_hosts=inv_hosts or {})


def remediated_targets(findings) -> set:
    """Canonical targets whose LATEST retest verdict is FIXED — remediation
    proof. These surfaces are excluded from re-attack planning exactly as the
    creditor refuses them collection (credit.py): historical confirmation is
    kept, current exploitability is gone, and only a newer `reproducible`
    re-entry (which latest_verdict reflects) re-opens them."""
    from .knowledge import canonical_url
    from .retest import latest_verdict, FIXED
    out = set()
    for f in (findings or []):
        if getattr(f, "confidence", "") == "confirmed" \
                and latest_verdict(f) == FIXED:
            target = getattr(f, "target", "")
            if target:
                out.add(canonical_url(target))
    return out


def offensive_opportunities(*, graph=None, tree=None, findings=(),
                            access=None, objective=None, hypotheses=None,
                            limit: int = 8) -> tuple[list[dict], list[dict]]:
    """Rank the CURRENT frontier into grounded attack opportunities.

    Candidates come ONLY from tree.actionable() (the work-selection authority);
    each is scored with the tree's own priority (plus its chained-boost, so the
    planner's reordering never demotes a chain press below an entry technique)
    and nudged by grounded context from the read-time projection:

      +30  an OUTSTANDING objective criterion aligns with the target
      +20  a HELD access holding exists on the target (foothold to press)
      +15  an evidence-backed hypothesis exists for the target (duck-typed
           HypothesisRegistry read — research trouble never breaks planning)
      -15  a FALSIFIED hypothesis exists for the target

    Remediated targets (latest retest FIXED) are excluded outright — returned
    as the second tuple element so the caller can journal the exclusion.
    Returns (opportunities, excluded_remediated)."""
    from .attack_tree import TECHNIQUES, technique_cost
    opportunities: list[dict] = []
    excluded: list[dict] = []
    if tree is None:
        return opportunities, excluded
    remediated = remediated_targets(findings)
    from .knowledge import canonical_url
    outstanding = ([(c.id, c.target) for c in objective.outstanding()]
                   if objective is not None else [])
    held_keys = {}
    if access is not None:
        for n in access.held():
            held_keys[canonical_url(getattr(n, "key", "") or "")] = \
                getattr(n, "source", "")
    # projection context: per-node verification/access/objective state
    context: dict[str, dict] = {}
    for path in authority_projection(graph=graph, tree=tree, findings=findings,
                                     access=access, objective=objective):
        for t in path.get("techniques", []):
            context[t["id"]] = path
    hyp_cache: dict[str, list] = {}

    def _hyp_for(target: str, technique: str) -> list:
        if hypotheses is None:
            return []
        key = f"{technique}@{target}"
        if key not in hyp_cache:
            try:
                # the driver passes the orchestrator's ResearchBundle; the
                # read API lives on its registry — unwrap when present
                reg = getattr(hypotheses, "registry", None) or hypotheses
                hyp_cache[key] = list(reg.list(asset_ref=target) or [])
            except Exception:
                hyp_cache[key] = []
        return hyp_cache[key]

    for node in tree.actionable(limit * 4):
        tid, target = node.technique, node.target
        tech = TECHNIQUES.get(tid)
        if tech is None:
            continue
        canon = canonical_url(target)
        if canon in remediated:
            excluded.append({"node_id": node.id, "technique": tid, "target": target,
                             "reason": "remediated: latest retest verdict is fixed"})
            continue
        score = (tech.priority if tech else 0) + (100 if tech.chained else 0)
        reasons = [f"tree frontier: priority {tech.priority}"
                   + (" (chained follow-up — press the foothold)" if tech.chained else "")]
        if any(_targets_align(ctarget, target) for _cid, ctarget in outstanding):
            score += 30
            hit = next(c.id for c in objective.outstanding()
                       if _targets_align(c.target, target))
            reasons.append(f"objective criterion {hit} outstanding on this target")
        if canon in held_keys:
            score += 20
            reasons.append(f"foothold held on target (source {held_keys[canon]})")
        hyps = _hyp_for(target, tid)
        with_evidence = [h for h in hyps if getattr(h, "evidence", None)]
        if with_evidence:
            score += 15
            reasons.append(f"hypothesis evidence ({len(with_evidence)} ref(s))")
        elif any(getattr(h, "verdict", "") == "falsified" for h in hyps):
            score -= 15
            reasons.append("a falsified hypothesis exists for this target")
        opportunities.append({
            "node_id": node.id, "technique": tid, "target": target,
            "role": "exploit", "score": score, "chained": bool(tech.chained),
            "opsec_cost": technique_cost(tid),
            "unlock_children": list(tech.unlocks),
            "reasons": reasons,
        })
    opportunities.sort(key=lambda o: o["score"], reverse=True)
    return opportunities[:limit], excluded


def map_surface_needed(graph: KnowledgeGraph | None) -> bool:
    """True when nothing is mapped yet — recon precedes offense (the
    methodology order: map the surface first, then test it)."""
    if graph is None:
        return True
    return not graph.nodes("endpoint")

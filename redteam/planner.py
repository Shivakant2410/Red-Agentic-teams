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

from .knowledge import ENDPOINT, HOST, SERVICE, KnowledgeGraph

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


def state_briefing(graph: KnowledgeGraph, max_targets: int = 6) -> str:
    s = graph.summary()
    counts = s["counts"]
    lines = ["[KNOWN STATE]"]
    lines.append(
        f"hosts={counts.get(HOST, 0)} services={counts.get(SERVICE, 0)} "
        f"endpoints={counts.get(ENDPOINT, 0)} | coverage {s['coverage_pct']}% "
        f"({s['coverage_tested']}/{s['coverage_total']} checks)"
    )
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

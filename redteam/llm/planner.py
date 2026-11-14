"""The model enters ONE queue — as an amplifier, under the same discipline.

The deterministic Brain generates bets from signals; when a model is
available it may PROPOSE more, after the deterministic queue drains, spending
only what is left of the budget. Every proposal goes through
Brain.admit_hypothesis: ranked, falsifiable, kill-able, proof-pipeline-gated —
or rejected with the reason, audited. A model cannot invent findings; it can
only propose tests.

OPSEC constraint stricter than anything in the surveyed systems: the digest is
credential-FREE (counts and URLs, never values) and proposals reference
harvested material by position ("@harvested:0"); the executor resolves refs
locally. The model proposes what to test — it never holds the material.

This mirrors reflection.py's failure policy: any parse/validation error, any
model failure, is logged and the run continues exactly as without a model.
"""
from __future__ import annotations

import json
import re

PLANNER_SYSTEM = """You are the hypothesis proposer in an authorized red-team engagement. \
You receive a factual, credential-free digest of what the deterministic attack brain \
currently holds: signals, gates, harvested-material COUNTS (never values), principals, \
workflow links, and the queue state. Propose 1-3 NEXT tests.

Rules:
- Output STRICT JSON, nothing else: {"hypotheses": [{kind, statement, prediction, probes, \
severity, cost, strength, cwe?, kill?}]}
- kind must be one of the executor_kinds listed in the digest.
- probes values must be primitive (string/number/boolean) or FLAT lists of strings.
- Reference harvested credentials ONLY as "@harvested:<index>" — the digest never \
contains their values and you must never request or guess them.
- statement and prediction must be falsifiable: state the condition under which the bet \
is WRONG (its kill condition).
- Base every claim ONLY on the digest. Do not invent endpoints, findings, or access that \
the digest does not imply. If nothing in the digest suggests a test, return \
{"hypotheses": []}.
"""

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def build_digest(brain) -> dict:
    """What the model may see. Counts and URLs; NEVER credential values."""
    st = brain.state
    kinds: dict[str, int] = {}
    for s in st.signals:
        kinds[s.kind] = kinds.get(s.kind, 0) + 1
    return {
        "base": brain._base,
        "principals": list(st.principals),
        "signal_kinds": kinds,
        "gates": [f"{u} ({s})" for u, s in st.gates[:8]],
        "harvested_credential_count": len(st.tokens),
        "credential_refs": [f"@harvested:{i}"
                            for i in range(min(3, len(st.tokens)))],
        "api_surface": list(st.api_paths[:8]),
        "workflow_links": list(st.workflow_links[:5]),
        "state_reads": [r["url"] for r in st.state_reads[:5]],
        "unexplored_paths": [p for p in st.unexplored
                             if p not in st.observed_urls][:8],
        "queue": [f"{h.kind} rank={h.rank}" for h in brain.queue[:5]],
        "executor_kinds": sorted(brain.EXECUTABLE_KINDS),
        "severities": ["critical", "high", "medium", "low"],
    }


def _parse_proposals(raw: str) -> list[dict]:
    """The model's output is data, not instructions: extract the JSON object,
    tolerate code fences, accept a bare list. Anything else raises."""
    text = raw or ""
    m = _JSON_FENCE.search(text)
    if m:
        text = m.group(1)
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    if start < 0:
        raise ValueError("no JSON object in proposal")
    parsed, _ = json.JSONDecoder().raw_decode(text[start:])
    if isinstance(parsed, dict):
        parsed = parsed.get("hypotheses", [])
    if not isinstance(parsed, list):
        raise ValueError("proposals must be a list")
    return [p for p in parsed if isinstance(p, dict)]


def propose(brain, chat_fn, audit=None, max_proposals: int = 3) -> list[tuple[bool, str]]:
    """Ask the model for bets; admit each through the SAME queue discipline."""
    digest = build_digest(brain)
    messages = [
        {"role": "system", "content": PLANNER_SYSTEM},
        {"role": "user", "content": json.dumps(digest)},
    ]
    raw = chat_fn(messages)
    try:
        proposals = _parse_proposals(raw)
    except (ValueError, TypeError) as exc:
        if audit:
            audit.record("brain.hypothesis.proposed", ok=False,
                         reason=f"parse: {exc}", raw=str(raw)[:200])
        return [(False, f"parse: {exc}")]
    out: list[tuple[bool, str]] = []
    for spec in proposals[:max_proposals]:
        spec = dict(spec)
        spec["source"] = f"llm:{str(spec.get('source', 'planner'))[:80]}"
        ok, why = brain.admit_hypothesis(spec)
        out.append((ok, why))
        if audit:
            audit.record("brain.hypothesis.proposed", ok=ok, reason=str(why)[:160])
    return out

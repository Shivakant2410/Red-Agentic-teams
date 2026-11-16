"""The ATLAS-side catalog and two-way map (our tool).

The registry (techniques.py) carries per-technique ATLAS anchors with an
honest verified/inferred split on the LINKAGE. This module completes the
other direction the user of a red-team tool actually asks: enumerate the
MITRE ATLAS techniques relevant to the LLM01/agentic attack surface this
module emulates, and answer coverage questions mechanically instead of by
narrative:

  ours -> atlas   which ATLAS techniques each registry technique anchors to
  atlas -> ours   which registry techniques exercise each ATLAS technique
  uncovered       ATLAS techniques in scope that NOTHING here exercises yet
  candidates      recommended additional anchors (label verified, linkage ours)

TWO DIFFERENT HONESTY FLAGS — do not conflate:

  AtlasTechnique.verified (here)  the ATLAS ENTRY exists with this label and
      tactic: every id/label/tactic in this catalog was checked against
      atlas.mitre.org mirrors (the T0051 page and the per-ID pages) on
      2026-11-11. No field in this catalog is guessed; T0024's tactic is
      corroborated (label verified via related-technique listings and the
      Exfiltration-tactic grouping), and the T0051 sub-technique tactics
      inherit the parent page.
  AtlasRef.verified (registry)    the LINKAGE technique->entry is established
      knowledge; False means the label is real but the mapping is this
      repo's judgment.

The catalog is the INSPECTED SLICE relevant to this module's channels,
stages and oracles — not the full matrix (the Aug-2026 ATLAS release carries
114 techniques / 83 sub-techniques) — and it never re-states a linkage the
registry does not make: the map is DERIVED from TECHNIQUES' own atlas
tuples (single source of truth).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .techniques import TECHNIQUES


@dataclass(frozen=True)
class AtlasTechnique:
    id: str           # "AML.T0051.001"
    label: str        # exact ATLAS name
    tactic: str       # ATLAS tactic(s), slash-separated when multiple
    maturity: str     # realized | demonstrated | feasible | …
    verified: bool    # entry existence verified (see module docstring)
    note: str         # why this entry matters to THIS module's surface


_CATALOG = (
    AtlasTechnique(
        "AML.T0051", "LLM Prompt Injection", "Execution", "realized", True,
        "the family every technique in this registry sits under; sub-"
        "technique split verified on the T0051 page"),
    AtlasTechnique(
        "AML.T0051.000", "LLM Prompt Injection: Direct", "Execution",
        "realized", True,
        "family A (user_message channel) and the plan-field direct-adjacent "
        "techniques C1/C2/C4"),
    AtlasTechnique(
        "AML.T0051.001", "LLM Prompt Injection: Indirect", "Execution",
        "realized", True,
        "family B (all eight untrusted-content channels), C3, D1, family E"),
    AtlasTechnique(
        "AML.T0051.002", "LLM Prompt Injection: Triggered", "Execution",
        "realized", True,
        "dormant instruction fired by a user action or system event: the "
        "memory-plant recall shape (B6) and the trigger-gated fun-tuning "
        "shape (D2); linkage flagged inferred in the registry"),
    AtlasTechnique(
        "AML.T0054", "LLM Jailbreak", "Privilege Escalation / Defense Evasion",
        "demonstrated", True,
        "guardrail suppression adjacent to injection: A2 (extraction "
        "demand), A5 (encoded evasion), A6 (optimized suffix)"),
    AtlasTechnique(
        "AML.T0053", "AI Agent Tool Invocation",
        "Execution / Privilege Escalation", "demonstrated", True,
        "the success stage every forbidden_tool-oracle technique aims at: "
        "the agent invoking a tool under attacker direction"),
    AtlasTechnique(
        "AML.T0056", "Extract LLM System Prompt", "Exfiltration", "feasible",
        True,
        "A2's exact technique (verbatim system-prompt echo demand); not yet "
        "anchored in the registry — listed as a candidate"),
    AtlasTechnique(
        "AML.T0057", "LLM Data Leakage", "Exfiltration", "realized", True,
        "broader sensitive-information leakage; OWASP LLM02 territory — "
        "this module scopes to canary-typed LLM01 movement evidence"),
    AtlasTechnique(
        "AML.T0077", "LLM Response Rendering", "Exfiltration",
        "demonstrated", True,
        "E2's exact relay: private data hidden in a response the user's "
        "client renders (markdown-image shape); candidate anchor"),
    AtlasTechnique(
        "AML.T0086", "Exfiltration via AI Agent Tool Invocation",
        "Exfiltration", "realized", True,
        "E3's exact shape: sensitive data encoded into tool input "
        "parameters and sent to an adversary-controlled location; "
        "candidate anchor"),
    AtlasTechnique(
        "AML.T0024", "Exfiltration via AI Inference API", "Exfiltration",
        "realized", True,
        "exfil through the model API itself (context echo); our relay "
        "evidence is canary-typed per channel instead — uncovered"),
    AtlasTechnique(
        "AML.T0025", "Exfiltration via Cyber Means", "Exfiltration",
        "realized", True,
        "classic post-foothold exfil (C2, DNS, HTTP) — infrastructure "
        "layer (ATT&CK overlap), outside the offline fixture; uncovered"),
    AtlasTechnique(
        "AML.T0020", "Poison Training Data",
        "Resource Development / Persistence", "realized", True,
        "the upstream action of the fun-tuning vector (D2): poisoning "
        "rows to implant trigger-gated behavior; candidate anchor"),
    AtlasTechnique(
        "AML.T0100", "AI Agent Clickbait", "Execution", "realized", True,
        "deceptive web content baiting computer-use agents into clicks/"
        "copy/navigation — needs a computer-use channel the fixture does "
        "not model; uncovered"),
    AtlasTechnique(
        "AML.T0103", "Deploy AI Agent", "Execution", "realized", True,
        "adversary-side capability (running agents in the victim "
        "environment), not a victim-surface technique; uncovered"),
    AtlasTechnique(
        "AML.T0105", "Escape to Host", "Privilege Escalation",
        "demonstrated", True,
        "container/VM breakout after agent compromise — the offline "
        "fixture has no OS layer; uncovered"),
)

ATLAS_TECHNIQUES: dict = {t.id: t for t in _CATALOG}

_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")

# Recommended ADDITIONAL anchors: the ATLAS label is verified; the linkage
# is this repo's judgment, so they are listed here rather than silently
# rewritten into the registry's verified tuples.
_CANDIDATES: tuple = (
    {"technique": "PI.A2", "atlas": "AML.T0056",
     "reason": ("A2's exact ATLAS technique (Extract LLM System Prompt, "
                "Exfiltration, feasible): the payload demands a verbatim "
                "system-prompt echo; the registry anchors stop at "
                "T0051.000 + T0054")},
    {"technique": "PI.E2", "atlas": "AML.T0077",
     "reason": ("markdown-image exfil crosses at RENDER time on the "
                "user's client (demonstrated technique), not at echo "
                "time — the relay E2 models is T0077's mechanism")},
    {"technique": "PI.E3", "atlas": "AML.T0086",
     "reason": ("fetch_url with the canary embedded in tool input "
                "parameters sent to an adversary-controlled location is "
                "T0086's realized shape verbatim")},
    {"technique": "PI.D2", "atlas": "AML.T0020",
     "reason": ("fun-tuning's upstream action is poisoning the training "
                "corpus (Resource Development + Persistence); keep "
                "T0051.002 for the trigger-gated behavior it implants")},
    {"technique": "forbidden_tool-oracle techniques (PI.A3, PI.A4, "
     "PI.B1-PI.B8, PI.C1-PI.C4, PI.D1)", "atlas": "AML.T0053",
     "reason": ("the success stage these oracles measure IS the agent's "
                "tool invocation under attacker direction (demonstrated, "
                "Execution/Privilege Escalation)")},
)

_VERIFIED_AGAINST = (
    "atlas.mitre.org mirrors (T0051 page + per-ID pages: T0053, T0054, "
    "T0056, T0057, T0077, T0086, T0020, T0025, T0100, T0103, T0105) on "
    "2026-11-11")


def atlas_map() -> dict:
    """Two-way map DERIVED from the registry's own atlas tuples. The parent
    technique (T0051) counts as exercised whenever any of its sub-techniques
    is anchored — anchoring a sub-technique exercises the family by
    definition."""
    by_technique: dict = {}
    by_atlas: dict = {}
    for t in TECHNIQUES:
        by_technique[t.id] = [
            {"id": r.id, "label": r.label, "verified": r.verified}
            for r in t.atlas]
        for r in t.atlas:
            by_atlas.setdefault(r.id, []).append(t.id)
    for aid in list(by_atlas):
        if aid.startswith("AML.T0051."):
            by_atlas.setdefault("AML.T0051", []).append(aid + "->subs")
    return {"by_technique": by_technique, "by_atlas": by_atlas}


def atlas_coverage() -> dict:
    """The ATLAS-side audit: which catalog entries the registry exercises,
    which it does not, and the candidate anchor additions. The mechanical
    answer to 'what does the ATLAS map say we are missing?'."""
    m = atlas_map()["by_atlas"]
    used: dict = {}
    for aid, tids in m.items():
        if aid.endswith("->subs"):
            continue
        used[aid] = tids
    uncovered = [ATLAS_TECHNIQUES[aid] for aid in ATLAS_TECHNIQUES
                 if aid not in used]
    anchors = [r for t in TECHNIQUES for r in t.atlas]
    return {
        "catalog_size": len(ATLAS_TECHNIQUES),
        "exercised": len(used),
        "uncovered": [{"id": u.id, "label": u.label, "tactic": u.tactic,
                       "note": u.note} for u in uncovered],
        "candidates": list(_CANDIDATES),
        "anchor_counts": {
            "total": len(anchors),
            "linkage_verified": sum(1 for a in anchors if a.verified),
            "linkage_inferred": sum(1 for a in anchors if not a.verified),
        },
    }


def atlas_audit() -> dict:
    """The full CLI payload: catalog, two-way map, coverage, and the
    verification statement."""
    m = atlas_map()
    return {
        "verified_against": _VERIFIED_AGAINST,
        "catalog": [{"id": c.id, "label": c.label, "tactic": c.tactic,
                     "maturity": c.maturity, "verified": c.verified,
                     "note": c.note}
                    for c in _CATALOG],
        "by_technique": m["by_technique"],
        # the parent's list carries the sub-technique ids implied by the
        # registry's anchors (the "->subs" marker marks implied, not direct)
        "by_atlas": {k: [v2.removesuffix("->subs") for v2 in v
                         if not v2.endswith("->subs")
                         or k == "AML.T0051"]
                     for k, v in m["by_atlas"].items()},
        **atlas_coverage(),
    }

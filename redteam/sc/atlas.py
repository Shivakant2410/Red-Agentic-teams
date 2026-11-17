"""The SC ATLAS-side catalog and two-way map (our tool).

The registry (techniques.py) carries per-technique ATLAS anchors with the
honest verified/inferred split on the LINKAGE. This module completes the
other direction the user of a red-team tool actually asks: enumerate the
MITRE ATLAS techniques relevant to the LLM03 supply-chain surface this
lane adjudicates, and answer coverage questions mechanically instead of
by narrative:

  ours -> atlas   which ATLAS techniques each registry technique anchors to
  atlas -> ours   which registry techniques exercise each ATLAS technique
  uncovered       ATLAS techniques in scope that NOTHING here anchors yet
  candidates      recommended additional anchors (label verified, linkage ours)

TWO DIFFERENT HONESTY FLAGS — do not conflate:

  AtlasTechnique.verified (here)  the ATLAS ENTRY exists with this label
      and tactic: every id/label/tactic in this catalog was checked
      against the live ATLAS pages on 2026-11-14 (the AML.T0010 page with
      all six sub-technique labels; the AML.T0011 page with all four;
      both via the gtkcyber.com mirror of atlas.mitre.org). AML.T0020's
      label and tactics were verified 2026-11-11 in the PI lane's session
      and are unchanged. Nothing here is guessed. Sub-technique maturity
      and tactic inherit the parent page, per the PI lane's convention.
  AtlasRef.verified (registry)    the LINKAGE technique->entry is
      established knowledge ("verified": a malicious package name IS
      AML.T0011.001's realized case) or this repo's judgment ("inferred":
      the fixture's pickle stands in for serialized weights).

The catalog is the INSPECTED SLICE relevant to this lane's artifact
surfaces — not the full matrix — and it never re-states a linkage the
registry does not make: the map is DERIVED from TECHNIQUES' own atlas
tuples (single source of truth).

One deliberate non-mapping is part of the catalog's honesty: AML.T0020
"Poison Training Data" is IN scope and UNCOVERED on purpose — PoisonGPT
is a post-training weight edit (ROME), not training-data poisoning, so
anchoring SC.P1 to T0020 would be the kind of plausible-sounding mapping
this repo exists to kill.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .techniques import TECHNIQUES


@dataclass(frozen=True)
class AtlasTechnique:
    id: str           # "AML.T0010.003"
    label: str        # exact ATLAS name
    tactic: str       # ATLAS tactic(s), slash-separated when multiple
    maturity: str     # realized | demonstrated | feasible | …
    verified: bool    # entry existence verified (see module docstring)
    note: str         # why this entry matters to THIS lane's surface


_CATALOG = (
    AtlasTechnique(
        "AML.T0010", "AI Supply Chain Compromise", "Initial Access",
        "realized", True,
        "the lane's parent technique — every family sits under it; "
        "exercised via its sub-techniques (the ->subs marker marks "
        "implied, not direct)"),
    AtlasTechnique(
        "AML.T0010.000", "Hardware", "Initial Access", "realized", True,
        "device/firmware-level compromise of AI hardware — OWASP risk #8 "
        "territory, no hardware fixtures in this lane; uncovered"),
    AtlasTechnique(
        "AML.T0010.001", "AI Software", "Initial Access", "realized", True,
        "SC.D1's exact technique (torchtriton compromised the AI software "
        "dependency itself); SC.V1 anchors it too — a vulnerable "
        "framework version is the software-side entry, our judgment"),
    AtlasTechnique(
        "AML.T0010.002", "Data", "Initial Access", "realized", True,
        "training-data compromise is OWASP LLM04's surface; deliberately "
        "out of this lane; uncovered"),
    AtlasTechnique(
        "AML.T0010.003", "Model", "Initial Access", "realized", True,
        "SC.P1's exact technique (PoisonGPT compromised the model "
        "artifact itself); SC.A1's fixture pickle stands in for "
        "serialized weights — that linkage is our judgment"),
    AtlasTechnique(
        "AML.T0010.004", "Container Registry", "Initial Access",
        "realized", True,
        "compromised container images for AI workloads — no container "
        "fixtures in this lane; uncovered"),
    AtlasTechnique(
        "AML.T0010.005", "AI Agent Tool", "Initial Access", "realized",
        True,
        "agent-tool poisoning lives in the skills lane (MCP rug-pull "
        "territory), not the artifact fixture; uncovered"),
    AtlasTechnique(
        "AML.T0011", "User Execution", "Execution", "realized", True,
        "the load-executes-the-artifact semantics this lane is built on: "
        "a pickle executes on LOAD, so admission is the only safe "
        "checkpoint; exercised via its sub-techniques"),
    AtlasTechnique(
        "AML.T0011.000", "Unsafe AI Artifacts", "Execution", "realized",
        True,
        "SC.A1's exact technique: the artifact is unsafe by construction "
        "and its load is the execution"),
    AtlasTechnique(
        "AML.T0011.001", "Malicious Package", "Execution", "realized",
        True,
        "SC.D1's exact technique: torchtriton is the realized case"),
    AtlasTechnique(
        "AML.T0011.002", "Poisoned AI Agent Tool", "Execution",
        "realized", True,
        "agent-tool poisoning — skills-lane territory; uncovered"),
    AtlasTechnique(
        "AML.T0011.003", "Malicious Link", "Execution", "realized", True,
        "chat-surface phishing is OWASP LLM01's indirect-injection "
        "territory; uncovered"),
    AtlasTechnique(
        "AML.T0020", "Poison Training Data",
        "Resource Development / Persistence", "realized", True,
        "deliberately NOT anchored: PoisonGPT is a post-training weight "
        "edit (ROME), not training-data poisoning — LLM04/T0020 is a "
        "different surface; uncovered on purpose"),
)

ATLAS_TECHNIQUES: dict = {t.id: t for t in _CATALOG}

_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")

# Recommended ADDITIONAL anchor: the ATLAS label is verified; the linkage
# is this repo's judgment, so it is listed here rather than silently
# rewritten into the registry's tuples.
_CANDIDATES: tuple = (
    {"technique": "SC.V1 (the ShadowRay exploitation shape)",
     "atlas": "AML.T0011.000",
     "reason": ("the in-the-wild campaign delivered RCE into operator-run "
                "clusters via the jobs API — the load/execute semantics "
                "of unsafe AI artifacts; kept as a candidate because the "
                "fixture adjudicates the PIN, not the exploitation "
                "session (declared known-uncovered)")},
)

_VERIFIED_AGAINST = (
    "atlas.mitre.org AML.T0010 page (all six sub-technique labels) and "
    "AML.T0011 page (all four) verified 2026-11-14 via the gtkcyber.com "
    "mirror; AML.T0020 label verified 2026-11-11 (PI lane session)")


def atlas_map() -> dict:
    """Two-way map DERIVED from the registry's own atlas tuples. The
    parent technique (T0010/T0011) counts as exercised whenever any of
    its sub-techniques is anchored — anchoring a sub-technique exercises
    the family by definition."""
    by_technique: dict = {}
    by_atlas: dict = {}
    for t in TECHNIQUES:
        by_technique[t.id] = [
            {"id": a["id"], "label": a["label"],
             "verified": a["linkage"] == "verified"}
            for a in t.atlas]
        for a in t.atlas:
            by_atlas.setdefault(a["id"], []).append(t.id)
    for parent, prefix in (("AML.T0010", "AML.T0010."),
                           ("AML.T0011", "AML.T0011.")):
        if any(aid.startswith(prefix) for aid in by_atlas):
            by_atlas.setdefault(parent, []).append(parent + "->subs")
    return {"by_technique": by_technique, "by_atlas": by_atlas}


def atlas_coverage() -> dict:
    """The ATLAS-side audit: which catalog entries the registry anchors,
    which it deliberately does not, and the candidate anchor additions.
    The mechanical answer to 'what does the ATLAS map say we are
    missing?'."""
    m = atlas_map()["by_atlas"]
    used: dict = {}
    for aid, tids in m.items():
        if aid.endswith("->subs"):
            continue
        used[aid] = tids
    uncovered = [ATLAS_TECHNIQUES[aid] for aid in ATLAS_TECHNIQUES
                 if aid not in used]
    anchors = [a for t in TECHNIQUES for a in t.atlas]
    return {
        "catalog_size": len(ATLAS_TECHNIQUES),
        "exercised": len(used),
        "uncovered": [{"id": u.id, "label": u.label, "tactic": u.tactic,
                       "note": u.note} for u in uncovered],
        "candidates": list(_CANDIDATES),
        "anchor_counts": {
            "total": len(anchors),
            "linkage_verified": sum(1 for a in anchors
                                    if a["linkage"] == "verified"),
            "linkage_inferred": sum(1 for a in anchors
                                    if a["linkage"] == "inferred"),
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
        # the parents' lists carry the sub-technique ids implied by the
        # registry's anchors (the "->subs" marker marks implied)
        "by_atlas": {k: [t.removesuffix("->subs") for t in v
                         if not t.endswith("->subs") or k.endswith("T0010")
                         or k.endswith("T0011")]
                     for k, v in m["by_atlas"].items()},
        **atlas_coverage(),
    }

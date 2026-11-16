"""SC ATLAS audit tests — written FIRST (TDD).

The contract these tests specify (redteam/sc/atlas.py, mirroring the PI
lane's ATLAS-side discipline for the supply-chain surface):

  (1) every registry anchor resolves into the catalog with the SAME
      label — the map is DERIVED from the registry's own atlas tuples
      (single source of truth, never re-stated);
  (2) the catalog is the VERIFIED slice relevant to the supply-chain
      surface: AML.T0010 with all six sub-technique labels, AML.T0011
      with all four, and AML.T0020 — every entry existence-verified,
      fully annotated, never guessed;
  (3) the two-way map is exact and inverse-consistent, with the
      parent-implied rule (anchoring a sub-technique exercises the
      parent);
  (4) the coverage audit mechanically partitions the catalog into
      exercised and uncovered, and NAMES the uncovered slice — including
      T0020 with the explicit ROME/post-training distinction instead of
      a silent omission;
  (5) the two honesty axes stay distinct: catalog-entry existence
      (verified) vs registry linkage (verified/inferred);
  (6) the CLI exposes the audit (python -m redteam.sc --atlas / --audit).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from redteam.sc.atlas import ATLAS_TECHNIQUES, atlas_coverage, atlas_map
from redteam.sc.techniques import TECHNIQUES

_REPO_ROOT = Path(__file__).resolve().parents[1]

_VERIFIED_CATALOG = {
    "AML.T0010": ("AI Supply Chain Compromise", "Initial Access"),
    "AML.T0010.000": ("Hardware", "Initial Access"),
    "AML.T0010.001": ("AI Software", "Initial Access"),
    "AML.T0010.002": ("Data", "Initial Access"),
    "AML.T0010.003": ("Model", "Initial Access"),
    "AML.T0010.004": ("Container Registry", "Initial Access"),
    "AML.T0010.005": ("AI Agent Tool", "Initial Access"),
    "AML.T0011": ("User Execution", "Execution"),
    "AML.T0011.000": ("Unsafe AI Artifacts", "Execution"),
    "AML.T0011.001": ("Malicious Package", "Execution"),
    "AML.T0011.002": ("Poisoned AI Agent Tool", "Execution"),
    "AML.T0011.003": ("Malicious Link", "Execution"),
    "AML.T0020": ("Poison Training Data",
                  "Resource Development / Persistence"),
}


def test_every_registry_anchor_resolves_with_matching_label():
    for t in TECHNIQUES:
        assert t.atlas, f"{t.id} has no ATLAS anchor"
        for a in t.atlas:
            assert a["id"] in ATLAS_TECHNIQUES, \
                f"{t.id} -> {a['id']}: anchor not in the ATLAS catalog"
            assert a["label"] == ATLAS_TECHNIQUES[a["id"]].label, \
                f"{t.id} -> {a['id']}: label drift between registry and " \
                "catalog"


def test_catalog_is_exactly_the_verified_slice():
    assert set(ATLAS_TECHNIQUES) == set(_VERIFIED_CATALOG)
    for aid, (label, tactic) in _VERIFIED_CATALOG.items():
        c = ATLAS_TECHNIQUES[aid]
        assert c.label == label, aid
        assert c.tactic == tactic, aid
        assert c.verified is True, aid
        assert c.maturity, aid
        assert c.note, f"{aid}: an unexplained catalog entry is dead weight"


def test_by_atlas_membership_is_exact():
    m = atlas_map()["by_atlas"]
    plain = {aid: set(v) for aid, v in m.items()
             if not aid.endswith("->subs")}
    assert plain["AML.T0010.001"] == {"SC.D1", "SC.V1"}
    assert plain["AML.T0010.003"] == {"SC.A1", "SC.P1"}
    assert plain["AML.T0011.000"] == {"SC.A1"}
    assert plain["AML.T0011.001"] == {"SC.D1"}


def test_parent_techniques_exercised_via_sub_anchors():
    """Anchoring a sub-technique exercises the parent family by
    definition — the map carries the implication explicitly."""
    m = atlas_map()["by_atlas"]
    for parent, subs in (("AML.T0010", "AML.T0010."),
                         ("AML.T0011", "AML.T0011.")):
        implied = [v for v in m.get(parent, []) if v.endswith("->subs")]
        assert implied, parent
        sub_ids = {aid for aid in m if aid.startswith(subs)
                   and not aid.endswith("->subs")
                   and m[aid]}
        assert sub_ids, parent
        assert m[parent], parent


def test_two_way_map_is_inverse_consistent():
    m = atlas_map()
    pairs = {(tid, a["id"])
             for tid, anchors in m["by_technique"].items()
             for a in anchors}
    for aid, tids in m["by_atlas"].items():
        for tid in tids:
            if tid.endswith("->subs"):
                continue
            assert (tid, aid) in pairs, (tid, aid)
    cov = atlas_coverage()
    used = {aid for aid in m["by_atlas"] if not aid.endswith("->subs")}
    uncovered_ids = {u["id"] for u in cov["uncovered"]}
    assert used | uncovered_ids == set(ATLAS_TECHNIQUES)
    assert not (used & uncovered_ids)


def test_coverage_pins():
    cov = atlas_coverage()
    assert cov["catalog_size"] == 13
    assert cov["exercised"] == 6   # T0010 + T0011 (parents) + 4 subs
    uncovered_ids = {u["id"] for u in cov["uncovered"]}
    assert uncovered_ids == {
        "AML.T0010.000", "AML.T0010.002", "AML.T0010.004",
        "AML.T0010.005", "AML.T0011.002", "AML.T0011.003", "AML.T0020"}
    assert cov["anchor_counts"] == {
        "total": 6, "linkage_verified": 4, "linkage_inferred": 2}


def test_t0020_is_deliberately_uncovered_with_the_rome_note():
    """The PoisonGPT mapping statement must be mechanical, not implied:
    T0020 stays uncovered ON PURPOSE because ROME is a post-training
    weight edit, not training-data poisoning."""
    cov = atlas_coverage()
    note = next(u["note"] for u in cov["uncovered"]
                if u["id"] == "AML.T0020")
    assert "post-training" in note and "ROME" in note
    assert all(a["id"] != "AML.T0020"
               for t in TECHNIQUES for a in t.atlas)


def test_two_honesty_axes_stay_distinct():
    # catalog axis: AML.T0010.003 EXISTS with label+tactic verified
    assert ATLAS_TECHNIQUES["AML.T0010.003"].verified is True
    # registry axis: SC.A1's LINKAGE to it is this repo's judgment
    a1 = next(t for t in TECHNIQUES if t.id == "SC.A1")
    ref = next(a for a in a1.atlas if a["id"] == "AML.T0010.003")
    assert ref["linkage"] == "inferred"
    # and the definitional mappings are marked verified
    d1 = next(t for t in TECHNIQUES if t.id == "SC.D1")
    ref = next(a for a in d1.atlas if a["id"] == "AML.T0011.001")
    assert ref["linkage"] == "verified"


def test_candidate_names_the_exploitation_shape():
    cov = atlas_coverage()
    cand = {(c["technique"], c["atlas"]) for c in cov["candidates"]}
    assert ("SC.V1 (the ShadowRay exploitation shape)",
            "AML.T0011.000") in cand
    for _, aid in cand:
        assert aid in ATLAS_TECHNIQUES
        assert re.match(r"^AML\.T\d{4}(\.\d{3})?$", aid)


def test_cli_atlas_and_audit_flags_print_the_audits():
    out = subprocess.run(
        [sys.executable, "-m", "redteam.sc", "--atlas"],
        capture_output=True, text=True, check=True, cwd=_REPO_ROOT)
    payload = json.loads(out.stdout)
    assert payload["catalog_size"] == 13
    assert payload["by_technique"]["SC.D1"][0]["id"] == "AML.T0010.001"
    # an unanchored catalog entry appears in coverage, never in the map
    assert "AML.T0010.004" not in payload["by_atlas"]
    assert "2026-11-14" in payload["verified_against"]

    out = subprocess.run(
        [sys.executable, "-m", "redteam.sc", "--audit"],
        capture_output=True, text=True, check=True, cwd=_REPO_ROOT)
    payload = json.loads(out.stdout)
    assert payload["techniques"] == 4
    assert payload["payloads"] == 15
    assert "training_data_poisoning" in payload["known_uncovered"]

    # no flags: argparse usage error, never a silent empty audit
    out = subprocess.run(
        [sys.executable, "-m", "redteam.sc"],
        capture_output=True, text=True, cwd=_REPO_ROOT)
    assert out.returncode != 0
    assert not out.stdout.strip()

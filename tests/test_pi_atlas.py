"""The ATLAS-side catalog (redteam/pi/atlas.py): the map the user of the
tool reads must be DERIVED from the registry's own anchors and the catalog
entries must be verified, never guessed. These tests pin: (1) every
registry anchor resolves into the catalog with the SAME label, (2) the
two-way map is exact, (3) the coverage audit mechanically names the ATLAS
slice nothing here exercises, (4) the two honesty axes (catalog-entry
existence vs registry linkage) stay distinct, (5) the CLI exposes it."""

import json
import re
import subprocess
import sys
from pathlib import Path

from redteam.pi.atlas import ATLAS_TECHNIQUES, atlas_coverage, atlas_map
from redteam.pi.techniques import TECHNIQUES

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_registry_anchor_resolves_with_matching_label():
    for t in TECHNIQUES:
        assert t.atlas, f"{t.id} has no ATLAS anchor"
        for r in t.atlas:
            assert r.id in ATLAS_TECHNIQUES, \
                f"{t.id} -> {r.id}: anchor not in the ATLAS catalog"
            assert r.label == ATLAS_TECHNIQUES[r.id].label, \
                f"{t.id} -> {r.id}: label drift between registry and catalog"


def test_catalog_well_formed_and_fully_annotated():
    for aid, c in ATLAS_TECHNIQUES.items():
        assert re.match(r"^AML\.T\d{4}(\.\d{3})?$", aid), aid
        assert c.tactic, aid
        assert c.maturity, aid
        assert c.note, f"{aid}: an unexplained catalog entry is dead weight"
        assert c.verified is True, \
            f"{aid}: entries with unverified existence must not ship"


def test_by_atlas_membership_is_exact():
    m = atlas_map()["by_atlas"]
    subs = {aid: set(v) for aid, v in m.items()
            if not aid.endswith("->subs") and aid != "AML.T0051"}
    assert subs["AML.T0051.000"] == {
        "PI.A1", "PI.A2", "PI.A3", "PI.A4", "PI.C1", "PI.C2", "PI.C4"}
    assert subs["AML.T0051.001"] == {
        "PI.B1", "PI.B2", "PI.B3", "PI.B4", "PI.B5", "PI.B6", "PI.B7",
        "PI.B8", "PI.C3", "PI.D1", "PI.E1", "PI.E2", "PI.E3", "PI.E4"}
    assert subs["AML.T0051.002"] == {"PI.A4", "PI.D2"}
    assert subs["AML.T0054"] == {"PI.A2", "PI.A5", "PI.A6"}


def test_two_way_map_is_inverse_consistent():
    m = atlas_map()
    pairs = {(tid, a["id"])
             for tid, anchors in m["by_technique"].items() for a in anchors}
    for aid, tids in m["by_atlas"].items():
        for tid in tids:
            if tid.endswith("->subs"):
                continue
            assert (tid, aid) in pairs, (tid, aid)
    # partition: every catalog entry is either exercised or named uncovered
    cov = atlas_coverage()
    used = {aid for aid in m["by_atlas"] if not aid.endswith("->subs")}
    uncovered_ids = {u["id"] for u in cov["uncovered"]}
    assert used | uncovered_ids == set(ATLAS_TECHNIQUES)
    assert not (used & uncovered_ids)


def test_coverage_names_the_unexercised_atlas_slice():
    cov = atlas_coverage()
    assert cov["catalog_size"] == 16
    assert cov["exercised"] == 5  # T0051 + the three sub-techniques + T0054
    uncovered_ids = {u["id"] for u in cov["uncovered"]}
    assert uncovered_ids == {
        "AML.T0053", "AML.T0056", "AML.T0057", "AML.T0077", "AML.T0086",
        "AML.T0024", "AML.T0025", "AML.T0020", "AML.T0100", "AML.T0103",
        "AML.T0105"}
    cand = {(c["technique"], c["atlas"]) for c in cov["candidates"]}
    assert ("PI.A2", "AML.T0056") in cand
    assert ("PI.E2", "AML.T0077") in cand
    assert ("PI.E3", "AML.T0086") in cand
    assert ("PI.D2", "AML.T0020") in cand
    assert any("AML.T0053" == a for _, a in cand)
    assert cov["anchor_counts"] == {
        "total": 26, "linkage_verified": 21, "linkage_inferred": 5}


def test_two_honesty_axes_stay_distinct():
    # catalog axis: T0051.002 EXISTS with label+tactic verified
    assert ATLAS_TECHNIQUES["AML.T0051.002"].verified is True
    # registry axis: its LINKAGE is this repo's judgment (inferred)
    d2 = next(t for t in TECHNIQUES if t.id == "PI.D2")
    ref = next(r for r in d2.atlas if r.id == "AML.T0051.002")
    assert ref.verified is False


def test_cli_atlas_flag_prints_the_audit():
    out = subprocess.run(
        [sys.executable, "-m", "redteam.pi", "--atlas"],
        capture_output=True, text=True, check=True, cwd=_REPO_ROOT)
    payload = json.loads(out.stdout)
    assert payload["catalog_size"] == 16
    assert payload["by_technique"]["PI.B6"][0]["id"] == "AML.T0051.001"
    # an unanchored catalog entry appears in coverage, never in the map
    assert "AML.T0086" not in payload["by_atlas"]
    assert "2026-11-11" in payload["verified_against"]

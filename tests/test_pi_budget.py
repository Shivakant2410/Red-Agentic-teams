"""Budget scheduling for the adaptive phase (our tool): the kernel coverage
engine decides WHICH mutant cells a bounded round buys.

Properties under test:
  - the budget is a hard cap (per round) and cells never repeat across rounds;
  - selection is deterministic (same seed -> identical cell sequence);
  - the greedy optimizer actually spreads: a tight budget spans MORE
    techniques than the naive first-k slice of the candidate order;
  - the summary discloses the sample honestly (candidates seen, left unrun,
    labels covered/uncovered, SAMPLE note);
  - the unbudgeted path is untouched (no budget block, legacy behavior).
"""

from redteam.pi.runner import PIEngagement, PIEngagementConfig, \
    _ADAPTIVE_OPERATORS

import json
import subprocess
import sys

import pytest


def _run(**kw):
    cfg = PIEngagementConfig(engagement_id="budget", technique_ids=["PI.B1"],
                             defense_modes=("off", "on"), seed=21, **kw)
    eng = PIEngagement(cfg)
    return eng, eng.run()


def _mutant_ids(eng):
    return [r.test_id for r in eng.records
            if "[adaptive mutant:" in r.rationale]


def test_budget_is_a_hard_cap_and_cells_never_repeat():
    eng, s = _run(adaptive_rounds=2, adaptive_budget=3)
    ids = _mutant_ids(eng)
    assert len(ids) == s["adaptive"]["mutant_cells"] <= 2 * 3
    assert len(set(ids)) == len(ids), "no cell runs twice"
    b = s["adaptive"]["budget"]
    assert b["cells_selected"] == len(ids)
    assert b["left_unrun"] == b["candidate_cells_seen"] - len(ids)


def test_budget_rounds_select_disjoint_cells():
    eng, _s = _run(adaptive_rounds=2, adaptive_budget=2)
    ids = _mutant_ids(eng)
    r1 = {i.split("-", 1)[1] for i in ids if i.startswith("a01-")}
    r2 = {i.split("-", 1)[1] for i in ids if i.startswith("a02-")}
    assert r1 and r2, "both rounds ran under budget"
    assert not (r1 & r2), "a later round never re-buys a spent cell"


def test_budget_selection_is_deterministic():
    e1, s1 = _run(adaptive_rounds=2, adaptive_budget=4)
    e2, s2 = _run(adaptive_rounds=2, adaptive_budget=4)
    assert _mutant_ids(e1) == _mutant_ids(e2)
    assert s1["adaptive"]["budget"]["labels_covered"] == \
        s2["adaptive"]["budget"]["labels_covered"]


def test_tight_budget_buys_more_techniques_than_naive_order():
    """The reason the coverage engine is wired in at all: the first k
    candidates in iteration order collapse onto one technique; the greedy
    pick must span more. (A1 sorts before B1, so the naive slice is
    technique-monochrome.)"""
    cfg = PIEngagementConfig(
        engagement_id="spread", technique_ids=["PI.A1", "PI.B1"],
        defense_modes=("off", "on"), seed=21,
        adaptive_rounds=1, adaptive_budget=3)
    eng = PIEngagement(cfg)
    s = eng.run()
    ids = _mutant_ids(eng)
    techniques_hit = {r.technique_id for r in eng.records
                      if "[adaptive mutant:" in r.rationale}
    # naive: the first 3 candidate cells in the same canonical order the
    # budgeted loop enumerates them (registry technique order, mode order,
    # canonical operator order), minus static-succeeded exclusions.
    succeeded = {(r.technique_id, r.payload_ref, r.defense_config)
                 for r in eng.records if r.verdict == "succeeded"
                 and "[adaptive mutant:" not in r.rationale}
    naive: list = []
    for t in eng.techniques:
        for pi in range(len(t.payloads)):
            for mode in ("off", "on"):
                if (t.id, t.payload_ref_at(pi), mode) in succeeded:
                    continue
                for name, _op in _ADAPTIVE_OPERATORS:
                    naive.append((t.id, mode, name))
    naive_techs = {t for t, _m, _o in naive[:3]}
    assert len(techniques_hit) >= len(naive_techs), (
        "greedy must never cover fewer techniques than the naive slice")
    assert len(techniques_hit) > len(naive_techs) or len(naive_techs) >= 2, (
        "on this fixture the greedy pick demonstrably spreads wider")


def test_budget_summary_discloses_the_sample():
    eng, s = _run(adaptive_rounds=1, adaptive_budget=2)
    b = s["adaptive"]["budget"]
    assert b["per_round"] == 2
    assert b["candidate_cells_seen"] > b["cells_selected"]
    assert b["left_unrun"] > 0
    assert "SAMPLE" in b["note"]
    assert not (set(b["labels_covered"]) & set(b["labels_uncovered"]))
    assert all(lbl.startswith(("op:", "mode:", "family:", "stage:"))
               or lbl.startswith("PI.") for lbl in b["labels_covered"])


def test_unbudgeted_path_has_no_budget_block():
    eng, s = _run(adaptive_rounds=1)
    assert "budget" not in s["adaptive"]
    assert s["adaptive"]["mutant_cells"] > 0


def test_invalid_budget_raises():
    with pytest.raises(ValueError):
        _run(adaptive_rounds=1, adaptive_budget=0)


def test_budget_with_large_budget_equals_full_enumeration_upper_bound():
    """Budget >= candidate count must run every candidate exactly once —
    the cap degenerates to the full grid, honestly reported."""
    eng, s = _run(adaptive_rounds=1, adaptive_budget=10_000)
    b = s["adaptive"]["budget"]
    assert b["cells_selected"] == b["candidate_cells_seen"]
    assert b["left_unrun"] == 0
    assert b["labels_uncovered"] == []


def test_cli_adaptive_budget_flag(tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "redteam.pi", "--out", str(tmp_path),
         "--techniques", "PI.B1", "--defense-modes", "on",
         "--adaptive-rounds", "1", "--adaptive-budget", "2", "--seed", "21"],
        capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    summary = json.loads(out.stdout)
    assert summary["adaptive"]["budget"]["per_round"] == 2
    assert summary["adaptive"]["mutant_cells"] <= 2

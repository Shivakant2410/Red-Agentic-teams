"""Cell-card publish gates (paper recs 6+7+8 wiring): no rate ships naked."""

import json

from redteam.cellcard import CellCard, rate_card, retry_card, seeded_card


# --- plain rate cards -----------------------------------------------------------------

def test_rate_card_carries_wilson_interval():
    card = rate_card("injection vs guard", 34, 100)
    lo, hi = card.ci
    assert card.rate == 0.34
    assert lo <= card.rate <= hi
    assert card.publishable
    assert "95% CI" in card.to_markdown()
    assert "34/100" in card.to_markdown()


def test_zero_evidence_is_held_not_published():
    card = rate_card("no attempts yet", 0, 0)
    assert not card.publishable
    assert any("n=0" in v for v in card.violations())
    assert "NOT PUBLISHABLE" in card.to_markdown()


def test_card_dict_is_json_roundtrippable_and_flags_gate():
    card = rate_card("held cell", 0, 0)
    d = card.to_dict()
    assert d["publishable"] is False
    assert json.dumps(d)   # must serialize cleanly for the dashboard board


# --- W7: retry cells must state policy + carry the null -------------------------------

def test_retry_cell_without_policy_is_held():
    card = CellCard(label="rawk cell", x=10, n=100, kind="retry", retries_k=5)
    assert not card.publishable
    assert any("retry policy" in v for v in card.violations())
    assert any("resampling-null" in v for v in card.violations())


def test_retry_card_attaches_null_and_publishes():
    # 10 sessions of k=2, one success per session: session rate 1.0 vs patience 0.75.
    attempts = [True, False] * 10
    card = retry_card("adaptive session", attempts, k=2, retry_policy="k=2 per session")
    assert card.kind == "retry"
    assert card.null is not None
    assert card.null["sessions"] == 10
    assert card.publishable
    assert "retry policy: k=2 per session" in card.to_markdown()
    # observed 1.0 sits inside the [0.48, 1.0] band of the 0.5-marginal null
    assert card.null["inside_null"] is True


def test_retry_null_flags_success_clustering():
    # 30 sessions of k=10, exactly one success per session (marginal 0.1):
    # session rate 1.0 towers over the patience baseline 0.651 -> OUTSIDE the null.
    attempts = [True] + [False] * 9
    attempts = attempts * 30
    card = retry_card("clustered cell", attempts, k=10, retry_policy="k=10")
    assert card.null["observed"] == 1.0
    assert card.null["null_rate"] < 0.7
    assert card.null["inside_null"] is False
    assert "OUTSIDE null" in card.to_markdown()


# --- W9: seeded cells report pass^k; <3 seeds need a caveat ---------------------------

def test_seeded_card_publishes_with_pass_k():
    card = seeded_card("task across seeds", [True] * 8, pass_group_k=8)
    assert card.kind == "seeded"
    assert card.pass_k is not None
    assert card.pass_k["pass_k"] == 1.0
    assert card.publishable
    assert "pass^8" in card.to_markdown()


def test_fewer_than_three_seeds_needs_explicit_caveat():
    card = seeded_card("rushed cell", [True, True], pass_group_k=2)
    assert not card.publishable
    assert any("seed" in v for v in card.violations())

    ok = seeded_card("rushed cell", [True, True], pass_group_k=2,
                     single_seed_caveat=True)
    assert ok.publishable
    assert "single-seed" in ok.to_markdown()


def test_seeds_fewer_than_group_size_yields_undefined_pass_k():
    card = seeded_card("tiny cell", [True], pass_group_k=8)
    assert card.pass_k is None
    assert not card.publishable


# --- W8: judge-scored cells need their calibration band -------------------------------

def test_judged_cell_without_band_is_held():
    card = rate_card("judge-scored cell", 24, 40, judge_used=True)
    assert not card.publishable
    assert any("calibration band" in v for v in card.violations())


def test_judged_cell_with_band_publishes():
    band = {"lo": 0.1, "hi": 0.9, "judge_accuracy": 0.75, "judge_lo": 0.706,
            "judge_hi": 0.778, "calibration_n": 569}
    card = rate_card("judge-scored cell", 24, 40, judge_used=True, judge_band=band)
    assert card.publishable
    md = card.to_markdown()
    assert "judge-calibrated true-rate band" in md
    assert "0.75" in md


def test_violations_list_every_rule_broken_at_once():
    card = CellCard(label="worst cell", x=0, n=0, kind="retry", judge_used=True)
    v = card.violations()
    assert len(v) == 4   # n=0, no policy, no null, no judge band

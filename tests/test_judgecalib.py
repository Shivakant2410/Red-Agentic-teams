"""Judge calibration (W8): worst-case true-rate bands from labeled agreement sets."""

from redteam.judgecalib import (MIN_CALIBRATION_RECORDS, JudgeCalibration,
                                wrap_judged_rate)


def _pairs(agreements: int, disagreements: int) -> list[tuple[bool, bool]]:
    pairs = [(True, True)] * agreements + [(True, False)] * disagreements
    return pairs


def test_accuracy_and_interval_from_labeled_pairs():
    calib = JudgeCalibration.from_pairs(_pairs(34, 6))     # 40 records, 85% agreement
    assert calib.n == 40
    assert calib.agreements == 34
    assert calib.accuracy == 0.85
    lo, hi = calib.ci
    assert 0.70 <= lo <= 0.85 <= hi <= 0.95
    assert calib.calibrated        # 40 >= MIN_CALIBRATION_RECORDS


def test_small_calibration_set_is_refused_certification():
    calib = JudgeCalibration.from_pairs(_pairs(5, 0))
    assert calib.n < MIN_CALIBRATION_RECORDS
    assert not calib.calibrated
    wrapped = wrap_judged_rate(calib, 6, 10)
    assert wrapped["calibrated"] is False


def test_correction_band_is_worst_case_symmetric():
    calib = JudgeCalibration.from_pairs(_pairs(34, 6))
    a_lo = calib.ci[0]
    slack = 1.0 - a_lo
    lo, hi = calib.correction_band(0.6)
    assert abs(lo - max(0.0, 0.6 - slack)) < 1e-3
    assert abs(hi - min(1.0, 0.6 + slack)) < 1e-3
    # the judged point estimate always sits inside its own band
    assert lo <= 0.6 <= hi


def test_band_clips_at_unit_interval():
    calib = JudgeCalibration.from_pairs(_pairs(30, 10))    # a_lo well below 0.75
    lo, hi = calib.correction_band(0.98)
    assert 0.0 <= lo <= 0.98 <= hi <= 1.0


def test_empty_calibration_is_maximally_honest():
    calib = JudgeCalibration()
    assert calib.n == 0
    assert calib.correction_band(0.5) == (0.0, 1.0)
    wrapped = wrap_judged_rate(calib, 1, 2)
    assert wrapped["true_band"] == [0.0, 1.0]
    assert wrapped["calibrated"] is False


def test_wrap_payload_fits_the_cellcard_gate():
    calib = JudgeCalibration.from_pairs(_pairs(34, 6))
    wrapped = wrap_judged_rate(calib, 24, 40)
    assert wrapped["judged_rate"] == 0.6
    assert wrapped["judge_accuracy"] == 0.85
    assert wrapped["calibration_n"] == 40
    # and the gate accepts a card carrying it:
    from redteam.cellcard import rate_card
    card = rate_card("judged cell", 24, 40, judge_used=True, judge_band=wrapped)
    assert card.publishable

"""Judge-calibration harness (W8) — a judged rate is a measurement with error.

The best measured agentic-safety judge agrees with human labels only 74.4% of
the time (R-Judge, 569 records; the paper's Table 3 puts the 95% CI at
[70.6, 77.8]). Any cell whose verdicts come from an LLM judge inherits that
error, and publishing the judged rate bare is publishing noise. From a
calibration set — records where a human label and the judge's label BOTH exist —
this module:

  1. estimates judge agreement with a Wilson 95% interval;
  2. wraps a judged rate in a worst-case correction band: a judge that is only
     `a_lo` accurate can disagree with the truth by up to (1 - a_lo) in EITHER
     direction, so the honest true-rate band is
         [max(0, p - (1 - a_lo)), min(1, p + (1 - a_lo))].
     Deliberately conservative — it assumes judge errors can all concentrate
     against the caller. This is a BAND, not a point correction;
  3. refuses to certify small calibration sets: below MIN_CALIBRATION_RECORDS
     the agreement interval is too wide to mean anything, so the wrapper marks
     the rate `calibrated: False` and the cellcard gate holds the card.

Honest simplification, stated: agreement with human labels on the calibration
set is used as the judge's accuracy. A class-imbalanced calibration set
overstates accuracy, so calibrate on a balanced set — the noisy-judge result
("Calibrate, don't curate") says labeled anchors, not more unlabeled data, are
what buy honest judged rates. Cross-model judge comparisons (W8's actual
acceptance test) ship intervals because wrap_judged_rate always carries the
judge's OWN agreement interval next to the band.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .stats import wilson_ci

MIN_CALIBRATION_RECORDS = 30   # below this, a_lo tells nothing — refuse to certify


@dataclass
class JudgeCalibration:
    """(human_label, judge_label) pairs from a labeled calibration set."""

    records: list[tuple[bool, bool]] = field(default_factory=list)

    @classmethod
    def from_pairs(cls, pairs: list[tuple[bool, bool]]) -> "JudgeCalibration":
        return cls(records=list(pairs))

    @property
    def n(self) -> int:
        return len(self.records)

    @property
    def agreements(self) -> int:
        return sum(1 for human, judge in self.records if human == judge)

    @property
    def accuracy(self) -> float:
        return round(self.agreements / self.n, 4) if self.n else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        """Wilson 95% interval on judge agreement (the judge's own error bar)."""
        return wilson_ci(self.agreements, self.n)

    @property
    def calibrated(self) -> bool:
        """Certified only when the calibration set is large enough to mean anything."""
        return self.n >= MIN_CALIBRATION_RECORDS

    def correction_band(self, p_hat: float) -> tuple[float, float]:
        """Worst-case true-rate band for a judged point estimate `p_hat`.

        With judge accuracy's LOWER bound a_lo, the judged rate can be off by
        (1 - a_lo) in either direction; the band clips to [0, 1]. An empty
        calibration set yields the maximally honest [0, 1].
        """
        if self.n == 0:
            return 0.0, 1.0
        a_lo = self.ci[0]
        slack = 1.0 - a_lo
        return (round(max(0.0, p_hat - slack), 4),
                round(min(1.0, p_hat + slack), 4))


def wrap_judged_rate(calib: JudgeCalibration, judged_x: int, judged_n: int) -> dict:
    """The W8 card payload: judged rate + its Wilson CI + the calibrated band.

    `judged_x/judged_n` is the judge's success count on the cell. The returned
    dict drops straight into CellCard.judge_band (cellcard.py), which refuses to
    publish a judge-scored cell without it.
    """
    p = judged_x / judged_n if judged_n else 0.0
    lo, hi = wilson_ci(judged_x, judged_n)
    band = calib.correction_band(p)
    return {
        "judged_rate": round(p, 4),
        "judged_ci": [lo, hi],
        "true_band": [band[0], band[1]],
        "judge_accuracy": calib.accuracy,
        "judge_lo": calib.ci[0],
        "judge_hi": calib.ci[1],
        "calibration_n": calib.n,
        "calibrated": calib.calibrated,
    }

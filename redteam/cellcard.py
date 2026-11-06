"""The standard cell card — the fail-closed gate between a measured rate and a claim.

The paper's section-8 observation, quoted: "the statistical layer is ahead of
the evaluation layer. The estimators (Wilson, pooling, retry null, pass^k) now
exist as a library; the cells that should consume them still print bare
numbers." This module closes that gap. It is the ONE schema every measured rate
in the framework travels in, with publish rules that REFUSE (not warn) when a
number would ship naked:

  - every proportion carries its Wilson 95% interval (stats.wilson_ci);
  - a cell that used retries must STATE its retry policy and attach the
    resampling-null verdict — a session rate without those is measuring the
    harness's patience, not the target's weakness (W7, paper sec. 7.5);
  - a multi-seed cell reports pass^k; a cell with fewer than 3 seeds ships only
    with an explicit single-seed caveat (W9 — tau-bench's pass^8 < 25% is the
    cautionary tale);
  - a judge-scored cell carries the judge-calibration band from judgecalib.py
    — a judged rate without a calibration band is W8 and does not ship;
  - n = 0 is "no evidence", not "0.0".

`publishable == False` is a dashboard-visible state, not an exception: the card
renders with a NOT PUBLISHABLE header line naming every violated rule, so the
gate is diagnostic. Callers that want hard enforcement can assert on
`publishable` (CI gates do exactly that).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .stats import pass_hat_k, resampling_null, wilson_ci


@dataclass
class CellCard:
    """One measured rate, dressed for publication. See module docstring for the rules."""

    label: str
    x: int = 0                     # successes
    n: int = 0                     # trials (0 = no evidence — always held)
    kind: str = "rate"             # rate | retry | seeded
    # W7: retry cells must state policy + carry the resampling-null verdict.
    retry_policy: str = ""
    retries_k: int = 0
    null: dict | None = None
    # W9: seeded cells must report pass^k; <3 seeds need an explicit caveat.
    seeds_k: int = 0               # seeds RUN (the publish rule is about this)
    pass_group_k: int = 0          # the k in pass^k
    single_seed_caveat: bool = False
    pass_k: dict | None = None
    # W8: judge-scored cells must carry their calibration band.
    judge_used: bool = False
    judge_band: dict | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float:
        """Raw point estimate x/n (the CI's center is the shrunk Wilson estimate)."""
        return round(self.x / self.n, 4) if self.n else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        return wilson_ci(self.x, self.n)

    def violations(self) -> list[str]:
        """Every publish rule this card fails. Empty list = publishable."""
        v: list[str] = []
        if self.n <= 0:
            v.append("no evidence (n=0) — zero attempts is not a rate")
        if self.kind == "retry":
            if not self.retry_policy:
                v.append("retries were used but no retry policy is stated — "
                         "an unlabeled session rate measures patience (W7)")
            if self.null is None:
                v.append("retries were used but the resampling-null verdict is "
                         "missing — cannot tell success clustering from luck (W7)")
        if self.kind == "seeded":
            if self.pass_k is None or self.pass_k.get("pass_k") is None:
                v.append("seeded cell missing its pass^k estimate (W9) — need at "
                         "least as many seeds as the pass^k group size")
            if 0 < self.seeds_k < 3 and not self.single_seed_caveat:
                v.append(f"only {self.seeds_k} seed(s) and no single-seed caveat (W9)")
        if self.judge_used and self.judge_band is None:
            v.append("judge-scored cell without a judge-calibration band (W8)")
        return v

    @property
    def publishable(self) -> bool:
        return not self.violations()

    def to_markdown(self) -> str:
        lo, hi = self.ci
        lines = [f"**{self.label}** — {self.x}/{self.n} = {self.rate:.3f} "
                 f"(95% CI [{lo:.3f}, {hi:.3f}])"]
        if self.kind == "retry":
            lines.append(f"- retry policy: {self.retry_policy or '(unstated)'}")
            if self.null:
                where = ("inside null — luck at the observed per-attempt rate "
                         "explains the session number"
                         if self.null.get("inside_null")
                         else "OUTSIDE null — success clusters beyond luck "
                              "(adaptation, or guard wear)")
                lines.append(
                    f"- retry null: per-attempt {self.null.get('per_attempt_rate')}, "
                    f"patience baseline {self.null.get('null_rate')} "
                    f"[{self.null.get('lo95')}, {self.null.get('hi95')}], "
                    f"observed {self.null.get('observed')} → {where}")
        if self.kind == "seeded":
            if self.pass_k is not None:
                lines.append(
                    f"- pass^{self.pass_group_k}: {self.pass_k.get('pass_k')} "
                    f"[{self.pass_k.get('lo95')}, {self.pass_k.get('hi95')}] "
                    f"over {self.seeds_k} seeds")
            if self.seeds_k < 3 and self.single_seed_caveat:
                lines.append("- caveat: single-seed cell — reliability across runs "
                             "is unmeasured (see tau-bench pass^8 < 25%)")
        if self.judge_used:
            if self.judge_band:
                lines.append(
                    f"- judge-calibrated true-rate band: "
                    f"[{self.judge_band.get('lo')}, {self.judge_band.get('hi')}] "
                    f"(judge agreement {self.judge_band.get('judge_accuracy')} "
                    f"[{self.judge_band.get('judge_lo')}, {self.judge_band.get('judge_hi')}], "
                    f"calibration n={self.judge_band.get('calibration_n')})")
            else:
                lines.append("- judge-calibrated band: MISSING — card held (W8)")
        for note in self.notes:
            lines.append(f"- note: {note}")
        violations = self.violations()
        if violations:
            lines.append("- **NOT PUBLISHABLE**: " + "; ".join(violations))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "label": self.label, "x": self.x, "n": self.n, "rate": self.rate,
            "ci": list(self.ci), "kind": self.kind,
            "retry_policy": self.retry_policy, "retries_k": self.retries_k,
            "null": self.null, "seeds_k": self.seeds_k,
            "pass_group_k": self.pass_group_k, "pass_k": self.pass_k,
            "single_seed_caveat": self.single_seed_caveat,
            "judge_used": self.judge_used, "judge_band": self.judge_band,
            "notes": list(self.notes), "publishable": self.publishable,
            "violations": self.violations(),
        }


def rate_card(label: str, x: int, n: int, *, judge_used: bool = False,
              judge_band: dict | None = None, notes: list[str] | None = None) -> CellCard:
    """Plain measured proportion: x successes in n decided attempts, Wilson-interval'd."""
    return CellCard(label=label, x=x, n=n, kind="rate", judge_used=judge_used,
                    judge_band=judge_band, notes=list(notes or []))


def retry_card(label: str, attempts: list[bool], k: int, retry_policy: str, *,
               judge_used: bool = False, judge_band: dict | None = None,
               notes: list[str] | None = None) -> CellCard:
    """A cell where the harness retried up to k times per session.

    The headline rate stays the honest PER-ATTEMPT proportion; the resampling
    null (stats.resampling_null) travels with it so nobody can quietly promote
    the inflated session rate to 'the ASR'. Leave `retry_policy` empty to see
    the gate hold the card — that is the point.
    """
    return CellCard(
        label=label, x=sum(1 for a in attempts if a), n=len(attempts),
        kind="retry", retry_policy=retry_policy, retries_k=k,
        null=resampling_null(attempts, k), judge_used=judge_used,
        judge_band=judge_band, notes=list(notes or []))


def seeded_card(label: str, seed_outcomes: list[bool], pass_group_k: int, *,
                single_seed_caveat: bool = False, judge_used: bool = False,
                judge_band: dict | None = None,
                notes: list[str] | None = None) -> CellCard:
    """A cell run once per seed: seed_outcomes[i] = did the task pass on seed i.

    The header rate is pass^1 across seeds (with its interval); pass^k over
    groups of `pass_group_k` seeds is attached per W9. Fewer than 3 seeds ships
    ONLY with single_seed_caveat=True — set by the caller, owned by the caller.
    """
    return CellCard(
        label=label, x=sum(1 for s in seed_outcomes if s), n=len(seed_outcomes),
        kind="seeded", seeds_k=len(seed_outcomes), pass_group_k=pass_group_k,
        single_seed_caveat=single_seed_caveat,
        # pass^k needs m >= k seeds to estimate; undefined stays None so the
        # gate holds the card instead of publishing an empty estimate.
        pass_k=(lambda pk: pk if pk["pass_k"] is not None else None)(
            pass_hat_k(seed_outcomes, pass_group_k)),
        judge_used=judge_used, judge_band=judge_band, notes=list(notes or []))

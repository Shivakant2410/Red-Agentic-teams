"""The statistical layer — honest numbers for attack-surface claims.

Every rate this framework reports (attack-success rates, probe compliance rates,
class-poisoning susceptibility) is a proportion measured on a finite sample. This
module is the single place where such numbers get their uncertainty, so no cell card
or report can ever print a bare "34.5%" again without a correction the reader can
reproduce. Four tools, each answering one failure mode we saw in the 2025-26 red-team
literature:

  - `wilson`      — a measured rate on n trials is a POINT; the card shows the interval.
                    (Score-based CIs beat Wald intervals at small n and near 0/1, which
                    is exactly where red-team numbers live.)
  - `rule_of_three` — "we tried n times and saw zero" is not "it's safe": the 95% upper
                    bound is ~3/n. 30 clean runs only bound p at 0.10; you need ~3000
                    for 0.001. Guards against the "our guard blocked everything" claim.
  - `session_rate`/`per_attempt` — retry-until-success over k attempts inflates a
                    per-attempt rate p into a per-session rate 1-(1-p)^k. A raw-retry
                    harness that reports the session number as "the ASR" is measuring
                    its own patience, not the model's weakness. Both directions given.
  - `resampling_null` — given per-attempt outcomes, what does LUCK alone produce when
                    you get k tries? Exchangeable resampling builds that null so an
                    observed "any success in k" can be compared against it.
  - `pass_hat_k`  — tau-bench-style pass^k: reliability across k independent runs, not
                    a lucky draw. Estimated by bootstrap (groups of k must ALL pass).
  - `beta_pool`   — pooling several studies'/cells' (successes, trials) under a flat
                    prior, WITHOUT treating them as one homogeneous binomial sample
                    (heterogeneity is the norm — different targets, guards, judges).
                    Returns the posterior mean/sd of Beta(x+1, n-x+1) per cell, plus a
                    weighted-signal view (precision^2 weighting) for the overall rate.
  - `union_bound` — across N weaponizable classes each with base rate p_i, the chance
                    AT LEAST ONE bites you; the expected count of material classes.
                    Freivalds' inequality justification: P(union) <= sum p_i, and the
                    product form 1 - prod(1-p_i) is exact under independence.

References for the choices (paper: "Red-Teaming AI Systems in the Agentic Era"):
  Wilson 1927, JASA 22:209-212; rule of three: Hanley & Lippman-Hand 1983,
  JAMA 249:1743-1745; pass^k: Yao et al. 2024, tau-bench (arXiv:2406.12045);
  exchangeable-bootstrap null: Efron 1979; Beta-Binomial pooling: Gelman et al., BDA.
"""

from __future__ import annotations

import math
import random

Z95 = 1.959963984540054  # two-sided 95% normal quantile


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion, centered form.

    Returns (p_hat, half_width). The interval is [p_hat - hw, p_hat + hw], clipped
    to [0, 1]. Unlike the Wald interval this never leaves [0,1] and stays honest at
    small n — a 3/5 cell prints 0.60 ± 0.40, not nonsense.
    """
    if n <= 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    hw = (z / denom) * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    return round(center, 4), round(min(hw, 1.0), 4)


def wilson_ci(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """(lower, upper) bounds of the Wilson interval, clipped to [0, 1]."""
    p, hw = wilson(successes, n, z)
    return round(max(0.0, p - hw), 4), round(min(1.0, p + hw), 4)


def rule_of_three(n: int, confidence: float = 0.95) -> float:
    """95%-ish upper bound on the true rate after n trials with ZERO events observed.

    Exact form is 1 - (1-confidence)^(1/n) — the largest p whose P(zero events in n)
    = (1-p)^n still reaches (1-confidence); for 95% confidence the classic
    approximation is 3/n. Returns the exact value (which converges to 3/n for large
    n), so the caller can print "~3/n" in prose while the number is defensible.
    """
    if n <= 0:
        return 1.0
    return round(1.0 - (1.0 - confidence) ** (1.0 / n), 5)


def session_rate(p: float, k: int) -> float:
    """Per-SESSION success rate when the attacker retries k times: 1-(1-p)^k.

    This is the raw-retry inflation formula. A cell that retries k times and reports
    'any success' is reporting this, not p.
    """
    if k <= 0:
        return 0.0
    return round(1.0 - (1.0 - p) ** k, 5)


def per_attempt(session: float, k: int) -> float:
    """Invert session_rate: recover the honest per-attempt rate from a session rate."""
    if k <= 0 or session <= 0.0:
        return 0.0
    session = min(session, 1.0)
    return round(1.0 - (1.0 - session) ** (1.0 / k), 5)


def resampling_null(attempts: list[bool], k: int) -> dict:
    """Retry-inflation null: is the measured session rate more than luck + patience?

    A raw-retry harness runs m disjoint sessions of k attempts and headlines 'any
    success in a session'. This estimator asks: if attempts were EXCHANGEABLE at the
    observed marginal rate p (pure luck, no adaptation, no skill), the session rate
    would be q = 1-(1-p)^k — this is the patience baseline, and with m observed
    sessions its sampling band is q ± 1.96*sqrt(q(1-q)/m).

    An observed rate OUTSIDE the band means attempts are not exchangeable: success
    clusters in a way luck cannot produce (the defender degrades under pressure, or
    the attacker learns within the run) — exactly the exchangeability violation that
    makes a flat per-attempt rate lie about session-level risk. Pure function of the
    inputs: no seed, no Monte Carlo.
    """
    n = len(attempts)
    sessions = n // k if k > 0 else 0
    if n == 0 or k <= 0 or sessions == 0:
        return {"per_attempt_rate": None, "null_rate": None, "lo95": None,
                "hi95": None, "observed": None, "inside_null": False, "sessions": 0}
    p_hat = sum(1 for a in attempts if a) / n
    q = 1.0 - (1.0 - p_hat) ** k
    se = math.sqrt(q * (1.0 - q) / sessions)
    lo, hi = max(0.0, q - Z95 * se), min(1.0, q + Z95 * se)
    window_hits = sum(1 for i in range(sessions)
                      if any(attempts[i * k:(i + 1) * k]))
    observed = window_hits / sessions
    return {
        "per_attempt_rate": round(p_hat, 4),
        "null_rate": round(q, 4),
        "lo95": round(lo, 4),
        "hi95": round(hi, 4),
        "observed": round(observed, 4),
        "inside_null": lo <= observed <= hi,
        "sessions": sessions,
    }


def pass_hat_k(outcomes: list[bool], k: int, trials: int = 10_000,
               seed: int = 0) -> dict:
    """Estimate pass^k — P(the task passes on ALL of k independent runs) — by bootstrap.

    tau-bench's pass^k degrades brutally (their agents: <25% at k=8); a cell that
    reports only pass^1 hides that. Resample m completed runs into groups of k with
    replacement; pass^k estimate = fraction of groups where every member passed.
    Deterministic given (seed, inputs). Fewer than k outcomes -> undefined (None).
    """
    m = len(outcomes)
    if m < k or k <= 0 or trials <= 0:
        return {"pass_k": None, "lo95": None, "hi95": None, "groups": 0}
    rng = random.Random(seed)
    all_pass = 0
    for _ in range(trials):
        group_pass = True
        for _ in range(k):
            if not outcomes[rng.randrange(m)]:
                group_pass = False
                break
        all_pass += group_pass
    lo, hi = wilson_ci(all_pass, trials)
    return {
        "pass_k": round(all_pass / trials, 4),
        "lo95": lo,
        "hi95": hi,
        "groups": trials,
    }


def beta_pool(x: int, n: int) -> dict:
    """Posterior mean/sd for a rate under a flat Beta(1,1) prior: Beta(x+1, n-x+1).

    This is how cells pool their evidence WITHOUT the homogeneous-sample lie (a plain
    x/n merge pretends every attempt is exchangeable across different targets, guards
    and judges — they are not). Each cell keeps its own posterior; combine cells by
    precision-weighting their means via `pooled_cells`.
    """
    if n < 0 or x < 0 or x > n:
        return {"mean": 0.0, "sd": 0.0, "n": n, "x": x}
    mean = (x + 1.0) / (n + 2.0)
    sd = math.sqrt(mean * (1.0 - mean) / (n + 3.0))
    return {"mean": round(mean, 4), "sd": round(sd, 5), "n": n, "x": x}


def pooled_cells(cells: list[dict]) -> dict:
    """Precision-weighted combination of per-cell beta_pool posteriors.

    weights = 1/sd^2 (inverse variance); mean = sum(w*mean)/sum(w); sd = 1/sqrt(sum w).
    Cells with zero variance (n huge) dominate; empty cells (sd 0) are dropped.
    """
    pts = [(c["mean"], c["sd"]) for c in cells if c.get("sd", 0.0) > 0.0]
    if not pts:
        return {"mean": 0.0, "sd": 0.0, "cells": 0}
    ws = [1.0 / (sd * sd) for _, sd in pts]
    mean = sum(w * m for w, (m, _) in zip(ws, pts)) / sum(ws)
    sd = 1.0 / math.sqrt(sum(ws))
    return {"mean": round(mean, 4), "sd": round(sd, 5), "cells": len(pts)}


def defense_ratio(undefended: dict, defended: dict) -> float:
    """How many times more likely an attack lands undefended vs defended (mean ratio)."""
    d = defended.get("mean", 0.0)
    return round(undefended.get("mean", 0.0) / d, 2) if d > 0 else float("inf")


def union_bound(base_rates: list[float]) -> dict:
    """Across N weaponizable classes: expected material classes and P(at least one).

    expected = sum(p_i) is the count a red-teamer should plan to face per engagement;
    p_any = 1 - prod(1 - p_i) is exact under independence and an upper-bound guide
    otherwise (union bound: P(union) <= sum p_i). Even tiny per-class rates compound:
    14 classes at ~0.4 expected still means 'at least one' is a near certainty.
    """
    ps = [max(0.0, min(1.0, p)) for p in base_rates]
    expected = sum(ps)
    p_any = 1.0
    for p in ps:
        p_any *= (1.0 - p)
    return {
        "expected": round(expected, 3),
        "p_at_least_one": round(1.0 - p_any, 4),
        "classes": len(ps),
    }

"""Tests for the statistical layer — the numbers must reproduce the paper's worked
examples, and every estimator must be deterministic given (seed, inputs)."""

from __future__ import annotations

import math
import random

from redteam.stats import (
    beta_pool, defense_ratio, pass_hat_k, per_attempt, pooled_cells,
    resampling_null, rule_of_three, session_rate, union_bound, wilson, wilson_ci,
)


# --- Wilson intervals -----------------------------------------------------------------

def test_wilson_center_and_width_match_paper_worked_example():
    #undefended pool anchor from the paper: x=683, n=2312 -> 0.296
    p, hw = wilson(683, 2312)
    assert abs(p - 0.296) < 0.002
    assert hw < 0.021 and hw > 0.015
    lo, hi = wilson_ci(683, 2312)
    assert lo < p < hi


def test_wilson_stays_in_range_where_wald_lies():
    #Wald at 3/5 gives +-0.43 and can cross [0,1] at extremes; Wilson must not.
    p, hw = wilson(3, 5)
    lo, hi = wilson_ci(3, 5)
    assert 0.0 <= lo and hi <= 1.0 and lo < p < hi
    #all-success small cell: upper bound reaches exactly 1, but the LOWER bound is
    #the informative edge (you cannot claim 100% on n=10)
    lo, hi = wilson_ci(10, 10)
    assert lo > 0.69 and hi <= 1.0


def test_wilson_zero_trials_is_safe():
    assert wilson(0, 0) == (0.0, 0.0)
    assert wilson_ci(0, 0) == (0.0, 0.0)


# --- rule of three --------------------------------------------------------------------

def test_rule_of_three_matches_ladder_from_the_paper():
    #n>=30/60/300/3000 bounds p at ~0.10/0.05/0.01/0.001
    assert rule_of_three(30) < 0.10 + 1e-4 and rule_of_three(30) > 0.095
    assert rule_of_three(60) < 0.0505
    assert rule_of_three(300) < 0.0101
    assert rule_of_three(3000) < 0.0011


def test_rule_of_three_degrades_to_certainty_for_no_evidence():
    assert rule_of_three(0) == 1.0


# --- retry inflation ------------------------------------------------------------------

def test_session_rate_is_the_retry_inflation_formula():
    #p=0.03 per attempt, 20 queries -> ~46% per session (PAIR-style numbers)
    assert abs(session_rate(0.03, 20) - (1 - 0.97 ** 20)) < 1e-4
    #retries inflate: 5 attempts at 5% beats a single 5% shot
    assert session_rate(0.05, 5) > 0.05


def test_per_attempt_inverts_session_rate_roundtrip():
    for p in (0.01, 0.05, 0.2, 0.5):
        assert abs(per_attempt(session_rate(p, 7), 7) - p) < 0.001
    assert per_attempt(0.0, 5) == 0.0 and per_attempt(0.5, 0) == 0.0


# --- resampling null ------------------------------------------------------------------

def test_resampling_null_flags_patience_when_attempts_are_iid():
    #seeded i.i.d. attempts at p=0.3: the session rate must sit inside the
    #exchangeable band — the harness measured patience, not skill (that is the
    #null's verdict, and it must be the NORMAL case for a static attacker).
    rng = random.Random(42)
    attempts = [rng.random() < 0.3 for _ in range(400)]
    r = resampling_null(attempts, k=5)
    assert r["sessions"] == 80 and r["inside_null"] is True, r
    #the band is centered on the SAMPLE-implied session rate (binomial noise means
    #p_hat ~= 0.3, not exactly 0.3 — the formula must hold on the sample, not the pop)
    assert abs(r["null_rate"] - (1 - (1 - r["per_attempt_rate"]) ** 5)) < 0.001


def test_resampling_null_flags_adaptation_when_successes_cluster_late():
    #marginal rate says p=0.125, so an exchangeable world puts the session rate near
    #1-(0.875)^5 = 0.49. But this history only succeeds in the LAST session (adaptive
    #attacker: the defender has been probed open by then) — observed 0.125 sits far
    #BELOW the band: attempts are not exchangeable, and the flat rate is lying.
    adaptive = [False] * 35 + [True] * 5
    r = resampling_null(adaptive, k=5)
    assert r["observed"] < r["lo95"] and r["inside_null"] is False, r


def test_resampling_null_flags_early_clustering_too():
    #mirror image: one known-good technique lands immediately, then never again —
    #also non-exchangeable (a one-trick history), also outside the band.
    early = [True] * 5 + [False] * 35
    r = resampling_null(early, k=5)
    assert r["inside_null"] is False, r


def test_resampling_null_handles_degenerate_inputs():
    assert resampling_null([], 5)["inside_null"] is False
    assert resampling_null([False] * 10, 3)["observed"] == 0.0
    assert resampling_null([False] * 2, 5)["observed"] is None  # too short for one session


# --- pass^k ---------------------------------------------------------------------------

def test_pass_hat_k_penalizes_flaky_runs():
    reliable = pass_hat_k([True] * 18 + [False] * 2, k=3, trials=4000, seed=11)
    flaky = pass_hat_k([True] * 12 + [False] * 8, k=3, trials=4000, seed=11)
    assert reliable["pass_k"] > flaky["pass_k"] * 3
    assert reliable["pass_k"] > 0.4 and flaky["pass_k"] < 0.35


def test_pass_hat_k_undefined_below_k_outcomes():
    assert pass_hat_k([True, True], k=3)["pass_k"] is None


def test_pass_hat_k_perfect_and_deterministic():
    r = pass_hat_k([True] * 10, k=2, trials=1000, seed=5)
    assert r["pass_k"] == 1.0
    assert pass_hat_k([True] * 10, k=2, trials=1000, seed=5) == r


# --- Beta pooling ---------------------------------------------------------------------

def test_beta_pool_reproduces_paper_pools():
    #undefended x=683 n=2312 -> mean 0.296 sd 0.010; defended x=93 n=1258 -> 0.075 sd 0.007
    u = beta_pool(683, 2312)
    d = beta_pool(93, 1258)
    assert abs(u["mean"] - 0.296) < 0.001 and 0.009 < u["sd"] < 0.010
    assert abs(d["mean"] - 0.075) < 0.001 and 0.007 < d["sd"] < 0.0075
    #defenses cut the pooled rate ~4x (paper: 3.96x)
    assert abs(defense_ratio(u, d) - 3.96) < 0.05


def test_pooled_cells_inverse_variance_weighting():
    #the precise cell should dominate the sloppy one
    precise = {"mean": 0.10, "sd": 0.005}
    sloppy = {"mean": 0.90, "sd": 0.30}
    out = pooled_cells([precise, sloppy])
    assert out["mean"] < 0.2 and out["cells"] == 2
    assert pooled_cells([])["cells"] == 0
    assert pooled_cells([{"mean": 0.5, "sd": 0.0}])["cells"] == 0


# --- union bound ----------------------------------------------------------------------

def test_union_bound_matches_paper_expectation():
    #paper: expected 6.0 material classes across 14, P(>=1) ~= 0.9999
    ps = [0.80, 0.38, 0.31, 0.27, 0.25, 0.24, 0.23, 0.21, 0.20, 0.20, 0.19, 0.19, 0.18, 0.15]
    ub = union_bound(ps)
    assert abs(ub["expected"] - sum(ps)) < 1e-9
    assert ub["p_at_least_one"] > 0.99


def test_union_bound_edge_cases():
    assert union_bound([])["expected"] == 0.0
    assert union_bound([0.0] * 14)["p_at_least_one"] == 0.0
    assert union_bound([1.0])["p_at_least_one"] == 1.0
    #clamping: out-of-range inputs cannot corrupt the product
    assert union_bound([2.0, -3.0])["expected"] == 1.0

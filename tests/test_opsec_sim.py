"""Phase B4 — tests for the offline OPSEC evaluation harness (redteam/opsec_sim.py).

These tests pin the DIRECTIONAL claims the harness exists to measure — not magic
numbers from one seed: every threshold below has slack around the observed value so
a pool-composition change moves the numbers, never flips a conclusion. All runs are
deterministic (same seed -> identical report, verified cross-process)."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from redteam.opsec_sim import LOUD_COST, Scenario, compare, main, sweep

# The default race: quiet 7 | challenge 6 | recovery 7, budget 12, seed 7.
DEFAULT = Scenario()


def test_determinism_same_seed_identical_report():
    a = compare(DEFAULT).to_dict()
    b = compare(DEFAULT).to_dict()
    assert a == b


def test_scheduler_spends_less_inside_the_challenge_window():
    rep = compare(DEFAULT)
    # Legacy pours the round budget into a target that is challenging everything;
    # the shipped controller cuts that exposure by a third or more.
    assert rep.legacy.window_spend > 0
    assert rep.challenge_spend_reduction > 0.30
    assert rep.scheduler.window_spend < rep.legacy.window_spend


def test_ablation_separates_queue_discipline_from_the_belief():
    rep = compare(DEFAULT)
    # Queue discipline alone reduces window exposure, the belief adds MORE on top
    # (a strictly positive belief share), and the shipped controller is the sum.
    assert rep.challenge_spend_reduction_raw > 0.0
    assert rep.belief_share > 0.0
    assert rep.challenge_spend_reduction > rep.challenge_spend_reduction_raw


def test_no_loud_claims_inside_the_window_under_pressure():
    rep = compare(DEFAULT)
    # The whole point of pivoting cheap-first: while the defender is challenging,
    # the shipped controller stops buying cost>=4 techniques entirely.
    assert rep.legacy.window_loud >= 1
    assert rep.scheduler.window_loud == 0
    assert rep.legacy.window_loud >= rep.scheduler.window_loud + 1


def test_belief_reacts_and_recovers_non_sticky():
    rep = compare(DEFAULT)
    # The POMDP actually heard the burst (peak risk high) and stood back down
    # (end risk ~0) — the belief is never permanently sticky.
    assert rep.scheduler.peak_risk > 0.5
    assert rep.end_risk < 0.05
    # ...and the swarm's volume returns within a couple of rounds of the window.
    assert rep.recovery_lag is not None
    assert rep.recovery_lag <= 3


def test_yield_trade_is_bounded_and_honest():
    rep = compare(DEFAULT)
    # The throttle is not free: the shipped controller keeps most (not all) of the
    # legacy engagement's yield. This test pins the trade, not a sales pitch.
    assert rep.yield_retained > 0.80
    assert rep.yield_retained < 1.0


def test_quiet_target_no_belief_reaction_bounded_price():
    # A defender that NEVER reacts: risk stays 0, so shipped == queue-only, and
    # the only difference from legacy is queue discipline — at a bounded price.
    quiet = Scenario(rounds=12, quiet_prefix=12, challenge_span=0, seed=7)
    rep = compare(quiet)
    # The forward filter never claims certainty: even on all-200 traffic the
    # posterior keeps a ~0.4% floor (measured) — assert it stays in that floor
    # band, orders of magnitude below anything that would throttle (risk*SCALE
    # must stay far under mu, and indeed spend is byte-identical to the
    # belief-disabled ablation).
    assert rep.scheduler.peak_risk < 0.05
    assert rep.scheduler.peak_risk * 4.0 < 2.0   # SCALE*risk < DEFAULT_MU
    assert rep.scheduler.total_spend == rep.raw_only.total_spend
    assert rep.yield_retained > 0.85
    # ...and the swarm still works: it spends every round.
    assert all(s > 0 for s in rep.scheduler.spend_by_round)


def test_cli_json_smoke_and_small_scenario():
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--json", "--rounds", "10", "--quiet", "4",
                     "--challenge", "2", "--seed", "3"])
    assert code == 0
    payload = json.loads(buf.getvalue())
    assert set(payload) == {"scenario", "legacy", "scheduler_raw_only",
                            "scheduler", "comparison"}
    comp = payload["comparison"]
    for key in ("challenge_spend_reduction_pct", "challenge_loud_reduction_pct",
                "yield_retained_pct", "recovery_lag_rounds", "belief_share_pct",
                "end_risk"):
        assert key in comp


def test_cli_sweep_smoke():
    small = Scenario(rounds=8, quiet_prefix=3, challenge_span=2, seed=5)
    rows = sweep(small)
    assert len(rows) == 9          # 3 mu x 3 V
    for row in rows:
        assert {"mu", "V", "challenge_spend_reduction_pct",
                "yield_retained_pct", "recovery_lag_rounds"} <= set(row)


def test_cli_human_table_smoke():
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--rounds", "8", "--quiet", "3", "--challenge", "2",
                     "--seed", "5"])
    assert code == 0
    out = buf.getvalue()
    assert "challenge-window spend reduction" in out
    assert "yield retained" in out

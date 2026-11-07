"""Phase A4: the POMDP detection-belief filter (redteam/sandbox/detection_belief.py).

The tests below are the falsifiable acceptance criteria for the hand-authored
TRANSITION_MATRIX / emission constants: quiet targets must read quiet, challenge
windows must spike the belief, the filter must recover (not stay sticky), and
the belief vector must stay a proper probability distribution. If a future
calibration pass retunes the constants, these tests are what it has to clear.
"""

from __future__ import annotations

import pytest

from redteam.sandbox.detection_belief import (
    ALERTED, BLOCKED, QUIET, SUSPICIOUS, STATES, TRANSITION_MATRIX,
    BeliefFilter, DetectionBelief, Observation, observe_http_response,
)


def _normal() -> Observation:
    return Observation("normal", False, False, False)


def _challenge(rate_limited: bool = True) -> Observation:
    return Observation("high", True, True, rate_limited)


def _drive(filt: BeliefFilter, obs: Observation, n: int) -> list[dict]:
    return [filt.update(obs) for _ in range(n)]


# -- model-constant sanity (guards future retuning) ---------------------------------

def test_transition_matrix_rows_sum_to_one():
    for row in TRANSITION_MATRIX:
        assert abs(sum(row) - 1.0) < 1e-9


def test_emission_rows_sum_to_one():
    from redteam.sandbox.detection_belief import (
        CHALLENGE_EMISSION, LATENCY_EMISSION, RATE_LIMIT_EMISSION,
        STATUS_SHIFT_EMISSION,
    )
    for table in (LATENCY_EMISSION, STATUS_SHIFT_EMISSION,
                  CHALLENGE_EMISSION, RATE_LIMIT_EMISSION):
        for row in table:
            assert abs(sum(row) - 1.0) < 1e-9


# -- belief dynamics -----------------------------------------------------------------

def test_belief_stays_near_quiet_under_normal_observation_sequence():
    filt = BeliefFilter()
    history = _drive(filt, _normal(), 12)
    final = history[-1]
    assert final[QUIET] > 0.70
    assert filt.risk_score() < 0.10          # no challenge, no shift, no throttle


def test_belief_shifts_toward_alerted_under_challenge_sequence():
    filt = BeliefFilter()
    _drive(filt, _challenge(), 3)
    assert filt.risk_score() > 0.50
    assert filt.belief[BLOCKED] + filt.belief[ALERTED] > 0.50


def test_single_challenge_observation_spikes_risk_immediately():
    """The scheduler relies on this: a challenge response must not wait for
    cheap techniques to accumulate before the risk queue reacts."""
    filt = BeliefFilter()
    filt.update(_challenge())
    assert filt.risk_score() > 0.50


def test_belief_recovers_toward_quiet_after_return_to_normal():
    filt = BeliefFilter()
    _drive(filt, _challenge(), 4)
    spiked = filt.risk_score()
    assert spiked > 0.50
    _drive(filt, _normal(), 4)
    assert filt.risk_score() < 0.25          # not sticky forever


def test_belief_vector_stays_a_distribution_after_every_update():
    filt = BeliefFilter()
    sequence = ([_normal()] * 3 + [_challenge()] * 3 + [_normal()] * 3
                + [Observation("elevated", True, False, False)] * 2 + [_normal()] * 2)
    for obs in sequence:
        post = filt.update(obs)
        assert abs(sum(post.values()) - 1.0) < 1e-9
        assert all(0.0 <= v <= 1.0 for v in post.values())
        assert set(post) == set(STATES)


def test_risk_score_stays_in_unit_interval_over_long_mixed_run():
    filt = BeliefFilter()
    for i in range(200):
        obs = _challenge() if i % 7 == 3 else _normal()
        filt.update(obs)
        assert 0.0 <= filt.risk_score() <= 1.0


def test_update_is_pure_function_of_prior_and_observation():
    """Two filters with the same prior must evolve identically; one filter's
    extra history must never leak into another's posterior."""
    a, b = BeliefFilter(), BeliefFilter()
    post_a = a.update(_normal())
    post_b = b.update(_normal())
    assert post_a == post_b
    _drive(a, _challenge(), 5)               # a's state moves on
    # b's next update must match a FRESH filter's second update exactly —
    # b's own history (one normal obs) fully determines it, nothing shared.
    b2 = BeliefFilter()
    b2.update(_normal())
    assert b.update(_normal()) == b2.update(_normal())


def test_explicit_prior_is_respected():
    filt = BeliefFilter(prior={QUIET: 0.1, SUSPICIOUS: 0.1, ALERTED: 0.1, BLOCKED: 0.7})
    assert filt.belief[BLOCKED] == pytest.approx(0.7)


# -- observation extraction (DetectionBelief) -----------------------------------------

def _belief() -> DetectionBelief:
    return DetectionBelief()


def test_challenge_header_announces_itself_at_any_status():
    b = _belief()
    obs = b.observe("api.acme.example", "/x", 200, 0.001,
                    headers={"cf-mitigated": "challenge"}, body="ok")
    assert obs.challenge_present


def test_challenge_body_marker_counts_only_on_block_status():
    b = _belief()
    obs_ok = b.observe("api.acme.example", "/x", 200, 0.001,
                       headers={}, body="learn to solve captchas today")
    assert not obs_ok.challenge_present
    obs_block = b.observe("api.acme.example", "/x", 403, 0.001,
                          headers={}, body="Attention Required")
    assert obs_block.challenge_present


def test_rate_limit_signals_429_retry_after_and_body():
    b = _belief()
    assert b.observe("h", "/p", 429, 0.001).rate_limit_signal
    assert b.observe("h", "/p", 503, 0.001,
                     headers={"Retry-After": "30"}).rate_limit_signal
    assert b.observe("h", "/p", 403, 0.001,
                     body="You have exceeded the rate limit").rate_limit_signal
    assert not b.observe("h", "/p", 200, 0.001, body="rate limit").rate_limit_signal


def test_latency_buckets_against_rolling_baseline():
    b = _belief()
    for _ in range(5):                       # baseline ~1ms of successful traffic
        b.observe("h", "/p", 200, 0.001)
    assert b.observe("h", "/p", 200, 0.0015).latency_bucket == "normal"
    assert b.observe("h", "/p", 200, 0.003).latency_bucket == "elevated"   # ~3x
    assert b.observe("h", "/p", 200, 0.010).latency_bucket == "high"       # ~10x


def test_slowdown_never_rebaselines_itself():
    """Baseline learning is success-gated: a tarpit must not raise the bar it
    is being measured against."""
    b = _belief()
    for _ in range(5):
        b.observe("h", "/p", 200, 0.001)
    for _ in range(6):                       # sustained slow replies
        b.observe("h", "/p", 200, 0.050)
    assert b.observe("h", "/p", 200, 0.001).latency_bucket == "normal"
    assert b.observe("h", "/p", 200, 0.050).latency_bucket == "high"


def test_status_class_shift_tracks_endpoint_baseline():
    b = _belief()
    b.observe("h", "/p", 200, 0.001)
    assert b.observe("h", "/p", 403, 0.001).status_class_shift
    assert not b.observe("h", "/p", 200, 0.001).status_class_shift


def test_failed_transport_is_skipped_entirely():
    """status 0 = no HTTP response = no defender evidence, no baseline poison."""
    b = _belief()
    obs = b.observe("h", "/p", 0, 5.0)
    assert (obs.latency_bucket, obs.status_class_shift,
            obs.challenge_present, obs.rate_limit_signal) == ("normal", False, False, False)
    assert ("h", "/p") not in b._latencies   # baseline never saw the 5.0s "exchange"
    b.observe("h", "/p", 200, 0.001)         # baseline starts fresh, not 5.0s
    assert b.observe("h", "/p", 200, 0.001).latency_bucket == "normal"


# -- the http.py hook ------------------------------------------------------------------

class _Ctx:
    pass


def test_observe_http_response_updates_attached_belief():
    ctx = _Ctx()
    ctx.detection_belief = _belief()
    before = ctx.detection_belief.risk_score()
    observe_http_response(ctx, {"url": "https://api.acme.example/a/b"}, 403, 0.5,
                          {"cf-mitigated": "challenge"}, "Attention Required")
    assert ctx.detection_belief.risk_score() > before


def test_observe_http_response_is_a_noop_without_a_belief_and_never_raises():
    class Boom:
        detection_belief = property(lambda self: (_ for _ in ()).throw(RuntimeError))
    observe_http_response(_Ctx(), {"url": "not a url"}, 200, 0.0, {}, "")  # no belief — fine
    observe_http_response(Boom(), {"url": None}, 200, 0.0, {}, "")         # hostile ctx — swallowed

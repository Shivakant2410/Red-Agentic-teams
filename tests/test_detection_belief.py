"""Phase B3 — the POMDP detection-belief filter (redteam/sandbox/detection_belief.py).

Covered here, per the phase spec:
- a normal (quiet) traffic sequence keeps the belief parked on QUIET,
- a challenge / rate-limit sequence drives the belief to ALERTED/BLOCKED,
- recovery: a return to clean traffic pulls the belief back (never sticky),
- the belief stays a distribution: every state in [0,1], sum == 1.0 each step,
- the SignalExtractor's per-endpoint baselines (latency, status-class) and the
  absolute challenge / rate-limit markers, through BeliefFilter.observe_response,
- tools/http.py's observation hook wiring (response return point -> filter).
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from redteam.sandbox.detection_belief import (
    CHANNELS,
    INITIAL_BELIEF,
    STATES,
    BeliefFilter,
    SignalExtractor,
)
from redteam.tools.http import observe_response as http_observe_response

CLEAN = tuple()                      # nothing fired — the "normal traffic" observation
CAUGHT = ("challenge_present", "rate_limit_signal")   # challenged + limited


def _risk(f: BeliefFilter) -> float:
    return f.risk_score()


# -- HMM core: the four required behaviors ---------------------------------------------

def test_normal_sequence_stays_quiet():
    f = BeliefFilter()
    for _ in range(10):
        f.update(CLEAN)
    assert _risk(f) < 0.10, f"clean traffic escalated: risk={_risk(f):.3f}"
    assert f.belief["QUIET"] > 0.85


def test_challenge_sequence_escalates_to_alerted_or_blocked():
    f = BeliefFilter()
    for _ in range(3):
        f.update(CAUGHT)
    assert _risk(f) > 0.75, f"challenge burst did not escalate: risk={_risk(f):.3f}"
    assert f.belief["ALERTED"] + f.belief["BLOCKED"] == pytest.approx(_risk(f))
    # escalation lands in the two scrutiny states, not back in SUSPICIOUS
    assert f.belief["ALERTED"] + f.belief["BLOCKED"] > f.belief["SUSPICIOUS"]


def test_recovery_after_conditions_return_to_normal():
    f = BeliefFilter()
    for _ in range(4):
        f.update(CAUGHT)
    assert _risk(f) > 0.75
    for _ in range(12):
        f.update(CLEAN)
    assert _risk(f) < 0.25, \
        f"belief is sticky — clean traffic for 12 steps left risk={_risk(f):.3f}"
    assert f.belief["QUIET"] > 0.70


def test_belief_is_a_distribution_after_every_step():
    f = BeliefFilter()
    seq = [CLEAN, CAUGHT, CLEAN, ("latency_delta",), CAUGHT, ("status_class_shift",),
           CLEAN, CAUGHT, CAUGHT, CLEAN]
    for obs in seq:
        b = f.update(obs)
        assert set(b) == set(STATES)
        for p in b.values():
            assert 0.0 <= p <= 1.0
        assert sum(b.values()) == pytest.approx(1.0, abs=1e-9)
        assert b == f.belief            # returned dict == stored snapshot


def test_risk_score_stays_bounded_through_a_violent_swing():
    f = BeliefFilter()
    for _ in range(30):
        f.update(CAUGHT)
        assert 0.0 <= _risk(f) <= 1.0
    for _ in range(30):
        f.update(CLEAN)
        assert 0.0 <= _risk(f) <= 1.0


def test_unknown_channels_are_ignored_not_fatal():
    f = BeliefFilter()
    f.update(CLEAN)
    strange = f.update(("mystery_signal", 42, None))
    assert set(strange) == set(STATES)
    assert sum(strange.values()) == pytest.approx(1.0)
    # a garbage channel must behave exactly like silence: same two-step control
    f2 = BeliefFilter()
    f2.update(CLEAN)
    f2.update(CLEAN)
    assert strange == pytest.approx(f2.belief)


def test_single_channel_string_accepted():
    f = BeliefFilter()
    b = f.update("challenge_present")       # str, not list — convenience form
    assert sum(b.values()) == pytest.approx(1.0)


def test_reset_returns_to_prior():
    f = BeliefFilter()
    for _ in range(3):
        f.update(CAUGHT)
    f.reset()
    assert f.belief == dict(zip(STATES, INITIAL_BELIEF))
    assert f.steps == 0


def test_concurrent_updates_keep_the_distribution_valid():
    f = BeliefFilter()
    errors: list[Exception] = []

    def worker():
        try:
            for _ in range(40):
                b = f.update(CAUGHT if threading.get_ident() % 2 else CLEAN)
                assert abs(sum(b.values()) - 1.0) < 1e-6
        except Exception as exc:   # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert abs(sum(f.belief.values()) - 1.0) < 1e-6


# -- SignalExtractor: relative channels need baselines, absolute ones do not -----------

def test_first_sight_of_an_endpoint_proves_nothing():
    ex = SignalExtractor()
    # slow, erroring, challenge-laden FIRST response: latency/status channels must
    # stay silent (no baseline); only the absolute markers may fire.
    obs = ex.extract("https://t.example/api/a", 500, 5.0,
                     {"cf-mitigated": "challenge"}, "Attention Required")
    assert "latency_delta" not in obs
    assert "status_class_shift" not in obs
    assert "challenge_present" in obs


def test_latency_delta_classifies_against_the_endpoint_median():
    ex = SignalExtractor()
    url = "https://t.example/api/items"
    for _ in range(4):
        assert "latency_delta" not in ex.extract(url, 200, 0.10, {}, "")
    assert "latency_delta" in ex.extract(url, 200, 0.16, {}, "")   # 1.6x median
    assert "latency_delta" not in ex.extract(url, 200, 0.10, {}, "")
    assert "latency_delta" in ex.extract(url, 200, 0.40, {}, "")   # 4x median


def test_latency_baseline_is_per_endpoint():
    ex = SignalExtractor()
    for _ in range(4):
        ex.extract("https://t.example/api/a", 200, 0.10, {}, "")
    # a DIFFERENT endpoint has no baseline: its first response never fires
    assert "latency_delta" not in ex.extract("https://t.example/api/b", 200, 5.0, {}, "")


def test_status_class_shift_fires_once_into_errors_then_rebases():
    ex = SignalExtractor()
    url = "https://t.example/api/orders"
    for _ in range(3):
        assert "status_class_shift" not in ex.extract(url, 200, 0.1, {}, "")
    assert "status_class_shift" in ex.extract(url, 500, 0.1, {}, "")
    assert "status_class_shift" not in ex.extract(url, 503, 0.1, {}, "")   # already shifted
    assert "status_class_shift" not in ex.extract(url, 200, 0.1, {}, "")   # success never fires


def test_challenge_markers_headers_cookies_body():
    ex = SignalExtractor()
    assert "challenge_present" in ex.extract("https://t/x", 200, 0.1,
                                             {"cf-mitigated": "challenge"}, "")
    assert "challenge_present" in ex.extract("https://t/x", 200, 0.1,
                                             {"Set-Cookie": "__cf_bm=abc; path=/"}, "")
    assert "challenge_present" in ex.extract("https://t/x", 403, 0.1, {},
                                             "Just a moment...")
    # a CDN banner WITHOUT a challenge cookie is not a challenge (most of the web)
    assert "challenge_present" not in ex.extract("https://t/x", 200, 0.1,
                                                 {"Server": "cloudflare",
                                                  "Set-Cookie": "sid=normal"}, "")


def test_rate_limit_markers():
    ex = SignalExtractor()
    assert "rate_limit_signal" in ex.extract("https://t/x", 429, 0.1, {}, "")
    assert "rate_limit_signal" in ex.extract("https://t/x", 403, 0.1,
                                             {"Retry-After": "30"}, "")
    assert "rate_limit_signal" in ex.extract("https://t/x", 200, 0.1,
                                             {"X-RateLimit-Remaining": "0"}, "")
    assert "rate_limit_signal" in ex.extract("https://t/x", 200, 0.1, {},
                                             "You have exceeded the rate limit")
    assert "rate_limit_signal" not in ex.extract("https://t/x", 200, 0.1, {}, "")


# -- observe_response: extractor + filter, and the http.py hook ------------------------

def test_observe_response_full_cycle_normal_challenge_normal():
    """The phase's e2e shape at the filter level: synthetic responses (the same
    fields the http hook hands over) walk the belief normal -> challenge -> normal."""
    f = BeliefFilter()
    clean = dict(url="https://t.example/api/items", status=200, elapsed_s=0.05,
                 headers={"content-type": "application/json"}, body='{"ok": true}')
    caught = dict(url="https://t.example/api/items", status=429, elapsed_s=0.05,
                  headers={"cf-mitigated": "challenge", "Retry-After": "60"},
                  body="Attention Required! Verify you are a human.")
    for _ in range(6):
        f.observe_response(**clean)
    assert _risk(f) < 0.10
    for _ in range(3):
        f.observe_response(**caught)
    assert _risk(f) > 0.75
    for _ in range(12):
        f.observe_response(**clean)
    assert _risk(f) < 0.25


def test_http_observation_hook_feeds_the_filter():
    """tools/http.py's hook is the single seam real traffic flows through: give it
    a ctx carrying a BeliefFilter and the filter must advance."""
    f = BeliefFilter()
    ctx = SimpleNamespace(detection=f)
    req = {"url": "https://t.example/api/items", "method": "GET"}
    http_observe_response(ctx, req, 429, 0.05, {"Retry-After": "10"}, "slow down")
    assert f.steps == 1
    assert _risk(f) > 0.0
    # no detection object on the ctx: the hook must be a silent no-op
    http_observe_response(SimpleNamespace(), req, 429, 0.05, {}, "")
    # and a broken filter must never take the request down with it
    class Broken:
        def observe_response(self, *a, **k):
            raise RuntimeError("boom")
    http_observe_response(SimpleNamespace(detection=Broken()), req, 429, 0.05, {}, "")

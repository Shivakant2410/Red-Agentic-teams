"""Tests for the verification engine — proving it confirms real signals and rejects noise."""

from __future__ import annotations

import itertools

from redteam.verify import DifferentialCheck, HttpCheck, verify


def test_stable_signal_is_confirmed():
    # A genuinely vulnerable endpoint: the marker is always present.
    check = HttpCheck(fetch=lambda: (200, "SQL syntax error near '''", 0.1),
                      body_regex="SQL syntax error")
    result = verify(check, trials=5, need=4)
    assert result.verdict == "confirmed"
    assert result.reproductions == 5


def test_no_signal_is_rejected():
    check = HttpCheck(fetch=lambda: (200, "welcome home", 0.1),
                      body_regex="SQL syntax error")
    result = verify(check, trials=5, need=4)
    assert result.verdict == "rejected"
    assert result.reproductions == 0


def test_flaky_signal_is_not_reproducible():
    # Marker appears only intermittently -> not a finding.
    seq = itertools.cycle([True, False, False, False, False])

    def fetch():
        body = "error: ORA-00933" if next(seq) else "ok"
        return (200, body, 0.1)

    check = HttpCheck(fetch=fetch, body_regex="ORA-00933")
    result = verify(check, trials=5, need=4)
    assert result.verdict == "not_reproducible"
    assert 0 < result.reproductions < 4


def test_time_based_differential_confirmed():
    # Baseline fast, payload consistently ~5s slower -> time-based blind injection.
    check = DifferentialCheck(
        fetch_baseline=lambda: (200, "ok", 0.12),
        fetch_payload=lambda: (200, "ok", 5.20),
        min_latency_delta=4.0,
    )
    result = verify(check, trials=4, need=3)
    assert result.verdict == "confirmed"


def test_differential_rejects_when_gap_absent():
    check = DifferentialCheck(
        fetch_baseline=lambda: (200, "ok", 0.12),
        fetch_payload=lambda: (200, "ok", 0.15),   # no meaningful delay
        min_latency_delta=4.0,
    )
    result = verify(check, trials=4, need=3)
    assert result.verdict == "rejected"

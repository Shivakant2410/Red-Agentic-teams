"""Race-condition / TOCTOU proof: a synchronized concurrent burst beats a
once-only guard, and the race_window predicate counts successes deterministically.
"""
import threading
import types

from redteam.proof import eval_condition
from redteam.tools import logic as logic_mod


def _ctx_with_fetch(fetch):
    """A minimal ToolContext stand-in: run_burst/fetch_once only need ctx for
    scope/session; we monkeypatch fetch_once, so a bare namespace suffices."""
    return types.SimpleNamespace(sessions=None, scope=None, audit=None)


def test_race_window_counts_successes():
    # 4 of 6 returned 200; only 1 was legitimate -> racable.
    resp = {"burst": [(200, "ok", 0.1, {})] * 4 + [(409, "conflict", 0.1, {})] * 2}
    ok, detail = eval_condition({"type": "race_window", "request": "burst",
                                 "success": {"status": 200}, "max_success": 1}, resp)
    assert ok is True and "4/6" in detail


def test_race_window_not_triggered_when_guard_holds():
    # Only 1 success -> the once-only guard held, no race.
    resp = {"burst": [(200, "ok", 0.1, {})] + [(409, "x", 0.1, {})] * 5}
    ok, _ = eval_condition({"type": "race_window", "request": "burst",
                            "success": {"status": 200}, "max_success": 1}, resp)
    assert ok is False


def test_race_window_respects_body_regex_success_shape():
    resp = {"burst": [(200, "credited", 0.1, {}), (200, "credited", 0.1, {}),
                      (200, "already used", 0.1, {})]}
    ok, _ = eval_condition({"type": "race_window", "request": "burst",
                            "success": {"status": 200, "body_regex": "credited"},
                            "max_success": 1}, resp)
    assert ok is True   # 2 "credited" successes, only 1 legit


def test_run_burst_fires_concurrently(monkeypatch):
    # Prove run_burst actually releases all requests together: each fetch records
    # how many threads were "in flight" when it ran; a real barrier means the peak
    # concurrency equals the burst count.
    inflight = {"n": 0, "peak": 0}
    lock = threading.Lock()

    def fake_fetch_once(ctx, req):
        with lock:
            inflight["n"] += 1
            inflight["peak"] = max(inflight["peak"], inflight["n"])
        # hold briefly so overlap is observable
        import time
        time.sleep(0.05)
        with lock:
            inflight["n"] -= 1
        return (200, "ok", 0.05, {})

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx_with_fetch(fake_fetch_once)
    results = logic_mod.run_burst(ctx, {"url": "https://x.test/redeem", "method": "POST"},
                                  count=8)
    assert len(results) == 8
    assert inflight["peak"] >= 2   # genuinely concurrent, not sequential


def test_run_burst_clamps_count(monkeypatch):
    monkeypatch.setattr(logic_mod, "fetch_once", lambda ctx, req: (200, "ok", 0.0, {}))
    ctx = _ctx_with_fetch(None)
    # count below 2 is clamped up to 2 (need at least 2 to race)
    assert len(logic_mod.run_burst(ctx, {"url": "https://x.test/a"}, count=1)) == 2
    # count above 30 is clamped down
    assert len(logic_mod.run_burst(ctx, {"url": "https://x.test/a"}, count=99)) == 30

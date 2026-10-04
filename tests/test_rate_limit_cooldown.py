"""A model that's hit its daily free-tier quota 429s on EVERY call for the rest of the
day. Without a same-run circuit breaker, a model pinned to a role gets retried first
every single turn regardless of how many times it already failed — burning one wasted
round-trip per turn for the whole run (observed: 100+ wasted calls in one real run, see
Phase 5 notes). This pins the fix: after a few consecutive 429s, the router stops trying
that model first and falls back immediately."""

from __future__ import annotations

from redteam.config import LlmConfig
from redteam.llm.openrouter import OpenRouterClient
from redteam.llm.routing import PLAN


class FakeResp:
    def __init__(self, payload=None, status=200, headers=None):
        self._p = payload or {}
        self.status_code = status
        self.headers = headers or {}
        self.text = "rate limited" if status == 429 else ""

    def json(self):
        return self._p


def _ok(model="m1"):
    return FakeResp({"choices": [{"message": {"role": "assistant", "content": "done"},
                                 "finish_reason": "stop"}], "model": model})


def _client(monkeypatch, responses):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    c = OpenRouterClient(LlmConfig(role_models={"plan": "dead-model"}))
    c.router._candidates = ["dead-model", "backup-model"]
    c.router._pools = {"cheap": [], "strong": ["dead-model", "backup-model"]}
    seq = iter(responses)
    monkeypatch.setattr(c._session, "post", lambda *a, **k: next(seq))
    return c


def test_persistent_429_moves_model_to_back_across_calls(monkeypatch):
    # Turn 1: dead-model 429s, backup-model succeeds (normal single-turn rotation).
    # Turn 2: SAME failure pattern — dead-model still first because only 1 consecutive 429 so far.
    # Turn 3: dead-model has now failed twice in a row -> must be skipped to the BACK,
    #         so backup-model should be tried FIRST (no wasted call to dead-model).
    responses = [
        FakeResp(status=429, headers={}), _ok("backup-model"),   # turn 1
        FakeResp(status=429, headers={}), _ok("backup-model"),   # turn 2 (2nd consecutive 429)
        _ok("backup-model"),                                      # turn 3: backup tried FIRST
    ]
    c = _client(monkeypatch, responses)

    r1 = c.chat([{"role": "user", "content": "go"}], role=PLAN)
    assert r1.model == "backup-model"
    r2 = c.chat([{"role": "user", "content": "go"}], role=PLAN)
    assert r2.model == "backup-model"
    # If the router didn't learn anything, turn 3 would try dead-model again (consuming
    # the first response in the queue, a 429) before falling back — there is only ONE
    # response left, so if dead-model were tried first this call would raise instead of
    # succeeding on the first (and only) remaining response.
    r3 = c.chat([{"role": "user", "content": "go"}], role=PLAN)
    assert r3.model == "backup-model"


def test_cooldown_clears_on_success(monkeypatch):
    """A model that recovers (succeeds again) is NOT banned forever — one success resets
    its consecutive-failure count, so it's eligible to be tried first again."""
    responses = [
        FakeResp(status=429), _ok("backup-model"),   # turn 1: 1st consecutive 429
        _ok("dead-model"),                            # turn 2: dead-model tried first, works
        _ok("dead-model"),                            # turn 3: still first, still works
    ]
    c = _client(monkeypatch, responses)
    c.chat([{"role": "user", "content": "go"}], role=PLAN)
    r2 = c.chat([{"role": "user", "content": "go"}], role=PLAN)
    assert r2.model == "dead-model"   # only 1 prior failure — not enough to cool down
    r3 = c.chat([{"role": "user", "content": "go"}], role=PLAN)
    assert r3.model == "dead-model"


def test_router_is_cooling_down_reflects_consecutive_failures():
    from redteam.llm.openrouter import ModelRouter
    router = ModelRouter(LlmConfig(), session=None)
    assert not router.is_cooling_down("m")
    router.on_rate_limited("m")
    assert not router.is_cooling_down("m")   # 1 failure: not yet
    router.on_rate_limited("m")
    assert router.is_cooling_down("m")       # 2 consecutive: now cooling down
    router.on_other_result("m")
    assert not router.is_cooling_down("m")   # any non-429 result resets it

import threading
from types import SimpleNamespace

import pytest

from redteam.llm.gateway import LLMGateway
from redteam.llm.openrouter import ChatResult
from redteam.llm.usage import UsageLimitExceeded, UsageStore


class _Provider:
    name = "test-provider"
    cfg = SimpleNamespace(priority=1)

    def __init__(self):
        self.called = 0

    def candidates_for(self, role):
        return ["test/model"]

    def pricing_for(self, model):
        return {"prompt": "0.000001", "completion": "0.000002"}

    def chat(self, messages, tools, model):
        self.called += 1
        return ChatResult(model, {"role": "assistant", "content": "ok"}, "stop",
                          {"prompt_tokens": 10, "completion_tokens": 5})


def _gateway(provider, store, daily_limit=10):
    gateway = LLMGateway.__new__(LLMGateway)
    gateway._cfg = SimpleNamespace(role_models={})
    gateway._audit = None
    gateway._usage_store = store
    gateway._daily_limit = daily_limit
    gateway._providers = [provider]
    gateway._consecutive_429s = {}
    gateway._lock = threading.Lock()
    return gateway


def test_multi_provider_gateway_records_per_call_usd_cost(tmp_path):
    store = UsageStore(tmp_path / "usage.sqlite3", run_id="run-1")
    provider = _Provider()
    result = _gateway(provider, store).chat([{"role": "user", "content": "hello"}], role="analysis")
    summary = store.summary_all()
    assert result.message["content"] == "ok"
    assert summary.requests == 1
    assert summary.prompt_tokens == 10
    assert summary.completion_tokens == 5
    assert summary.known_cost_usd == pytest.approx(0.00002)
    assert summary.unknown_cost_requests == 0


def test_daily_usage_limit_blocks_before_provider_request(tmp_path):
    store = UsageStore(tmp_path / "usage.sqlite3", run_id="run-1")
    store.reserve_request("analysis", "prior/model", daily_limit=1)
    provider = _Provider()
    with pytest.raises(UsageLimitExceeded):
        _gateway(provider, store, daily_limit=1).chat(
            [{"role": "user", "content": "hello"}], role="analysis")
    assert provider.called == 0

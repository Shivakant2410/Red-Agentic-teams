"""Ollama backend: local-only discovery, role pools, message conversion, concurrency cap."""

from __future__ import annotations

import json
import threading
import time

import pytest

from redteam.config import ConfigError, LlmConfig, _load_llm
from redteam.llm import FallbackClient, make_client
from redteam.llm.ollama import (OllamaClient, from_ollama_message, to_ollama_messages)
from redteam.llm.openrouter import NoModelsAvailable, OpenRouterClient

TAGS = {"models": [
    {"name": "minimax-m3.1-flash:cloud", "remote_host": "https://ollama.com",
     "details": {"parameter_size": "428B"}, "capabilities": ["completion", "tools"]},
    {"name": "qwen2.5-coder:1.5b", "details": {"parameter_size": "1.5B"},
     "capabilities": ["completion", "tools"]},
    {"name": "qwen-27b-iq2m:latest", "details": {"parameter_size": "26.9B"},
     "capabilities": ["completion", "tools", "thinking"]},
    {"name": "qwen3:4b", "details": {"parameter_size": "4.0B"},
     "capabilities": ["completion", "tools"]},
    {"name": "embed-only", "details": {"parameter_size": "0.3B"}, "capabilities": ["embedding"]},
]}


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body or {}, json.dumps(body or {})

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise __import__("requests").HTTPError(str(self.status_code))


class FakeSession:
    def __init__(self, replies=None, tags=TAGS, delay=0.0):
        self.replies = list(replies or [])
        self.tags, self.delay = tags, delay
        self.posts: list[dict] = []
        self.in_flight = self.peak = 0
        self._lock = threading.Lock()

    def get(self, url, timeout=None):
        return _Resp(body=self.tags)

    def post(self, url, data=None, timeout=None):
        with self._lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            self.posts.append(json.loads(data))
            reply = self.replies.pop(0) if self.replies else _Resp(
                body={"message": {"content": "ok"}, "done_reason": "stop"})
        time.sleep(self.delay)
        with self._lock:
            self.in_flight -= 1
        return reply


def _client(session, **cfg):
    return OllamaClient(LlmConfig(providers=("ollama",), **cfg), session=session)


def test_cloud_and_non_tool_models_are_excluded_by_default():
    c = _client(FakeSession())
    assert c.router.discover() == ["qwen-27b-iq2m:latest", "qwen3:4b", "qwen2.5-coder:1.5b"]


def test_cloud_mode_routes_only_to_cloud_models():
    c = _client(FakeSession(), ollama_models="cloud")
    assert c.router.discover() == ["minimax-m3.1-flash:cloud"]
    assert c.router.candidates_for("plan") == ["minimax-m3.1-flash:cloud"]


def test_all_mode_puts_the_big_cloud_model_on_hard_roles():
    c = _client(FakeSession(), ollama_models="all")
    assert c.router.candidates_for("plan")[0] == "minimax-m3.1-flash:cloud"
    assert c.router.candidates_for("parse")[0] == "qwen2.5-coder:1.5b"


def test_cloud_calls_bypass_the_local_concurrency_cap():
    s = FakeSession(delay=0.05)
    c = _client(s, ollama_models="cloud", max_concurrency=1)
    workers = [threading.Thread(target=c.chat, args=([{"role": "user", "content": "x"}],))
               for _ in range(4)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert len(s.posts) == 4 and s.peak > 1


def test_pins_for_models_this_daemon_lacks_are_ignored():
    c = _client(FakeSession(), role_models={"plan": "nvidia/nemotron-3-ultra-550b-a55b:free"})
    assert c.router.candidates_for("plan")[0] == "qwen-27b-iq2m:latest"


def test_strong_roles_get_the_biggest_model_and_cheap_roles_the_smallest():
    c = _client(FakeSession())
    assert c.router.candidates_for("plan")[0] == "qwen-27b-iq2m:latest"
    assert c.router.candidates_for("parse")[0] == "qwen2.5-coder:1.5b"


def test_role_pin_goes_first():
    c = _client(FakeSession(), role_models={"plan": "qwen3:4b"})
    assert c.router.candidates_for("plan")[0] == "qwen3:4b"


def test_no_usable_models_is_a_clear_error():
    c = _client(FakeSession(tags={"models": [TAGS["models"][0]]}))
    with pytest.raises(NoModelsAvailable, match="ollama_models='local'"):
        c.router.discover()


def test_payload_sets_num_ctx_and_tools():
    s = FakeSession()
    tools = [{"type": "function", "function": {"name": "http_request", "parameters": {}}}]
    _client(s, num_ctx=32768).chat([{"role": "user", "content": "hi"}], tools=tools)
    assert s.posts[0]["options"]["num_ctx"] == 32768
    assert s.posts[0]["tools"] == tools and s.posts[0]["stream"] is False


def test_tool_calls_round_trip_between_openai_and_ollama_shapes():
    msg = from_ollama_message({"content": "", "tool_calls": [
        {"function": {"name": "http_request", "arguments": {"url": "http://t/"}}}]})
    call = msg["tool_calls"][0]
    assert call["id"].startswith("call_")
    assert json.loads(call["function"]["arguments"]) == {"url": "http://t/"}

    history = [msg, {"role": "tool", "tool_call_id": call["id"], "content": "200 OK"}]
    native = to_ollama_messages(history)
    assert native[0]["tool_calls"][0]["function"]["arguments"] == {"url": "http://t/"}
    assert native[1] == {"role": "tool", "content": "200 OK", "tool_name": "http_request"}


HTTP_TOOL = [{"type": "function", "function": {"name": "http_request", "parameters": {}}}]


@pytest.mark.parametrize("content", [
    # Observed verbatim from qwen2.5-coder:1.5b on this project's tool schema.
    '{"name": "http_request", "arguments": {"method": "GET", "url": "http://t/health"}}',
    'Sure:\n```json\n{"name": "http_request", "arguments": {"method": "GET", "url": "http://t/health"}}\n```',
    '<tool_call>{"name": "http_request", "arguments": {"method": "GET", "url": "http://t/health"}}</tool_call>',
])
def test_text_tool_calls_from_small_models_are_salvaged(content):
    s = FakeSession(replies=[_Resp(body={"message": {"content": content}})])
    result = _client(s).chat([{"role": "user", "content": "x"}], tools=HTTP_TOOL)
    assert result.finish_reason == "tool_calls" and result.message["content"] == ""
    call = result.message["tool_calls"][0]["function"]
    assert call["name"] == "http_request"
    assert json.loads(call["arguments"]) == {"method": "GET", "url": "http://t/health"}


@pytest.mark.parametrize("content", [
    '{"name": "kali_exec", "arguments": {"command": "id"}}',   # not offered this turn
    'Use {"name": "http_request"} next.',                       # prose, not a call
])
def test_salvage_never_invents_calls(content):
    s = FakeSession(replies=[_Resp(body={"message": {"content": content}})])
    result = _client(s).chat([{"role": "user", "content": "x"}], tools=HTTP_TOOL)
    assert "tool_calls" not in result.message and result.message["content"] == content


def test_degenerate_reply_rotates_to_next_model():
    s = FakeSession(replies=[_Resp(body={"message": {"content": ""}}),
                             _Resp(body={"message": {"content": "real answer"}})])
    result = _client(s).chat([{"role": "user", "content": "x"}])
    assert result.message["content"] == "real answer"
    assert [p["model"] for p in s.posts] == ["qwen-27b-iq2m:latest", "qwen3:4b"]


def test_error_status_rotates_and_exhaustion_raises():
    s = FakeSession(replies=[_Resp(500)] * 3)
    with pytest.raises(NoModelsAvailable):
        _client(s).chat([{"role": "user", "content": "x"}])
    assert len(s.posts) == 3


def test_usage_maps_ollama_counters():
    s = FakeSession(replies=[_Resp(body={"message": {"content": "a"},
                                         "prompt_eval_count": 100, "eval_count": 7})])
    assert _client(s).chat([{"role": "user", "content": "x"}]).usage == {
        "prompt_tokens": 100, "completion_tokens": 7, "total_tokens": 107}


def test_swarm_workers_share_a_bounded_number_of_inference_slots():
    s = FakeSession(delay=0.05)
    c = _client(s, max_concurrency=1)
    workers = [threading.Thread(target=c.chat, args=([{"role": "user", "content": "x"}],))
               for _ in range(4)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert len(s.posts) == 4 and s.peak == 1


def test_config_single_provider_shorthand():
    cfg = _load_llm({"llm": {"provider": "ollama"}})
    assert cfg.providers == ("ollama",) and cfg.ollama_models == "local"
    assert cfg.ollama_url == "http://localhost:11434"
    assert isinstance(make_client(cfg), OllamaClient)


@pytest.mark.parametrize("llm", [
    {"provider": "nope"}, {"providers": []}, {"providers": ["ollama", "ollama"]},
    {"ollama_models": "some"},
])
def test_config_rejects_bad_llm_blocks(llm):
    with pytest.raises(ConfigError):
        _load_llm({"llm": llm})


def test_openrouter_remains_the_default(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    assert isinstance(make_client(_load_llm({})), OpenRouterClient)


def test_both_providers_build_a_fallback_chain_in_order(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    cfg = _load_llm({"llm": {"providers": ["ollama", "openrouter"], "ollama_models": "cloud"}})
    client = make_client(cfg)
    assert isinstance(client, FallbackClient)
    assert [type(b).__name__ for _, b in client._backends] == ["OllamaClient", "OpenRouterClient"]


class _Backend:
    def __init__(self, result=None):
        self.result, self.calls = result, 0

    def chat(self, messages, tools=None, role="plan"):
        self.calls += 1
        if self.result is None:
            raise NoModelsAvailable("quota spent")
        return self.result


def test_fallback_moves_to_the_next_provider_only_when_one_is_exhausted():
    audit = []
    first, second = _Backend(), _Backend(result="served")
    client = FallbackClient([("ollama", first), ("openrouter", second)],
                            audit=type("A", (), {"record": lambda s, e, **k: audit.append(e)})())
    assert client.chat([]) == "served" and first.calls == second.calls == 1
    assert audit == ["llm.provider_exhausted"]

    healthy = _Backend(result="first")
    unused = _Backend(result="second")
    assert FallbackClient([("a", healthy), ("b", unused)]).chat([]) == "first"
    assert unused.calls == 0


def test_fallback_raises_when_every_provider_fails():
    with pytest.raises(NoModelsAvailable, match="ollama: quota spent .* openrouter: quota spent"):
        FallbackClient([("ollama", _Backend()), ("openrouter", _Backend())]).chat([])

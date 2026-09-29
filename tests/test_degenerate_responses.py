"""Degenerate free-model responses must be rotated past, not read as agent decisions."""

from __future__ import annotations

import json

import pytest

from redteam.config import LlmConfig
from redteam.llm.openrouter import NoModelsAvailable, OpenRouterClient


class FakeResp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.headers, self.text = payload, status, {}, ""

    def json(self):
        return self._p


def _client(monkeypatch, responses):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    c = OpenRouterClient(LlmConfig())
    c.router._candidates = ["m1", "m2", "m3"]
    c.router._pools = {"cheap": [], "strong": ["m1", "m2", "m3"]}
    seq = iter(responses)
    monkeypatch.setattr(c._session, "post", lambda *a, **k: next(seq))
    return c


def _msg(content=None, tool_calls=None):
    m = {"role": "assistant", "content": content}
    if tool_calls:
        m["tool_calls"] = tool_calls
    return FakeResp({"choices": [{"message": m, "finish_reason": "stop"}]})


def test_empty_response_rotates_to_next_model(monkeypatch):
    good = _msg(content="here is the plan")
    c = _client(monkeypatch, [_msg(), good])       # first degenerate, second real
    result = c.chat([{"role": "user", "content": "go"}])
    assert result.model == "m2" and "plan" in result.message["content"]


def test_tool_call_without_content_is_valid(monkeypatch):
    calls = [{"id": "1", "type": "function",
              "function": {"name": "browser_navigate", "arguments": "{}"}}]
    c = _client(monkeypatch, [_msg(tool_calls=calls)])
    result = c.chat([{"role": "user", "content": "go"}])
    assert result.message["tool_calls"]             # not treated as degenerate


def test_all_degenerate_raises_rather_than_faking_silence(monkeypatch):
    c = _client(monkeypatch, [_msg(), _msg(), _msg()])
    with pytest.raises(NoModelsAvailable):
        c.chat([{"role": "user", "content": "go"}])


def test_whitespace_only_content_is_degenerate(monkeypatch):
    c = _client(monkeypatch, [_msg(content="   \n "), _msg(content="real answer")])
    result = c.chat([{"role": "user", "content": "go"}])
    assert result.message["content"] == "real answer"

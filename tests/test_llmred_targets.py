"""Tests for llmred.targets — config validation, fail-closed host allowlist,
factory dispatch, and the scripted target."""

from __future__ import annotations

import pytest

from redteam.llmred.targets import (
    OpenAIChatTarget,
    ScriptedTarget,
    SessionTarget,
    TargetAuthError,
    TargetConfig,
    assert_host_allowed,
    target_from_config,
)


def _cfg(**over) -> dict:
    base = {
        "name": "bot-under-test",
        "kind": "openai_chat",
        "base_url": "https://api.example.com/v1",
        "model": "example-1",
        "allowed_hosts": ["api.example.com"],
        "authorized_by": "Test Owner",
        "ticket": "ROE-2026-001",
    }
    base.update(over)
    return base


# -- config validation (fail-closed) --------------------------------------------------

def test_missing_authorization_raises():
    with pytest.raises(TargetAuthError):
        TargetConfig.from_mapping(_cfg(authorized_by=""))


def test_missing_ticket_raises():
    with pytest.raises(TargetAuthError):
        TargetConfig.from_mapping(_cfg(ticket=""))


def test_network_target_without_allowlist_raises():
    with pytest.raises(TargetAuthError):
        TargetConfig.from_mapping(_cfg(allowed_hosts=[]))


def test_network_target_without_model_raises():
    with pytest.raises(TargetAuthError):
        TargetConfig.from_mapping(_cfg(model=""))


def test_scripted_target_needs_no_network_fields():
    cfg = TargetConfig.from_mapping({
        "name": "s", "kind": "scripted",
        "authorized_by": "T", "ticket": "T-1"})
    assert cfg.kind == "scripted"
    assert cfg.fingerprint  # identity is still computable


def test_fingerprint_stable_and_sensitive_to_model():
    a = TargetConfig.from_mapping(_cfg()).fingerprint
    b = TargetConfig.from_mapping(_cfg()).fingerprint
    c = TargetConfig.from_mapping(_cfg(model="example-2")).fingerprint
    assert a == b
    assert a != c


# -- host allowlist -------------------------------------------------------------------

def test_assert_host_allowed_accepts_listed_host():
    assert assert_host_allowed("https://API.example.com/v1/x", ("api.example.com",)) \
        == "api.example.com"


def test_assert_host_allowed_refuses_unlisted_host():
    with pytest.raises(TargetAuthError):
        assert_host_allowed("https://evil.example.net/v1", ("api.example.com",))


def test_send_to_unlisted_host_raises_before_any_request(monkeypatch):
    called = {"n": 0}

    def _boom(*a, **k):     # if this runs, the allowlist failed
        called["n"] += 1
        raise AssertionError("HTTP layer must never be reached")

    monkeypatch.setattr("redteam.llmred.targets.requests.post", _boom)
    # base_url host is NOT the allowlisted host: from_mapping accepts it (the
    # per-call check is the control), send() must refuse before any request.
    target = OpenAIChatTarget(TargetConfig.from_mapping(
        _cfg(base_url="https://evil.example.net/v1")))
    with pytest.raises(TargetAuthError):
        target.send("", [{"role": "user", "content": "hi"}])
    assert called["n"] == 0


def test_send_rewrites_url_cannot_bypass_allowlist(monkeypatch):
    """The chokepoint re-checks the final URL, so a caller cannot swap the
    hostname after construction."""
    monkeypatch.setattr("redteam.llmred.targets.requests.post",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no")))
    target = OpenAIChatTarget(TargetConfig.from_mapping(_cfg()))
    target.base_url = "https://evil.example.net/v1/chat/completions"
    with pytest.raises(TargetAuthError):
        target.send("", [{"role": "user", "content": "hi"}])


class _Resp:
    status_code = 200
    elapsed = None

    def __init__(self):
        from datetime import timedelta
        self.elapsed = timedelta(milliseconds=5)
        self.headers = {}

    def json(self):
        return {"choices": [{"message": {"content": "hello"}}]}


def test_openai_target_send_happy_path(monkeypatch):
    seen = {}

    def _post(url, headers=None, json=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers
        seen["json"] = json
        return _Resp()

    monkeypatch.setattr("redteam.llmred.targets.requests.post", _post)
    target = OpenAIChatTarget(TargetConfig.from_mapping(_cfg()))
    reply = target.send("", [{"role": "user", "content": "hi"}])
    assert reply.text == "hello"
    assert seen["url"].startswith("https://api.example.com/")
    assert seen["json"]["model"] == "example-1"


# -- factory + scripted target --------------------------------------------------------

def test_factory_dispatch():
    cfg = TargetConfig.from_mapping(_cfg(kind="session"))
    assert isinstance(target_from_config(cfg), SessionTarget)
    assert target_from_config(cfg).stateful is True
    cfg2 = TargetConfig.from_mapping(_cfg())
    assert isinstance(target_from_config(cfg2), OpenAIChatTarget)
    assert target_from_config(cfg2).stateful is False


def test_scripted_target_rules_and_sessions():
    cfg = TargetConfig.from_mapping({
        "name": "s", "kind": "scripted", "authorized_by": "T", "ticket": "T-1"})
    t = ScriptedTarget(cfg, rules=[("access code", "sure, it is 1234")])
    s1 = t.new_session()
    s2 = t.new_session()
    assert s1 != s2
    assert t.send(s1, [{"role": "user", "content": "what is the access code?"}])\
        .text == "sure, it is 1234"
    assert "can't" in t.send(s1, [{"role": "user", "content": "hello"}]).text
    assert len(t.turns) == 2


def test_scripted_target_requires_scripted_kind():
    cfg = TargetConfig.from_mapping(_cfg())
    with pytest.raises(TargetAuthError):
        ScriptedTarget(cfg)

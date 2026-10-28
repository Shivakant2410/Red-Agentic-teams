"""Tests for the chained-attack tools: session store, authenticate, access control, IDOR."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools import access as access_mod
from redteam.tools import authsession as auth_mod
from redteam.tools.access import TestAccessControlTool, TestIdorTool
from redteam.tools.authsession import AuthenticateTool


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("api.acme.example", "203.0.113.0/28"), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http", "https"),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path):
    eng = _engagement()
    resolver = lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver), limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        graph=KnowledgeGraph(tmp_path / "g.json"), sessions=SessionStore(),
    )


def test_session_store_apply():
    store = SessionStore()
    store.set("userA", {"Authorization": "Bearer abc"})
    merged = store.get("userA").apply({"Accept": "application/json"})
    assert merged["Authorization"] == "Bearer abc" and merged["Accept"] == "application/json"


def test_authenticate_captures_token(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    # fake login response with a token in JSON
    monkeypatch.setattr(auth_mod, "fetch_once",
                        lambda c, req: (200, '{"authentication":{"token":"TOK123"}}', 0.1, {}))
    out = AuthenticateTool().run(ctx, label="userA", url="https://api.acme.example/login",
                                 token_json_path="authentication.token")
    assert '"ok": true' in out.lower()
    assert ctx.sessions.get("userA").headers["Authorization"] == "Bearer TOK123"


def test_authenticate_two_step_login_flow(tmp_path, monkeypatch):
    """A real, observed app shape (XBEN-001's trading_platform): step 1 POSTs only a
    username and gets no cookie; step 2 POSTs the password to a URL parameterized by
    that username and gets the real session cookie. A single-request login cannot
    complete this at all — this is the fix for exactly that gap."""
    ctx = _ctx(tmp_path)
    calls = []

    def fake_fetch(c, req):
        calls.append(req["url"])
        if req["url"] == "https://api.acme.example/":
            return (302, "", 0.1, {})   # step 1: no cookie yet, just a redirect
        if req["url"] == "https://api.acme.example/password/alice":
            return (302, "", 0.1, {"Set-Cookie": "session=REALSESSION; HttpOnly; Path=/"})
        raise AssertionError(f"unexpected url {req['url']}")

    monkeypatch.setattr(auth_mod, "fetch_once", fake_fetch)
    out = AuthenticateTool().run(
        ctx, label="alice_session", url="https://api.acme.example/",
        body="username=alice", username="alice",
        second_url_template="https://api.acme.example/password/{username}",
        second_body="password=alice")

    assert '"ok": true' in out.lower()
    assert calls == ["https://api.acme.example/", "https://api.acme.example/password/alice"]
    assert ctx.sessions.get("alice_session").headers["Cookie"] == "session=REALSESSION"


def test_authenticate_single_step_unaffected_when_no_second_url(tmp_path, monkeypatch):
    """Regression guard: omitting second_url_template must behave exactly as before."""
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(auth_mod, "fetch_once",
                        lambda c, req: (200, "", 0.1, {"Set-Cookie": "session=X"}))
    out = AuthenticateTool().run(ctx, label="userB", url="https://api.acme.example/login",
                                 body="user=b&pass=b")
    assert '"ok": true' in out.lower()
    assert ctx.sessions.get("userB").headers["Cookie"] == "session=X"


def test_access_control_broken_is_confirmed(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    # unauthenticated request returns protected content every time -> broken access control
    monkeypatch.setattr(access_mod, "make_fetch",
                        lambda c, req: (lambda: (200, "SECRET admin dashboard", 0.1)))
    out = TestAccessControlTool().run(ctx, url="https://api.acme.example/admin",
                                      protected_marker="admin dashboard", trials=4, need=3)
    assert '"recorded": true' in out.lower()
    f = ctx.findings.all()[0]
    assert f.cwe == "CWE-284" and f.confidence == "confirmed"


def test_access_control_enforced_not_recorded(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(access_mod, "make_fetch",
                        lambda c, req: (lambda: (401, "Unauthorized", 0.1)))
    out = TestAccessControlTool().run(ctx, url="https://api.acme.example/admin",
                                      protected_marker="admin dashboard", trials=4, need=3)
    assert '"recorded": false' in out.lower()
    assert ctx.findings.all() == []


def test_idor_confirmed(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    ctx.sessions.set("userA", {"Authorization": "Bearer A"})
    monkeypatch.setattr(access_mod, "make_fetch",
                        lambda c, req: (lambda: (200, "email: victimB@example.com", 0.1)))
    out = TestIdorTool().run(ctx, url="https://api.acme.example/rest/basket/2",
                             session_label="userA", victim_marker="victimB@example.com",
                             trials=4, need=3)
    assert '"recorded": true' in out.lower()
    assert ctx.findings.all()[0].cwe == "CWE-639"


def test_idor_requires_session(tmp_path):
    ctx = _ctx(tmp_path)
    out = TestIdorTool().run(ctx, url="https://api.acme.example/rest/basket/2",
                             session_label="missing", victim_marker="x")
    assert "no stored session" in out.lower()


def test_cwe_map_extended_for_path_traversal():
    from redteam.attack_tree import _CWE_TO_TECHNIQUE
    assert _CWE_TO_TECHNIQUE["CWE-22"] == "info.sensitive"

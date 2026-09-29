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

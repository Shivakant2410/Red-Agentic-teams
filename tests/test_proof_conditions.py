"""Condition-shape robustness — live dry-run regressions (20261030).

Two real-model runs against two different labs reached for the NESTED condition
shorthand ({"body_regex": {...}}) before the documented flat form
({"type": "body_regex", ...}), each burning turns and ~30k tokens on
"unknown condition type None" rejections. The propose side now normalizes at
entry (so the stored check_spec is flat), and the independent re-check
normalizes too (so pre-fix stored specs still replay).
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

import redteam.tools.http as http_mod
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.verify_tool import VerifyVulnerabilityTool, _normalize_conditions


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("api.acme.example",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("1.2.3.4", 0))]
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
        sessions=SessionStore(),
    )
    ctx.sessions.set("member", {"Authorization": "Bearer tok-b"})
    return ctx


@pytest.fixture
def forum_http(monkeypatch):
    """The dry-run lab's essential shape: POST plants a reply, GET renders it raw."""
    stored = []

    def _fake(req):
        method = (req.get("method") or "GET").upper()
        if method == "POST":
            stored.append(req.get("body") or "")
            return 200, json.dumps({"ok": True}), 0.001, {}
        body = ("<html><body><div class='reply'>"
                + "".join(stored) + "</div></body></html>")
        return 200, body, 0.001, {"Content-Type": "text/html"}

    monkeypatch.setattr(http_mod, "_host_request", _fake)


_NESTED = [{"body_regex": {"request": "view", "pattern": "MARKER_XYZ", "present": True}}]
_FLAT = [{"type": "body_regex", "request": "view", "pattern": "MARKER_XYZ",
          "present": True}]


def test_normalizer_flats_and_shorthands():
    assert _normalize_conditions(_NESTED) == _FLAT
    assert _normalize_conditions(_FLAT) == _FLAT            # idempotent
    assert _normalize_conditions([]) == []
    # unknown single-key dicts and multi-key dicts pass through untouched
    assert _normalize_conditions([{"wat": {"a": 1}}]) == [{"wat": {"a": 1}}]
    assert _normalize_conditions([{"type": "status", "request": "view",
                                   "equals": 200}]) == [{"type": "status",
                                                         "request": "view",
                                                         "equals": 200}]


@pytest.mark.parametrize("conditions", [_NESTED, _FLAT], ids=["nested", "flat"])
def test_verify_vulnerability_accepts_both_shapes(tmp_path, forum_http, conditions):
    """The exact call shape the real models attempted — nested and flat must both
    land as a recorded, replayable pending finding."""
    ctx = _ctx(tmp_path)
    out = VerifyVulnerabilityTool().run(
        ctx,
        title="Stored XSS in replies", severity="high",
        target="http://api.acme.example/topic/7",
        summary="reply content renders unescaped",
        requests={
            "plant": {"method": "POST", "url": "http://api.acme.example/reply",
                      "body": "content=MARKER_XYZ", "session_label": "member"},
            "view": {"method": "GET", "url": "http://api.acme.example/topic/7",
                     "session_label": "member"},
        },
        conditions=conditions,
    )
    data = json.loads(out)
    assert data["verdict"] == "pending_verification", out
    assert data["recorded"] is True
    f = ctx.findings.get(data["finding_id"])
    # the STORED spec must be flat so independent replay is well-formed
    assert f.check_spec["conditions"] == _FLAT


def test_unknown_condition_type_still_rejected(tmp_path, forum_http):
    ctx = _ctx(tmp_path)
    out = VerifyVulnerabilityTool().run(
        ctx, title="x", severity="low", target="http://api.acme.example/",
        summary="s",
        requests={"view": {"method": "GET", "url": "http://api.acme.example/topic/7"}},
        conditions=[{"type": "no_such_type", "request": "view"}],
    )
    data = json.loads(out)
    assert data["verdict"] != "pending_verification"
    assert data["recorded"] is False

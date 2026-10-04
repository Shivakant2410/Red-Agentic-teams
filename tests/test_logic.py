"""Tests for the business-logic proof primitive (verify_workflow_abuse) and its
independent-verification path — Phase 3: the class of bug pattern-matched vuln scanning
misses entirely (price tampering, race conditions, one-shot actions reused)."""

from __future__ import annotations

import datetime as _dt
import json

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools import logic as logic_mod
from redteam.tools.logic import VerifyWorkflowAbuseTool

R = lambda status, body, elapsed=0.1, headers=None: (status, body, elapsed, headers or {})


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("shop.acme.example",), excluded_hosts=(),
        allowed_ports=(443,), allowed_schemes=("https",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("203.0.113.5", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sessions=SessionStore(),
    )


def _double_redeem_steps(coupon: str, second_status: int):
    """attack: redeem `coupon` twice; second redemption SHOULD be rejected but isn't."""
    return [
        {"name": "first", "method": "POST", "url": f"https://shop.acme.example/redeem?code={coupon}"},
        {"name": "second", "method": "POST", "url": f"https://shop.acme.example/redeem?code={coupon}"},
    ]


def test_double_redeem_pending_when_attack_succeeds_and_control_correctly_rejects(tmp_path, monkeypatch):
    responses = {
        ("POST", "https://shop.acme.example/redeem?code=ATTACK1"): [R(200, "redeemed"), R(200, "redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=CONTROL1"): [R(200, "redeemed"), R(409, "already redeemed")],
    }

    def fake_fetch_once(ctx, req):
        key = (req["method"], req["url"])
        return responses[key].pop(0)

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx(tmp_path)

    out = VerifyWorkflowAbuseTool().run(
        ctx, title="Coupon reuse", severity="high", target="https://shop.acme.example/redeem",
        summary="a coupon can be redeemed more than once",
        attack_steps=_double_redeem_steps("ATTACK1", 200),
        control_steps=_double_redeem_steps("CONTROL1", 409),
        invariant=[{"type": "status", "request": "second", "equals": 200}],
    )
    data = json.loads(out)
    assert data["verdict"] == "pending_verification"
    assert data["recorded"] is True
    f = ctx.findings.get(data["finding_id"])
    assert f.confidence == "pending_verification"
    assert f.check_type == "workflow"
    assert f.cwe == "CWE-840"


def test_falsified_when_control_also_violates_invariant(tmp_path, monkeypatch):
    """If the honest workflow ALSO lets a second redemption through, it's not abuse —
    it's just how the app works (maybe redemptions are meant to be repeatable)."""
    responses = {
        ("POST", "https://shop.acme.example/redeem?code=ATTACK1"): [R(200, "redeemed"), R(200, "redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=CONTROL1"): [R(200, "redeemed"), R(200, "redeemed")],
    }

    def fake_fetch_once(ctx, req):
        key = (req["method"], req["url"])
        return responses[key].pop(0)

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx(tmp_path)

    out = VerifyWorkflowAbuseTool().run(
        ctx, title="Coupon reuse", severity="high", target="https://shop.acme.example/redeem",
        summary="maybe not actually abuse",
        attack_steps=_double_redeem_steps("ATTACK1", 200),
        control_steps=_double_redeem_steps("CONTROL1", 200),
        invariant=[{"type": "status", "request": "second", "equals": 200}],
    )
    data = json.loads(out)
    assert data["verdict"] == "falsified"
    assert data["recorded"] is False
    assert ctx.findings.all() == []


def test_not_reproducible_when_attack_itself_fails(tmp_path, monkeypatch):
    """The app correctly rejects the second redemption — there is no bug to record."""
    responses = {
        ("POST", "https://shop.acme.example/redeem?code=ATTACK1"): [R(200, "redeemed"), R(409, "already redeemed")],
    }

    def fake_fetch_once(ctx, req):
        key = (req["method"], req["url"])
        return responses[key].pop(0)

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx(tmp_path)

    out = VerifyWorkflowAbuseTool().run(
        ctx, title="Coupon reuse?", severity="high", target="https://shop.acme.example/redeem",
        summary="suspected reuse",
        attack_steps=_double_redeem_steps("ATTACK1", 409),
        control_steps=_double_redeem_steps("CONTROL1", 409),
        invariant=[{"type": "status", "request": "second", "equals": 200}],
    )
    data = json.loads(out)
    assert data["verdict"] == "not_reproducible"
    assert ctx.findings.all() == []


def test_independent_verify_requires_fresh_steps_not_verbatim_replay(tmp_path, monkeypatch):
    """A one-shot workflow bug cannot be independently re-checked by replaying the SAME
    coupon — it's already consumed. verify_finding_independently must refuse without
    fresh_attack_steps/fresh_control_steps rather than silently (and wrongly) falsify it."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool

    responses = {
        ("POST", "https://shop.acme.example/redeem?code=ATTACK1"): [R(200, "redeemed"), R(200, "redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=CONTROL1"): [R(200, "redeemed"), R(409, "already redeemed")],
    }

    def fake_fetch_once(ctx, req):
        key = (req["method"], req["url"])
        return responses[key].pop(0)

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx(tmp_path)
    pending = VerifyWorkflowAbuseTool().run(
        ctx, title="Coupon reuse", severity="high", target="https://shop.acme.example/redeem",
        summary="reuse", attack_steps=_double_redeem_steps("ATTACK1", 200),
        control_steps=_double_redeem_steps("CONTROL1", 409),
        invariant=[{"type": "status", "request": "second", "equals": 200}])
    finding_id = json.loads(pending)["finding_id"]

    # No fresh steps supplied -> must refuse, not silently replay/falsify.
    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=finding_id)
    data = json.loads(out)
    assert data["verdict"] == "not_reproducible"
    assert "fresh" in data["detail"].lower()
    assert ctx.findings.get(finding_id).confidence == "not_reproducible"


def test_independent_verify_confirms_with_fresh_identifier(tmp_path, monkeypatch):
    """Given fresh steps against a NEW coupon, independent verification replays the same
    SHAPE of attack and promotes to confirmed when it reproduces with a failing control."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool

    responses = {
        ("POST", "https://shop.acme.example/redeem?code=ATTACK1"): [R(200, "redeemed"), R(200, "redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=CONTROL1"): [R(200, "redeemed"), R(409, "already redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=ATTACK2"): [R(200, "redeemed"), R(200, "redeemed")],
        ("POST", "https://shop.acme.example/redeem?code=CONTROL2"): [R(200, "redeemed"), R(409, "already redeemed")],
    }

    def fake_fetch_once(ctx, req):
        key = (req["method"], req["url"])
        return responses[key].pop(0)

    monkeypatch.setattr(logic_mod, "fetch_once", fake_fetch_once)
    ctx = _ctx(tmp_path)
    pending = VerifyWorkflowAbuseTool().run(
        ctx, title="Coupon reuse", severity="high", target="https://shop.acme.example/redeem",
        summary="reuse", attack_steps=_double_redeem_steps("ATTACK1", 200),
        control_steps=_double_redeem_steps("CONTROL1", 409),
        invariant=[{"type": "status", "request": "second", "equals": 200}])
    finding_id = json.loads(pending)["finding_id"]

    out = VerifyFindingIndependentlyTool().run(
        ctx, finding_id=finding_id,
        fresh_attack_steps=_double_redeem_steps("ATTACK2", 200),
        fresh_control_steps=_double_redeem_steps("CONTROL2", 409))
    data = json.loads(out)
    assert data["verdict"] == "confirmed"
    assert ctx.findings.get(finding_id).confidence == "confirmed"


def test_out_of_scope_attack_step_blocked(tmp_path):
    ctx = _ctx(tmp_path)
    out = VerifyWorkflowAbuseTool().run(
        ctx, title="x", severity="low", target="https://evil.example/",
        summary="s", attack_steps=[{"name": "a", "method": "GET", "url": "https://evil.example/"}],
        control_steps=[{"name": "a", "method": "GET", "url": "https://evil.example/"}],
        invariant=[{"type": "status", "request": "a", "equals": 200}])
    assert "out of scope" in out.lower()
    assert ctx.findings.all() == []

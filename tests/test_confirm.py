"""Tests for the confirm_finding tool — reproduction gating end to end (with a fake sandbox)."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext
from redteam.tools.confirm import ConfirmFindingTool, _MARKER


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


class FakeSandbox:
    """Returns curl-style output with the confirm tool's status/time trailer."""
    def __init__(self, status, body, elapsed):
        self._status, self._body, self._elapsed = status, body, elapsed

    def exec(self, command, timeout=None):
        class R:
            pass
        r = R()
        r.stdout = f"{self._body}\n{_MARKER}{self._status} {self._elapsed}"
        r.stderr = ""
        r.exit_code = 0
        r.timed_out = False
        return r


def _ctx(tmp_path, sandbox):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("203.0.113.5", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=sandbox,
        graph=KnowledgeGraph(tmp_path / "g.json"),
    )


def test_confirmed_finding_is_recorded(tmp_path):
    # A reproducing check now lands as pending_verification, not confirmed — the agent
    # that proposed it does not get to grade it. See tools/independent_verify.py.
    ctx = _ctx(tmp_path, FakeSandbox(200, "You have an SQL syntax error near", 0.1))
    tool = ConfirmFindingTool()
    out = tool.run(ctx, title="SQLi", severity="high", target="https://api.acme.example/p?id=1",
                   summary="error-based sqli", check_type="http",
                   request={"method": "GET", "url": "https://api.acme.example/p?id=1'"},
                   body_regex="SQL syntax error", trials=5, need=4)
    assert '"recorded": true' in out.lower()
    findings = ctx.findings.all()
    assert len(findings) == 1
    assert findings[0].confidence == "pending_verification"
    assert findings[0].reproductions == 5
    assert findings[0].check_type == "http"
    assert findings[0].check_spec["request"]["url"] == "https://api.acme.example/p?id=1'"


def test_unreproducible_finding_is_not_recorded(tmp_path):
    ctx = _ctx(tmp_path, FakeSandbox(200, "welcome, nothing to see", 0.1))
    tool = ConfirmFindingTool()
    out = tool.run(ctx, title="SQLi?", severity="high", target="https://api.acme.example/p?id=1",
                   summary="maybe", check_type="http",
                   request={"method": "GET", "url": "https://api.acme.example/p?id=1'"},
                   body_regex="SQL syntax error", trials=5, need=4)
    assert '"recorded": false' in out.lower()
    assert "rejected" in out.lower()
    assert ctx.findings.all() == []      # the false positive never made it in


def test_host_fetch_fallback_confirms_without_sandbox(tmp_path, monkeypatch):
    # No sandbox: confirm_finding must fall back to a scope-checked host request.
    class FakeResp:
        status_code = 200
        text = "You have an SQL syntax error near"

    import redteam.tools.confirm as confirm_mod
    monkeypatch.setattr(confirm_mod.requests, "request",
                        lambda *a, **k: FakeResp())

    ctx = _ctx(tmp_path, sandbox=None)
    out = ConfirmFindingTool().run(
        ctx, title="SQLi", severity="high", target="https://api.acme.example/login",
        summary="error-based", check_type="http",
        request={"method": "GET", "url": "https://api.acme.example/login?id=1'"},
        body_regex="SQL syntax error", trials=3, need=3)
    assert '"recorded": true' in out.lower()
    assert ctx.findings.all()[0].confidence == "pending_verification"


def test_independent_verify_promotes_a_real_pending_finding(tmp_path, monkeypatch):
    """The full Phase 1 loop: confirm_finding -> pending_verification -> independent
    re-check -> confirmed, via a SEPARATE tool call (no sandbox needed for this leg)."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool

    ctx = _ctx(tmp_path, FakeSandbox(200, "You have an SQL syntax error near", 0.1))
    pending = ConfirmFindingTool().run(
        ctx, title="SQLi", severity="high", target="https://api.acme.example/p?id=1",
        summary="error-based sqli", check_type="http",
        request={"method": "GET", "url": "https://api.acme.example/p?id=1'"},
        body_regex="SQL syntax error", trials=5, need=4)
    import json
    finding_id = json.loads(pending)["finding_id"]
    assert ctx.findings.get(finding_id).confidence == "pending_verification"

    # Re-check replays via make_fetch (host path, no sandbox needed) — same fake backend
    # would 404/err on a real network call, so patch requests.request for the replay too,
    # returning the SQLi signal only for the payload URL (with the quote) and NOT for the
    # auto-derived benign control (quote stripped) — a real bug behaves exactly this way.
    class FakeRaw:
        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self, n, decode_content=True):
            return self._payload[:n]

    class FakeResp:
        def __init__(self, text: str, status=200):
            self.raw = FakeRaw(text.encode())
            self.status_code, self.encoding, self.headers = status, "utf-8", {}

    def fake_request(method, url, **kw):
        if "'" in url:
            return FakeResp("You have an SQL syntax error near")
        return FakeResp("welcome, nothing to see")

    import redteam.tools.http as http_mod
    monkeypatch.setattr(http_mod.requests, "request", fake_request)
    ctx2 = ToolContext(scope=ctx.scope, limiter=ctx.limiter, audit=ctx.audit,
                       findings=ctx.findings, approve=ctx.approve, sandbox=None, graph=ctx.graph)

    out = VerifyFindingIndependentlyTool().run(ctx2, finding_id=finding_id)
    assert '"verdict": "confirmed"' in out
    assert ctx.findings.get(finding_id).confidence == "confirmed"
    assert ctx.findings.get(finding_id).independent_verdict == "confirmed"


def test_independent_verify_falsifies_a_planted_false_positive(tmp_path, monkeypatch):
    """If the benign control produces the SAME signal as the payload, the finding must be
    falsified, not confirmed — this is the exact failure mode the gate exists to catch."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool

    ctx = _ctx(tmp_path, FakeSandbox(200, "You have an SQL syntax error near", 0.1))
    pending = ConfirmFindingTool().run(
        ctx, title="SQLi", severity="high", target="https://api.acme.example/p?id=1",
        summary="error-based sqli", check_type="http",
        request={"method": "GET", "url": "https://api.acme.example/p?id=1'"},
        body_regex="SQL syntax error", trials=5, need=4)
    import json
    finding_id = json.loads(pending)["finding_id"]

    class FakeRaw:
        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self, n, decode_content=True):
            return self._payload[:n]

    class FakeResp:
        def __init__(self, text: str, status=200):
            self.raw = FakeRaw(text.encode())
            self.status_code, self.encoding, self.headers = status, "utf-8", {}

    def fake_request(method, url, **kw):
        # The endpoint returns the "error" text regardless of input — a false positive.
        return FakeResp("You have an SQL syntax error near")

    import redteam.tools.http as http_mod
    monkeypatch.setattr(http_mod.requests, "request", fake_request)
    ctx2 = ToolContext(scope=ctx.scope, limiter=ctx.limiter, audit=ctx.audit,
                       findings=ctx.findings, approve=ctx.approve, sandbox=None, graph=ctx.graph)

    out = VerifyFindingIndependentlyTool().run(ctx2, finding_id=finding_id)
    assert '"verdict": "falsified"' in out
    assert ctx.findings.get(finding_id).confidence == "falsified"


def test_out_of_scope_target_blocked(tmp_path):
    ctx = _ctx(tmp_path, FakeSandbox(200, "x", 0.1))
    tool = ConfirmFindingTool()
    out = tool.run(ctx, title="x", severity="low", target="https://evil.example/",
                   summary="s", check_type="http",
                   request={"method": "GET", "url": "https://evil.example/"},
                   body_regex="x")
    assert "out of scope" in out.lower()
    assert ctx.findings.all() == []

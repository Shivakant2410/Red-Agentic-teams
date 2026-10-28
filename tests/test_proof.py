"""Tests for the agent-designed proof engine and verify_vulnerability tool."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.proof import ProofCheck, eval_condition
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools import verify_tool as vt
from redteam.tools.verify_tool import VerifyVulnerabilityTool

R = lambda status, body, elapsed=0.1, headers=None: (status, body, elapsed, headers or {})


def test_condition_status():
    ok, _ = eval_condition({"type": "status", "request": "p", "equals": 200}, {"p": R(200, "")})
    assert ok
    bad, _ = eval_condition({"type": "status", "request": "p", "equals": 200}, {"p": R(403, "")})
    assert not bad


def test_condition_json_differs_is_idor_oracle():
    resp = {"base": R(200, '{"data":{"id":1,"owner":"me"}}'),
            "pay":  R(200, '{"data":{"id":2,"owner":"victim"}}')}
    ok, _ = eval_condition({"type": "json_differs", "request_a": "base", "request_b": "pay",
                            "json_path": "data.id"}, resp)
    assert ok
    # same object -> not IDOR
    resp2 = {"base": R(200, '{"data":{"id":1}}'), "pay": R(200, '{"data":{"id":1}}')}
    ok2, _ = eval_condition({"type": "json_differs", "request_a": "base", "request_b": "pay",
                             "json_path": "data.id"}, resp2)
    assert not ok2


def test_condition_reflected_unescaped_is_xss_oracle():
    ok, _ = eval_condition({"type": "reflected_unescaped", "request": "p", "token": "<rtx931>"},
                           {"p": R(200, "<html><rtx931></html>")})
    assert ok
    # escaped reflection -> NOT confirmed
    bad, _ = eval_condition({"type": "reflected_unescaped", "request": "p", "token": "<rtx931>"},
                            {"p": R(200, "<html>&lt;rtx931&gt;</html>")})
    assert not bad


def test_condition_latency_delta():
    ok, _ = eval_condition({"type": "latency_delta", "request_a": "b", "request_b": "p",
                            "min_delta": 4.0}, {"b": R(200, "", 0.1), "p": R(200, "", 5.2)})
    assert ok


def test_proofcheck_all_conditions_must_hold():
    fetchers = {"p": lambda: R(200, "<rtx>")}
    good = ProofCheck(fetchers, [{"type": "status", "request": "p", "equals": 200},
                                 {"type": "reflected_unescaped", "request": "p", "token": "<rtx>"}])
    assert good.run().passed
    bad = ProofCheck(fetchers, [{"type": "status", "request": "p", "equals": 500}])
    assert not bad.run().passed


def _ctx(tmp_path):
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example", "203.0.113.0/28"), excluded_hosts=(),
                     allowed_ports=(80, 443), allowed_schemes=("http", "https"),
                     max_requests_per_second=100.0, max_total_requests=1000,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    resolver = lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]
    return ToolContext(scope=ScopeGuard(eng, resolver=resolver), limiter=RateLimiter(100, 1000),
                       audit=type("A", (), {"record": lambda *a, **k: None})(),
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"), sessions=SessionStore())


def test_verify_vulnerability_idor_confirmed(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    def fake_make_fetch(c, req):
        url = req["url"]
        return (lambda: R(200, '{"data":{"id":1}}')) if url.endswith("/1") \
            else (lambda: R(200, '{"data":{"id":2}}'))
    monkeypatch.setattr(vt, "make_fetch", fake_make_fetch)
    out = VerifyVulnerabilityTool().run(
        ctx, title="IDOR basket", severity="high", target="http://api.acme.example/basket/2",
        summary="cross-user", cwe="CWE-639",
        requests={"baseline": {"url": "http://api.acme.example/basket/1"},
                  "payload": {"url": "http://api.acme.example/basket/2"}},
        conditions=[{"type": "status", "request": "payload", "equals": 200},
                    {"type": "json_differs", "request_a": "baseline", "request_b": "payload",
                     "json_path": "data.id"}], trials=3, need=3)
    assert '"recorded": true' in out.lower()
    assert ctx.findings.all()[0].cwe == "CWE-639"


def test_verify_vulnerability_xss_rejected_when_escaped(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(vt, "make_fetch", lambda c, req: (lambda: R(200, "&lt;rtx931&gt;")))
    out = VerifyVulnerabilityTool().run(
        ctx, title="XSS?", severity="medium", target="http://api.acme.example/search",
        summary="reflected?", cwe="CWE-79",
        requests={"payload": {"url": "http://api.acme.example/search?q=<rtx931>"}},
        conditions=[{"type": "reflected_unescaped", "request": "payload", "token": "<rtx931>"}],
        trials=3, need=3)
    assert '"recorded": false' in out.lower()
    assert ctx.findings.all() == []

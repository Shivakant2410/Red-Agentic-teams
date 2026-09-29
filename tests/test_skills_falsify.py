"""Tests for the executable skill library and adversarial (negative-control) falsification."""

from __future__ import annotations

import datetime as _dt

import pytest

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.falsify import run_negative_control
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.skills import SkillLibrary, parameterize, substitute
from redteam.tools import ToolContext
from redteam.tools import skill_tools as st
from redteam.tools.skill_tools import ApplySkillTool

R = lambda status, body, elapsed=0.1, headers=None: (status, body, elapsed, headers or {})


# --- skill library --------------------------------------------------------

def test_parameterize_and_substitute_roundtrip():
    reqs = {"baseline": {"url": "http://x/basket/1"}, "payload": {"url": "http://x/basket/2"}}
    tmpl, params = parameterize(reqs)
    assert set(params) == {"baseline_url", "payload_url"}
    assert tmpl["payload"]["url"] == "{{payload_url}}"
    out = substitute(tmpl, {"baseline_url": "http://y/a/7", "payload_url": "http://y/a/8"})
    assert out["payload"]["url"] == "http://y/a/8"


def test_substitute_missing_param_raises():
    tmpl, _ = parameterize({"payload": {"url": "http://x/1"}})
    with pytest.raises(KeyError):
        substitute(tmpl, {})


def test_capture_stores_executable_template_and_merges(tmp_path):
    lib = SkillLibrary(tmp_path / "skills.json")
    conds = [{"type": "status", "request": "payload", "equals": 200}]
    reqs = {"payload": {"url": "http://x/a"}}
    s1 = lib.capture("IDOR basket", "proves idor", reqs, conds, cwe="CWE-639")
    s2 = lib.capture("IDOR basket", "proves idor", reqs, conds, cwe="CWE-639")
    assert s1.id == s2.id and s2.successes == 2      # merged, not duplicated
    assert "{{payload_url}}" in s1.requests["payload"]["url"]   # stored as a template


def test_skill_persistence_and_briefing(tmp_path):
    p = tmp_path / "skills.json"
    lib = SkillLibrary(p)
    lib.capture("XSS reflect", "proves reflected xss", {"payload": {"url": "http://x/s?q=1"}},
                [{"type": "reflected_unescaped", "request": "payload", "token": "<t>"}], cwe="CWE-79")
    lib2 = SkillLibrary(p)
    assert lib2.summary()["skills"] == 1
    b = lib2.briefing(query="xss reflected")
    assert "PROVEN SKILLS" in b and "apply_skill" in b and "payload_url" in b


# --- adversarial falsification -------------------------------------------

def test_negative_control_falsifies_signal_present_anyway():
    # The "vulnerable" marker appears for the benign control too -> not attack-caused.
    fetchers = {"payload": lambda: R(200, "Welcome admin panel")}
    conds = [{"type": "body_regex", "request": "payload", "pattern": "admin panel"}]
    res = run_negative_control(fetchers, conds, lambda: R(200, "Welcome admin panel"), "payload")
    assert res.falsified is True
    assert "FALSIFIED" in res.detail


def test_negative_control_passes_when_effect_is_attack_caused():
    fetchers = {"payload": lambda: R(200, "SQL syntax error")}
    conds = [{"type": "body_regex", "request": "payload", "pattern": "SQL syntax error"}]
    res = run_negative_control(fetchers, conds, lambda: R(200, "normal page"), "payload")
    assert res.falsified is False


def test_control_skipped_when_replaces_name_unknown():
    fetchers = {"payload": lambda: R(200, "x")}
    res = run_negative_control(fetchers, [], lambda: R(200, "x"), "nope")
    assert res.falsified is False and "skipped" in res.detail


# --- apply_skill ----------------------------------------------------------

def _ctx(tmp_path):
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example", "203.0.113.0/28"), excluded_hosts=(),
                     allowed_ports=(80, 443), allowed_schemes=("http", "https"),
                     max_requests_per_second=100.0, max_total_requests=1000,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    return ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                       limiter=RateLimiter(100, 1000),
                       audit=type("A", (), {"record": lambda *a, **k: None})(),
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"), sessions=SessionStore(),
                       skills=SkillLibrary(tmp_path / "s.json"))


def test_apply_skill_reuses_proven_proof(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    skill = ctx.skills.capture(
        "IDOR", "proves idor via differing object ids",
        {"baseline": {"url": "http://api.acme.example/b/1"},
         "payload": {"url": "http://api.acme.example/b/2"}},
        [{"type": "status", "request": "payload", "equals": 200},
         {"type": "json_differs", "request_a": "baseline", "request_b": "payload",
          "json_path": "id"}], cwe="CWE-639")

    def fake_make_fetch(c, req):
        return (lambda: R(200, '{"id":1}')) if req["url"].endswith("/7") else (lambda: R(200, '{"id":2}'))
    monkeypatch.setattr(st, "make_fetch", fake_make_fetch)

    out = ApplySkillTool().run(ctx, skill_id=skill.id,
                               params={"baseline_url": "http://api.acme.example/b/7",
                                       "payload_url": "http://api.acme.example/b/8"},
                               title="IDOR on /b", target="http://api.acme.example/b/8",
                               trials=3, need=3)
    assert '"recorded": true' in out.lower()
    assert ctx.findings.all()[0].cwe == "CWE-639"


def test_apply_skill_reports_missing_params(tmp_path):
    ctx = _ctx(tmp_path)
    skill = ctx.skills.capture("S", "d", {"payload": {"url": "http://api.acme.example/a"}},
                               [{"type": "status", "request": "payload", "equals": 200}])
    out = ApplySkillTool().run(ctx, skill_id=skill.id, params={}, title="t",
                               target="http://api.acme.example/a")
    assert "payload_url" in out and "ERROR" in out


def test_apply_skill_unknown_id(tmp_path):
    ctx = _ctx(tmp_path)
    out = ApplySkillTool().run(ctx, skill_id="deadbeef", params={}, title="t", target="x")
    assert "unknown skill_id" in out.lower()

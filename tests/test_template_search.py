"""Tests for just-in-time template research (search on demand, store only what's proven)."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.skills import SkillLibrary
from redteam.tools import ToolContext
from redteam.tools import template_search as ts
from redteam.tools.template_search import ApplyTemplateTool, FindAttackTemplatesTool

R = lambda status, body, elapsed=0.1, headers=None: (status, body, elapsed, headers or {})

TEMPLATE = """
id: acme-git-config
info:
  name: Acme Git Config Exposure
  severity: medium
  description: Exposed .git/config
  classification:
    cwe-id: CWE-200
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
        part: body
"""


def _corpus(tmp_path):
    root = tmp_path / "corpus" / "http" / "exposures"
    root.mkdir(parents=True)
    (root / "git-config-exposure.yaml").write_text(TEMPLATE, encoding="utf-8")
    return tmp_path / "corpus" / "http"


def _ctx(tmp_path, corpus):
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example", "203.0.113.0/28"), excluded_hosts=(),
                     allowed_ports=(80, 443), allowed_schemes=("http", "https"),
                     max_requests_per_second=100.0, max_total_requests=1000,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    ctx = ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                      limiter=RateLimiter(100, 1000),
                      audit=type("A", (), {"record": lambda *a, **k: None})(),
                      findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                      graph=KnowledgeGraph(tmp_path / "g.json"),
                      skills=SkillLibrary(tmp_path / "s.json"))
    ctx.template_corpus = str(corpus)
    return ctx


def test_search_finds_relevant_template(tmp_path):
    corpus = _corpus(tmp_path)
    ctx = _ctx(tmp_path, corpus)
    out = FindAttackTemplatesTool().run(ctx, query="git config exposure")
    assert "Acme Git Config Exposure" in out and "ref" in out


def test_search_returns_nothing_for_irrelevant_query(tmp_path):
    ctx = _ctx(tmp_path, _corpus(tmp_path))
    out = FindAttackTemplatesTool().run(ctx, query="kerberos delegation active directory")
    assert '"results": []' in out


def test_nothing_is_stored_by_searching(tmp_path):
    ctx = _ctx(tmp_path, _corpus(tmp_path))
    FindAttackTemplatesTool().run(ctx, query="git config")
    assert ctx.skills.summary()["skills"] == 0     # research alone persists nothing


def test_apply_template_confirms_and_promotes_to_skill(tmp_path, monkeypatch):
    corpus = _corpus(tmp_path)
    ctx = _ctx(tmp_path, corpus)
    ref = str(corpus / "exposures" / "git-config-exposure.yaml")
    monkeypatch.setattr(ts, "make_fetch", lambda c, req: (lambda: R(200, "[core]\nrepo=1")))
    out = ApplyTemplateTool().run(ctx, ref=ref, target_url="https://api.acme.example")
    assert '"recorded": true' in out.lower()
    assert ctx.findings.all()[0].cwe == "CWE-200"
    assert ctx.skills.summary()["skills"] == 1     # promoted only because it PROVED out


def test_apply_template_not_affected_records_nothing(tmp_path, monkeypatch):
    corpus = _corpus(tmp_path)
    ctx = _ctx(tmp_path, corpus)
    ref = str(corpus / "exposures" / "git-config-exposure.yaml")
    monkeypatch.setattr(ts, "make_fetch", lambda c, req: (lambda: R(404, "not found")))
    out = ApplyTemplateTool().run(ctx, ref=ref, target_url="https://api.acme.example")
    assert '"recorded": false' in out.lower()
    assert ctx.findings.all() == [] and ctx.skills.summary()["skills"] == 0


def test_ref_outside_corpus_is_rejected(tmp_path):
    ctx = _ctx(tmp_path, _corpus(tmp_path))
    out = ApplyTemplateTool().run(ctx, ref=str(tmp_path / "evil.yaml"),
                                  target_url="https://api.acme.example")
    assert "ERROR" in out

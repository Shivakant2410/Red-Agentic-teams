"""System-prompt honesty — the prompt describes the tools that ACTUALLY exist.

Cross-checked live-fire claims (operator eval, 2026-11-02): with no Docker the
system prompt still advertised kali_exec, so the model hallucinated it
("unknown tool 'kali_exec'" burned real turns). Also: the engagement schema's
target list IS the scope grid, but the model never saw derived base URLs in
text and flailed until the operator wrote the URL into the objective.
"""

from __future__ import annotations

import datetime as _dt

from redteam.agent import RedTeamAgent
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext, build_registry


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(),
        allowed_ports=(8899, 8892), allowed_schemes=("http",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=True, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _agent(tools: dict, tmp_path) -> RedTeamAgent:
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("127.0.0.1", 0))]
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
    )
    return RedTeamAgent(eng, tools, ctx, client=object(), max_steps=4,
                        graph=ctx.graph)


def test_prompt_hides_absent_tools(monkeypatch, tmp_path):
    monkeypatch.setenv("RED_LOCAL_EXEC", "0")
    tools = build_registry(enable_sandbox=False, enable_browser=False)
    prompt = _agent(tools, tmp_path)._system()
    assert "kali_exec" not in prompt, "prompt advertises a tool the registry lacks"
    assert "NO shell in this run" in prompt
    assert "NO browser in this run" in prompt


def test_prompt_describes_present_shell(monkeypatch, tmp_path):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    tools = build_registry(enable_sandbox=False, enable_browser=False)
    prompt = _agent(tools, tmp_path)._system()
    assert "local_exec" in prompt
    assert "NO shell" not in prompt


def test_prompt_lists_roe_derived_target_urls(tmp_path):
    tools = build_registry(enable_sandbox=False, enable_browser=False)
    prompt = _agent(tools, tmp_path)._system()
    # 127.0.0.1 x (8899, 8892) x http -> both ports surfaced as candidate URLs
    assert "http://127.0.0.1:8899" in prompt
    assert "http://127.0.0.1:8892" in prompt

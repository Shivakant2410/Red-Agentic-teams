"""Tests for the multi-agent orchestrator (specialist sequencing over shared state)."""

from __future__ import annotations

import datetime as _dt

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.llm.routing import PARSE, PLAN
from redteam.orchestrator import EXPLOIT, RECON, Orchestrator
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext


class RecordingAudit:
    def __init__(self):
        self.events = []

    def record(self, event, **f):
        self.events.append({"event": event, **f})

    def read_all(self):
        return self.events


class FakeClient:
    """Returns a no-tool-call assistant message, so each specialist run ends immediately.
    Records which role each call used so we can assert model-tier routing."""
    def __init__(self):
        self.roles_used = []

    def chat(self, messages, tools=None, role="plan"):
        self.roles_used.append(role)
        return ChatResult(model="fake", message={"role": "assistant", "content": "done"},
                          finish_reason="stop", usage={})


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


def _ctx(tmp_path, audit):
    eng = _engagement()
    return ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                       limiter=RateLimiter(100, 1000), audit=audit,
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"))


def test_profiles_use_correct_model_tiers():
    assert RECON.role == PARSE          # recon = breadth = cheaper model
    assert EXPLOIT.role == PLAN         # exploit = depth = strongest model


def test_orchestrator_runs_recon_then_exploit(tmp_path):
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    client = FakeClient()
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=client,
                        graph=ctx.graph, attack_tree=None, memory=None)
    orch.run("map and exploit the app")

    phases = [e.get("phase") for e in audit.events if e["event"] == "orchestrator.phase"]
    assert "recon" in phases and "exploit" in phases
    assert audit.events[0]["event"] == "orchestrator.start"
    assert any(e["event"] == "orchestrator.finish" for e in audit.events)
    # recon ran on the cheap tier, exploit on the strong tier
    assert PARSE in client.roles_used and PLAN in client.roles_used


def test_specialist_gets_only_its_tools(tmp_path):
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    # a registry with a couple named tools
    fake_tools = {"browser_navigate": object(), "confirm_finding": object(),
                  "verify_vulnerability": object()}
    orch = Orchestrator(_engagement(), tools=fake_tools, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph)
    recon_agent = orch._make_specialist(RECON)
    exploit_agent = orch._make_specialist(EXPLOIT)
    assert "browser_navigate" in recon_agent._tools
    assert "confirm_finding" not in recon_agent._tools     # recon can't exploit
    assert "verify_vulnerability" in exploit_agent._tools

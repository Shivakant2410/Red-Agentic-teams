"""Tests for agent-loop message hygiene (regressions that kill live runs)."""

from __future__ import annotations

import datetime as _dt

from redteam.access import AccessGraph
from redteam.agent import RedTeamAgent
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.killchain import KillChain
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.objective import DATA_ACCESS, Objective, SuccessCriterion
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext


class NullContentClient:
    """Mimics a model that stops with content=None (very common)."""

    def __init__(self):
        self.sent = []

    def chat(self, messages, tools=None, role="plan"):
        self.sent.append([dict(m) for m in messages])
        return ChatResult(model="fake", message={"role": "assistant", "content": None},
                          finish_reason="stop", usage={})


def _ctx(tmp_path):
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example",), excluded_hosts=(),
                     allowed_ports=(443,), allowed_schemes=("https",),
                     max_requests_per_second=100.0, max_total_requests=100,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    obj = Objective(name="o", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read db", target="prod-db")])
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
        limiter=RateLimiter(100, 100),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        access=AccessGraph(tmp_path / "a.json"), objective=obj,
        killchain=KillChain(tmp_path / "k.json"))
    return eng, ctx


def test_null_content_is_never_replayed_to_the_api(tmp_path):
    """Replaying content=None made every model return 400 and killed a live run."""
    eng, ctx = _ctx(tmp_path)
    client = NullContentClient()
    RedTeamAgent(eng, {}, ctx, client, max_steps=6).run("reach the objective")
    # The nudge means later requests replay earlier assistant turns; none may carry None.
    for conversation in client.sent:
        for m in conversation:
            assert m.get("content") is not None, "null content replayed -> HTTP 400"


def test_agent_pushes_back_before_giving_up_on_an_unmet_objective(tmp_path):
    eng, ctx = _ctx(tmp_path)
    client = NullContentClient()
    RedTeamAgent(eng, {}, ctx, client, max_steps=8).run("reach the objective")
    # It should not accept the first "I'm done" while the objective is unmet.
    assert len(client.sent) > 1


class NoOpToolCallClient:
    """Calls a dummy tool every turn (so the agent never hits the no-tool-calls branch),
    but nothing it does ever changes graph/findings — i.e. a model stuck on a dead end."""

    def __init__(self):
        self.calls = 0

    def chat(self, messages, tools=None, role="plan"):
        self.calls += 1
        tc = {"id": f"call{self.calls}", "type": "function",
             "function": {"name": "noop_tool", "arguments": "{}"}}
        return ChatResult(model="fake",
                          message={"role": "assistant", "content": "trying again",
                                   "tool_calls": [tc]},
                          finish_reason="tool_calls", usage={})


class NoopTool:
    name = "noop_tool"

    def schema(self):
        return {"name": "noop_tool", "input_schema": {"type": "object", "properties": {}},
                "strict": True}

    def run(self, ctx, **kwargs):
        return "did nothing useful"


def test_agent_ends_its_turn_after_repeated_stalls_instead_of_grinding_to_max_steps(tmp_path):
    """Phase 4: a specialist stuck on a dead end (no graph/finding progress for many turns
    in a row) must stop well before max_steps, freeing the orchestrator to hand off to a
    different specialist with a fresh context, rather than grinding in-context forever."""
    eng, ctx = _ctx(tmp_path)
    ctx.graph = KnowledgeGraph(tmp_path / "g.json")   # stall detection needs a graph to compare against
    client = NoOpToolCallClient()
    agent = RedTeamAgent(eng, {"noop_tool": NoopTool()}, ctx, client,
                         max_steps=100, graph=ctx.graph)
    agent.run("find something")
    # 3 stall cycles of 4 turns each (nudged twice, stopped on the 3rd) is well under 100.
    assert client.calls < 25

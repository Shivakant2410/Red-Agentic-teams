"""Tests for agent-loop message hygiene (regressions that kill live runs)."""

from __future__ import annotations

import datetime as _dt

from redteam.access import AccessGraph
from redteam.agent import RedTeamAgent
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.killchain import KillChain
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

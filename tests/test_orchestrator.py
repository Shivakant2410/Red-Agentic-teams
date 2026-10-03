"""Tests for the multi-agent orchestrator (specialist sequencing over shared state)."""

from __future__ import annotations

import datetime as _dt

from redteam.access import CREDENTIAL, HOST, PRINCIPAL, AccessGraph
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.killchain import ACHIEVED, CREDENTIAL_ACCESS, INITIAL_ACCESS, KillChain, RECON as KC_RECON
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.llm.routing import PARSE, PLAN
from redteam.objective import DATA_ACCESS, Objective, SuccessCriterion
from redteam.orchestrator import ACCESS, EXPLOIT, LOGIC, RECON, Orchestrator
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


def _ctx(tmp_path, audit, access=None, killchain=None, objective=None):
    eng = _engagement()
    return ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                       limiter=RateLimiter(100, 1000), audit=audit,
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"), access=access, killchain=killchain,
                       objective=objective)


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
                  "verify_vulnerability": object(), "try_credential": object(),
                  "prove_privilege": object()}
    orch = Orchestrator(_engagement(), tools=fake_tools, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph)
    recon_agent = orch._make_specialist(RECON)
    exploit_agent = orch._make_specialist(EXPLOIT)
    access_agent = orch._make_specialist(ACCESS)
    assert "browser_navigate" in recon_agent._tools
    assert "confirm_finding" not in recon_agent._tools     # recon can't exploit
    assert "verify_vulnerability" in exploit_agent._tools
    assert "try_credential" in access_agent._tools and "prove_privilege" in access_agent._tools
    assert "verify_vulnerability" not in access_agent._tools   # access can't hunt new bugs


def test_recon_can_authenticate_but_not_prove_findings(tmp_path):
    """Recon needs to get PAST a login wall to map what's behind it (a real blocker:
    XBEN-001's two-step login burned recon's whole budget guessing URLs by hand instead
    of using authenticate) - but logging in is mapping, not exploiting, so recon must
    still lack every proof tool."""
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    fake_tools = {"browser_navigate": object(), "authenticate": object(),
                  "confirm_finding": object(), "verify_vulnerability": object(),
                  "verify_workflow_abuse": object()}
    orch = Orchestrator(_engagement(), tools=fake_tools, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph)
    recon_agent = orch._make_specialist(RECON)
    assert "authenticate" in recon_agent._tools
    assert "confirm_finding" not in recon_agent._tools
    assert "verify_vulnerability" not in recon_agent._tools
    assert "verify_workflow_abuse" not in recon_agent._tools


def test_profiles_access_tier_is_cheap():
    assert ACCESS.role == PARSE   # procedural/mechanical -> cheaper model, like recon


def test_access_round_runs_when_killchain_recommends_pressing(tmp_path):
    """A confirmed credential foothold -> KillChain.recommend() names a pressing stage
    (not just RECON/INITIAL_ACCESS) -> the orchestrator must run an ACCESS round."""
    audit = RecordingAudit()
    access = AccessGraph()
    access.hold(CREDENTIAL, "tok", evidence="authenticated", source="try_credential")
    killchain = KillChain()
    killchain.mark(KC_RECON, ACHIEVED)
    killchain.mark(INITIAL_ACCESS, ACHIEVED)
    ctx = _ctx(tmp_path, audit, access=access, killchain=killchain)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, max_exploit_rounds=1)
    orch.run("press the foothold")

    phases = [e.get("phase") for e in audit.events if e["event"] == "orchestrator.phase"]
    assert "access" in phases


def test_access_round_skipped_when_no_foothold(tmp_path):
    """No access held at all -> KillChain.recommend() says RECON/INITIAL_ACCESS, which is
    NOT a pressing stage -> no ACCESS round should run."""
    audit = RecordingAudit()
    access = AccessGraph()
    killchain = KillChain()
    ctx = _ctx(tmp_path, audit, access=access, killchain=killchain)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, max_exploit_rounds=1)
    orch.run("map the app")

    phases = [e.get("phase") for e in audit.events if e["event"] == "orchestrator.phase"]
    assert "access" not in phases


def test_access_loop_stops_on_stall_not_after_one_round(tmp_path):
    """If pressing the foothold doesn't advance the kill chain (the fake client never
    actually calls a tool), the loop must stop after the FIRST round rather than grinding
    through every max_access_rounds — the stall check, not the round ceiling, should fire."""
    audit = RecordingAudit()
    access = AccessGraph()
    access.hold(CREDENTIAL, "tok", evidence="authenticated", source="try_credential")
    killchain = KillChain()
    killchain.mark(KC_RECON, ACHIEVED)
    killchain.mark(INITIAL_ACCESS, ACHIEVED)
    ctx = _ctx(tmp_path, audit, access=access, killchain=killchain)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, max_exploit_rounds=1, max_access_rounds=10)
    orch.run("press the foothold")

    access_rounds = [e for e in audit.events
                     if e["event"] == "orchestrator.phase" and e.get("phase") == "access"]
    assert len(access_rounds) == 1   # stalled after round 0, never reached round 10


def test_profiles_logic_tier_is_strong():
    assert LOGIC.role == PLAN   # business logic needs domain reasoning, not pattern-matching


def test_logic_round_skipped_on_a_non_workflow_surface(tmp_path):
    """A graph with only static-looking endpoints should never trigger the logic round —
    no point spending a round hunting business logic on an app with no workflow."""
    audit = RecordingAudit()
    graph = KnowledgeGraph(tmp_path / "g.json")
    from redteam.knowledge import ENDPOINT
    graph.observe(ENDPOINT, "https://api.acme.example/about")
    graph.observe(ENDPOINT, "https://api.acme.example/contact")
    ctx = _ctx(tmp_path, audit)
    ctx.graph = graph
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=graph, max_exploit_rounds=1)
    orch.run("map the app")

    phases = [e.get("phase") for e in audit.events if e["event"] == "orchestrator.phase"]
    assert "logic" not in phases


def test_logic_round_runs_on_a_workflow_shaped_surface(tmp_path):
    """A graph with a checkout/coupon-shaped endpoint should trigger exactly one logic
    round (not per-exploit-round — business logic doesn't chain the way access does)."""
    audit = RecordingAudit()
    graph = KnowledgeGraph(tmp_path / "g.json")
    from redteam.knowledge import ENDPOINT
    graph.observe(ENDPOINT, "https://shop.acme.example/cart/checkout")
    graph.observe(ENDPOINT, "https://shop.acme.example/coupon/redeem")
    ctx = _ctx(tmp_path, audit)
    ctx.graph = graph
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=graph, max_exploit_rounds=2)
    orch.run("map and exploit the app")

    logic_rounds = [e for e in audit.events
                   if e["event"] == "orchestrator.phase" and e.get("phase") == "logic"]
    assert len(logic_rounds) == 1


def test_logic_specialist_gets_only_its_tools(tmp_path):
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    fake_tools = {"verify_workflow_abuse": object(), "confirm_finding": object(),
                  "authenticate": object()}
    orch = Orchestrator(_engagement(), tools=fake_tools, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph)
    logic_agent = orch._make_specialist(LOGIC)
    assert "verify_workflow_abuse" in logic_agent._tools
    assert "authenticate" in logic_agent._tools
    assert "confirm_finding" not in logic_agent._tools   # logic doesn't hunt injection/XSS


# --- Phase 4: no hardcoded round cap short-circuits a run with budget/work remaining ----

def test_exploit_round_ceiling_is_a_safety_cap_not_a_target():
    """The default ceiling must be large enough that it's a worst-case safety bound, not
    something a normal engagement would hit — pinning this catches a regression back to
    the old hardcoded default of 2, which could cut a run short with budget/work left."""
    orch = Orchestrator(_engagement(), tools={}, ctx=None, client=None)
    assert orch._max_exploit_rounds > 2


def test_exploit_rounds_stop_as_soon_as_objective_is_achieved(tmp_path):
    """The orchestrator must not keep spending exploit rounds once the objective is met,
    even if max_exploit_rounds / untested work would otherwise allow more — this is the
    objective-achieved stop condition, independent of the round ceiling."""
    audit = RecordingAudit()
    obj = Objective(name="o", criteria=[SuccessCriterion("c1", DATA_ACCESS, "read db", target="x")])
    obj.mark("c1", "already proven before this run")   # pre-achieved
    ctx = _ctx(tmp_path, audit, objective=obj)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, max_exploit_rounds=10)
    orch.run("finish the objective")

    exploit_rounds = [e for e in audit.events
                     if e["event"] == "orchestrator.phase" and e.get("phase") == "exploit"]
    assert exploit_rounds == []   # achieved before round 0 even started
    assert any(e["event"] == "orchestrator.objective_achieved" for e in audit.events)

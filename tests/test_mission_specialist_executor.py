"""Phase 3 tests — MissionSpecialistExecutor: the real specialist delegation.

The discipline this locks:
  - the executor wraps the EXISTING Orchestrator and maps one task_view to one
    real RedTeamAgent invocation through Orchestrator.execute_task;
  - routing reuses the platform's own profiles and profile_for() — no second
    registry, unknown roles fail loud;
  - the mission scheduler remains the ONLY owner of task/AttackTree/hypothesis
    claims (the executor never claims);
  - shared run context: the specialist runs on the same ctx/graph/tree/findings/
    budget the run assembled — no second environment;
  - task step budgets can only TIGHTEN the profile ceiling (never widen);
  - execution success is an EXECUTION outcome (C4): never a confirmation,
    never fabricated evidence, verification only through the existing
    independent verifier.
No live model calls: the agent loop is driven by a FakeClient or the specialist
construction is stubbed at _make_specialist.
"""
from __future__ import annotations

import datetime as _dt
import threading

import pytest

from redteam.attack_tree import AttackTree
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.mission.executor import (EXEC_FAILED, EXEC_SUCCEEDED,
                                      ExecutionResult)
from redteam.mission.specialist_executor import MissionSpecialistExecutor
from redteam.orchestrator import (ACCESS, EXPLOIT, LOGIC, RECON, VERIFY,
                                  Orchestrator)
from redteam.ratelimit import RateLimiter
from redteam.runtime import BudgetTracker
from redteam.scope import ScopeGuard
from redteam.specialists import A03, profile_for
from redteam.states import TASK_FAILED, TASK_SUCCEEDED
from redteam.tools import ToolContext, build_registry

import mission_helpers as H


# -- fakes (the test_specialists / test_bandit_wiring patterns) ------------------

class RecordingAudit:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def record(self, event, **f):
        with self._lock:
            self.events.append({"event": event, **f})

    def read_all(self):
        with self._lock:
            return list(self.events)


class FakeClient:
    """No-tool-call assistant message: every specialist run ends immediately."""

    def chat(self, messages, tools=None, role="plan"):
        return ChatResult(model="fake",
                          message={"role": "assistant", "content": "slice done"},
                          finish_reason="stop", usage={})


class StubAgent:
    """Stands in for the constructed RedTeamAgent: records the instruction,
    optionally raises or records findings. Proves what execute_task built and
    sent WITHOUT running the model loop."""

    def __init__(self, *, error: Exception | None = None, outcome: str = "stub done",
                 finding: Finding | None = None, audit=None, soft_failure: str = ""):
        self.calls: list[str] = []
        self._error = error
        self._outcome = outcome
        self._finding = finding
        self._audit = audit
        self._soft_failure = soft_failure

    def run(self, objective: str, on_text=None) -> str:
        self.calls.append(objective)
        if self._finding is not None:
            self._ctx.findings.add(self._finding)
        if self._soft_failure:
            if self._audit is not None:
                self._audit.record("agent.no_models", error=self._soft_failure)
            return self._soft_failure
        if self._error is not None:
            raise self._error
        return self._outcome


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
    return ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
        limiter=RateLimiter(100, 1000), audit=audit,
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        graph=None, access=None, killchain=None, objective=None)


class _Env:
    """The shared run environment ONE orchestrator is built over."""

    def __init__(self, tmp_path):
        self.audit = RecordingAudit()
        self.ctx = _ctx(tmp_path, self.audit)
        self.graph = KnowledgeGraph(tmp_path / "g.json")
        self.tree = AttackTree(tmp_path / "attack_tree.json")
        self.budget = BudgetTracker(max_seconds=600, max_tokens=100000)
        self.tools = build_registry(enable_sandbox=False, enable_browser=False)
        self.orch = Orchestrator(_engagement(), self.tools, self.ctx, FakeClient(),
                                 graph=self.graph, attack_tree=self.tree)
        self.orch.with_runtime(budget=self.budget)


def _task_view(**over) -> dict:
    view = {"task_id": "task-1", "mission_id": "m1", "run_id": "m1",
            "title": "probe the idor", "role": "recon", "technique": "",
            "target": "api.acme.example", "node_id": "", "status": "running",
            "attempts": 0, "max_attempts": 2, "owner": "recon",
            "lease_expires_at": "", "max_steps": 7, "opsec_allowance": 0.0,
            "dependencies": [], "evidence": [], "result": "", "error": ""}
    view.update(over)
    return view


def _spy_specialist(env: _Env, stub: StubAgent) -> dict:
    """Wrap _make_specialist: capture routing + construction, run the stub."""
    captured = {}
    real_make = env.orch._make_specialist

    def spy(profile, addon_suffix="", agent_name=None, max_steps=None):
        captured.update(profile=profile, agent_name=agent_name,
                        max_steps=max_steps, agent=None)
        return stub

    env.orch._make_specialist = spy
    return captured


# =============================================================================
# A. Executor tests
# =============================================================================

def test_executor_accepts_the_existing_orchestrator_and_maps_success(tmp_path):
    env = _Env(tmp_path)
    stub = StubAgent()
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch, objective="engagement objective")
    res = ex.run(_task_view())
    assert isinstance(res, ExecutionResult)
    assert res.status == EXEC_SUCCEEDED
    assert res.result == "stub done"
    assert res.error == ""
    # the task view reached the specialist as the instruction
    assert len(stub.calls) == 1
    assert "probe the idor" in stub.calls[0]


def test_executor_maps_exceptions_to_failed_and_preserves_the_error(tmp_path):
    env = _Env(tmp_path)
    stub = StubAgent(error=RuntimeError("model exploded mid-task"))
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view())
    assert res.status == EXEC_FAILED
    assert "RuntimeError" in res.error and "model exploded mid-task" in res.error


def test_executor_maps_soft_agent_failures_to_failed(tmp_path):
    # RedTeamAgent.run degrades instead of raising when the model layer is
    # unavailable (agent.no_models) — an honest EXEC_FAILED, not a green task.
    env = _Env(tmp_path)
    stub = StubAgent(soft_failure="Could not get a model response: quota",
                     audit=env.audit)
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view())
    assert res.status == EXEC_FAILED
    assert "agent.no_models" in res.error


def test_executor_does_not_fabricate_evidence(tmp_path):
    env = _Env(tmp_path)
    stub = StubAgent()          # adds no findings
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view())
    assert res.status == EXEC_SUCCEEDED
    assert res.evidence == ()   # nothing produced -> nothing attached


def test_executor_attaches_real_new_finding_refs_only(tmp_path):
    env = _Env(tmp_path)
    new_pending = Finding(title="idor lead", severity="low",
                          target="api.acme.example", summary="candidate",
                          confidence="pending_verification")
    stub = StubAgent(finding=new_pending)
    stub._ctx = env.ctx
    _spy_specialist(env, stub)
    # a PRE-EXISTING finding must not be attributed to this task
    pre = env.ctx.findings.add(Finding(title="pre-existing", severity="info",
                                       target="api.acme.example", summary="old"))
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view())
    assert res.status == EXEC_SUCCEEDED
    assert len(res.evidence) == 1
    ref = res.evidence[0]
    assert ref["kind"] == "finding" and ref["ref"] == new_pending.id
    assert ref["confidence"] == "pending_verification"
    assert pre.id != new_pending.id


def test_executor_never_carries_confirmed_confidence(tmp_path):
    # C4: even if a confirmed finding appears mid-task (the pipeline confirmed
    # it), the executor's evidence must NOT carry confidence='confirmed' — and
    # the ExecutionResult contract itself rejects it by construction.
    env = _Env(tmp_path)
    confirmed = Finding(title="confirmed mid-task", severity="medium",
                        target="api.acme.example", summary="proven",
                        confidence="confirmed")
    stub = StubAgent(finding=confirmed)
    stub._ctx = env.ctx
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view())
    assert res.status == EXEC_SUCCEEDED
    assert all(ev.get("confidence") != "confirmed" for ev in res.evidence)
    with pytest.raises(Exception):
        ExecutionResult(status=EXEC_SUCCEEDED, result="x",
                        evidence=({"kind": "finding", "ref": "f",
                                   "confidence": "confirmed"},))


def test_task_instruction_is_task_scoped_not_the_whole_plan(tmp_path):
    env = _Env(tmp_path)
    stub = StubAgent()
    _spy_specialist(env, stub)
    ex = MissionSpecialistExecutor(env.orch, objective="prove the record boundary")
    ex.run(_task_view(title="probe the idor", role="exploit",
                      technique="auth.test", target="https://t.test/",
                      node_id="auth.test@https://t.test/", max_steps=7))
    instruction = stub.calls[0]
    assert "probe the idor" in instruction
    assert "auth.test on https://t.test/" in instruction
    assert "STEP BUDGET: at most 7" in instruction
    assert "prove the record boundary" in instruction
    # the plan's OTHER tasks never leak into this instruction
    assert "harvest the admin token" not in instruction
    # the executor-level no-reclaim discipline is stated for node tasks
    assert "do not claim or release" in instruction


# =============================================================================
# B. Specialist routing tests
# =============================================================================

def test_recon_routes_to_recon(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    MissionSpecialistExecutor(env.orch).run(_task_view(role="recon"))
    assert captured["profile"] is RECON


def test_exploit_routes_through_profile_for(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    MissionSpecialistExecutor(env.orch).run(_task_view(
        role="exploit", technique="injection.sqli", target="api.acme.example",
        node_id="injection.sqli@api.acme.example"))
    assert captured["profile"] is profile_for("injection.sqli")
    assert captured["profile"] is A03.profile   # the class expert, not a copy


def test_unknown_exploit_technique_falls_back_to_exploit(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    MissionSpecialistExecutor(env.orch).run(_task_view(
        role="exploit", technique="no.such.class", target="api.acme.example"))
    assert captured["profile"] is EXPLOIT


def test_access_routes_to_access_and_logic_to_logic(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    ex = MissionSpecialistExecutor(env.orch)
    ex.run(_task_view(role="access"))
    assert captured["profile"] is ACCESS
    ex.run(_task_view(role="logic"))
    assert captured["profile"] is LOGIC


def test_unknown_role_fails_loud(tmp_path):
    env = _Env(tmp_path)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view(role="wizard"))
    assert res.status == EXEC_FAILED
    assert "no specialist routing" in res.error


def test_verify_uses_the_existing_independent_verifier(tmp_path, monkeypatch):
    env = _Env(tmp_path)
    pending = env.ctx.findings.add(Finding(
        title="idor", severity="high", target="api.acme.example",
        summary="s", confidence="pending_verification"))
    calls = []

    def spy_verify_pass(engagement, tools, ctx, client, objective, budget=None,
                        on_text=None):
        calls.append({"tools": tools, "ctx": ctx, "budget": budget,
                      "objective": objective})
        ctx.findings.promote(pending.id, "confirmed", "replayed")
        return 0

    monkeypatch.setattr("redteam.orchestrator.run_verify_pass", spy_verify_pass)
    ex = MissionSpecialistExecutor(env.orch, objective="run objective")
    res = ex.run(_task_view(role="verify", title="verify pending"))
    assert res.status == EXEC_SUCCEEDED
    assert "independent verification pass complete" in res.result
    assert "0 still pending" in res.result
    assert len(calls) == 1                       # the EXISTING pass, once
    assert calls[0]["ctx"] is env.ctx            # shared FindingStore context
    assert calls[0]["budget"] is env.budget      # engagement budget authority
    # promotion went through the EXISTING pipeline, not the executor
    assert env.ctx.findings.get(pending.id).confidence == "confirmed"
    # the executor's own result carries no confirmation claim
    assert all(ev.get("confidence") != "confirmed" for ev in res.evidence)


def test_verify_with_no_pending_findings_is_an_honest_noop(tmp_path, monkeypatch):
    env = _Env(tmp_path)
    calls = []
    monkeypatch.setattr("redteam.orchestrator.run_verify_pass",
                        lambda *a, **k: calls.append(a) or 0)
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view(role="verify"))
    assert res.status == EXEC_SUCCEEDED
    assert "nothing to verify" in res.result
    assert calls == []            # the verifier was not invoked needlessly


# =============================================================================
# C. Shared-context tests
# =============================================================================

def test_specialist_uses_the_shared_run_context(tmp_path):
    env = _Env(tmp_path)
    captured_agent = {}

    real_make = env.orch._make_specialist

    def spy(profile, addon_suffix="", agent_name=None, max_steps=None):
        agent = real_make(profile, addon_suffix, agent_name, max_steps)
        captured_agent["agent"] = agent
        return agent

    env.orch._make_specialist = spy
    ex = MissionSpecialistExecutor(env.orch)
    res = ex.run(_task_view(role="recon"))
    assert res.status == EXEC_SUCCEEDED
    agent = captured_agent["agent"]
    assert isinstance(agent._tools, dict)
    # ONE environment: every authority is THE run's own object
    assert agent._ctx is env.ctx
    assert agent._graph is env.graph
    assert agent._attack_tree is env.tree
    assert agent._budget is env.budget
    assert set(agent._tools) <= set(env.tools)
    # and the audit trail lands on the SAME audit log
    events = [e["event"] for e in env.audit.events]
    assert "mission.task.execute" in events
    assert "agent.start" in events
    assert env.orch.ctx is env.ctx


# =============================================================================
# D. Claim ownership tests
# =============================================================================

def test_scheduler_claims_once_executor_never_reclaims(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="idor probe", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/",
                                 max_steps=8)
    env = _Env(tmp_path)
    env.orch._attack_tree = tree      # the SAME tree the scheduler claims
    executor = MissionSpecialistExecutor(env.orch, objective="lab objective")

    claim_calls = []
    real_claim = tree.claim

    def counting_claim(technique, target, **kw):
        claim_calls.append((technique, target))
        return real_claim(technique, target, **kw)

    tree.claim = counting_claim

    hyp_calls = []

    class RecordingHypotheses:
        def claim_or_register(self, **kw):
            hyp_calls.append(kw)
            class _Hyp:
                hypothesis_id = "hyp-1"
            return _Hyp(), ()

    scheduler = H.make_scheduler(commander, tree, executor=executor,
                                 hypotheses=RecordingHypotheses(), clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["dispatched"] is True and result["outcome"] == "succeeded"
    assert commander.task(task.task_id).status == TASK_SUCCEEDED
    # the trio ran ONCE — scheduler-owned; the executor added no claims
    assert len(claim_calls) == 1
    assert len(hyp_calls) == 1
    # the real specialist was invoked (audit), through the task interface
    events = [e["event"] for e in env.audit.events]
    assert "mission.task.execute" in events and "agent.start" in events


def test_scheduler_failure_path_intact_when_specialist_raises(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="recon slice", role="recon", actor="op")
    env = _Env(tmp_path)
    stub = StubAgent(error=RuntimeError("specialist exploded"))
    _spy_specialist(env, stub)
    executor = MissionSpecialistExecutor(env.orch)
    scheduler = H.make_scheduler(commander, tree=None, executor=executor,
                                 clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "failed"
    done = commander.task(task.task_id)
    assert done.status == TASK_FAILED
    assert "specialist exploded" in done.error


def test_scheduler_completion_path_intact(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="recon slice", role="recon", actor="op")
    env = _Env(tmp_path)
    _spy_specialist(env, StubAgent(outcome="mapped the slice"))
    executor = MissionSpecialistExecutor(env.orch)
    scheduler = H.make_scheduler(commander, tree=None, executor=executor,
                                 clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "succeeded"
    done = commander.task(task.task_id)
    assert done.status == TASK_SUCCEEDED
    assert done.result == "mapped the slice"
    # evidence refs flowed into the task record through the scheduler
    assert done.evidence == []


# =============================================================================
# E. Task limits
# =============================================================================

def test_task_max_steps_is_respected(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    MissionSpecialistExecutor(env.orch).run(_task_view(role="recon", max_steps=7))
    assert captured["max_steps"] == 7


def test_task_limits_never_widen_the_profile_ceiling(tmp_path):
    env = _Env(tmp_path)
    captured = _spy_specialist(env, StubAgent())
    ex = MissionSpecialistExecutor(env.orch)
    ex.run(_task_view(role="recon", max_steps=99))
    assert captured["max_steps"] == RECON.max_steps      # 22, not 99
    ex.run(_task_view(role="exploit", technique="no.such.class",
                      max_steps=500))
    assert captured["max_steps"] == EXPLOIT.max_steps    # 40, not 500


def test_engagement_authorities_stay_authoritative(tmp_path):
    env = _Env(tmp_path)
    agent_holder = {}
    real_make = env.orch._make_specialist

    def spy(profile, addon_suffix="", agent_name=None, max_steps=None):
        agent = real_make(profile, addon_suffix, agent_name, max_steps)
        agent_holder["agent"] = agent
        return agent

    env.orch._make_specialist = spy
    MissionSpecialistExecutor(env.orch).run(_task_view(role="recon"))
    agent = agent_holder["agent"]
    # the engagement budget tracker and THE scoped ctx ride through unchanged
    assert agent._budget is env.budget
    assert agent._ctx is env.ctx
    assert agent._ctx.scope is env.ctx.scope
    # the RoE the task ran under is the engagement's own — nothing widened
    assert set(env.ctx.scope.allowed_hosts) == {"api.acme.example"}


# =============================================================================
# G-adjacent: the driver default is the real executor on the production path
# =============================================================================

def test_driver_production_path_requires_no_mock(tmp_path, capsys):
    """run.py's mission branch constructs the real executor; the driver's
    no-executor seam must be LOUD, never silent."""
    from redteam.mission.driver import run_mission_driver
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander_opts = type("O", (), {"max_steps": 40,
                                    "round_noise_budget": 12.0})()
    env = _Env(tmp_path)
    executor = MissionSpecialistExecutor(env.orch, objective="probe the lab app")
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=mission_dir, objective="probe",
        executor=executor, clock=clock, opts=commander_opts, say=lambda t: None)
    assert summary["executor"] == "MissionSpecialistExecutor"
    assert summary["status"] == "succeeded"
    assert all(t["result"] == "slice done" for t in summary["tasks"])

    # no-executor = the explicit test/simulation seam: mock runs LOUDLY
    (tmp_path / "loud-mock").mkdir()
    run_mission_driver(engagement=_engagement(), out_dir=tmp_path / "loud-mock",
                       objective="probe", clock=clock, opts=commander_opts)
    captured = capsys.readouterr()
    assert "MOCK execution" in (captured.out + captured.err)

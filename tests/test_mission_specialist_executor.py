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
import http.server
import json
import threading

import pytest

from redteam.access import AccessGraph
from redteam.attack_tree import AttackTree
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.credit import credit_confirmed_findings
from redteam.findings import Finding, FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.killchain import ACHIEVED, INITIAL_ACCESS, KillChain
from redteam.llm.openrouter import ChatResult
from redteam.mission.executor import (EXEC_FAILED, EXEC_SUCCEEDED,
                                      ExecutionResult)
from redteam.mission.specialist_executor import MissionSpecialistExecutor
from redteam.mission.driver import mission_outcome, run_mission_driver
from redteam.objective import DATA_ACCESS, Objective, SuccessCriterion
from redteam.orchestrator import (ACCESS, EXPLOIT, LOGIC, RECON, VERIFY,
                                  Orchestrator)
from redteam.ratelimit import RateLimiter
from redteam.retest import (FIXED, build_ctx_for_run,
                            engagement_from_scope_json, retest_run)
from redteam.runtime import BudgetTracker
from redteam.scope import ScopeGuard
from redteam.specialists import A03, profile_for
from redteam.states import (MISSION_FAILED, MISSION_SUCCEEDED, TASK_FAILED,
                            TASK_PENDING, TASK_SUCCEEDED)
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

    def __init__(self, tmp_path, *, with_access=False):
        self.audit = RecordingAudit()
        self.ctx = _ctx(tmp_path, self.audit)
        if with_access:
            # the REAL foothold authorities on the shared context (no fakes):
            # AccessGraph nodes are "demonstrated, not assumed"; KillChain
            # tracks INITIAL_ACCESS. Nothing else in the env changes.
            self.ctx.access = AccessGraph(tmp_path / "access.json")
            self.ctx.killchain = KillChain(tmp_path / "killchain.json")
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
    env = _Env(tmp_path, with_access=True)
    # the ACCESS routing assertion needs its prerequisite met: a demonstrated,
    # active foothold (the correction gate now requires one before construction)
    env.ctx.access.hold("session", "web-sess-1", evidence="demonstrated")
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


# =============================================================================
# ACCESS prerequisite gate: a demonstrated, ACTIVE foothold is required before
# the ACCESS specialist is constructed or run. The gate reads ONLY the
# existing AccessGraph / KillChain evidence; the mission scheduler's readiness
# gate keeps a prerequisite-less ACCESS task PENDING (the existing not-ready
# semantics — exactly like unsatisfied dependencies). Lifecycle untouched.
# =============================================================================

def _access_env(tmp_path):
    """_Env with the real AccessGraph/KillChain + a construction spy."""
    env = _Env(tmp_path, with_access=True)
    env.executor = MissionSpecialistExecutor(
        env.orch, objective="press the confirmed foothold toward the objective")
    captured = {}
    real_make = env.orch._make_specialist

    def spy(profile, addon_suffix="", agent_name=None, max_steps=None):
        captured["constructed"] = True
        captured["profile"] = profile
        return real_make(profile, addon_suffix, agent_name, max_steps)

    env.orch._make_specialist = spy
    return env, captured


def _access_stack(tmp_path, env):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    scheduler = H.make_scheduler(commander, tree=None, executor=env.executor,
                                 clock=clock,
                                 prerequisite=env.orch.access_precondition_reason)
    return commander, scheduler, clock


def test_access_task_without_foothold_is_not_dispatchable(tmp_path):
    env, captured = _access_env(tmp_path)
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    task = commander.create_task(title="press the foothold", role="access",
                                 actor="op")
    # readiness gate: the task must WAIT — it stays PENDING, nothing is claimed
    assert scheduler.ready_tasks() == []
    assert commander.task(task.task_id).status == TASK_PENDING
    assert captured == {}                     # no specialist was ever constructed
    assert env.audit.events == []             # no agent turn, no task.execute


def test_access_task_direct_dispatch_refuses_without_a_specialist(tmp_path):
    # defense in depth: even a direct dispatch (bypassing readiness) cannot
    # reach the specialist — execute_task refuses before construction and the
    # existing failure path records the reason.
    env, captured = _access_env(tmp_path)
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    task = commander.create_task(title="press the foothold", role="access",
                                 actor="op")
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "failed"
    done = commander.task(task.task_id)
    assert done.status == TASK_FAILED
    assert "access prerequisite not met" in done.error
    assert captured == {}                     # _make_specialist never ran
    assert "agent.start" not in [e["event"] for e in env.audit.events]


def test_access_task_with_demonstrated_foothold_executes(tmp_path):
    env, captured = _access_env(tmp_path)
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    task = commander.create_task(title="press the foothold", role="access",
                                 actor="op")
    # the EXISTING authority speaks: a demonstrated session on the AccessGraph
    env.ctx.access.hold("session", "web-sess-1",
                        evidence="verified login replay (confirm-grade)")
    assert [t.task_id for t in scheduler.ready_tasks()] == [task.task_id]
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "succeeded"
    assert commander.task(task.task_id).status == TASK_SUCCEEDED
    assert captured["profile"] is ACCESS       # routing preserved


def test_revoked_foothold_does_not_satisfy_the_gate(tmp_path):
    env, captured = _access_env(tmp_path)
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    task = commander.create_task(title="press the foothold", role="access",
                                 actor="op")
    env.ctx.access.hold("session", "web-sess-1", evidence="proven")
    assert [t.task_id for t in scheduler.ready_tasks()] == [task.task_id]
    # invalidated through the canonical lifecycle (PR #13): revoke() flips
    # held, stamps invalidated_at/reason and KEEPS the evidence — the
    # revocation record (a revoked foothold is no longer active evidence)
    env.ctx.access.revoke("session", "web-sess-1", reason="retest fixed")
    assert env.ctx.access.held() == []
    assert len(env.ctx.access.revoked_nodes()) == 1
    assert scheduler.ready_tasks() == []
    assert commander.task(task.task_id).status == TASK_PENDING
    assert captured == {}
    # demonstrated again -> dispatchable again (the gate re-checks every round;
    # hold() re-activation is the only sanctioned revoked -> held transition)
    env.ctx.access.hold("session", "web-sess-1", evidence="re-proven")
    assert [t.task_id for t in scheduler.ready_tasks()] == [task.task_id]


def test_killchain_initial_access_achieved_satisfies_the_gate(tmp_path):
    env, captured = _access_env(tmp_path)
    view = _task_view(role="access")
    assert env.orch.access_precondition_reason(view) != ""
    # the other existing authority: KillChain INITIAL_ACCESS achieved
    env.ctx.killchain.mark(INITIAL_ACCESS, ACHIEVED, note="first foothold proven")
    assert env.orch.access_precondition_reason(view) == ""
    # a non-achieved stage never substitutes (active-only evidence)
    env2, _c2 = _access_env(tmp_path / "env2")
    env2.ctx.killchain.mark(INITIAL_ACCESS, "in_progress", note="trying")
    assert env2.orch.access_precondition_reason(view) != ""


def test_invalidated_holding_contradicts_the_killchain_fallback(tmp_path):
    # The fallback's boundary, made explicit: an achieved INITIAL_ACCESS stage
    # is a HISTORICAL milestone — it never stands in for a foothold whose
    # supporting evidence was invalidated (the graph's own record).
    env, _ = _access_env(tmp_path)
    view = _task_view(role="access")
    env.ctx.access.hold("session", "web-sess-1", evidence="was proven")
    env.ctx.killchain.mark(INITIAL_ACCESS, ACHIEVED, note="milestone")
    assert env.orch.access_precondition_reason(view) == ""   # active holding wins
    env.ctx.access.revoke("session", "web-sess-1", reason="retest fixed")
    reason = env.orch.access_precondition_reason(view)
    assert "invalidated" in reason and "must not stand in" in reason
    # re-demonstration (hold() re-activation) re-opens the gate
    env.ctx.access.hold("session", "web-sess-1", evidence="re-proven")
    assert env.orch.access_precondition_reason(view) == ""
    # a graph that NEVER tracked a holding (observe-only, no evidence) may
    # still fall back to the stage — no revocation record exists to contradict
    env2, _c2 = _access_env(tmp_path / "env2")
    env2.ctx.access.observe("session", "seen-only")
    env2.ctx.killchain.mark(INITIAL_ACCESS, ACHIEVED, note="milestone")
    assert env2.orch.access_precondition_reason(_task_view(role="access")) == ""


def test_non_access_tasks_are_unaffected_by_the_gate(tmp_path):
    env, captured = _access_env(tmp_path)     # NO foothold held
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    recon = commander.create_task(title="map", role="recon", actor="op")
    exploit = commander.create_task(title="check", role="exploit", actor="op",
                                    technique="auth.test",
                                    target="https://t.test/")
    logic = commander.create_task(title="workflow", role="logic", actor="op")
    ready = {t.task_id: t.role for t in scheduler.ready_tasks()}
    assert set(ready.values()) == {"recon", "exploit", "logic"}   # gate is access-only
    assert scheduler.dispatch(recon.task_id)["outcome"] == "succeeded"
    assert captured["profile"] is RECON
    assert scheduler.dispatch(exploit.task_id)["outcome"] == "succeeded"
    assert captured["profile"] is profile_for("auth.test")
    assert scheduler.dispatch(logic.task_id)["outcome"] == "succeeded"
    assert captured["profile"] is LOGIC


def test_gate_allows_dispatch_once_the_foothold_appears_mid_mission(tmp_path):
    env, captured = _access_env(tmp_path)
    commander, scheduler, _clock = _access_stack(tmp_path, env)
    recon = commander.create_task(title="map", role="recon", actor="op")
    access = commander.create_task(title="press", role="access", actor="op",
                                   dependencies=(recon.task_id,))
    # round 1: recon dispatches; the access task stays pending BOTH because of
    # its dependency and the (unmet) foothold gate
    ready_roles = {t.role for t in scheduler.ready_tasks()}
    assert ready_roles == {"recon"}
    assert scheduler.dispatch(recon.task_id)["outcome"] == "succeeded"
    assert scheduler.ready_tasks() == []      # dep satisfied, foothold NOT
    # exploitation demonstrates a foothold through the existing pipeline
    env.ctx.access.hold("session", "web-sess-1", evidence="confirmed foothold")
    # round 2: the SAME pending task is now dispatchable — no re-creation
    assert [t.task_id for t in scheduler.ready_tasks()] == [access.task_id]
    assert scheduler.dispatch(access.task_id)["outcome"] == "succeeded"
    assert commander.task(access.task_id).status == TASK_SUCCEEDED


def test_driver_wires_the_access_gate(tmp_path):
    from redteam.mission.driver import run_mission_driver
    env, captured = _access_env(tmp_path)
    (tmp_path / "mission_plan.json").write_text(json.dumps({"tasks": [
        {"title": "press the foothold", "role": "access"},
    ]}), encoding="utf-8")
    commander_opts = type("O", (), {"max_steps": 40,
                                    "round_noise_budget": 12.0})()
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=tmp_path, objective="probe",
        executor=MissionSpecialistExecutor(env.orch, objective="probe"),
        clock=H.FakeClock(), opts=commander_opts, say=lambda t: None,
        access_gate=env.orch.access_precondition_reason)
    # honest endgame: the access work never became possible -> mission FAILED,
    # the task stayed PENDING, and no specialist was ever invoked
    assert summary["status"] == "failed"
    assert summary["tasks"][0]["status"] == TASK_PENDING
    assert captured == {}
    assert "agent.start" not in [e["event"] for e in env.audit.events]


# =============================================================================
# Mission-success truthfulness (review follow-up): "everything reached A
# terminal state" is not "everything succeeded". With real specialists on the
# production path, an all-failed, mixed, or cancelled mission must never read
# MISSION_SUCCEEDED — success requires every task TASK_SUCCEEDED.
# =============================================================================


class _StatusExecutor:
    """Phase 2 protocol seam: every task ends with the scripted EXEC status."""

    def __init__(self, status: str):
        self.status = status

    def run(self, task_view: dict) -> ExecutionResult:
        if self.status == EXEC_FAILED:
            return ExecutionResult(status=EXEC_FAILED, error="scripted failure")
        return ExecutionResult(status=EXEC_SUCCEEDED, result="scripted ok")


class _RoleScriptExecutor:
    """recon succeeds, exploit fails — the mixed-success/failure mission."""

    def run(self, task_view: dict) -> ExecutionResult:
        if task_view.get("role") == "exploit":
            return ExecutionResult(status=EXEC_FAILED, error="scripted failure")
        return ExecutionResult(status=EXEC_SUCCEEDED, result="scripted ok")


def _write_plan(tmp_path, specs):
    (tmp_path / "mission_plan.json").write_text(
        json.dumps({"tasks": specs}), encoding="utf-8")


def _driver_opts():
    return type("O", (), {"max_steps": 40, "round_noise_budget": 12.0})()


def test_all_failed_mission_is_reported_failed(tmp_path):
    _write_plan(tmp_path, [{"title": "map", "role": "recon"},
                           {"title": "check", "role": "exploit",
                            "technique": "auth.test",
                            "target": "https://t.test/"}])
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=tmp_path, objective="probe",
        executor=_StatusExecutor(EXEC_FAILED), clock=H.FakeClock(),
        opts=_driver_opts(), say=lambda t: None)
    assert summary["status"] == MISSION_FAILED          # NOT "succeeded"
    assert {t["status"] for t in summary["tasks"]} == {TASK_FAILED}


def test_mixed_success_and_failure_is_reported_failed(tmp_path):
    _write_plan(tmp_path, [{"title": "map", "role": "recon"},
                           {"title": "check", "role": "exploit",
                            "technique": "auth.test",
                            "target": "https://t.test/"}])
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=tmp_path, objective="probe",
        executor=_RoleScriptExecutor(), clock=H.FakeClock(),
        opts=_driver_opts(), say=lambda t: None)
    assert summary["status"] == MISSION_FAILED
    statuses = {t["role"]: t["status"] for t in summary["tasks"]}
    assert statuses == {"recon": TASK_SUCCEEDED, "exploit": TASK_FAILED}


def test_all_succeeded_mission_reports_succeeded(tmp_path):
    _write_plan(tmp_path, [{"title": "map", "role": "recon"},
                           {"title": "check", "role": "exploit",
                            "technique": "auth.test",
                            "target": "https://t.test/"}])
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=tmp_path, objective="probe",
        executor=_StatusExecutor(EXEC_SUCCEEDED), clock=H.FakeClock(),
        opts=_driver_opts(), say=lambda t: None)
    assert summary["status"] == MISSION_SUCCEEDED
    assert all(t["status"] == TASK_SUCCEEDED for t in summary["tasks"])


def test_default_mission_generates_frontier_task_and_verifies_automatically(tmp_path):
    """No mission_plan: recon -> canonical frontier -> exploit -> independent VERIFY."""
    from redteam.mission.executor import ExecutionResult
    mission_dir, clock = H.make_mission_dir(tmp_path)
    tree = AttackTree(tmp_path / "tree.json")
    target = "https://api.acme.example/orders"
    tree.seed_endpoint(target)

    class DynamicExecutor:
        def __init__(self):
            self.pending = []
            self.frontier_used = False
            self.calls = []
            self.reconciled = 0

        def run(self, task_view):
            role = task_view["role"]
            self.calls.append(role)
            if role == "exploit":
                self.pending = [type("FindingRef", (), {"id": "finding-1"})()]
            elif role == "verify":
                self.pending = []
            return ExecutionResult(status=EXEC_SUCCEEDED, result=f"{role} slice done")

        def pending_findings(self):
            return list(self.pending)

        def attack_frontier(self, limit=6):
            if self.frontier_used:
                return []
            self.frontier_used = True
            return [{"title": "a03-injection: injection.sqli on " + target,
                     "role": "exploit", "technique": "injection.sqli",
                     "target": target, "max_steps": 8}]

        def reconcile_after_verification(self):
            self.reconciled += 1
            return {}

        def objective_achieved(self):
            return None

        def budget_available(self):
            return True

    executor = DynamicExecutor()
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=mission_dir, objective="prove an injection flaw",
        attack_tree=tree, executor=executor, clock=clock,
        opts=_driver_opts(), say=lambda t: None)

    assert executor.calls == ["recon", "exploit", "verify"]
    assert executor.reconciled == 1
    assert {t["role"] for t in summary["tasks"]} == {"recon", "exploit", "verify"}
    assert all(t["status"] == TASK_SUCCEEDED for t in summary["tasks"])
    assert summary["dynamic"] is True
    assert summary["pending_verification"] == 0
    assert summary["objective_achieved"] is None
    assert summary["stop_reason"] == "frontier_exhausted"
    assert summary["execution_complete"] is True
    # The scheduler releases the execution claim; it does not mark the node
    # complete merely because the specialist task returned successfully.
    assert tree.node("injection.sqli", target).status == "todo"


def test_mission_attempt_updates_the_scheduler_claimed_hypothesis(tmp_path):
    from redteam.attack_tree import TECHNIQUES
    from redteam.swarm import AWAITING_VERIFICATION, weakness_for_technique

    env = _Env(tmp_path)
    technique = "injection.sqli"
    target = "https://api.acme.example/orders"
    claim = (f"{technique} on {target}: "
             f"{TECHNIQUES[technique].description}")
    hyp, _ = env.orch._research.claim_or_register(
        asset_ref=target, weakness_class=weakness_for_technique(technique),
        claim=claim, agent="exploit", technique=technique)
    finding = env.ctx.findings.add(Finding(
        title="SQLi candidate", severity="high", target=target,
        summary="differential proof", confidence="pending_verification"))

    env.orch.record_mission_task_outcome(
        {"task_id": "task-1", "node_id": f"{technique}@{target}",
         "role": "exploit", "hypothesis_id": hyp.hypothesis_id},
        [{"kind": "finding", "ref": finding.id,
          "confidence": "pending_verification"}])

    updated = env.orch._research.registry.get(hyp.hypothesis_id)
    assert updated.status == AWAITING_VERIFICATION
    assert any(ev.get("artifact_ref") == finding.id
               and ev.get("kind") == "finding"
               for ev in updated.evidence_refs)
    assert env.orch._research_finding_hyp[finding.id] == hyp.hypothesis_id
    assert env.orch._research_hyp_by_node[f"{technique}@{target}"] == hyp.hypothesis_id


def test_mission_outcome_rejects_pending_findings_and_unmet_objective():
    T = type("T", (), {"status": TASK_SUCCEEDED})
    assert mission_outcome([T()], pending_verification=1) == (
        MISSION_FAILED, "unresolved_verification")
    assert mission_outcome([T()], objective_achieved=False) == (
        MISSION_FAILED, "objective_not_achieved")
    assert mission_outcome([T()], objective_achieved=True) == (
        MISSION_SUCCEEDED, "")


def test_mission_outcome_counts_cancelled_as_failure():
    # TASK_CANCELLED exists in the states machine (reserved vocabulary — no
    # producer writes it yet); the outcome calc is safe against it regardless:
    # success is EVERY task at the intended successful terminal outcome.
    T = type("T", (), {"status": TASK_SUCCEEDED})
    C = type("T", (), {"status": "cancelled"})
    F = type("T", (), {"status": TASK_FAILED})
    assert mission_outcome([T(), T()]) == (MISSION_SUCCEEDED, "")
    for tasks in ([C()], [T(), C()], [F()], [T(), F()], []):
        status, reason = mission_outcome(tasks)
        assert status == MISSION_FAILED
        assert "successful terminal state" in reason


# =============================================================================
# Revocation vs the KillChain fallback (review follow-up): a FIXED retest must
# revoke the demonstrated foothold, and the achieved INITIAL_ACCESS stage must
# NOT stand in for it. Run end to end on the REAL, SINGLE canonical path — the
# creditor (structured finding_id provenance), retest.py's own FIXED-gated
# invalidate_after_fix (AccessGraph.revoke()), and the orchestrator gate
# reading revoked_nodes(). No second invalidation implementation exists.
# =============================================================================


class _GateLabHandler(http.server.BaseHTTPRequestHandler):
    """Local lab: /vuln is vulnerable; every other path behaves patched."""

    def _respond(self):
        if self.path.startswith("/vuln"):
            body = b"ADMIN PANEL secret"
        else:
            body = b"302 login required"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond

    def log_message(self, *a):  # silence test noise
        pass


@pytest.fixture()
def gate_lab_target():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _GateLabHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _gate_lab_env(tmp_path, base):
    """A REAL retest-run context (frozen scope.json, FindingStore on disk, no
    LLM — exactly what build_ctx_for_run gives a retest) with the shared
    AccessGraph/KillChain authorities attached, and the run's Orchestrator
    over that same context."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    port = int(base.rsplit(":", 1)[1])
    (run_dir / "scope.json").write_text(json.dumps(
        {"allowed_hosts": ["127.0.0.1"], "excluded_hosts": [],
         "allowed_ports": [port], "allowed_schemes": ["http"],
         "max_requests_per_second": 100.0, "max_total_requests": 1000,
         "allow_private_ranges": True}), encoding="utf-8")
    # the finding was CONFIRMED in the original run (historical state on disk);
    # its stored recipe now replays against patched behavior -> FIXED verdict
    finding = Finding(title="unauth admin panel", severity="high",
                      target=f"{base}/patched",
                      summary="admin panel reachable without a session",
                      confidence="confirmed",
                      evidence="200 with ADMIN PANEL marker", check_type="http",
                      check_spec={"request": {"method": "GET",
                                              "url": f"{base}/patched"},
                                  "body_regex": "ADMIN PANEL"})
    (run_dir / "findings.json").write_text(json.dumps([finding.__dict__]),
                                           encoding="utf-8")
    eng = engagement_from_scope_json(run_dir)
    ctx = build_ctx_for_run(eng, run_dir)
    ctx.access = AccessGraph(run_dir / "access.json")
    ctx.killchain = KillChain(run_dir / "killchain.json")
    ctx.objective = Objective(name="read the admin panel", criteria=[
        SuccessCriterion(id="c-data", kind=DATA_ACCESS,
                         description="read the admin panel data",
                         target=f"{base}/patched")])
    orch = Orchestrator(eng, build_registry(enable_sandbox=False,
                                            enable_browser=False),
                        ctx, FakeClient(),
                        graph=KnowledgeGraph(tmp_path / "g.json"),
                        attack_tree=AttackTree(tmp_path / "attack_tree.json"))
    orch.with_runtime(budget=BudgetTracker(max_seconds=600, max_tokens=100000))
    captured = {}
    real_make = orch._make_specialist

    def spy(profile, addon_suffix="", agent_name=None, max_steps=None):
        captured["constructed"] = True
        captured["profile"] = profile
        return real_make(profile, addon_suffix, agent_name, max_steps)

    orch._make_specialist = spy
    return ctx, orch, captured


def test_fixed_retest_invalidates_the_foothold_and_blocks_access(
        tmp_path, gate_lab_target):
    ctx, orch, captured = _gate_lab_env(tmp_path, gate_lab_target)
    # 1. demonstrate a foothold: the CREDITOR holds it from the confirmed
    #    finding; the KillChain journals the INITIAL_ACCESS milestone
    applied = credit_confirmed_findings(ctx)
    assert applied, "the confirmed finding must collect its criterion"
    held = ctx.access.held()
    assert len(held) == 1 and held[0].source == "verified_finding"
    assert f"confirmed finding {applied[0]['finding']}" in held[0].evidence
    ctx.killchain.mark(INITIAL_ACCESS, ACHIEVED, note="first foothold proven")
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    executor = MissionSpecialistExecutor(orch, objective="press the foothold")
    scheduler = H.make_scheduler(commander, tree=None, executor=executor,
                                 clock=clock,
                                 prerequisite=orch.access_precondition_reason)
    task = commander.create_task(title="press the foothold", role="access",
                                 actor="op")
    assert [t.task_id for t in scheduler.ready_tasks()] == [task.task_id]
    # 2. run a REAL retest of the stored recipe against the now-patched lab:
    #    verdict FIXED, recorded on the finding's remediation timeline — and
    #    retest_run ITSELF drives the canonical invalidation (the authorities
    #    are forwarded exactly as the retest CLI and the retest endpoint do)
    results = retest_run(ctx.findings, ctx, trials=3, need=2,
                         access=getattr(ctx, "access", None),
                         graph=getattr(ctx, "graph", None))
    assert results[0]["verdict"] == FIXED
    # 3. the FIXED verdict revoked the holding the finding created, through the
    #    graph's own lifecycle (revoke(): held=False, invalidated_at/reason
    #    stamped, evidence retained — the structured finding_id provenance the
    #    creditor wrote is the match key; no free-text parsing)
    invalidated = results[0]["invalidation"]
    assert invalidated["revoked"] == [{"kind": held[0].kind, "key": held[0].key}]
    assert ctx.access.held() == []
    revoked = ctx.access.revoked_nodes()
    assert len(revoked) == 1 and revoked[0].id == held[0].id
    assert revoked[0].evidence and revoked[0].invalidated_at
    assert "retest fixed" in revoked[0].invalidation_reason
    # the audit trail records the revocation against the finding
    assert any(e["event"] == "retest.invalidated" for e in ctx.audit.read_all())
    #    THE expected behavior, explicit: the achieved INITIAL_ACCESS stage is
    #    a historical milestone and does NOT stand in for the revoked
    #    foothold — the ACCESS task is blocked, nothing constructed, nothing run
    assert scheduler.ready_tasks() == []
    assert commander.task(task.task_id).status == TASK_PENDING
    assert captured == {}
    # 4. a newly demonstrated foothold re-opens the gate for the SAME task
    #    (hold() re-activation is the only sanctioned revoked -> held path)
    ctx.access.hold("resource", f"{gate_lab_target}/patched",
                    evidence="re-proven by a fresh confirmed session")
    assert ctx.access.revoked_nodes() == []
    assert [t.task_id for t in scheduler.ready_tasks()] == [task.task_id]

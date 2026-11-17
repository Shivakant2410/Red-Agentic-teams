"""T6 — the four budget planes are mechanically separate (C3).

Pins: task budget carve inheritance (C3 rule 4), OPSEC gating changes WHICH
tasks dispatch but never halts, execution failure never masquerades as an
OPSEC or RoE event, completion never implies confirmation (C4), and the
Commander structurally cannot touch the tree or findings.
"""
from __future__ import annotations

import pytest

from redteam.mission.errors import TaskBudgetError, ValidationError
from redteam.mission.executor import ExecutionResult, MockExecutor
from redteam.states import TASK_SUCCEEDED

import mission_helpers as H


def test_task_budget_carve_cannot_exceed_engagement(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock,
                                 roe_caps={"max_steps": 40,
                                           "round_noise_budget": 12.0})
    commander.start_mission("op")
    with pytest.raises(TaskBudgetError):
        commander.create_task(title="x", role="exploit", actor="op",
                              max_steps=41)                     # > RoE carve cap
    with pytest.raises(TaskBudgetError):
        commander.create_task(title="x", role="exploit", actor="op",
                              opsec_allowance=12.5)             # > round budget
    ok = commander.create_task(title="x", role="exploit", actor="op",
                               max_steps=40, opsec_allowance=12.0)
    assert ok.max_steps == 40 and ok.opsec_allowance == 12.0


def test_opsec_gating_changes_dispatch_not_liveness(tmp_path):
    """The OPSEC plane is a soft control: an unaffordable task simply does not
    dispatch this round (claim gating); nothing fails, nothing halts."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    commander.start_mission("op")
    cheap = commander.create_task(title="cheap", role="recon", actor="op",
                                  opsec_allowance=2.0)
    loud = commander.create_task(title="loud", role="exploit", actor="op",
                                 opsec_allowance=10.0)
    scheduler = H.make_scheduler(commander, tree, clock=clock,
                                 round_noise_budget=5.0)
    ready_ids = [t.task_id for t in scheduler.ready_tasks()]
    assert cheap.task_id in ready_ids and loud.task_id not in ready_ids
    result = scheduler.dispatch(cheap.task_id)
    assert result["dispatched"] is True
    # Mission is still RUNNING and the loud task is still pending — throttled,
    # not failed, not halted:
    assert commander.mission.status == "running"
    assert commander.task(loud.task_id).status == "pending"
    types = H.journal_types(mission_dir)
    assert "MISSION_HALTED" not in types and "TASK_FAILED" not in types


def test_execution_failure_is_task_plane_never_mission_halt(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")
    executor = MockExecutor()
    executor.fail_for(task.task_id, "scripted failure")
    scheduler = H.make_scheduler(commander, tree, executor=executor, clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "failed"
    failed = commander.task(task.task_id)
    assert failed.status == "failed" and failed.error == "scripted failure"
    assert commander.mission.status == "running"          # execution plane only
    types = H.journal_types(mission_dir)
    assert "TASK_FAILED" in types
    assert "MISSION_HALTED" not in types                  # distinct event types


def test_completion_is_not_confirmation_and_not_tree_completion(tmp_path):
    """C4 as structure: a succeeded task leaves the tree node in_progress and
    stores only REFERENCES; 'confirmed' is refused at the API boundary."""
    mission_dir, clock, commander, tree, task = _mission_with_node(tmp_path)
    executor = MockExecutor(script={task.task_id: {
        "status": "succeeded", "result": "probe ran",
        "evidence": [{"kind": "observation", "ref": "traffic://req-1"}]}})
    scheduler = H.make_scheduler(commander, tree, executor=executor, clock=clock)
    scheduler.dispatch(task.task_id)
    done = commander.task(task.task_id)
    assert done.status == TASK_SUCCEEDED
    node = tree.node("auth.test", "https://t.test/")
    assert node.status == "in_progress"          # NOT completed by task success
    ev = done.evidence[0]
    assert ev["ref"] == "traffic://req-1" and ev["confidence"] == ""


def _mission_with_node(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")
    return mission_dir, clock, commander, tree, task


def test_executor_cannot_emit_confirmed_evidence(tmp_path):
    """Only the independent verification pipeline confirms (C4) — the executor
    boundary refuses the word."""
    with pytest.raises(ValidationError):
        ExecutionResult(status="succeeded",
                        evidence=[{"kind": "finding", "ref": "F-1",
                                   "confidence": "confirmed"}])


def test_commander_structurally_has_no_authority_references(tmp_path):
    """The C4 guarantee by construction: the Commander holds no AttackTree and
    no FindingStore — inferring a confirmed finding or tree completion from
    task success is IMPOSSIBLE from its API surface."""
    mission_dir, clock, commander, tree, task = _mission_with_node(tmp_path)
    for attr in ("tree", "_tree", "findings", "store", "_store",
                 "objective", "_objective"):
        assert not hasattr(commander, attr), attr
    # No method can confirm a finding, complete a tree node, or credit an
    # objective (mark_running is the claim trio's CLAIMED->RUNNING edge, not an
    # authority mutation — its name only matches "mark" by the states.py
    # vocabulary).
    for name in dir(commander):
        assert "confirm" not in name, name
        assert name not in ("mark_completed", "confirm_finding",
                            "credit_objective", "set_finding_confidence"), name


def test_mission_success_requires_terminal_tasks_not_findings(tmp_path):
    """A mission may SUCCEED with zero confirmed findings — success is an
    execution outcome; findings are the verification pipeline's vocabulary."""
    from redteam.mission.driver import run_mission_driver
    mission_dir, clock = H.make_mission_dir(tmp_path)
    summary = run_mission_driver(
        engagement=_FakeEngagement(), out_dir=mission_dir,
        objective="probe", attack_tree=None, clock=clock,
        executor=MockExecutor())
    assert summary["status"] == "succeeded"
    assert all(t["status"] == "succeeded" for t in summary["tasks"])
    assert not any(e.get("confidence") == "confirmed"
                   for t in summary["tasks"] for e in t["evidence"])


class _FakeEngagement:
    name = "eng-1"
    ticket = "ROE-2026-17"

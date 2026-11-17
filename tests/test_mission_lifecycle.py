"""T1 — mission + mission_task lifecycle machines (states.py as the ONE registry).

Pins: legal transitions through the Commander, illegal ones rejected, terminal
states final, journal events emitted per transition, and the machine registry
exposes both Phase 2 machines with the writer matrix.
"""
from __future__ import annotations

import pytest

from redteam.states import (MISSION_CANCELLED, MISSION_FAILED, MISSION_HALTED,
                            MISSION_PLANNED, MISSION_RUNNING, MISSION_SUCCEEDED,
                            TASK_BLOCKED_DUPLICATE, TASK_CANCELLED, TASK_CLAIMED,
                            TASK_EXPIRED, TASK_FAILED, TASK_PENDING,
                            TASK_RUNNING, TASK_SUCCEEDED, can_transition,
                            describe, machines)
from redteam.mission.errors import (InvalidTaskTransitionError, ValidationError)

import mission_helpers as H


def test_machines_registered():
    spec_m = describe("mission")
    spec_t = describe("mission_task")
    assert spec_m["initial"] == MISSION_PLANNED
    assert spec_t["initial"] == TASK_PENDING
    assert spec_m["terminal"] == (MISSION_SUCCEEDED, MISSION_FAILED,
                                  MISSION_HALTED, MISSION_CANCELLED)
    assert set(spec_t["terminal"]) == {TASK_SUCCEEDED, TASK_CANCELLED}


def test_mission_transition_table():
    assert can_transition("mission", MISSION_PLANNED, MISSION_RUNNING)
    assert can_transition("mission", MISSION_RUNNING, MISSION_SUCCEEDED)
    assert can_transition("mission", MISSION_RUNNING, MISSION_HALTED)
    assert not can_transition("mission", MISSION_PLANNED, MISSION_SUCCEEDED)
    assert not can_transition("mission", MISSION_PLANNED, MISSION_FAILED)
    assert not can_transition("mission", MISSION_SUCCEEDED, MISSION_RUNNING)
    assert not can_transition("mission", MISSION_HALTED, MISSION_RUNNING)


def test_task_transition_table():
    assert can_transition("mission_task", TASK_PENDING, TASK_CLAIMED)
    assert can_transition("mission_task", TASK_CLAIMED, TASK_PENDING)  # rollback
    assert can_transition("mission_task", TASK_CLAIMED, TASK_BLOCKED_DUPLICATE)
    assert can_transition("mission_task", TASK_RUNNING, TASK_EXPIRED)
    assert can_transition("mission_task", TASK_EXPIRED, TASK_PENDING)  # retry
    assert can_transition("mission_task", TASK_EXPIRED, TASK_FAILED)   # exhausted
    assert can_transition("mission_task", TASK_FAILED, TASK_PENDING)   # re-trial
    assert not can_transition("mission_task", TASK_PENDING, TASK_SUCCEEDED)
    assert not can_transition("mission_task", TASK_RUNNING, TASK_PENDING)
    assert not can_transition("mission_task", TASK_SUCCEEDED, TASK_CLAIMED)


def test_mission_lifecycle_happy_path(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    assert commander.mission.status == MISSION_PLANNED
    commander.start_mission("op")
    assert commander.mission.status == MISSION_RUNNING
    commander.set_mission_status(MISSION_SUCCEEDED, "op")
    assert commander.mission.status == MISSION_SUCCEEDED
    types = H.journal_types(mission_dir)
    assert "MISSION_STARTED" in types and "MISSION_STATE_CHANGED" in types


def test_mission_illegal_transitions_rejected(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    with pytest.raises(InvalidTaskTransitionError):
        commander.set_mission_status(MISSION_SUCCEEDED, "op")   # planned -> succeeded
    commander.start_mission("op")
    commander.set_mission_status(MISSION_HALTED, "op", reason="STOP file")
    assert commander.mission.halt_reason == "STOP file"
    with pytest.raises(InvalidTaskTransitionError):
        commander.start_mission("op")                            # halted is terminal
    assert commander.mission.status == MISSION_HALTED


def test_task_lifecycle_full_roundtrip(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="probe auth", role="exploit", actor="op")
    assert task.status == TASK_PENDING
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    assert commander.task(task.task_id).status == TASK_CLAIMED
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    assert commander.task(task.task_id).status == TASK_RUNNING
    commander.complete_task(task.task_id, actor="exploit", lease_token=1,
                            result="ran")
    done = commander.task(task.task_id)
    assert done.status == TASK_SUCCEEDED and done.result == "ran"
    assert done.owner == "" and done.lease_expires_at == ""   # ownership released
    types = H.journal_types(mission_dir)
    assert types.count("TASK_CLAIMED") == 1 and types.count("TASK_SUCCEEDED") == 1


def test_task_illegal_transitions_rejected(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="probe auth", role="exploit", actor="op")
    # CAS guard: a claimed task is not claimable again.
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    with pytest.raises(InvalidTaskTransitionError):
        commander.reserve_task(task.task_id, actor="other", lease_token=2,
                               lease_expires_at=clock.iso())
    # Complete-before-claim is illegal for ANY writer (fence fires first for a
    # non-owner; the transition table is the deeper contract).
    from redteam.mission.errors import TaskOwnershipError
    with pytest.raises(TaskOwnershipError):
        commander.complete_task(task.task_id, actor="op", lease_token=9)
    # A fenced writer cannot push an illegal transition either: double-dispatch.
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    with pytest.raises(InvalidTaskTransitionError):
        commander.mark_running(task.task_id, actor="exploit", lease_token=1)


def test_create_task_validation(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    with pytest.raises(ValidationError):
        commander.create_task(title="  ", role="exploit", actor="op")
    with pytest.raises(ValidationError):
        commander.create_task(title="x", role="nonexistent-role", actor="op")
    with pytest.raises(ValidationError):
        commander.create_task(title="x", role="exploit", actor="op",
                              dependencies=("task-nope",))
    ok = commander.create_task(title="x", role="exploit", actor="op",
                               technique="auth.test", target="https://t.test/")
    assert ok.node_id == "auth.test@https://t.test/"


def test_unknown_task_reads_raise(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    from redteam.mission.errors import UnknownTaskError
    with pytest.raises(UnknownTaskError):
        commander.task("task-missing")


def test_writer_matrix_documented(tmp_path):
    """The states.py writer matrix documents WHO may write which task state —
    the fenced worker, the sweep, the scheduler, recovery. Structural check:
    the Phase 2 writers are all present (D1 contract: tables are the contract)."""
    writers = describe("mission_task")["writers"]
    roles = " ".join(w["writer"] for w in writers)
    for fragment in ("claim trio", "fenced worker completion", "lease sweep",
                     "recovery reconcile", "operator cancel"):
        assert fragment in roles, fragment

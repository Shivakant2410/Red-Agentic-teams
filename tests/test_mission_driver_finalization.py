"""Mission lifecycle correctness (Builder 04 §8): the coordination driver must
finalize the mission snapshot on EVERY exit path — objective achieved, budget
exhausted, operator stop, coordination fault — never leave it dangling
"running", and never mark success merely because dispatched tasks succeeded.

Note on the fault seams: the scheduler deliberately CONVERTS executor.run()
exceptions into failed tasks (recovery owns the retry), so a specialist crash
cannot dangle the mission by itself. What CAN escape dispatch is a
coordination-level fault (journal/tree) — and the driver calls executor
introspection (frontier selection, budget check) OUTSIDE dispatch, which is the
escalation seam exercised here.

The live-fire 20261118 campaign surfaced the defect class: a killed server left
manifest.json and mission.json both "running" forever.
"""

from __future__ import annotations

import json

import pytest

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import EXEC_SUCCEEDED, ExecutionResult
from redteam.runtime import Halt

import datetime as _dt

import mission_helpers as H


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


class _GoodRunMixin:
    """Runs each dispatch successfully (MockExecutor semantics)."""

    def run(self, task_view):
        return ExecutionResult(status=EXEC_SUCCEEDED,
                               result="mock execution completed")

    def objective_achieved(self):
        return None

    def pending_findings(self):
        return []

    def access_state(self):
        return {}


class FaultyFrontierExecutor(_GoodRunMixin):
    """Coordination-level fault escaping dispatch: frontier selection explodes."""

    def attack_frontier(self, limit=999):
        raise RuntimeError("attack tree coordinator exploded")


class HaltFrontierExecutor(_GoodRunMixin):
    """Kill-switch/budget Halt surfacing outside dispatch."""

    def attack_frontier(self, limit=999):
        raise Halt("kill switch present (STOP)")


class SpendsBudgetExecutor(_GoodRunMixin):
    """Clean stop: the executor reports the budget gone AFTER the first dispatch
    (the loop-top check passes for round 0, then the budget is dead)."""

    def __init__(self):
        self._checks = 0

    def budget_available(self):
        self._checks += 1
        return self._checks <= 1


def _mission_record(out_dir):
    rec = json.loads((out_dir / "mission.json").read_text(encoding="utf-8"))
    return rec.get("mission") if isinstance(rec.get("mission"), dict) else rec


def _opts():
    return type("O", (), {"max_steps": 2, "round_noise_budget": 0.0})()


def test_coordination_fault_finalizes_mission_snapshot(tmp_path):
    mission_dir = tmp_path / "fault"
    mission_dir.mkdir()
    with pytest.raises(RuntimeError, match="coordinator exploded"):
        run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                           objective="probe", executor=FaultyFrontierExecutor(),
                           clock=H.FakeClock(), opts=_opts(), say=lambda _t: None)
    rec = _mission_record(mission_dir)
    assert rec["status"] == "failed"
    assert rec["halt_reason"].startswith("executor_failure")
    # the journal (durable authority) records the terminal transition too —
    # a FAILED mission goes through MISSION_STATE_CHANGED (halt_reason rides
    # the same payload); a HALTED one emits MISSION_HALTED
    assert "MISSION_STATE_CHANGED" in H.journal_types(mission_dir)


def test_halt_finalizes_mission_snapshot_as_halted(tmp_path):
    mission_dir = tmp_path / "halt"
    mission_dir.mkdir()
    with pytest.raises(Halt):
        run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                           objective="probe", executor=HaltFrontierExecutor(),
                           clock=H.FakeClock(), opts=_opts(), say=lambda _t: None)
    rec = _mission_record(mission_dir)
    assert rec["status"] == "halted"
    assert "kill switch" in rec["halt_reason"]
    assert "MISSION_HALTED" in H.journal_types(mission_dir)


def test_budget_exhausted_stop_is_halted_not_succeeded(tmp_path):
    """A mission whose budget dies after its FIRST task succeeded must never
    read as a success: task success is not objective achievement (Builder 04 §8)."""
    mission_dir = tmp_path / "budget"
    mission_dir.mkdir()
    summary = run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                                 objective="probe", executor=SpendsBudgetExecutor(),
                                 clock=H.FakeClock(), opts=_opts(),
                                 say=lambda _t: None)
    assert summary["stop_reason"] == "budget_exhausted"
    assert summary["status"] == "halted"
    rec = _mission_record(mission_dir)
    assert rec["status"] == "halted"
    assert rec["halt_reason"] == "budget_exhausted"
    # the dispatched task DID succeed — execution progress is preserved,
    # but the mission itself is incomplete, not successful
    assert any(t["status"] == "succeeded" for t in summary["tasks"])


def test_uninterrupted_all_succeeded_still_succeeds(tmp_path):
    """The existing contract is preserved: without structured objective criteria,
    an execution-complete mission (all tasks succeeded, nothing pending
    verification) remains SUCCEEDED."""
    mission_dir = tmp_path / "clean"
    mission_dir.mkdir()
    summary = run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                                 objective="probe",
                                 executor=_GoodRunMixin(),
                                 clock=H.FakeClock(), opts=_opts(),
                                 say=lambda _t: None)
    assert summary["status"] == "succeeded"
    rec = _mission_record(mission_dir)
    assert rec["status"] == "succeeded"

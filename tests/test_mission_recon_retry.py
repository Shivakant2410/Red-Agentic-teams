"""Bounded RECON execution-failure retry (RECON-first reliability).

Pins the live-fire 20261118 defect: a failed INITIAL recon task in a dynamic
mission used to be terminal (dynamic tasks shipped max_attempts=1 and nothing
wrote the FAILED->PENDING edge the state machine already documents), the
attack frontier was never consulted, and the driver disguised an unmapped
surface as "frontier_exhausted". Now:
  - recon is requeued PENDING on execution failure (scheduler policy: recon
    only), bounded by max_attempts=2 — no infinite loop;
  - exhausted retries journal TASK_EXHAUSTED and surface as the honest
    "recon_failed" stop reason (never "frontier_exhausted");
  - a recovered recon run opens the frontier and the mission proceeds;
  - non-recon failures stay terminal (execution failure is task-plane).
"""
from __future__ import annotations

import datetime as _dt

from redteam.attack_tree import AttackTree
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import (EXEC_FAILED, EXEC_SUCCEEDED,
                                      ExecutionResult)
from redteam.states import MISSION_FAILED

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


def _driver_opts():
    return type("O", (), {"max_steps": 40, "round_noise_budget": 12.0})()


class _FlakyReconExecutor:
    """Recon fails on its first N dispatches (or always); everything else is
    honest. The frontier yields one node exactly once, only reachable after a
    successful recon."""

    def __init__(self, recon_failures: int = 0, *, always_fail_recon: bool = False):
        self.recon_failures = recon_failures
        self.always_fail = always_fail_recon
        self.calls: list[str] = []
        self.frontier_used = False

    def run(self, task_view):
        role = task_view["role"]
        self.calls.append(role)
        if role == "recon" and (self.always_fail or self.recon_failures > 0):
            if not self.always_fail:
                self.recon_failures -= 1
            return ExecutionResult(status=EXEC_FAILED, error="recon exploded",
                                   result="")
        return ExecutionResult(status=EXEC_SUCCEEDED, result=f"{role} done")

    def pending_findings(self):
        return []

    def attack_frontier(self, limit=6):
        if self.frontier_used:
            return []
        self.frontier_used = True
        return [{"title": "probe auth bypass",
                 "role": "exploit", "technique": "auth.test",
                 "target": "https://api.acme.example/", "max_steps": 8}]

    def objective_achieved(self):
        return None

    def budget_available(self):
        return True


def test_failed_initial_recon_is_requeued_and_mission_recovers(tmp_path):
    """One failed recon pass must not orphan the mission: TASK_REQUEUED is
    journaled, the second attempt runs, and the frontier opens."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    tree = AttackTree(tmp_path / "tree.json")
    tree.seed_endpoint("https://api.acme.example/")
    executor = _FlakyReconExecutor(recon_failures=1)
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=mission_dir,
        objective="map then probe", attack_tree=tree, executor=executor,
        clock=clock, opts=_driver_opts(), say=lambda t: None)

    assert executor.calls[:2] == ["recon", "recon"]
    assert "exploit" in executor.calls
    assert "TASK_REQUEUED" in H.journal_types(mission_dir)
    assert summary["stop_reason"] != "recon_failed"
    assert summary["stop_reason"] != "frontier_exhausted" or \
        "exploit" in executor.calls  # frontier WAS evaluated after recon


def test_exhausted_recon_reports_recon_failed_never_frontier_exhausted(tmp_path):
    """Two bounded attempts, then the honest failure: the surface was never
    mapped, so the stop reason says exactly that."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    executor = _FlakyReconExecutor(always_fail_recon=True)
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=mission_dir,
        objective="map then probe", attack_tree=AttackTree(tmp_path / "tree.json"),
        executor=executor, clock=clock, opts=_driver_opts(), say=lambda t: None)

    assert executor.calls == ["recon", "recon"]      # bounded: 2 attempts, no loop
    assert summary["stop_reason"] == "recon_failed"
    assert summary["status"] == MISSION_FAILED
    assert "TASK_EXHAUSTED" in H.journal_types(mission_dir)
    recon = [t for t in summary["tasks"] if t["role"] == "recon"]
    assert len(recon) == 1 and recon[0]["status"] == "failed"


def test_non_recon_failure_stays_terminal_no_requeue(tmp_path):
    """Policy is recon-only: a failed exploit task is NOT requeued (execution
    failure remains task-plane; no unbounded retry of offensive work)."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    tree = AttackTree(tmp_path / "tree.json")
    tree.seed_endpoint("https://api.acme.example/")

    class ExploitAlwaysFails(_FlakyReconExecutor):
        def run(self, task_view):
            role = task_view["role"]
            self.calls.append(role)
            if role == "exploit":
                return ExecutionResult(status=EXEC_FAILED,
                                       error="exploit exploded", result="")
            return ExecutionResult(status=EXEC_SUCCEEDED, result=f"{role} done")

    executor = ExploitAlwaysFails()
    summary = run_mission_driver(
        engagement=_engagement(), out_dir=mission_dir,
        objective="map then probe", attack_tree=tree, executor=executor,
        clock=clock, opts=_driver_opts(), say=lambda t: None)

    assert executor.calls == ["recon", "exploit"]    # exploit ran ONCE
    assert "TASK_REQUEUED" not in H.journal_types(mission_dir)
    assert summary["stop_reason"] == "frontier_exhausted"

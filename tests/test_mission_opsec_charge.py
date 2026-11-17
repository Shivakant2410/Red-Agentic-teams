"""The C3 OPSEC round-budget charge — claim-time accounting is REAL.

Regression tests for the bug the Phase F1 adaptive tests surfaced (previously
on main): `_opsec_affordable` gated readiness against a permanently-empty
ledger because dispatch never CHARGED the allowance, so a 2.0 round budget
dispatched every task. The allowance must be spent at claim time, re-checked
at the claim gate itself, and freed by the round-boundary sweep.
"""
from __future__ import annotations

import pytest
from mission_helpers import (FakeClock, make_commander, make_mission_dir,
                             make_scheduler, make_tree)

from redteam.mission.executor import EXEC_SUCCEEDED, ExecutionResult
from redteam.mission.scheduler import MissionScheduler


@pytest.fixture()
def stack(tmp_path):
    clock = FakeClock()
    mission_dir, _ = make_mission_dir(tmp_path, clock)
    commander = make_commander(mission_dir, clock,
                               roe_caps={"max_steps": 40, "round_noise_budget": 2.0})
    tree = make_tree(mission_dir, clock)
    tree.seed_endpoint("http://127.0.0.1:8896/api")   # entry techniques for the claims
    scheduler = make_scheduler(commander, tree, clock=clock,
                               round_noise_budget=2.0,
                               executor=MockSucceed())
    return clock, commander, scheduler


class MockSucceed:
    def run(self, task_view):
        return ExecutionResult(EXEC_SUCCEEDED, "ok")


def _node_task(commander, technique: str, allowance: float):
    return commander.create_task(
        title=f"{technique} check", role="exploit", actor="test",
        technique=technique, target="http://127.0.0.1:8896/api",
        max_steps=5, opsec_allowance=allowance, max_attempts=2)


def test_claim_charges_the_round_budget(stack):
    clock, commander, scheduler = stack
    commander.start_mission("test")
    expensive = _node_task(commander, "injection.cmd", 2.0)
    cheap = _node_task(commander, "auth.test", 1.0)

    first = scheduler.dispatch(expensive.task_id)
    assert first["dispatched"] is True
    # the claim SPENT the whole 2.0 round budget
    second = scheduler.dispatch(cheap.task_id)
    assert second["dispatched"] is False
    assert second["outcome"] == "opsec_budget"
    # the refused claim stays PENDING (not failed, not claimed)
    assert commander.task(cheap.task_id).status == "pending"
    assert commander.task(cheap.task_id).owner == ""


def test_sweep_reset_reopens_the_round_gate(stack):
    clock, commander, scheduler = stack
    commander.start_mission("test")
    first = _node_task(commander, "injection.cmd", 2.0)
    second = _node_task(commander, "auth.test", 1.0)
    assert scheduler.dispatch(first.task_id)["dispatched"] is True
    assert scheduler.dispatch(second.task_id)["outcome"] == "opsec_budget"
    # the round boundary (sweep) resets the spend: the refused claim becomes
    # affordable in the NEXT round and dispatches
    scheduler.sweep(now=clock())
    assert scheduler.dispatch(second.task_id)["dispatched"] is True


def test_partial_spend_allows_smaller_claims(stack):
    clock, commander, scheduler = stack
    commander.start_mission("test")
    a = _node_task(commander, "auth.test", 1.0)
    b = _node_task(commander, "xss.reflected", 1.0)
    c = _node_task(commander, "ssrf", 2.0)
    assert scheduler.dispatch(a.task_id)["dispatched"] is True
    assert scheduler.dispatch(b.task_id)["dispatched"] is True   # 1+1 <= 2
    assert scheduler.dispatch(c.task_id)["outcome"] == "opsec_budget"


def test_zero_allowance_never_gated(stack):
    clock, commander, scheduler = stack
    commander.start_mission("test")
    verify = commander.create_task(title="verify", role="verify", actor="test",
                                   max_steps=5, opsec_allowance=0.0)
    assert scheduler.dispatch(verify.task_id)["dispatched"] is True

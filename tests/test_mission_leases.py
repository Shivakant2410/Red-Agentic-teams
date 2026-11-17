"""T5 — lease ownership, FENCING TOKENS, and recovery (C5).

The reviewer's clarification 3, as tests: every worker mutation validates the
CURRENT lease token; a timeout alone never proves an external operation stopped
— the token, not the clock, disqualifies a superseded writer; a live worker is
never stolen from (sweep consults the liveness hook); expired claims re-arm per
retry policy and the tree's documented release path runs at the sweep.
"""
from __future__ import annotations

import pytest

from redteam.mission.errors import (LeaseFencingError, TaskOwnershipError)
from redteam.mission.scheduler import recover_mission
from redteam.states import TASK_PENDING, TASK_RUNNING, TASK_SUCCEEDED

import mission_helpers as H


def _running_task(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    tree.claim("auth.test", "https://t.test/", owner="exploit", lease_seconds=900)
    return mission_dir, clock, commander, tree, task


def test_fenced_completion_accepts_current_token(tmp_path):
    _, _, commander, _, task = _running_task(tmp_path)
    commander.complete_task(task.task_id, actor="exploit", lease_token=1,
                            result="done")
    assert commander.task(task.task_id).status == TASK_SUCCEEDED


def test_fencing_rejects_stale_token_even_before_deadline(tmp_path):
    """THE fence: after a reclaim bumps the generation, the OLD worker's write
    is rejected even though the wall-clock deadline may still be in its favor.
    Timeout alone never proves an operation stopped — the token is authoritative."""
    mission_dir, clock, commander, _, task = _running_task(tmp_path)
    # Recovery-style reclaim: lease considered expired by an operator-forced
    # reconcile, token bumped 1 -> 2, task re-armed.
    clock.advance(1000)
    from redteam.mission.scheduler import MissionScheduler
    scheduler = H.make_scheduler(commander, H.make_tree(mission_dir, clock),
                                 clock=clock)
    scheduler.apply_reconcile(scheduler.reconcile())
    assert commander.task(task.task_id).lease_token == 2
    # The superseded worker (still holding token 1) finally finishes its work:
    # rejected (ownership AND fencing both fire after a reclaim cleared the
    # owner) and audited — never applied.
    with pytest.raises((LeaseFencingError, TaskOwnershipError)):
        commander.complete_task(task.task_id, actor="exploit", lease_token=1)
    # The rejection is AUDITED, not silent — TASK_RESULT_REJECTED on the journal.
    types = H.journal_types(mission_dir)
    assert "TASK_RESULT_REJECTED" in types
    # And it cannot overwrite the new generation's state:
    assert commander.task(task.task_id).lease_token == 2


def test_fencing_rejects_wrong_owner(tmp_path):
    _, _, commander, _, task = _running_task(tmp_path)
    with pytest.raises(TaskOwnershipError):
        commander.complete_task(task.task_id, actor="impostor", lease_token=1)
    with pytest.raises(LeaseFencingError):
        commander.complete_task(task.task_id, actor="exploit", lease_token=99)
    with pytest.raises(LeaseFencingError):
        commander.complete_task(task.task_id, actor="exploit", lease_token=0)


def test_fencing_covers_every_worker_mutation(tmp_path):
    _, clock, commander, _, task = _running_task(tmp_path)
    for call, kwargs in (
            (commander.fail_task, {"error": "x"}),
            (commander.attach_evidence, {"kind": "observation", "ref": "r1"}),
            (commander.renew_lease, {"lease_expires_at": clock.iso()})):
        with pytest.raises((TaskOwnershipError, LeaseFencingError)):
            call(task.task_id, actor="exploit", lease_token=42, **kwargs)


def test_sweep_never_steals_from_a_live_worker(tmp_path):
    """C5.2 same-process rule: the liveness hook says the worker is alive ->
    no reclaim, no token bump — the lease is auto-extended and the in-flight
    worker's writes stay fenced-valid."""
    mission_dir, clock, commander, tree, task = _running_task(tmp_path)
    clock.advance(1000)     # deadline passed, but the worker is alive:
    commander.sweep_expired(now=clock(),
                            worker_alive=lambda task_id: True)
    live = commander.task(task.task_id)
    assert live.status == TASK_RUNNING
    assert live.lease_token == 1 and live.owner == "exploit"
    # The live worker's completion is still accepted after the auto-extension:
    commander.complete_task(task.task_id, actor="exploit", lease_token=1)
    assert commander.task(task.task_id).status == TASK_SUCCEEDED


def test_sweep_expires_dead_worker_and_rearms(tmp_path):
    mission_dir, clock, commander, tree, task = _running_task(tmp_path)
    clock.advance(1000)     # no liveness -> dead
    from redteam.mission.scheduler import MissionScheduler
    scheduler = MissionScheduler(commander, tree=tree, clock=clock)
    swept = scheduler.sweep(now=clock())
    assert swept["tasks_expired"] == [task.task_id]
    t = commander.task(task.task_id)
    assert t.status == TASK_PENDING and t.attempts == 1 and t.lease_token == 2
    # The tree claim was swept by the documented release path, journaled:
    node = tree.node("auth.test", "https://t.test/")
    assert node.status == "todo" and node.owner == ""
    assert "TREE_RELEASED" in H.journal_types(mission_dir)


def test_retry_policy_exhaustion(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="t", role="recon", actor="op",
                                 max_attempts=2)
    for round_no in range(2):
        token = commander.task(task.task_id).lease_token + 1
        commander.reserve_task(task.task_id, actor="recon", lease_token=token,
                               lease_expires_at=clock.iso())
        commander.mark_running(task.task_id, actor="recon", lease_token=token)
        clock.advance(1000)
        commander.sweep_expired(now=clock())
    exhausted = commander.task(task.task_id)
    assert exhausted.status == "failed" and exhausted.attempts == 2
    types = H.journal_types(mission_dir)
    assert types.count("TASK_LEASE_EXPIRED") == 2
    assert "TASK_REARMED" in types and "TASK_EXHAUSTED" in types


def test_recovery_with_live_lease_waits_not_steals(tmp_path):
    """Cross-process recovery into a LIVE lease: in_flight_unknown — recovery
    waits out the grace instead of stealing (the old process may still run)."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="t", role="recon", actor="op")
    from datetime import timedelta
    commander.reserve_task(task.task_id, actor="recon", lease_token=1,
                           lease_expires_at=(clock() + timedelta(seconds=900)).isoformat())
    commander.mark_running(task.task_id, actor="recon", lease_token=1)
    _, scheduler2, report = recover_mission(mission_dir, clock=clock)
    assert report["reconcile_actions"] == ["in_flight_unknown"]
    still = commander2_task = scheduler2.commander.task(task.task_id)
    assert still.status == TASK_RUNNING and still.owner == "recon"
    assert still.lease_token == 1       # ownership unchanged by the restart
    del commander2_task


def test_renewal_keeps_generation_expiry_moves(tmp_path):
    _, clock, commander, _, task = _running_task(tmp_path)
    from datetime import timedelta
    renewed = (clock() + timedelta(seconds=900)).isoformat()
    commander.renew_lease(task.task_id, actor="exploit", lease_token=1,
                          lease_expires_at=renewed)
    t = commander.task(task.task_id)
    assert t.lease_expires_at == renewed and t.lease_token == 1
    # The sweep now sees a LIVE lease — no expiry despite wall-clock age.
    commander.sweep_expired(now=clock())
    assert commander.task(task.task_id).status == TASK_RUNNING

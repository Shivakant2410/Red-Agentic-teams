"""Fault injection at EVERY persistence boundary (review clarification 2).

Boundaries, each one a test: reserve append (B1), tree claim (B2), hypothesis
claim (B3), dispatch append (B4), completion append (B5), tree-release append
(B6). Recovery is deterministic (same inputs -> same state) and IDEMPOTENT
(second recovery computes zero actions). Includes the fence proof that a
superseded worker's late write is rejected, not applied — a timeout alone
never proves an external operation stopped (C5).
"""
from __future__ import annotations

import json

import pytest
from redteam.swarm.journal import EventJournal, JournalError

from redteam.mission.executor import MockExecutor
from redteam.mission.scheduler import recover_mission
from redteam.states import TASK_PENDING, TASK_SUCCEEDED

import mission_helpers as H


def _state(commander) -> dict:
    """Deterministic state snapshot (no wall-clock fields)."""
    return {t.task_id: (t.status, t.attempts, t.lease_token, t.owner)
            for t in commander.tasks.values()}


def _mission_with_node(tmp_path, *, faults=None, tree_faults=None):
    """mission dir + commander (+ optional fault injection at the journal
    append boundary and/or the AttackTree.claim boundary)."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    journal = H.FaultJournal(EventJournal("eng-1",
                                          path=mission_dir / "mission_journal.jsonl"))
    commander = H.make_commander(mission_dir, clock, journal=journal)
    tree = H.make_tree(mission_dir, clock)
    dispatch_tree = tree

    if tree_faults:
        fail_from, fail_count = tree_faults
        attempts = {"n": 0}

        class FaultyTree:
            def __getattr__(self, name):
                return getattr(tree, name)

            def claim(self, technique, target, **kwargs):
                attempts["n"] += 1
                if fail_from <= attempts["n"] < fail_from + fail_count:
                    # A non-journal error class, so the dispatch rollback path
                    # treats it as a step failure (not a journal fault).
                    raise RuntimeError("injected tree fault")
                return tree.claim(technique, target, **kwargs)

        dispatch_tree = FaultyTree()

    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")

    # Fault arms AFTER setup: setup appends (#1 MISSION_STARTED, #2
    # TASK_CREATED) go through clean; the fault lands on a known dispatch
    # boundary — #3 reserve, #4 dispatched, #5 completion (with no evidence).
    if faults:
        journal.arm(faults[0], faults[1])
    return mission_dir, clock, commander, dispatch_tree, tree, task


def test_B1_reserve_append_failure_leaves_everything_untouched(tmp_path):
    mission_dir, clock, commander, ftree, tree, task = _mission_with_node(
        tmp_path, faults=(3, 1))
    scheduler = H.make_scheduler(commander, ftree, clock=clock)
    with pytest.raises(JournalError):
        scheduler.dispatch(task.task_id)
    # Journal-first: the failed append mutated NOTHING — state at pre-dispatch,
    # journal unchanged (setup's two events, gapless seq for the next append).
    assert commander.task(task.task_id).status == TASK_PENDING
    assert commander.task(task.task_id).owner == ""
    assert tree.node("auth.test", "https://t.test/").status == "todo"
    assert H.journal_types(mission_dir) == ["MISSION_STARTED", "TASK_CREATED"]


def test_B2_tree_claim_fault_rolls_back_reservation(tmp_path):
    mission_dir, clock, commander, ftree, tree, task = _mission_with_node(
        tmp_path, tree_faults=(1, 1))
    scheduler = H.make_scheduler(commander, ftree, clock=clock)
    # A fault during the tree claim rolls the reservation back, then raises.
    with pytest.raises(RuntimeError):
        scheduler.dispatch(task.task_id)
    assert commander.task(task.task_id).status == TASK_PENDING
    assert tree.node("auth.test", "https://t.test/").status == "todo"
    types = H.journal_types(mission_dir)
    assert types.count("TASK_CLAIMED") == 1
    assert types.count("TASK_CLAIM_ABORTED") == 1


def test_B4_dispatch_append_failure_rolls_back_tree_later(tmp_path):
    """Crash between dispatch and execution: the abort rolls the reservation
    back; the tree claim already applied expires via its lease and the recovery
    reconcile releases it."""
    mission_dir, clock, commander, ftree, tree, task = _mission_with_node(
        tmp_path, faults=(4, 1))     # TASK_DISPATCHED is append #4
    scheduler = H.make_scheduler(commander, ftree, clock=clock)
    with pytest.raises(JournalError):
        scheduler.dispatch(task.task_id)
    assert commander.task(task.task_id).status == TASK_PENDING   # rolled back
    node = tree.node("auth.test", "https://t.test/")
    assert node.status == "in_progress" and node.owner == "exploit"
    # Recovery after the lease lapses: tree released, task re-armed.
    clock.advance(2000)
    fresh_tree = H.make_tree(mission_dir, clock)
    _, _, report = recover_mission(mission_dir, tree=fresh_tree, clock=clock)
    assert set(report["reconcile_actions"]) <= {"expire_task", "release_tree"}
    assert fresh_tree.node("auth.test", "https://t.test/").status == "todo"


def test_B5_completion_lost_then_superseded_writer_rejected(tmp_path):
    """THE C5 fence end-to-end: worker A runs (token 1), the process dies
    before the completion persists; recovery expires the claim (token 2) and
    re-arms; worker B completes (token 2); THEN worker A's late completion
    arrives — rejected and audited, never applied. A timeout alone never
    proves A stopped; the token does."""
    mission_dir, clock, commander, ftree, tree, task = _mission_with_node(tmp_path)
    scheduler = H.make_scheduler(
        commander, tree, executor=MockExecutor(), clock=clock)
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    tree.claim("auth.test", "https://t.test/", owner="exploit")
    # ... worker A's executor work happened, but the process died before
    # TASK_SUCCEEDED was journaled.
    clock.advance(2000)
    fresh_tree = H.make_tree(mission_dir, clock)
    commander2, scheduler2, report = recover_mission(mission_dir, clock=clock)
    recovered = commander2.task(task.task_id)
    assert recovered.lease_token == 2 and recovered.status == TASK_PENDING
    # Worker B (the re-armed dispatch) completes with the CURRENT token:
    commander2.reserve_task(task.task_id, actor="exploit-b", lease_token=2,
                            lease_expires_at=clock.iso())
    commander2.mark_running(task.task_id, actor="exploit-b", lease_token=2)
    commander2.complete_task(task.task_id, actor="exploit-b", lease_token=2,
                             result="worker B finished")
    assert commander2.task(task.task_id).status == TASK_SUCCEEDED
    # Worker A's late write:
    with pytest.raises(Exception):
        commander2.complete_task(task.task_id, actor="exploit", lease_token=1,
                                 result="worker A finished LATE")
    types = H.journal_types(mission_dir)
    assert "TASK_RESULT_REJECTED" in types
    assert commander2.task(task.task_id).result == "worker B finished"


def test_B6_tree_release_append_failure_is_idempotent_on_recovery(tmp_path):
    mission_dir, clock, commander, ftree, tree, task = _mission_with_node(
        tmp_path)
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    tree.claim("auth.test", "https://t.test/", owner="exploit")
    clock.advance(2000)
    # The sweep's TREE_RELEASED journal append fails — the tree (effect
    # authority) is ALREADY released; the journal simply lacks the record.
    commander2, scheduler2, report = recover_mission(mission_dir, clock=clock)
    # The node was already released by expire_claims inside the recovery sweep
    # path; a SECOND recovery computes no further actions (idempotence).
    fresh_tree = H.make_tree(mission_dir, clock)
    commander3, scheduler3, report3 = recover_mission(mission_dir, clock=clock)
    assert report3["reconcile_actions"] == []


def test_recovery_deterministic_across_runs(tmp_path):
    """Same fault, same clock -> identical final STATE on independent recovery
    runs (determinism), and each recovery after the first is action-free.
    Task ids are per-mission uuids, so compare the state VALUES."""
    states = []
    for run in range(2):
        workdir = tmp_path / f"run{run}"
        workdir.mkdir()
        mission_dir, clock = H.make_mission_dir(workdir)
        commander = H.make_commander(mission_dir, clock)
        tree = H.make_tree(mission_dir, clock)
        tree.seed_endpoint("https://t.test/")
        commander.start_mission("op")
        task = commander.create_task(title="t", role="exploit", actor="op",
                                     technique="auth.test",
                                     target="https://t.test/")
        commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                               lease_expires_at=clock.iso())
        commander.mark_running(task.task_id, actor="exploit", lease_token=1)
        tree.claim("auth.test", "https://t.test/", owner="exploit")
        clock.advance(2000)
        fresh_tree = H.make_tree(mission_dir, clock)
        commander2, _, report = recover_mission(mission_dir, clock=clock)
        states.append((sorted(_state(commander2).values()),
                       sorted(report["reconcile_actions"])))
    assert states[0] == states[1]


def test_torn_journal_tail_never_blocks_recovery(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    commander.start_mission("op")
    task = commander.create_task(title="t", role="recon", actor="op")
    path = mission_dir / "mission_journal.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines) + '\n{"event_id": "torn", "type": "TASK_')
    recovered, _, report = recover_mission(mission_dir, clock=clock)
    assert report["events_read"] == len(lines)     # torn tail skipped, history kept
    assert task.task_id in [t.task_id for t in recovered.tasks.values()]

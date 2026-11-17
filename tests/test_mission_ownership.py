"""T3 — atomic task ownership across the claim trio.

The trio in reversible-reservation order (design doc C2.2): task CAS ->
AttackTree.claim -> hypothesis claim -> dispatch. Pins: single winner under
thread races, the per-step rollback table, the recovery reconcile matrix, and
reconcile determinism.
"""
from __future__ import annotations

import json
import threading

import pytest

from redteam.attack_tree import AttackTree
from redteam.mission.executor import ExecutionResult
from redteam.mission.scheduler import recover_mission
from redteam.states import TASK_BLOCKED_DUPLICATE, TASK_PENDING, TASK_SUCCEEDED
from redteam.swarm import ResearchBundle

import mission_helpers as H


def _ready_mission(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="idor probe", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")
    return mission_dir, clock, commander, tree, task


def _executor():
    from redteam.mission.executor import MockExecutor
    return MockExecutor()


def test_claim_trio_full_sequence(tmp_path):
    mission_dir, clock, commander, tree, task = _ready_mission(tmp_path)
    scheduler = H.make_scheduler(commander, tree, executor=_executor(), clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["dispatched"] is True and result["outcome"] == "succeeded"
    done = commander.task(task.task_id)
    assert done.status == TASK_SUCCEEDED
    # Ownership was triple-recorded and then released by completion:
    node = tree.node("auth.test", "https://t.test/")
    assert done.owner == ""          # released on terminal
    assert node.status == "in_progress"   # C4: the tree is NOT completed by task
                                     # success — only sync() on a CONFIRMED finding
                                     # completes a node
    types = H.journal_types(mission_dir)
    assert types[:3] == ["MISSION_STARTED", "TASK_CREATED", "TASK_CLAIMED"]
    assert "TASK_DISPATCHED" in types and "TASK_SUCCEEDED" in types


def test_tree_claim_lost_rolls_back_reservation(tmp_path):
    mission_dir, clock, commander, tree, task = _ready_mission(tmp_path)
    # Someone else wins the tree node first (the selector authority).
    assert tree.claim("auth.test", "https://t.test/", owner="other-w")
    scheduler = H.make_scheduler(commander, tree, clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "tree_claim_lost"
    rolled_back = commander.task(task.task_id)
    assert rolled_back.status == TASK_PENDING        # journaled CAS rollback
    assert rolled_back.owner == "" and rolled_back.lease_expires_at == ""
    assert rolled_back.lease_token == 1              # generation minted, stays
    types = H.journal_types(mission_dir)
    assert "TASK_CLAIMED" in types and "TASK_CLAIM_ABORTED" in types


def test_duplicate_hypothesis_blocks_and_releases_tree(tmp_path):
    mission_dir, clock, commander, tree, task = _ready_mission(tmp_path)
    bundle = ResearchBundle.for_run("eng-1")
    # Another worker owns the equivalent investigation already.
    from redteam.attack_tree import TECHNIQUES
    from redteam.swarm import weakness_for_technique
    technique = TECHNIQUES["auth.test"]
    hyp, _ = bundle.claim_or_register(
        asset_ref="https://t.test/",
        weakness_class=weakness_for_technique("auth.test"),
        claim=f"auth.test on https://t.test/: {technique.description}",
        agent="other-w", technique="auth.test")
    scheduler = H.make_scheduler(commander, tree, hypotheses=bundle, clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["outcome"] == "blocked_duplicate"
    blocked = commander.task(task.task_id)
    assert blocked.status == TASK_BLOCKED_DUPLICATE
    node = tree.node("auth.test", "https://t.test/")
    assert node.status == "todo"            # the tree claim was rolled back
    types = H.journal_types(mission_dir)
    assert "TASK_BLOCKED" in types and "TREE_RELEASED" in types


def test_research_layer_failure_degrades_never_crashes(tmp_path):
    mission_dir, clock, commander, tree, task = _ready_mission(tmp_path)

    class BrokenBundle:
        def claim_or_register(self, **kwargs):
            raise RuntimeError("forum down")

    scheduler = H.make_scheduler(commander, tree, executor=_executor(),
                                 hypotheses=BrokenBundle(), clock=clock)
    result = scheduler.dispatch(task.task_id)
    assert result["dispatched"] is True and result["outcome"] == "succeeded"


def test_dependency_gating(tmp_path):
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    commander.start_mission("op")
    first = commander.create_task(title="recon first", role="recon", actor="op")
    second = commander.create_task(title="exploit after", role="exploit",
                                   actor="op", dependencies=(first.task_id,))
    scheduler = H.make_scheduler(commander, tree, executor=_executor(),
                                 clock=clock)
    ready = [t.task_id for t in scheduler.ready_tasks()]
    assert ready == [first.task_id]         # dependency not yet satisfied
    scheduler.dispatch(first.task_id)
    ready = [t.task_id for t in scheduler.ready_tasks()]
    assert ready == [second.task_id]


def test_concurrent_dispatch_single_winner(tmp_path):
    """N threads race the same task: exactly ONE winner owns it; losers get an
    explicit refusal — the test_swarm_concurrency pattern applied to the trio."""
    mission_dir, clock, commander, tree, task = _ready_mission(tmp_path)
    scheduler = H.make_scheduler(commander, tree, executor=_executor(),
                                 clock=clock)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker():
        result = scheduler.dispatch(task.task_id)
        with lock:
            outcomes.append(result["outcome"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    won = [o for o in outcomes if o == "succeeded"]
    lost = [o for o in outcomes if o == "not_claimable"]
    assert len(won) == 1 and len(lost) == 7
    assert commander.task(task.task_id).status == TASK_SUCCEEDED
    # Exactly one CLAIMED event in the journal despite eight racers.
    types = H.journal_types(mission_dir)
    assert types.count("TASK_CLAIMED") == 1


def test_reconcile_matrix_crash_windows(tmp_path):
    """Every C2.4 crash window, computed by the PURE reconcile function:
    deterministic, no mutation until apply_reconcile."""
    from redteam.states import TASK_CLAIMED, TASK_RUNNING
    # Window: claimed, lease LIVE -> in_flight_unknown (never stolen mid-grace).
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/")
    from datetime import timedelta
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=(clock() + timedelta(seconds=900)).isoformat())
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    tree.claim("auth.test", "https://t.test/", owner="exploit")
    scheduler = H.make_scheduler(commander, tree, clock=clock)
    actions = scheduler.reconcile()
    assert [a.action for a in actions] == ["in_flight_unknown"]

    # Window: lease EXPIRED -> expire_task + the paired tree release.
    clock.advance(1000)
    actions = scheduler.reconcile()
    assert [a.action for a in actions] == ["expire_task", "release_tree"]

    # Window: task SUCCEEDED, tree node still IN_PROGRESS under the dead
    # worker's claim -> release_tree (the tree node's own lease also expired;
    # the tree is never completed by task success — C4).
    clock.advance(0)
    commander.complete_task(task.task_id, actor="exploit", lease_token=1)
    actions = scheduler.reconcile()
    assert [a.action for a in actions] == ["release_tree"]


def test_recovery_end_to_end_deterministic_and_idempotent(tmp_path):
    """Process death after reserve+dispatch, before completion: recovery replays
    the journal, expires the dead claim, re-arms per retry policy — and a SECOND
    recovery run computes ZERO actions (idempotence)."""
    mission_dir, clock = H.make_mission_dir(tmp_path)
    commander = H.make_commander(mission_dir, clock)
    tree = H.make_tree(mission_dir, clock)
    tree.seed_endpoint("https://t.test/")
    commander.start_mission("op")
    task = commander.create_task(title="t", role="exploit", actor="op",
                                 technique="auth.test", target="https://t.test/",
                                 max_attempts=2)
    commander.reserve_task(task.task_id, actor="exploit", lease_token=1,
                           lease_expires_at=clock.iso())
    commander.mark_running(task.task_id, actor="exploit", lease_token=1)
    tree.claim("auth.test", "https://t.test/", owner="exploit")

    clock.advance(2000)     # past lease + well past grace
    fresh_tree = H.make_tree(mission_dir, clock)
    commander2, scheduler2, report = recover_mission(
        mission_dir, tree=fresh_tree, clock=clock)
    assert report["events_applied"] == report["events_read"]
    assert report["skipped"] == 0
    recovered = commander2.task(task.task_id)
    assert recovered.attempts == 1 and recovered.lease_token == 2
    assert recovered.status == TASK_PENDING          # re-armed (attempts remain)
    # Tree node swept back to TODO by the recovery reconcile (its lease expired).
    node = fresh_tree.node("auth.test", "https://t.test/")
    assert node.status == "todo" and node.owner == ""

    # Idempotence: a second recovery with the same inputs computes no actions.
    actions = scheduler2.reconcile()
    assert actions == ()
    commander3, _, report3 = recover_mission(mission_dir, tree=fresh_tree,
                                             clock=clock)
    assert report3["reconcile_actions"] == []


def test_double_execution_prevented_when_tree_completed(tmp_path):
    """The effect authority prevents re-execution: the tree node COMPLETED (a
    confirmed finding landed via sync()) while the journal never saw the task
    completion — recovery must NOT re-dispatch the completed node's task."""
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
    tree.claim("auth.test", "https://t.test/", owner="exploit")
    # The effect happened: the independent pipeline confirmed, sync() completed
    # the node — but the process died before TASK_SUCCEEDED was journaled.
    tree.mark("auth.test", "https://t.test/", "completed")
    clock.advance(2000)
    fresh_tree = H.make_tree(mission_dir, clock)
    commander2, scheduler2, _ = recover_mission(mission_dir, tree=fresh_tree,
                                                clock=clock)
    recovered = commander2.task(task.task_id)
    assert recovered.status == TASK_PENDING          # re-armed per retry policy
    # ...but the node can never be re-executed: a COMPLETED tree node is not
    # TODO, so claim() refuses and dispatch aborts before any work runs.
    result = scheduler2.dispatch(recovered.task_id)
    assert result["dispatched"] is False
    assert result["outcome"] == "tree_claim_lost"
    assert fresh_tree.node("auth.test", "https://t.test/").status == "completed"

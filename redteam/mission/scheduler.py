"""The mission scheduler — dispatch, leases, recovery reconcile.

The claim trio (design doc C2.2), in reversible-reservation order:
  1. Commander.reserve_task  — journaled CAS pending->claimed (token minted)
  2. AttackTree.claim        — the work-selection authority (owner + lease)
  3. HypothesisRegistry      — duplicate suppression (optional, duck-typed)
  4. dispatch                — fenced RUNNING + executor + fenced completion
Any later step failing rolls the earlier ones back WITH journal events; the
rollback table in tests/test_mission_ownership.py pins every row.

`reconcile()` is the PURE recovery function: reads journal + tree + tasks, returns
actions without mutating (design doc C2.4). `recover_mission()` applies them —
replay is idempotent (event_id set) and reconcile is idempotent (acts only on
tasks still in CLAIMED/RUNNING), so running recovery twice is a no-op the
second time (tests pin this).

OPSEC gating (C3): a task's opsec_allowance is charged against the round budget
only at claim time and only shapes WHICH tasks dispatch (claim gating); it
never kills a running task and never halts the mission.
"""
from __future__ import annotations

import datetime as _dt
import threading
from dataclasses import dataclass
from typing import Callable

from ..attack_tree import AttackTree, TECHNIQUES
from ..states import (MISSION_RUNNING, TASK_BLOCKED_DUPLICATE, TASK_CLAIMED,
                      TASK_EXPIRED, TASK_FAILED, TASK_PENDING, TASK_RUNNING,
                      TASK_SUCCEEDED)
from ..swarm.journal import EventJournal, JournalError
from .commander import Commander
from .errors import (InvalidTaskTransitionError, LeaseFencingError,
                     TaskOwnershipError, UnknownTaskError)
from .events import EVENT_TREE_RELEASED, new_mission_event
from .executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult
from .task import TASK_LEASE_SECONDS

RECOVERY_ACTOR = "mission-recovery"


def _expired(lease_expires_at: str, now: _dt.datetime) -> bool:
    if not lease_expires_at:
        return True      # no recorded deadline = nothing protects the claim
    try:
        deadline = _dt.datetime.fromisoformat(lease_expires_at)
    except ValueError:
        return True
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=_dt.timezone.utc)
    return deadline <= now


@dataclass(frozen=True)
class ReconcileAction:
    """One recovery action computed from intent (journal) vs effect (tree)."""
    action: str            # "in_flight_unknown" | "expire_task" | "release_tree"
    task_id: str = ""
    node_id: str = ""
    detail: str = ""


class MissionScheduler:
    def __init__(self, commander: Commander, *, tree: AttackTree | None = None,
                 hypotheses=None, executor=None,
                 clock: Callable[[], _dt.datetime] | None = None,
                 round_noise_budget: float = 12.0,
                 lease_seconds: float = TASK_LEASE_SECONDS,
                 worker_alive: Callable[[str], bool] | None = None,
                 prerequisite: Callable[[dict], str] | None = None):
        self.commander = commander
        self.tree = tree
        self.hypotheses = hypotheses        # duck-typed claim_or_register carrier
        self.executor = executor
        self._clock = clock or commander._clock
        self.round_noise_budget = float(round_noise_budget)
        self.lease_seconds = max(float(lease_seconds), 1.0)
        self.worker_alive = worker_alive
        # Duck-typed readiness hook (run.py wires the orchestrator's ACCESS
        # foothold gate): task_view -> "" when the task may dispatch, else the
        # reason it must WAIT. The gate owns no state; the lifecycle effect is
        # the existing one — the task stays PENDING and is re-examined every
        # round, exactly like unsatisfied dependencies.
        self.prerequisite = prerequisite
        self._lock = threading.RLock()
        self._opsec_spent = 0.0             # credits charged this round

    # -- readiness + OPSEC gating ---------------------------------------------

    def _deps_satisfied(self, task) -> bool:
        return all(self.commander.tasks[dep].status == TASK_SUCCEEDED
                   for dep in task.dependencies)

    def _opsec_affordable(self, task) -> bool:
        return (self._opsec_spent + task.opsec_allowance) <= self.round_noise_budget

    def _prerequisite_clear(self, task) -> bool:
        if self.prerequisite is None:
            return True
        # No swallow: a gate fault surfaces at the coordination boundary like
        # any other failed mutation (the codebase rule: never paper over a
        # failing check). The orchestrator's gate is a total function over
        # getattr'd authorities, so this is a bug-loudness guarantee, not a
        # runtime path.
        return not self.prerequisite(task.view())

    def ready_tasks(self, *, now: _dt.datetime | None = None) -> list:
        """Dispatchable tasks: mission RUNNING, PENDING, dependencies SUCCEEDED,
        role registered, OPSEC allowance affordable this round, prerequisite
        clear (e.g. the ACCESS foothold gate). Ordering is deterministic
        (task_id sort) — the mission layer does not re-invent the AttackTree's
        ranking authority; it only respects task dependencies."""
        with self._lock:
            if self.commander.mission.status != MISSION_RUNNING:
                return []
            return [t for t in sorted(self.commander.tasks.values(),
                                      key=lambda t: t.task_id)
                    if t.status == TASK_PENDING
                    and self._deps_satisfied(t)
                    and self._opsec_affordable(t)
                    and self._prerequisite_clear(t)]

    # -- the claim trio ----------------------------------------------------------

    def dispatch(self, task_id: str, *, agent_id: str | None = None) -> dict:
        """Claim and execute one task through the trio. Returns a dict:
        {"dispatched": bool, "outcome": "completed"|"failed"|"blocked"|
         "reserved"|"aborted"..., "task_id", "lease_token", "hypothesis_id",
         "result"}."""
        with self._lock:
            task = self.commander.task(task_id)
            if task.status != TASK_PENDING:
                return {"dispatched": False, "outcome": "not_claimable",
                        "task_id": task_id, "lease_token": 0,
                        "hypothesis_id": "", "result": ""}
            agent = agent_id or task.role
            token = int(task.lease_token) + 1          # mint the next generation
            deadline = (self._clock() +
                        _dt.timedelta(seconds=self.lease_seconds)).isoformat()
            # -- step 1: reserve (journaled CAS) --
            self.commander.reserve_task(task_id, actor=agent, lease_token=token,
                                        lease_expires_at=deadline)
            # -- steps 2-4: any failure rolls the reservation back (journaled),
            #    then propagates. The failed step's own mutation never happened
            #    (journal-first); tree claims that DID apply expire via their
            #    lease and the recovery reconcile releases them.
            try:
                return self._dispatch_reserved(task, agent, token)
            except Exception:
                try:
                    self.commander.abort_claim(task_id, actor=agent,
                                               lease_token=token,
                                               reason="dispatch_fault")
                except Exception:
                    pass        # recovery reconcile owns the rest
                raise

    def _dispatch_reserved(self, task, agent: str, token: int) -> dict:
        task_id = task.task_id
        # -- step 2: AttackTree.claim (work-selection authority) --
        if task.node_id and self.tree is not None:
            won = self.tree.claim(task.technique, task.target, owner=agent,
                                  lease_seconds=self.lease_seconds)
            if not won:
                self.commander.abort_claim(task_id, actor=agent, lease_token=token,
                                           reason="tree_claim_lost")
                return {"dispatched": False, "outcome": "tree_claim_lost",
                        "task_id": task_id, "lease_token": token,
                        "hypothesis_id": "", "result": ""}
        # -- step 3: hypothesis claim (duplicate-suppression authority) --
        # The degrade-on-error contract covers ONLY the research claim itself
        # (orchestrator's verified behavior: research trouble must never break
        # a run). The block/rollback below runs OUTSIDE the swallow — a failing
        # rollback must propagate, never be papered over by the degrade.
        hyp_id = ""
        hyp = None
        research_error = False
        if self.hypotheses is not None and task.node_id:
            technique = TECHNIQUES.get(task.technique)
            claim_text = (f"{task.technique} on {task.target}"
                          + (f": {technique.description}" if technique else ""))
            try:
                # Use the same canonical weakness class + claim identity as
                # Orchestrator._research_claim_for_node so mission and classic
                # work converge on the run's one hypothesis record.
                from ..swarm import weakness_for_technique
                hyp, _events = self.hypotheses.claim_or_register(
                    asset_ref=task.target,
                    weakness_class=weakness_for_technique(task.technique),
                    claim=claim_text, agent=agent, technique=task.technique)
                hyp_id = hyp.hypothesis_id if hyp is not None else ""
            except Exception:
                # Research-layer failure: degrade to unresearched execution —
                # the verified orchestrator contract, never a crash.
                research_error = True
                hyp = None
                hyp_id = ""
        if (self.hypotheses is not None and task.node_id
                and hyp is None and not research_error):
            # Duplicate investigation this round: block the task and release
            # the tree node (rollback of step 2) — the round-local leak the
            # tree lease/release primitives close. (A research-layer ERROR is
            # NOT a duplicate: that path proceeds unresearched, above.)
            self.commander.block_task(task_id, actor=agent,
                                      lease_token=token,
                                      reason="duplicate_hypothesis")
            if task.node_id and self.tree is not None:
                self._release_tree_node(task, "duplicate_hypothesis")
            return {"dispatched": False, "outcome": "blocked_duplicate",
                    "task_id": task_id, "lease_token": token,
                    "hypothesis_id": "", "result": ""}
        # -- step 4: dispatch + fenced execution --
        self.commander.mark_running(task_id, actor=agent, lease_token=token)
        result = None
        if self.executor is not None:
            try:
                task_view = self.commander.task_view(task_id)
                # Ephemeral handoff only: the scheduler remains the hypothesis
                # claim authority; the executor uses this id to attach the
                # attempt's real finding evidence to that same canonical record.
                task_view["hypothesis_id"] = hyp_id
                result = self.executor.run(task_view)
            except Exception as exc:
                self.commander.fail_task(task_id, actor=agent, lease_token=token,
                                         error=f"executor error: {exc}")
                return {"dispatched": True, "outcome": "failed",
                        "task_id": task_id, "lease_token": token,
                        "hypothesis_id": hyp_id, "result": str(exc)}
            for ev in result.evidence:
                self.commander.attach_evidence(task_id, actor=agent,
                                               lease_token=token,
                                               kind=str(ev.get("kind", "artifact")),
                                               ref=str(ev.get("ref", "")),
                                               confidence=str(ev.get("confidence", "")))
            if result.status == EXEC_SUCCEEDED:
                self.commander.complete_task(task_id, actor=agent,
                                             lease_token=token, result=result.result)
            else:
                self.commander.fail_task(task_id, actor=agent, lease_token=token,
                                         error=result.error)
        return {"dispatched": True,
                "outcome": (result.status if result is not None else "reserved"),
                "task_id": task_id, "lease_token": token,
                "hypothesis_id": hyp_id,
                "result": result.result if result is not None else ""}

    # -- sweep ---------------------------------------------------------------------

    def sweep(self, *, now: _dt.datetime | None = None) -> dict:
        """Round-boundary lease sweep: expired tasks (fenced, no-steal honored)
        + expired tree claims (the documented release path, journaled here as
        TREE_RELEASED)."""
        now = now or self._clock()
        expired = self.commander.sweep_expired(now=now,
                                               worker_alive=self.worker_alive)
        released = []
        if self.tree is not None:
            for node_id in self.tree.expire_claims(now=now):
                released.append(node_id)
                self._journal_tree_release(node_id, actor="lease-sweep",
                                           reason="lease_expired", now=now)
        # OPSEC credits spent this round reset at the boundary (per-round
        # budget, C3): reservations died with their tasks' sweeps.
        self._opsec_spent = 0.0
        return {"tasks_expired": expired, "tree_released": released}

    def _release_tree_node(self, task, reason: str,
                           now: _dt.datetime | None = None) -> bool:
        """Release a node claim on behalf of its recorded owner (the task
        record, else the node's own owner field — the supervisor's claim
        CLEANUP only; outcome writes stay fenced). Audited with the recovery
        actor and the released owner for the operator trail."""
        if self.tree is None or not task.node_id:
            return False
        node = self.tree.node(task.technique, task.target)
        actor = task.owner or (node.owner if node is not None else "") \
            or RECOVERY_ACTOR
        released = self.tree.release(task.technique, task.target, actor,
                                     reason=reason)
        if released:
            event = new_mission_event(
                EVENT_TREE_RELEASED,
                engagement_id=self.commander._journal.engagement_id,
                mission_id=self.commander.mission.mission_id,
                actor=RECOVERY_ACTOR,
                payload={"node_id": task.node_id, "reason": reason,
                         "released_owner": actor},
                clock=self._clock)
            self.commander._journal.append(event)
        return released

    def _journal_tree_release(self, node_id: str, *, actor: str, reason: str,
                              now: _dt.datetime | None = None) -> None:
        event = new_mission_event(
            EVENT_TREE_RELEASED, engagement_id=self.commander._journal.engagement_id,
            mission_id=self.commander.mission.mission_id, actor=actor,
            payload={"node_id": node_id, "reason": reason},
            clock=self._clock)
        self.commander._journal.append(event)

    # -- recovery: reconcile (PURE) + apply ----------------------------------------

    def reconcile(self, *, now: _dt.datetime | None = None) -> tuple[ReconcileAction, ...]:
        """Pure: what SHOULD happen to make intent (journal/task state) and
        effect (tree) consistent, given `now`. No mutation. Deterministic
        (task_id order); idempotent (actions only target still-active claims
        and un-released owned nodes)."""
        now = now or self._clock()
        actions: list[ReconcileAction] = []
        for task in sorted(self.commander.tasks.values(), key=lambda t: t.task_id):
            if task.status in (TASK_CLAIMED, TASK_RUNNING):
                deadline = None
                if task.lease_expires_at:
                    try:
                        deadline = _dt.datetime.fromisoformat(task.lease_expires_at)
                        if deadline.tzinfo is None:
                            deadline = deadline.replace(tzinfo=_dt.timezone.utc)
                    except ValueError:
                        deadline = None
                if deadline is not None and deadline > now:
                    actions.append(ReconcileAction(
                        "in_flight_unknown", task.task_id,
                        detail="lease live; waiting out the grace before reclaim"))
                else:
                    actions.append(ReconcileAction(
                        "expire_task", task.task_id, task.node_id,
                        detail="lease expired (or never recorded)"))
                    # The dead worker's tree claim must not outlive its task:
                    # pair the expiry with the documented tree release.
                    if task.node_id and self.tree is not None:
                        node = self.tree.node(task.technique, task.target)
                        if node is not None and node.status == "in_progress" \
                                and node.owner:
                            actions.append(ReconcileAction(
                                "release_tree", task.task_id, task.node_id,
                                detail="expired worker's tree claim"))
            if task.status in (TASK_SUCCEEDED, TASK_FAILED) and task.node_id \
                    and self.tree is not None:
                node = self.tree.node(task.technique, task.target)
                if node is not None and node.status == "in_progress" and node.owner:
                    # C4: task success does NOT complete the tree — the node
                    # completes via sync() on a CONFIRMED finding. Recovery
                    # only releases the dead worker's CLAIM (supervisor acting
                    # for the recorded owner; audited TREE_RELEASED), so
                    # verification can still confirm independently.
                    actions.append(ReconcileAction(
                        "release_tree", task.task_id, task.node_id,
                        detail=f"owner task {task.status}; awaiting verification"
                        if task.status == TASK_SUCCEEDED
                        else "failed worker must not block a re-trial"))
            if task.status in (TASK_PENDING, TASK_BLOCKED_DUPLICATE, TASK_EXPIRED) \
                    and task.node_id and self.tree is not None:
                # Orphaned claim: the task rolled back (crash between the abort
                # and the tree release) but the tree node is still held — and
                # its lease has lapsed. Release it so the round can proceed.
                node = self.tree.node(task.technique, task.target)
                if node is not None and node.status == "in_progress" and node.owner \
                        and _expired(node.lease_expires_at, now):
                    actions.append(ReconcileAction(
                        "release_tree", task.task_id, task.node_id,
                        detail="orphaned tree claim after rollback"))
        return tuple(actions)

    def apply_reconcile(self, actions) -> list[str]:
        """Execute reconcile actions through the SAME mutation paths the live
        sweep uses (one code path). Returns applied action names."""
        applied = []
        for action in actions:
            if action.action == "expire_task":
                self.commander.expire_task(action.task_id, now=self._clock())
                applied.append("expire_task")
            elif action.action == "release_tree":
                task = self.commander.task(action.task_id)
                # The recovery supervisor releases the claim ON BEHALF of its
                # recorded owner (task record, else the node's owner field);
                # audited as mission-recovery. STATE writes stay fenced — only
                # claim cleanup runs here.
                if self._release_tree_node(task, "recovery_reconcile"):
                    applied.append("release_tree")
            # "in_flight_unknown" is deliberately a no-op: a live lease is
            # honored across restart (C5.3) — the old process may still run.
        return applied


# -- full recovery entry point ---------------------------------------------------

def recover_mission(mission_dir, *, tree: AttackTree | None = None,
                    executor=None, hypotheses=None, clock=None,
                    worker_alive=None, now: _dt.datetime | None = None,
                    round_noise_budget: float = 12.0):
    """Rebuild a mission from its files after a process death:
      1. mission.json           -> Mission record
      2. mission_journal.jsonl  -> replay into a fresh Commander (idempotent,
                                   malformed/unknown events skipped + counted)
      3. reconcile              -> computed actions, applied through the live
                                   sweep's mutation paths
    Returns (commander, scheduler, report) where report counts replay skips.
    A SECOND call with the same inputs produces zero actions (idempotence)."""
    from .mission import Mission
    from pathlib import Path

    mission_dir = Path(mission_dir)
    mission = Mission.load(mission_dir / "mission.json")
    journal = EventJournal(mission.engagement,
                           path=mission_dir / "mission_journal.jsonl")
    commander = Commander(mission, journal, clock=clock)
    report = {"events_read": 0, "events_applied": 0, "skipped": 0,
              "issues": []}
    for event in journal.read_all():
        report["events_read"] += 1
        try:
            commander.apply_event(event)
            report["events_applied"] += 1
        except (ValueError, TypeError, KeyError) as exc:
            report["skipped"] += 1
            report["issues"].append({"seq": event.get("seq", 0),
                                     "event_id": event.get("event_id", ""),
                                     "detail": str(exc)})
    scheduler = MissionScheduler(commander, tree=tree, executor=executor,
                                 hypotheses=hypotheses, clock=clock,
                                 round_noise_budget=round_noise_budget,
                                 worker_alive=worker_alive)
    actions = scheduler.reconcile(now=now)
    scheduler.apply_reconcile(actions)
    report["reconcile_actions"] = [a.action for a in actions]
    return commander, scheduler, report

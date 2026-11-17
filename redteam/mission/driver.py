"""The mission driver — the wired execution path for `RunOptions.driver ==
"mission"` (the third branch of the same fork the classic single-agent and
multi-agent drivers hang off, run.py).

It runs the FULL coordination core for real: mission.json + mission_journal.jsonl
artifacts, agent registration (derived roster), task creation with budget
inheritance, the claim trio against the run's real AttackTree, lease sweeps,
dependency rounds, recovery reconcile.

Phase 3: the EXECUTOR is real on the production path — run.py constructs the
run's Orchestrator over the shared context and passes a
MissionSpecialistExecutor, so every dispatch invokes the existing
RedTeamAgent specialists. MockExecutor remains ONLY the explicit test /
simulation / fault-injection seam: passing no executor prints a loud warning
and the mock's own task results still say "mock execution" — mock execution is
never silent.

Task plan source: `mission_plan.json` in the run directory
  {"tasks": [{"title", "role", "technique", "target", "dependencies": [..],
              "max_steps", "opsec_allowance", "max_attempts"}, ...]}
Node tasks are seeded into the tree as entry techniques before dispatch (the
tree remains the work-selection authority — the driver never dispatches a node
the tree does not hold). Without a plan file, one smoke task runs so the
coordination path is observable end to end.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..states import MISSION_FAILED, MISSION_SUCCEEDED, TASK_SUCCEEDED
from ..swarm.journal import EventJournal
from .commander import Commander
from .events import EVENT_MISSION_CREATED, new_mission_event
from .executor import MockExecutor
from .mission import Mission
from .registry import AgentRegistry
from .scheduler import MissionScheduler
from .task import TASK_LEASE_SECONDS

MAX_ROUNDS = 50          # dependency-depth safety cap (a cycle cannot proceed)
DRIVER_ACTOR = "mission-driver"


def _injectable_clock(clock=None):
    return clock or (lambda: datetime.now(timezone.utc))


def build_mission(out_dir: Path, *, engagement_name: str, engagement_ticket: str,
                  objective: str, clock=None) -> tuple[Mission, EventJournal]:
    """Create + persist the mission record. C1: mission_id == the run directory
    name (minted by the SAME contract that mints run_ids), stored as a
    separate field; run_ids is the 1:N-capable list."""
    out_dir = Path(out_dir)
    mission_id = out_dir.name
    mission = Mission(mission_id=mission_id, run_ids=[mission_id],
                      engagement=engagement_name, ticket=engagement_ticket,
                      objective=objective, driver="mission")
    mission.save(out_dir / "mission.json")
    journal = EventJournal(engagement_name, path=out_dir / "mission_journal.jsonl")
    journal.append(new_mission_event(
        EVENT_MISSION_CREATED, engagement_id=engagement_name,
        mission_id=mission_id, actor=DRIVER_ACTOR,
        payload={"mission": mission.to_dict()}, clock=clock))
    return mission, journal


def load_plan(out_dir: Path) -> list[dict]:
    path = Path(out_dir) / "mission_plan.json"
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    tasks = raw.get("tasks") or []
    if not isinstance(tasks, list):
        raise ValueError("mission_plan.json 'tasks' must be a list")
    return tasks


def mission_outcome(tasks, *, objective_achieved=None,
                   pending_verification: int = 0,
                   stop_reason: str = "") -> tuple[str, str]:
    """Return mission lifecycle status without conflating execution and impact.

    A structured objective is successful only when Objective.achieved is true.
    Without structured criteria, a mission is execution-complete only when all
    tasks succeeded AND no finding remains pending independent verification.
    """
    tasks = list(tasks)
    if objective_achieved is True:
        return MISSION_SUCCEEDED, ""
    if objective_achieved is False:
        return MISSION_FAILED, stop_reason or "objective_not_achieved"
    if pending_verification:
        return MISSION_FAILED, "unresolved_verification"
    if tasks and all(t.status == TASK_SUCCEEDED for t in tasks):
        return MISSION_SUCCEEDED, ""
    return (MISSION_FAILED,
            stop_reason or "not every task reached a successful terminal state")


def run_mission_driver(*, engagement, out_dir, objective: str,
                       attack_tree=None, bus=None, opts=None,
                       executor=None, hypotheses=None, clock=None,
                       access_gate=None,
                       say=lambda text: None) -> dict:
    """Execute the mission coordination loop.

    `executor`: the production path passes a MissionSpecialistExecutor built
    on the run's Orchestrator (run.py); tests inject scripted executors (and
    fault-injected journals/trees) against this exact entry point. None here
    means the explicit test/simulation seam — MockExecutor runs, LOUDLY (see
    the module docstring).

    `hypotheses`: optional duplicate-suppression authority (duck-typed
    claim_or_register carrier — the orchestrator's ResearchBundle). Claim
    step 3 of the trio stays with the scheduler; the executor never claims.

    `access_gate`: optional readiness hook (duck-typed task_view -> "" |
    reason) consulted in ready_tasks; run.py wires the orchestrator's ACCESS
    foothold gate, so a prerequisite-less ACCESS task stays PENDING — the
    existing not-ready semantics — instead of being claimed and dispatched.
    """
    clock = _injectable_clock(clock)
    out_dir = Path(out_dir)
    mission, journal = build_mission(
        out_dir, engagement_name=engagement.name,
        engagement_ticket=str(getattr(engagement, "ticket", "") or ""),
        objective=objective, clock=clock)

    roe_caps = {"max_steps": int(getattr(opts, "max_steps", 40) or 40),
                "round_noise_budget": float(getattr(opts, "round_noise_budget",
                                                    12.0) or 0.0) or 12.0}
    agents = AgentRegistry(journal=journal, clock=clock,
                           mission_id=mission.mission_id)
    commander = Commander(mission, journal, agents=agents, bus=bus, clock=clock,
                          roe_caps=roe_caps,
                          record_path=out_dir / "mission.json")
    if executor is None:
        # The test/simulation seam must never be silent: the warning goes to
        # stderr UNCONDITIONALLY (the default `say` here is a no-op) plus the
        # caller's channel, and the mock's own task results say "mock
        # execution".
        import sys
        warning = ("WARNING: no executor provided to run_mission_driver — "
                   "running MOCK execution (the explicit test/simulation seam). "
                   "Production mission runs must pass a MissionSpecialistExecutor "
                   "over the run's Orchestrator.")
        sys.stderr.write(warning + "\n")
        say(warning)
        executor = MockExecutor()
    scheduler = MissionScheduler(
        commander, tree=attack_tree, executor=executor, hypotheses=hypotheses,
        clock=clock,
        round_noise_budget=roe_caps["round_noise_budget"],
        lease_seconds=TASK_LEASE_SECONDS,
        prerequisite=access_gate)

    commander.start_mission(DRIVER_ACTOR)

    plan = load_plan(out_dir)
    dynamic = not bool(plan)
    created: list[str] = []
    seen_nodes: set[str] = set()
    verified_pending_ids: set[str] = set()
    unresolved_verification = False
    stop_reason = ""

    def create_task(spec: dict):
        technique = str(spec.get("technique", "") or "")
        target = str(spec.get("target", "") or "")
        task = commander.create_task(
            title=str(spec.get("title", "")) or f"{technique} on {target}",
            role=str(spec.get("role", "")), actor=DRIVER_ACTOR,
            technique=technique, target=target,
            dependencies=tuple(spec.get("dependencies") or ()),
            max_steps=int(spec.get("max_steps", 20)),
            opsec_allowance=float(spec.get("opsec_allowance", 0.0)),
            max_attempts=int(spec.get("max_attempts", 1 if dynamic else 2)))
        created.append(task.task_id)
        return task

    if dynamic:
        # Deterministic recon has already run in execute_run(); this bounded
        # specialist pass enriches the live surface before we ask the canonical
        # AttackTree for offensive work.
        recon_steps = min(int(getattr(opts, "max_steps", 22) or 22), 22)
        create_task({"title": "Map the discovered attack surface",
                     "role": "recon", "max_steps": recon_steps})
    else:
        # Explicit mission_plan.json remains a replay/operator override.
        for spec in plan:
            technique = str(spec.get("technique", "") or "")
            target = str(spec.get("target", "") or "")
            if technique and target and attack_tree is not None:
                attack_tree.seed_endpoint(target)
            create_task(spec)

    rounds = 0
    while rounds < MAX_ROUNDS:
        if dynamic:
            objective_state = (executor.objective_achieved()
                               if hasattr(executor, "objective_achieved") else None)
            if objective_state is True:
                stop_reason = "objective_achieved"
                break
            if hasattr(executor, "budget_available") and not executor.budget_available():
                stop_reason = "budget_exhausted"
                break

            pending = (executor.pending_findings()
                       if hasattr(executor, "pending_findings") else [])
            pending_ids = {str(getattr(f, "id", "")) for f in pending}
            unverified_ids = pending_ids - verified_pending_ids
            active_verify = any(
                t.role == "verify" and t.status in
                ("pending", "claimed", "running")
                for t in commander.tasks.values())
            if unverified_ids and not active_verify:
                verify_steps = min(int(getattr(opts, "max_steps", 15) or 15), 15)
                create_task({"title": "Independently verify pending findings",
                             "role": "verify", "max_steps": verify_steps})

            # Only ask the canonical selector for more exploit work after the
            # recon task has completed and any newly-created VERIFY task has run.
            has_recon = any(t.role == "recon" for t in commander.tasks.values())
            recon_done = has_recon and all(
                t.status == TASK_SUCCEEDED for t in commander.tasks.values()
                if t.role == "recon")
            has_unverified = bool(unverified_ids) or active_verify
            if recon_done and not has_unverified:
                frontier = (executor.attack_frontier(limit=6)
                            if hasattr(executor, "attack_frontier") else [])
                new_specs = []
                for spec in frontier:
                    node_id = f"{spec.get('technique', '')}@{spec.get('target', '')}"
                    if not spec.get("technique") or not spec.get("target") or node_id in seen_nodes:
                        continue
                    seen_nodes.add(node_id)
                    cap = int(getattr(opts, "max_steps", 40) or 40)
                    spec = dict(spec)
                    spec["max_steps"] = min(int(spec.get("max_steps", cap)), cap)
                    new_specs.append(spec)
                    break  # incremental dispatch: one ranked node at a time
                if new_specs:
                    create_task(new_specs[0])
                elif not any(t.status in ("pending", "claimed", "running")
                             for t in commander.tasks.values()):
                    stop_reason = ("unresolved_verification" if pending
                                   else "frontier_exhausted")
                    break

        ready = scheduler.ready_tasks()
        if not ready:
            scheduler.sweep(now=clock())
            ready = scheduler.ready_tasks()
            if not ready:
                active = [t for t in commander.tasks.values()
                          if t.status in ("claimed", "running", "pending",
                                          "expired", "blocked_duplicate")]
                if not active:
                    break
                # No progress possible (e.g. a permanently blocked duplicate):
                # stop rather than spin or re-dispatch the same node in this round.
                if rounds > 0:
                    stop_reason = "frontier_exhausted" if dynamic else ""
                    break
        for task in ready:
            result = scheduler.dispatch(task.task_id)
            rounds += 1
            if dynamic:
                if task.node_id:
                    # A task is attempted at most once per mission execution.
                    # A fresh mission may retry it; this run must move on.
                    seen_nodes.add(task.node_id)
                if task.role == "verify":
                    if hasattr(executor, "reconcile_after_verification"):
                        executor.reconcile_after_verification()
                    pending_after = (executor.pending_findings()
                                     if hasattr(executor, "pending_findings") else [])
                    verified_pending_ids.update(
                        str(getattr(f, "id", "")) for f in pending)
                    if pending_after:
                        unresolved_verification = True
                    # Release any completed task's still-held tree claim through
                    # the scheduler's existing recovery reconciliation path.
                    actions = scheduler.reconcile(now=clock())
                    scheduler.apply_reconcile(actions)
                    break
                if task.role == "exploit":
                    pending_now = (executor.pending_findings()
                                   if hasattr(executor, "pending_findings") else [])
                    if pending_now:
                        # Verification is a separate task and always precedes
                        # the next frontier selection.
                        break
                    actions = scheduler.reconcile(now=clock())
                    scheduler.apply_reconcile(actions)
                if result.get("outcome") not in ("completed", "succeeded", "reserved"):
                    # Keep progressing through other ranked nodes; the failed
                    # node is not repeated within this mission execution.
                    actions = scheduler.reconcile(now=clock())
                    scheduler.apply_reconcile(actions)
            else:
                # Explicit operator plans preserve their dependency-round behavior.
                continue
        if not dynamic:
            rounds += 1
        elif not ready:
            break

    if dynamic and not stop_reason:
        objective_state = (executor.objective_achieved()
                           if hasattr(executor, "objective_achieved") else None)
        pending = (executor.pending_findings()
                   if hasattr(executor, "pending_findings") else [])
        if objective_state is True:
            stop_reason = "objective_achieved"
        elif pending or unresolved_verification:
            stop_reason = "unresolved_verification"
        elif rounds >= MAX_ROUNDS:
            stop_reason = "round_limit"
        else:
            stop_reason = "frontier_exhausted"

    objective_state = (executor.objective_achieved()
                       if hasattr(executor, "objective_achieved") else None)
    pending = (executor.pending_findings()
               if hasattr(executor, "pending_findings") else [])
    if pending and not stop_reason:
        stop_reason = "unresolved_verification"
    failed_tasks = [t for t in commander.tasks.values()
                    if t.status not in (TASK_SUCCEEDED, "pending")]
    if failed_tasks and not stop_reason:
        stop_reason = "execution_failure"
    status, reason = mission_outcome(
        commander.tasks.values(),
        objective_achieved=objective_state,
        pending_verification=len(pending),
        stop_reason=stop_reason)
    commander.set_mission_status(status, DRIVER_ACTOR, reason=reason)
    summary = {"mission_id": mission.mission_id, "run_id": mission.primary_run_id,
               "rounds": rounds, "tasks": commander.tasks_view(),
               "status": commander.mission.status,
               "executor": type(executor).__name__,
               "dynamic": dynamic,
               "stop_reason": stop_reason,
               "objective_achieved": objective_state,
               "execution_complete": all(t.status == TASK_SUCCEEDED
                                         for t in commander.tasks.values()),
               "pending_verification": len(pending)}
    say(f"mission {mission.mission_id}: {commander.mission.status} "
        f"({rounds} dispatches, {len(created)} tasks; {stop_reason or 'plan complete'})")
    return summary

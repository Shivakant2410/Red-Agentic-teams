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


def mission_outcome(tasks) -> tuple[str, str]:
    """(mission_status, reason) from the tasks' terminal states — the honest
    endgame calc. Success requires EVERY task to have reached the intended
    successful terminal outcome (TASK_SUCCEEDED): failed / cancelled / expired
    / exhausted ends — and tasks that never became dispatchable — make the
    mission FAILED. "Everything reached A terminal state" is not "everything
    succeeded": with real specialists on the production path, an all-failed
    mission must never read MISSION_SUCCEEDED.
    (TASK_CANCELLED exists in the states machine as reserved vocabulary; no
    producer writes it yet — the calc is safe against it regardless.)"""
    tasks = list(tasks)
    if tasks and all(t.status == TASK_SUCCEEDED for t in tasks):
        return MISSION_SUCCEEDED, ""
    return (MISSION_FAILED,
            "not every task reached a successful terminal state")


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
    if not plan:
        plan = [{"title": "coordination self-check", "role": "recon"}]
    created: list[str] = []
    for spec in plan:
        technique = str(spec.get("technique", "") or "")
        target = str(spec.get("target", "") or "")
        if technique and target and attack_tree is not None:
            attack_tree.seed_endpoint(target)   # tree stays the work selector
        task = commander.create_task(
            title=str(spec.get("title", "")) or f"{technique} on {target}",
            role=str(spec.get("role", "")), actor=DRIVER_ACTOR,
            technique=technique, target=target,
            dependencies=tuple(spec.get("dependencies") or ()),
            max_steps=int(spec.get("max_steps", 20)),
            opsec_allowance=float(spec.get("opsec_allowance", 0.0)),
            max_attempts=int(spec.get("max_attempts", 2)))
        created.append(task.task_id)

    # -- dispatch rounds: dependencies resolve across rounds; each round ends
    #    with a lease sweep (the round boundary, C5.1) --
    rounds = 0
    while rounds < MAX_ROUNDS:
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
                # No progress possible (e.g. permanently blocked duplicates):
                # one sweep + re-check, then stop trying.
                if rounds > 0 and not ready:
                    break
        for task in ready:
            scheduler.dispatch(task.task_id)
        rounds += 1

    # A mission succeeded only when EVERY task reached the intended successful
    # terminal outcome (TASK_SUCCEEDED) — see mission_outcome() above.
    status, reason = mission_outcome(commander.tasks.values())
    commander.set_mission_status(status, DRIVER_ACTOR, reason=reason)
    summary = {"mission_id": mission.mission_id, "run_id": mission.primary_run_id,
               "rounds": rounds, "tasks": commander.tasks_view(),
               "status": commander.mission.status,
               "executor": type(executor).__name__}
    say(f"mission {mission.mission_id}: {commander.mission.status} "
        f"({rounds} rounds, {len(created)} tasks)")
    return summary

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

Phase F1 (Issue #15) — ADAPTIVE mode (`adaptive=True`, wired by run.py via
RunOptions.mission_adaptive): the loop no longer depends on a manually
prepared plan. Each round it (1) refreshes canonical intelligence from ACTUAL
outcomes (tree.sync: confirmed findings complete nodes and unlock chained
follow-ups, falsified findings fail them, newly observed endpoints seed entry
techniques), (2) synthesizes work from the read-time attack-path projection
ranking (mission/adaptive.py over planner.offensive_opportunities — never a
second execution authority), and (3) stops on an HONEST reason: the objective
is achieved, viable paths are exhausted, the operator stopped the run, or the
round cap is hit. Static mission plans remain supported unchanged (seed
tasks + the exact pre-F1 loop semantics) when adaptive=False — the test /
replay / explicit-override mechanism.
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
                       graph=None, findings=None, access=None,
                       objective_model=None, stop_check=None,
                       adaptive: bool = False,
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

    Adaptive mode (Phase F1) reads the run's shared authorities for planning:
    `graph` (KnowledgeGraph), `findings` (FindingStore), `access`
    (AccessGraph), `objective_model` (the engagement Objective — named apart
    from the objective STRING) and `stop_check` (a callable -> "" | reason,
    wired by run.py to the budget tracker / STOP kill file). All are optional;
    adaptive synthesis degrades gracefully to the static loop when an input is
    absent. The driver holds NO authority of its own — it only composes.
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
    #    with a lease sweep (the round boundary, C5.1). Adaptive mode adds the
    #    observe -> re-plan step at the TOP of each round (Issue #15 WS3):
    #    canonical intelligence is refreshed from ACTUAL outcomes (tree.sync —
    #    confirmed findings complete nodes and unlock chained follow-ups,
    #    falsified findings fail them, newly observed endpoints seed entry
    #    techniques), then work is synthesized from the ranked projection. --
    rounds = 0
    stop_reason = ""
    synthesis_reports: list[dict] = []
    while rounds < MAX_ROUNDS:
        if adaptive:
            from .adaptive import assess_viability, mission_briefing, synthesize_round
            if attack_tree is not None:
                attack_tree.sync(
                    graph=graph,
                    findings=list(findings.all()) if findings is not None else None)
            synthesis_reports.append(synthesize_round(
                commander=commander, journal=journal, tree=attack_tree,
                graph=graph, findings=findings, access=access,
                objective=objective_model, hypotheses=hypotheses,
                clock=clock, round_no=rounds + 1,
                max_steps=min(20, int(roe_caps["max_steps"])),
                round_noise_budget=float(roe_caps["round_noise_budget"]),
                engagement_id=engagement.name,
                mission_id=mission.mission_id))
            say(mission_briefing(objective=objective_model, tree=attack_tree,
                                 findings=findings, access=access, graph=graph))
        ready = scheduler.ready_tasks()
        if not ready:
            scheduler.sweep(now=clock())
            ready = scheduler.ready_tasks()
            if not ready:
                if adaptive:
                    # The honest stop decision BEFORE giving up (Issue #15):
                    # operator stop > round cap > objective achieved >
                    # grounded exhaustion. A continue here means live
                    # intelligence says work exists that is not yet
                    # dispatchable (e.g. the ACCESS gate waits on a foothold,
                    # an OPSEC-heavy node waits for the round reset).
                    stop, reason = assess_viability(
                        commander=commander, tree=attack_tree,
                        findings=findings, objective=objective_model,
                        round_no=rounds, max_rounds=MAX_ROUNDS,
                        stop_check=stop_check,
                        last_report=synthesis_reports[-1] if synthesis_reports else None,
                        scheduler=scheduler)
                    if stop:
                        stop_reason = reason
                        break
                    if rounds > 0:
                        # One grace round already passed (round 0 -> 1):
                        # dispatch is synchronous, the sweep just ran, and
                        # nothing became dispatchable — another idle round
                        # cannot change that. Stop and report the endgame.
                        stop_reason = stop_reason or \
                            "no dispatchable work remained (blocked or unsatisfiable)"
                        break
                else:
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
        if adaptive:
            # Round-boundary claim hygiene: the recovery reconcile's supervisor
            # cleanup runs LIVE too — a task that reached a terminal state this
            # round releases its tree claim (audited TREE_RELEASED) so the
            # frontier stops showing a claim the mission will never act on.
            # Node STATE still moves only through verification (C4); the
            # one-task-per-node dedup means a released claim is never
            # re-dispatched without new intelligence.
            actions = scheduler.reconcile(now=clock())
            scheduler.apply_reconcile(actions)
        rounds += 1

    # A mission succeeded only when EVERY task reached the intended successful
    # terminal outcome (TASK_SUCCEEDED) — see mission_outcome() above. In
    # adaptive mode the OBJECTIVE is the mission's success contract (Issue #15:
    # "continues until the objective is achieved"), so an achieved objective
    # outranks the task-level calc — with both facts kept visible in the
    # recorded reason when they disagree.
    status, reason = mission_outcome(commander.tasks.values())
    if adaptive:
        from .events import EVENT_MISSION_STOPPED, new_mission_event
        journal.append(new_mission_event(
            EVENT_MISSION_STOPPED, engagement_id=engagement.name,
            mission_id=mission.mission_id, actor=DRIVER_ACTOR,
            payload={"stop_reason": stop_reason, "rounds": rounds,
                     "task_outcome": status,
                     "synthesis_rounds": len(synthesis_reports),
                     "tasks_created": len(commander.tasks)}, clock=clock))
        if stop_reason == "objective achieved" and objective_model is not None:
            done, total = objective_model.progress()
            reason = (f"objective achieved ({done}/{total} criteria)"
                      + ("; task-level: " + reason if status != MISSION_SUCCEEDED else ""))
            status = MISSION_SUCCEEDED
        elif stop_reason and status != MISSION_SUCCEEDED:
            reason = f"{stop_reason}; {reason}"
    commander.set_mission_status(status, DRIVER_ACTOR, reason=reason)
    summary = {"mission_id": mission.mission_id, "run_id": mission.primary_run_id,
               "rounds": rounds, "tasks": commander.tasks_view(),
               "status": commander.mission.status,
               "executor": type(executor).__name__,
               "stop_reason": stop_reason,
               "adaptive": adaptive}
    say(f"mission {mission.mission_id}: {commander.mission.status} "
        f"({rounds} rounds, {len(created)} tasks)"
        + (f" — stopped: {stop_reason}" if stop_reason else ""))
    return summary

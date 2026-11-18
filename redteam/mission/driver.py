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

Task plan source: `mission_plan.json` in the run directory remains an explicit
operator/replay override. Without it, the default path runs a bounded RECON
specialist, incrementally selects TODO work from the canonical ranked
AttackTree, automatically dispatches independent VERIFY for pending findings,
reconciles the existing graph/hypothesis/tree/credit authorities, then
re-evaluates KillChain-gated ACCESS and workflow-gated LOGIC opportunities.
Node tasks are never selected or claimed by a second planner.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..states import (MISSION_FAILED, MISSION_HALTED, MISSION_SUCCEEDED,
                      TASK_SUCCEEDED)
from ..runtime import Halt
from ..swarm.journal import EventJournal
from .commander import Commander
from .events import (EVENT_MISSION_CREATED, EVENT_TASK_REARMED,
                     new_mission_event)
from .executor import MockExecutor
from .mission import Mission
from .registry import AgentRegistry
from .scheduler import MissionScheduler
from .task import TASK_LEASE_SECONDS

MAX_ROUNDS = 50          # bounded mission dispatch safety cap
DRIVER_ACTOR = "mission-driver"


def _injectable_clock(clock=None):
    return clock or (lambda: datetime.now(timezone.utc))


def _safe_executor_call(executor, method: str, default):
    """Call an optional executor introspection method, treating a raising
    executor as "unknown" instead of crashing mission finalization."""
    try:
        if hasattr(executor, method):
            return getattr(executor, method)()
    except Exception:
        pass
    return default


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
                   stop_reason: str = "",
                   interrupted: str = "") -> tuple[str, str]:
    """Return mission lifecycle status without conflating execution and impact.

    A structured objective is successful only when Objective.achieved is true.
    Without structured criteria, a mission is execution-complete only when all
    tasks succeeded AND no finding remains pending independent verification.

    `interrupted` marks an INCOMPLETE mission: "halted" (budget/round-limit/kill
    switch — the operator-recognizable stop) or "fault" (coordination crash).
    An interrupted mission never reads SUCCEEDED merely because its dispatched
    tasks succeeded: task success is not objective achievement. A structured
    objective that was genuinely achieved still wins (the contract was met
    before the interruption)."""
    tasks = list(tasks)
    if objective_achieved is True:
        return MISSION_SUCCEEDED, ""
    if objective_achieved is False:
        return MISSION_FAILED, stop_reason or "objective_not_achieved"
    if pending_verification:
        return MISSION_FAILED, stop_reason or "unresolved_verification"
    if interrupted == "fault":
        return MISSION_FAILED, stop_reason or "executor_failure"
    if interrupted == "halted":
        return MISSION_HALTED, stop_reason or "interrupted"
    if tasks and all(t.status == TASK_SUCCEEDED for t in tasks):
        return MISSION_SUCCEEDED, ""
    return (MISSION_FAILED,
            stop_reason or "not every task reached a successful terminal state")


def run_mission_driver(*, engagement, out_dir, objective: str,
                       attack_tree=None, bus=None, opts=None,
                       executor=None, hypotheses=None, clock=None,
                       access_gate=None,
                       say=lambda text: None) -> dict:
    """Execute a mission, using an explicit plan only when the operator supplied one.

    No-plan runs use the live AttackTree frontier and existing specialist/verifier
    adapters; plan-file runs preserve the explicit dependency-round override.

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
    seen_access_states: set[tuple] = set()
    logic_task_created = False
    verified_pending_ids: set[str] = set()
    unresolved_verification = False
    no_models_streak = 0
    failed_nodes: dict[str, tuple] = {}   # node_id -> (evidence fingerprint, failed task id)
    rearm_counts: dict[str, int] = {}     # bounded: ONE evidence-driven re-arm per node
    stop_reason = ""

    def evidence_fingerprint() -> tuple:
        """Cheap observable evidence signal: access holds, pending findings and
        the frontier's distinct targets. A CHANGE means the previously failed
        approach may now be materially different (new endpoints discovered, new
        access demonstrated) — which is the only honest reason to retry it."""
        try:
            access = str(executor.access_state() or "")[:200]
        except Exception:
            access = ""
        try:
            pending = len(executor.pending_findings() or [])
        except Exception:
            pending = -1
        try:
            targets = tuple(sorted({str(s.get("target", "")) for s in
                                    (executor.attack_frontier(limit=999) or [])}))[:24]
        except Exception:
            targets = ()
        return (access, pending, targets)

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
    reflection_round = 0
    interrupted_exc: BaseException | None = None
    interrupted = ""           # "" | "halted" (budget/kill switch) | "fault" (crash)
    try:
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
                    access_task_created = False
                    access_state = (executor.access_state()
                                    if hasattr(executor, "access_state") else {})
                    if access_state:
                        signature = (
                            tuple(access_state.get("recommendations", ())),
                            tuple(access_state.get("achieved", ())),
                            tuple(access_state.get("holdings", ())))
                        if signature not in seen_access_states:
                            seen_access_states.add(signature)
                            cap = int(getattr(opts, "max_steps", 20) or 20)
                            create_task({
                                "title": "Press confirmed foothold toward: "
                                         + ", ".join(access_state["recommendations"]),
                                "role": "access", "max_steps": min(cap, 20)})
                            access_task_created = True

                    if not access_task_created:
                        # Evidence-driven re-arm pass (before selection): a failed
                        # node whose evidence fingerprint changed gets ONE more
                        # attempt; the journaled TASK_REARMED keeps it observable.
                        if failed_nodes:
                            fp = evidence_fingerprint()
                            for stale in [n for n, f in failed_nodes.items()
                                          if f[0] != fp and rearm_counts.get(n, 0) < 1]:
                                _fp, orig_task_id = failed_nodes.pop(stale)
                                rearm_counts[stale] = rearm_counts.get(stale, 0) + 1
                                seen_nodes.discard(stale)
                                journal.append(new_mission_event(
                                    EVENT_TASK_REARMED, engagement_id=engagement.name,
                                    mission_id=mission.mission_id, actor=DRIVER_ACTOR,
                                    task_id=orig_task_id,
                                    payload={"node_id": stale,
                                             "reason": "new evidence since failure"}))
                        frontier = (executor.attack_frontier(limit=999)
                                    if hasattr(executor, "attack_frontier") else [])
                        new_specs = []
                        for spec in frontier:
                            node_id = f"{spec.get('technique', '')}@{spec.get('target', '')}"
                            if (not spec.get("technique") or not spec.get("target")
                                    or node_id in seen_nodes):
                                continue
                            seen_nodes.add(node_id)
                            cap = int(getattr(opts, "max_steps", 40) or 40)
                            spec = dict(spec)
                            spec["max_steps"] = min(int(spec.get("max_steps", cap)), cap)
                            new_specs.append(spec)
                            break  # incremental dispatch: one ranked node at a time
                        if new_specs:
                            create_task(new_specs[0])
                        elif (not logic_task_created
                              and hasattr(executor, "logic_required")
                              and executor.logic_required()):
                            cap = int(getattr(opts, "max_steps", 25) or 25)
                            create_task({"title": "Test workflow and business-logic invariants",
                                         "role": "logic", "max_steps": min(cap, 25)})
                            logic_task_created = True
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
                    blocked_access = [t for t in commander.tasks.values()
                                      if t.role == "access" and t.status == "pending"]
                    if blocked_access and access_gate is not None:
                        gate_reason = access_gate(blocked_access[0].view())
                        if gate_reason:
                            stop_reason = "access_prerequisite_unmet"
                            break
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
                if dynamic:
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
                        if hasattr(executor, "reflect_after_round"):
                            executor.reflect_after_round(objective, reflection_round)
                            reflection_round += 1
                        break
                    if task.role in ("exploit", "access", "logic"):
                        pending_now = (executor.pending_findings()
                                       if hasattr(executor, "pending_findings") else [])
                        if pending_now:
                            # Verification is a separate task and always precedes
                            # the next frontier selection or reflection boundary.
                            break
                        if task.role == "exploit":
                            actions = scheduler.reconcile(now=clock())
                            scheduler.apply_reconcile(actions)
                        if hasattr(executor, "reflect_after_round"):
                            executor.reflect_after_round(objective, reflection_round)
                            reflection_round += 1
                    if result.get("outcome") not in ("completed", "succeeded", "reserved"):
                        # Keep progressing through other ranked nodes; the failed
                        # node is not repeated within this mission execution.
                        actions = scheduler.reconcile(now=clock())
                        scheduler.apply_reconcile(actions)
                        # Reliability (live-fire 20261118 campaign matrix): a
                        # specialist that dies on `agent.no_models` means the
                        # configured provider is unavailable — grinding the rest
                        # of the frontier through it only burns the engagement
                        # window and the provider quota. Halt honestly after two
                        # consecutive provider-dead failures instead of
                        # advancing a static task list through an outage.
                        if "no_models" in str(getattr(task, "error", "") or ""):
                            no_models_streak += 1
                            if no_models_streak >= 2:
                                raise Halt("provider_unavailable")
                        else:
                            no_models_streak = 0
                        if task.node_id:
                            # Replanning (Builder 04): remember WHY the node failed.
                            # If observable evidence changes later (new endpoints in
                            # the frontier, new access holds, new findings), the node
                            # becomes re-armable ONCE — a materially different next
                            # attempt, not a blind static-list advance.
                            failed_nodes[task.node_id] = (evidence_fingerprint(),
                                                          task.task_id)
                else:
                    # Explicit operator plans preserve their dependency-round behavior,
                    # but still use the same post-VERIFY reconciliation authority.
                    if (task.role == "verify"
                            and result.get("outcome") in ("completed", "succeeded", "reserved")
                            and hasattr(executor, "reconcile_after_verification")):
                        executor.reconcile_after_verification()
                        if hasattr(executor, "reflect_after_round"):
                            executor.reflect_after_round(objective, reflection_round)
                            reflection_round += 1
                    continue
            if not dynamic:
                rounds += 1
            elif not ready:
                break
    except Halt as exc:
        # Budget/kill-switch stop mid-round: the mission must still finalize.
        # run.py translates the re-raise into a halted RUN manifest.
        interrupted_exc = exc
        interrupted = "halted"
        stop_reason = str(getattr(exc, "reason", "") or exc) or "halted"
        say(f"mission interrupted: {stop_reason}")
    except Exception as exc:  # noqa: BLE001 — the snapshot must never dangle "running"
        # A specialist/tool/coordination crash must not skip mission finalization
        # (live-fire 20261118: an interrupted dispatch left mission.json "running"
        # forever). Finalize honestly below, then let the caller see the failure.
        interrupted_exc = exc
        interrupted = "fault"
        stop_reason = f"executor_failure: {type(exc).__name__}"
        say(f"mission interrupted by executor failure: {exc}")

    if dynamic and not stop_reason:
        objective_state = _safe_executor_call(executor, "objective_achieved", None)
        pending = _safe_executor_call(executor, "pending_findings", [])
        if objective_state is True:
            stop_reason = "objective_achieved"
        elif pending or unresolved_verification:
            stop_reason = "unresolved_verification"
        elif rounds >= MAX_ROUNDS:
            stop_reason = "round_limit"
            interrupted = "halted"
        else:
            stop_reason = "frontier_exhausted"
    # An executor that reports the budget gone (or a coordination round cap hit)
    # is an INCOMPLETE mission — never a quiet success (Builder 04 §8: task
    # execution success must not be conflated with objective achievement).
    if stop_reason in ("budget_exhausted", "round_limit") and not interrupted:
        interrupted = "halted"

    objective_state = _safe_executor_call(executor, "objective_achieved", None)
    pending = _safe_executor_call(executor, "pending_findings", [])
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
        stop_reason=stop_reason,
        interrupted=interrupted)
    if reason and not stop_reason:
        stop_reason = reason
    try:
        commander.set_mission_status(status, DRIVER_ACTOR, reason=stop_reason)
    except Exception:
        # The journal holds the durable authority; a snapshot write failing here
        # must never mask the original executor failure (or skip the return).
        pass
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
    if interrupted_exc is not None:
        raise interrupted_exc
    return summary

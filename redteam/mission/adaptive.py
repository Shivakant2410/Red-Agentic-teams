"""The adaptive mission loop's planning brain — plan → execute → observe →
re-plan (Issue #15). This module is COMPOSITION ONLY: it owns no authority and
no store. Every decision it makes reads the existing authorities and every
work item it creates is a canonical AttackTree node the scheduler claims
through the existing claim trio:

  read   — planner.offensive_opportunities(): the read-time attack-path
           projection (graph_view.join_attack_paths over the LIVE
           KnowledgeGraph / AttackTree / FindingStore / AccessGraph /
           Objective) ranks the tree's actionable() frontier;
  create — one mission task per not-yet-tasked frontier node (dedup by
           node_id across ALL task states: a node is tried by at most one
           task per mission unless its state changes through verification);
           plus the round's recon task (map the surface first) and the
           independent-verification task (the ONLY confirmation route);
  judge  — assess_viability(): the honest stop reasons — objective achieved,
           viable paths exhausted, round cap, operator stop;
  record — one MISSION_SYNTHESIS journal event per round (the planning
           decision trail) and MISSION_STOPPED on exit (WS5).

MissionScheduler owns task reservation and claims; the AttackTree remains the
work-selection authority; FindingStore + independent verification remain the
only route to confirmed findings. Nothing here bypasses any of them.
"""
from __future__ import annotations

from .events import EVENT_MISSION_SYNTHESIS, new_mission_event
from ..states import (TASK_BLOCKED_DUPLICATE, TASK_CLAIMED, TASK_EXPIRED,
                      TASK_PENDING, TASK_RUNNING)

SYNTHESIS_ACTOR = "mission-synthesis"

# Active (non-terminal) task states — a task in one of these owns its work.
_ACTIVE_TASK_STATES = (TASK_PENDING, TASK_CLAIMED, TASK_RUNNING,
                       TASK_BLOCKED_DUPLICATE, TASK_EXPIRED)


def _existing_node_tasks(commander) -> dict[str, list]:
    """node_id -> tasks ever created for it. A node is synthesized at most once
    per mission: its single task runs to a terminal state through the
    scheduler's retry policy (max_attempts), and the NODE state moves only
    through verification (C4) — so one task per node is the honest contract,
    and it is also what makes synthesis idempotent across recovery (the replay
    rebuilds the same task set; re-synthesis dedups against it)."""
    out: dict[str, list] = {}
    for t in commander.tasks.values():
        if t.node_id:
            out.setdefault(t.node_id, []).append(t)
    return out


def _active_role_task(commander, role: str) -> bool:
    """True when a non-terminal task of this role exists (the round's verify /
    recon task is already in flight — never create a second)."""
    return any(t.role == role and t.status in _ACTIVE_TASK_STATES
               for t in commander.tasks.values())


def synthesize_round(*, commander, journal, tree, graph=None, findings=None,
                     access=None, objective=None, hypotheses=None,
                     clock=None, round_no: int = 1,
                     max_steps: int = 20, engagement_id: str = "engagement",
                     mission_id: str = "mission",
                     round_noise_budget: float = 12.0) -> dict:
    """One adaptive planning round: rank the frontier from live intelligence,
    create tasks for not-yet-tasked nodes, keep recon/verify coverage. Returns
    the round report (also journaled as MISSION_SYNTHESIS).

    Task budgets: the OPSEC allowance is the technique's own price
    (attack_tree.TECHNIQUE_COST — the same cost surface the bandit and the
    scheduler's claim gating use); the step carve is the passed max_steps.
    A technique priced ABOVE the engagement's round noise budget is SKIPPED
    with a journaled reason — reserving more than the RoE allows would violate
    C3 (the Commander raises), and silently under-reserving would fake
    affordability; an unaffordable technique is honestly out of this
    engagement's budget."""
    from ..planner import map_surface_needed, offensive_opportunities

    findings_all = list(findings.all()) if findings is not None else []
    # the synthesizer ranks the WHOLE actionable frontier (32 = a sane per-round
    # synthesis ceiling) and dedups against existing tasks itself — a small
    # briefing limit would let already-tasked nodes crowd NEW surface out of
    # the ranking by tie-order, and a discovery would change nothing
    opportunities, excluded = offensive_opportunities(
        graph=graph, tree=tree, findings=findings_all, access=access,
        objective=objective, hypotheses=hypotheses, limit=32)
    existing = _existing_node_tasks(commander)
    pre_existing = set(existing.keys())

    created: list[dict] = []
    skipped: list[dict] = []
    for opp in opportunities:
        if opp["node_id"] in existing:
            skipped.append({"node_id": opp["node_id"],
                            "reason": "already tasked this mission"})
            continue
        if float(opp["opsec_cost"]) > float(round_noise_budget):
            skipped.append({"node_id": opp["node_id"],
                            "reason": f"opsec price {opp['opsec_cost']} exceeds "
                                      f"the round noise budget {round_noise_budget}"})
            continue
        task = commander.create_task(
            title=f"{opp['technique']} on {opp['target']} (synthesized)",
            role="exploit", actor=SYNTHESIS_ACTOR,
            technique=opp["technique"], target=opp["target"],
            max_steps=max_steps,
            opsec_allowance=float(opp["opsec_cost"]),
            max_attempts=2)
        existing[opp["node_id"]] = [task]
        created.append({"task_id": task.task_id, "node_id": opp["node_id"],
                        "role": "exploit",
                        "technique": opp["technique"], "target": opp["target"],
                        "score": opp["score"], "reasons": opp["reasons"],
                        "unlock_children": opp["unlock_children"]})

    # recon first: with nothing mapped there is nothing to attack — one recon
    # task per round until the surface exists (the RECON specialist populates
    # the shared KnowledgeGraph; the next round's projection sees it).
    recon_created = ""
    if map_surface_needed(graph) and not _active_role_task(commander, "recon"):
        task = commander.create_task(
            title="map the attack surface (recon)", role="recon",
            actor=SYNTHESIS_ACTOR, max_steps=max_steps,
            opsec_allowance=0.0, max_attempts=2)
        recon_created = task.task_id
        created.append({"task_id": task.task_id, "node_id": "", "role": "recon",
                        "technique": "", "target": "", "score": 0.0,
                        "reasons": ["no endpoints mapped — recon precedes offense"],
                        "unlock_children": []})

    # independent verification: pending findings need the verifier before they
    # can complete tree nodes or credit the objective (the ONLY confirmation
    # authority — one active verify task at a time).
    verify_created = ""
    pending_count = len(findings.pending()) if findings is not None else 0
    if pending_count and not _active_role_task(commander, "verify"):
        task = commander.create_task(
            title=f"independent verification pass ({pending_count} pending)",
            role="verify", actor=SYNTHESIS_ACTOR, max_steps=max_steps,
            opsec_allowance=0.0, max_attempts=2)
        verify_created = task.task_id
        created.append({"task_id": task.task_id, "node_id": "", "role": "verify",
                        "technique": "", "target": "", "score": 0.0,
                        "reasons": [f"{pending_count} finding(s) pending "
                                    "independent verification"],
                        "unlock_children": []})

    # opportunities that could still become tasks in a LATER round (their node
    # has no task yet and none was created for them this round)
    open_opportunities = sum(
        1 for o in opportunities
        if o["node_id"] not in pre_existing and o["node_id"] not in existing)

    report = {
        "round": round_no,
        "created": created,
        "skipped": skipped,
        "excluded_remediated": excluded,
        "open_opportunities": open_opportunities,
        "recon_task": recon_created,
        "verify_task": verify_created,
        "pending_findings": pending_count,
    }
    journal.append(new_mission_event(
        EVENT_MISSION_SYNTHESIS, engagement_id=engagement_id,
        mission_id=mission_id, actor=SYNTHESIS_ACTOR,
        payload={"round": report}, clock=clock))
    return report


def assess_viability(*, commander, tree, findings=None, objective=None,
                     round_no: int, max_rounds: int = 50,
                     stop_check=None, last_report: dict | None = None,
                     scheduler=None) -> tuple[bool, str]:
    """The honest stop decision ("" = keep going). Order matters: an operator
    stop wins, then the round cap, then achievement, then exhaustion.

    Exhaustion is grounded in what could STILL become work, not in the raw
    frontier: no operator stop, nothing pending verification, no task in
    flight, nothing dispatchable, AND no remaining opportunity (every
    actionable frontier node already has its one task this mission). A node
    whose single task already ran is exhausted even while the tree still shows
    it TODO — the node state moves only through verification (C4), and
    re-running the same proof without new evidence is exactly the repetition
    Issue #15 forbids."""
    reason = ""
    if stop_check is not None:
        try:
            reason = str(stop_check() or "")
        except Exception:
            reason = ""
    if reason:
        return True, f"operator stop: {reason}"
    if round_no >= max_rounds:
        return True, "round cap reached"
    if objective is not None and getattr(objective, "achieved", False):
        return True, "objective achieved"
    pending = len(findings.pending()) if findings is not None else 0
    remaining = int((last_report or {}).get("open_opportunities") or 0)
    in_flight = any(t.status in (TASK_CLAIMED, TASK_RUNNING)
                    for t in commander.tasks.values())
    dispatchable = bool(scheduler.ready_tasks()) if scheduler is not None else False
    if remaining <= 0 and pending == 0 and not in_flight and not dispatchable:
        return True, "viable paths exhausted"
    return False, ""


def mission_briefing(*, objective=None, tree=None, findings=None, access=None,
                     graph=None) -> str:
    """Compact, factual digest of the engagement state for the round log —
    the same authorities the planner ranks over, rendered for the operator."""
    lines = ["[MISSION BRIEFING]"]
    if objective is not None:
        done, total = objective.progress()
        lines.append(f"OBJECTIVE: {done}/{total} criteria"
                     + (" — ACHIEVED" if objective.achieved else ""))
    if findings is not None:
        conf: dict[str, int] = {}
        for f in findings.all():
            conf[f.confidence] = conf.get(f.confidence, 0) + 1
        lines.append("FINDINGS: " + (", ".join(f"{k}={v}" for k, v in sorted(conf.items()))
                                     or "none"))
    if tree is not None:
        lines.append(tree.briefing(limit=3))
    if access is not None:
        held = access.held()
        if held:
            lines.append("HOLDINGS: " + ", ".join(f"{n.kind}:{n.key}" for n in held[:5]))
    if graph is not None:
        s = graph.summary()
        c = s.get("counts", {})
        lines.append(f"SURFACE: hosts={c.get('host', 0)} services={c.get('service', 0)} "
                     f"endpoints={c.get('endpoint', 0)} | coverage {s.get('coverage_pct', 0)}%")
    return "\n".join(lines)

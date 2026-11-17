"""The Phase 3 executor: real specialist delegation through the EXISTING
orchestrator path. This replaces MockExecutor on the normal production mission
run (the mock stays behind for unit tests, explicit simulation, and
deterministic fault injection — see driver.py).

Architecture (one execution path, no second framework):

    MissionScheduler          claim trio: reserve -> tree.claim -> hypothesis -> RUNNING
      |                       (the scheduler owns ALL claims — never re-made here)
      v
    MissionSpecialistExecutor.run(task_view)              [this file]
      v
    Orchestrator.execute_task(task_view)                  [task-level interface]
      v
    Orchestrator._make_specialist(profile)                [existing construction]
      v
    RedTeamAgent.run(instruction)                         [existing agent loop]
      v
    existing tools / graph / findings / evidence pipeline  [shared run context]

The executor owns NO authorities: no registry, no store, no tree, no verifier,
no budget of its own. It maps ONE task_view to ONE specialist invocation and
reports the EXECUTION outcome (C4 vocabulary: succeeded means the work ran —
it is never a confirmed finding and never an attack-tree completion). Evidence
refs are real finding ids the invocation produced through the existing
pipeline, never fabricated and never confidence="confirmed" (the
ExecutionResult contract rejects that by construction; the independent
verification pipeline remains the only confirmation authority).
"""
from __future__ import annotations

from .executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult

# Soft failures RedTeamAgent.run returns as TEXT instead of raising (its own
# degrade-on-error contract). They are audited events as well; the executor
# reads the audit diff rather than pattern-matching arbitrary agent prose.
_SOFT_FAILURE_AUDIT_EVENTS = ("agent.no_models", "agent.halt", "agent.budget_exhausted")

# The task result record lives in mission.json — cap the agent's prose so one
# chatty specialist cannot bloat the mission record (the full text stays in
# the audit/journal trail).
_RESULT_TEXT_CAP = 4000


class MissionSpecialistExecutor:
    """Adapter: one mission task_view -> one real RedTeamAgent invocation.

    Wraps the run's EXISTING Orchestrator (constructed by run.py over the
    shared engagement/ctx/graph/tree/findings/budget). It constructs nothing
    of its own: routing, instruction building, specialist construction and
    execution all happen through Orchestrator.execute_task, which reuses
    _make_specialist and run_verify_pass.
    """

    def __init__(self, orchestrator, *, objective: str = "", on_text=None):
        self._orchestrator = orchestrator
        self._objective = objective
        self._on_text = on_text

    # -- mission autonomy adapters (read/reconcile existing authorities) ---------

    def pending_findings(self) -> list:
        return self._orchestrator.ctx.findings.pending()

    def attack_frontier(self, limit: int = 6) -> list[dict]:
        return self._orchestrator.mission_attack_frontier(limit=limit)

    def reconcile_after_verification(self) -> dict:
        return self._orchestrator.mission_reconcile_after_verification()

    def objective_achieved(self) -> bool | None:
        return self._orchestrator.mission_objective_achieved()

    def access_state(self) -> dict:
        return self._orchestrator.mission_access_state()

    def logic_required(self) -> bool:
        return self._orchestrator.mission_logic_required()

    def reflect_after_round(self, objective: str, round_no: int) -> None:
        self._orchestrator.mission_reflect_after_round(objective, round_no)

    def budget_available(self) -> bool:
        budget = getattr(self._orchestrator, "_budget", None)
        if budget is None:
            return True
        try:
            budget.check()
            return True
        except Exception:
            return False

    # -- the executor contract ---------------------------------------------------

    def run(self, task_view: dict) -> ExecutionResult:
        task_id = str(task_view.get("task_id", ""))
        ctx = self._orchestrator.ctx
        findings_before = {f.id for f in ctx.findings.all()}
        audit_before = len(ctx.audit.read_all())
        try:
            final_text = self._orchestrator.execute_task(
                task_view, on_text=self._on_text, objective=self._objective)
        except Exception as exc:
            evidence = self._new_evidence_refs(ctx, findings_before)
            self._record_hypothesis_outcome(task_view, evidence)
            # Preserve the useful error information; the scheduler fences the
            # task failure + journal event — the executor only reports.
            return ExecutionResult(
                status=EXEC_FAILED,
                result="",
                error=f"{type(exc).__name__}: {exc}",
                evidence=evidence)
        evidence = self._new_evidence_refs(ctx, findings_before)
        # Soft failures: the agent loop degrades instead of raising when the
        # model layer is unavailable or the engagement budget halts the turn.
        # Those land in the audit (agent.no_models / agent.halt /
        # agent.budget_exhausted) — an honest EXEC_FAILED, not a green task.
        new_audit = ctx.audit.read_all()[audit_before:]
        soft = next((e for e in new_audit
                     if e.get("event") in _SOFT_FAILURE_AUDIT_EVENTS), None)
        self._record_hypothesis_outcome(task_view, evidence)
        if soft is not None:
            detail = (soft.get("error") or soft.get("reason")
                      or soft.get("halt_reason") or "")
            return ExecutionResult(
                status=EXEC_FAILED,
                result=str(final_text or "")[:_RESULT_TEXT_CAP],
                error=f"{soft.get('event')}: {detail}".strip(": "),
                evidence=evidence)
        return ExecutionResult(
            status=EXEC_SUCCEEDED,
            result=str(final_text or "")[:_RESULT_TEXT_CAP],
            evidence=evidence)

    def _record_hypothesis_outcome(self, task_view: dict, evidence) -> None:
        try:
            self._orchestrator.record_mission_task_outcome(task_view, evidence)
        except Exception as exc:
            self._orchestrator.ctx.audit.record(
                "research.error", stage="mission_executor_outcome", error=str(exc))

    # -- evidence: real refs only ---------------------------------------------------

    def _new_evidence_refs(self, ctx, findings_before: set) -> tuple[dict, ...]:
        """Finding ids this invocation created, through the existing
        FindingStore — never fabricated, never confidence='confirmed' (only the
        independent verification pipeline confirms; C4)."""
        refs = []
        for f in ctx.findings.all():
            if f.id in findings_before or f.confidence == "confirmed":
                continue
            refs.append({"kind": "finding", "ref": f.id,
                         "confidence": f.confidence})
        return tuple(refs)

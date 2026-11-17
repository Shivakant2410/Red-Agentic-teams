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
            # Preserve the useful error information; the scheduler fences the
            # task failure + journal event — the executor only reports.
            return ExecutionResult(
                status=EXEC_FAILED,
                result="",
                error=f"{type(exc).__name__}: {exc}")
        # Soft failures: the agent loop degrades instead of raising when the
        # model layer is unavailable or the engagement budget halts the turn.
        # Those land in the audit (agent.no_models / agent.halt /
        # agent.budget_exhausted) — an honest EXEC_FAILED, not a green task.
        new_audit = ctx.audit.read_all()[audit_before:]
        soft = next((e for e in new_audit
                     if e.get("event") in _SOFT_FAILURE_AUDIT_EVENTS), None)
        if soft is not None:
            detail = (soft.get("error") or soft.get("reason")
                      or soft.get("halt_reason") or "")
            return ExecutionResult(
                status=EXEC_FAILED,
                result=str(final_text or "")[:_RESULT_TEXT_CAP],
                error=f"{soft.get('event')}: {detail}".strip(": "))
        return ExecutionResult(
            status=EXEC_SUCCEEDED,
            result=str(final_text or "")[:_RESULT_TEXT_CAP],
            evidence=self._new_evidence_refs(ctx, findings_before))

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

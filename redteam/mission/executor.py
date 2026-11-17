"""The Phase 2 executor: a scripted, deterministic stand-in for real specialist
delegation (which lands in Phase 4 through the existing orchestrator path).

ExecutionResult.status is an EXECUTION outcome — "succeeded" means the scripted
work ran, nothing more (C4: it is never a confirmed finding and never an
attack-tree completion). The C-4 guard is structural: MockExecutor refuses to
emit evidence with confidence="confirmed", because only the independent
verification pipeline (FindingStore.promote / verify.py) may confirm.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ValidationError

EXEC_SUCCEEDED = "succeeded"
EXEC_FAILED = "failed"
EXEC_STATUSES = (EXEC_SUCCEEDED, EXEC_FAILED)


@dataclass
class ExecutionResult:
    status: str                              # EXEC_SUCCEEDED | EXEC_FAILED
    result: str = ""
    error: str = ""
    evidence: tuple[dict, ...] = ()          # {"kind": str, "ref": str} references

    def __post_init__(self) -> None:
        if self.status not in EXEC_STATUSES:
            raise ValidationError(
                f"execution status must be one of {EXEC_STATUSES}, got {self.status!r}")
        for ev in self.evidence:
            if ev.get("confidence") == "confirmed":
                raise ValidationError(
                    "an executor may never emit confidence='confirmed' — only the "
                    "independent verification pipeline confirms (C4)")


class MockExecutor:
    """Scripted outcomes keyed by task_id (or node_id), deterministic defaults.
    `step_cost` lets tests exercise budget interaction without real work."""

    def __init__(self, script: dict[str, ExecutionResult | dict] | None = None):
        self.script: dict[str, ExecutionResult] = {}
        for key, value in (script or {}).items():
            self.script[key] = (value if isinstance(value, ExecutionResult)
                                else ExecutionResult(**value))

    def run(self, task_view: dict) -> ExecutionResult:
        entry = self.script.get(task_view["task_id"])
        if entry is None:
            entry = self.script.get(task_view.get("node_id") or "")
        if entry is None:
            entry = ExecutionResult(status=EXEC_SUCCEEDED,
                                    result="mock execution completed")
        return entry

    # -- fault injection seam (tests/test_mission_recovery.py) ---------------

    def fail_for(self, task_id: str, error: str) -> None:
        """Script a failure for one task (execution-plane exhaustion, C3)."""
        self.script[task_id] = ExecutionResult(status=EXEC_FAILED, error=error)

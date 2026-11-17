"""Mission layer error taxonomy (docs/builder01-phase2-mission-design.md).

Deliberately separate from swarm.hypotheses' SwarmError family: the mission
layer is a coordination layer ABOVE the authorities (FindingStore, AttackTree,
ScopeGuard, EventBus, verification), and its failure modes are coordination
failures — ownership, fencing, budgets, lifecycle — not research-layer ones.
SwarmError raised by an injected HypothesisRegistry propagates unchanged.
"""

from __future__ import annotations


class MissionError(Exception):
    """Base class for mission-layer failures."""


class UnknownTaskError(MissionError):
    """A task id the Commander has never seen."""


class InvalidTaskTransitionError(MissionError):
    """A mission/mission_task transition the states.py tables do not allow."""


class TaskOwnershipError(MissionError):
    """A mutation by an agent that does not own the task (lease owner mismatch)."""


class LeaseFencingError(MissionError):
    """A mutation carrying a stale lease token — the writer was superseded.

    This is the C5 fence: the token is bumped on every reclaim/expiry sweep, so
    a late write from a worker the recovery layer already re-armed lands here
    and is audited (TASK_RESULT_REJECTED) instead of overwriting the new
    owner's state. A timeout alone never proves an external operation stopped —
    the token, not the clock, is what disqualifies the writer."""


class TaskBudgetError(MissionError):
    """A task whose budget carve exceeds what the engagement allows (C3 rule 4:
    per-task budgets inherit DOWN from the RoE, never widen it)."""


class ValidationError(MissionError):
    """Malformed mission-layer input (missing title, unknown role, bad evidence)."""


class MissionStateError(MissionError):
    """An operation the mission's current lifecycle state does not allow."""

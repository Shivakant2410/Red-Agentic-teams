"""redteam.mission — the Phase 2 mission coordination core.

Layering contract (docs/builder01-phase2-mission-design.md): this package
COORDINATES the authoritative components (FindingStore, AttackTree, ScopeGuard,
egress enforcement, EventBus, independent verification) and never replaces
them. The Commander holds no reference to any authority by construction — task
success is an execution outcome, nothing more (C4).

Public surface (Phase 2): Mission, MissionTask, Commander, MissionScheduler,
AgentRegistry, MockExecutor, recover_mission, ReconcileAction + the error
taxonomy. The journal is the shared EventJournal (swarm/journal.py) with
per-type required fields — no second journal implementation.
"""
from __future__ import annotations

from .commander import Commander
from .errors import (InvalidTaskTransitionError, LeaseFencingError,
                     MissionError, MissionStateError, TaskBudgetError,
                     TaskOwnershipError, UnknownTaskError, ValidationError)
from .events import new_mission_event
from .executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult, MockExecutor
from .mission import Mission
from .registry import AgentRegistry, MissionAgent, default_roster
from .scheduler import MissionScheduler, ReconcileAction, recover_mission
from .task import MISSION_TASK_SCHEMA_VERSION, TASK_LEASE_SECONDS, MissionTask, new_task_id

__all__ = [
    "Commander", "Mission", "MissionTask", "MissionScheduler",
    "AgentRegistry", "MissionAgent", "default_roster",
    "MockExecutor", "ExecutionResult", "EXEC_SUCCEEDED", "EXEC_FAILED",
    "recover_mission", "ReconcileAction", "new_mission_event", "new_task_id",
    "TASK_LEASE_SECONDS", "MISSION_TASK_SCHEMA_VERSION",
    "MissionError", "InvalidTaskTransitionError", "TaskOwnershipError",
    "LeaseFencingError", "TaskBudgetError", "ValidationError",
    "UnknownTaskError", "MissionStateError",
]

"""The mission task — one claimable unit of mission work.

C1 identity: every task carries the immutable triple (task_id, mission_id,
run_id). mission_id and run_id are SEPARATE fields, consumed as given — no
downstream component may assume equality (Phase 2 mints them equal by
construction; the model already supports 1 mission : N runs).

C3 budgets: a task carries three INDEPENDENT budget fields, never one bag:
  - execution plane: max_steps (carved down from RunOptions.max_steps)
  - OPSEC plane:     opsec_allowance (credits reserved from the round budget)
  - retry policy:    max_attempts (attempts are incremented by the lease sweep)
Exhaustion semantics differ per plane and are never conflated (mission tests
T6 pin this).

C4: `evidence` holds REFERENCES (kind + ref + provenance). A task succeeding
is an execution outcome; it never implies a confirmed finding — only the
independent verification pipeline can confirm, and the Commander's
attach_evidence refuses confidence="confirmed" by construction.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..states import TASK_PENDING

# The default claim lease — the SAME floor the hypothesis layer uses
# (swarm.hypotheses.DEFAULT_LEASE_SECONDS). The scheduler may raise it per
# dispatch; the mission driver wires the grace rule (task deadline +
# 2 x SandboxConfig.command_timeout, floored here).
TASK_LEASE_SECONDS = 900.0

MISSION_TASK_SCHEMA_VERSION = 1


def new_task_id() -> str:
    return f"task-{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class MissionTask:
    """One task record. Persisted inside mission.json (the Commander's task
    set); the journal carries the full snapshot on TASK_CREATED and deltas
    after, so replay rebuilds this state deterministically."""
    task_id: str
    mission_id: str                 # C1: separate logical field
    run_id: str                     # C1: separate physical field
    title: str
    role: str = ""                  # required registry role that executes this
    technique: str = ""             # attack-tree technique id ("" = non-node task)
    target: str = ""
    node_id: str = ""               # f"{technique}@{target}" ("" = non-node task)
    status: str = TASK_PENDING
    attempts: int = 0
    max_attempts: int = 2
    owner: str = ""                 # current lease owner (agent id)
    lease_token: int = 0            # fencing generation (C5): 0 = never leased
    lease_expires_at: str = ""      # ISO-8601 deadline; "" = no lease recorded
    # -- three-plane budgets (C3) --
    max_steps: int = 20             # execution plane carve
    opsec_allowance: float = 0.0    # OPSEC plane credits reserved at claim time
    # -- structure --
    dependencies: tuple[str, ...] = ()   # task_ids that must be SUCCEEDED first
    evidence: list[dict] = field(default_factory=list)   # refs only — never proof
    result: str = ""                # execution outcome note (NOT confirmation)
    error: str = ""
    created: str = field(default_factory=_now_iso)
    updated: str = field(default_factory=_now_iso)

    def touch(self) -> None:
        self.updated = _now_iso()

    def to_dict(self) -> dict:
        return {"schema_version": MISSION_TASK_SCHEMA_VERSION,
                "task_id": self.task_id, "mission_id": self.mission_id,
                "run_id": self.run_id, "title": self.title, "role": self.role,
                "technique": self.technique, "target": self.target,
                "node_id": self.node_id, "status": self.status,
                "attempts": self.attempts, "max_attempts": self.max_attempts,
                "owner": self.owner, "lease_token": self.lease_token,
                "lease_expires_at": self.lease_expires_at,
                "max_steps": self.max_steps,
                "opsec_allowance": self.opsec_allowance,
                "dependencies": list(self.dependencies),
                "evidence": list(self.evidence),
                "result": self.result, "error": self.error,
                "created": self.created, "updated": self.updated}

    @classmethod
    def from_dict(cls, raw: dict) -> "MissionTask":
        return cls(task_id=raw["task_id"], mission_id=raw["mission_id"],
                   run_id=raw["run_id"], title=raw.get("title", ""),
                   role=raw.get("role", ""), technique=raw.get("technique", ""),
                   target=raw.get("target", ""), node_id=raw.get("node_id", ""),
                   status=raw.get("status", TASK_PENDING),
                   attempts=int(raw.get("attempts", 0)),
                   max_attempts=int(raw.get("max_attempts", 2)),
                   owner=raw.get("owner", ""),
                   lease_token=int(raw.get("lease_token", 0)),
                   lease_expires_at=raw.get("lease_expires_at", ""),
                   max_steps=int(raw.get("max_steps", 20)),
                   opsec_allowance=float(raw.get("opsec_allowance", 0.0)),
                   dependencies=tuple(raw.get("dependencies") or ()),
                   evidence=list(raw.get("evidence") or []),
                   result=raw.get("result", ""), error=raw.get("error", ""),
                   created=raw.get("created", ""), updated=raw.get("updated", ""))

    def view(self) -> dict:
        """API/executor shape. NOTE: `lease_token` is deliberately absent — the
        token travels only to the dispatched worker via the scheduler's return
        value; a view consumer can read state but can never fence-mutate."""
        return {"task_id": self.task_id, "mission_id": self.mission_id,
                "run_id": self.run_id, "title": self.title, "role": self.role,
                "technique": self.technique, "target": self.target,
                "node_id": self.node_id, "status": self.status,
                "attempts": self.attempts, "max_attempts": self.max_attempts,
                "owner": self.owner,
                "lease_expires_at": self.lease_expires_at,
                "max_steps": self.max_steps,
                "opsec_allowance": self.opsec_allowance,
                "dependencies": list(self.dependencies),
                "evidence": [dict(e) for e in self.evidence],
                "result": self.result, "error": self.error}

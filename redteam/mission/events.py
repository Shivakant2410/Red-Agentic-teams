"""Mission journal event vocabulary (the mission layer's side of the shared
append-only EventJournal — see swarm/journal.py's per-type required-field
table: MISSION_/AGENT_/TREE_ types carry mission_id, TASK_ types carry
mission_id + task_id).

The journal is the INTENT authority; mission.json is the current state and the
tree/findings files are the EFFECT authorities. Every state mutation here is
journal-first (`_append_and_apply` mirrors HypothesisRegistry: a failed write
leaves state untouched).
"""

from __future__ import annotations

from typing import Callable

from ..swarm.journal import new_event_id, utc_now

# -- event types -----------------------------------------------------------------

EVENT_MISSION_CREATED = "MISSION_CREATED"
EVENT_MISSION_STARTED = "MISSION_STARTED"
EVENT_MISSION_STATE_CHANGED = "MISSION_STATE_CHANGED"
EVENT_MISSION_HALTED = "MISSION_HALTED"

EVENT_TASK_CREATED = "TASK_CREATED"
EVENT_TASK_CLAIMED = "TASK_CLAIMED"
EVENT_TASK_CLAIM_ABORTED = "TASK_CLAIM_ABORTED"
EVENT_TASK_DISPATCHED = "TASK_DISPATCHED"
EVENT_TASK_BLOCKED = "TASK_BLOCKED"
EVENT_TASK_LEASE_RENEWED = "TASK_LEASE_RENEWED"
EVENT_TASK_LEASE_EXPIRED = "TASK_LEASE_EXPIRED"
EVENT_TASK_REARMED = "TASK_REARMED"
EVENT_TASK_EXHAUSTED = "TASK_EXHAUSTED"
EVENT_TASK_SUCCEEDED = "TASK_SUCCEEDED"
EVENT_TASK_FAILED = "TASK_FAILED"
EVENT_TASK_RESULT_REJECTED = "TASK_RESULT_REJECTED"   # fenced stale write (audit)
EVENT_TASK_EVIDENCE = "TASK_EVIDENCE"

EVENT_TREE_RELEASED = "TREE_RELEASED"                 # tree effect, journaled here
EVENT_AGENT_REGISTERED = "AGENT_REGISTERED"
EVENT_MISSION_SYNTHESIS = "MISSION_SYNTHESIS"         # one adaptive planning round
EVENT_MISSION_STOPPED = "MISSION_STOPPED"             # why the loop ended (WS5)

# -- event construction -----------------------------------------------------------


def new_mission_event(etype: str, *, engagement_id: str, mission_id: str,
                      actor: str, task_id: str = "",
                      payload: dict | None = None,
                      clock: Callable | None = None) -> dict:
    """Build one mission-layer journal event. Identity fields live at the TOP
    level (the journal's per-type validation reads them there), free-form detail
    lives in `payload`. `entity` marks the layer for human readers; consumers
    ignore unknown fields by design (flat-dict format).

    NOTE: the journal's pre-existing validation rejects EMPTY payloads
    (truthiness check — preserved verbatim for backward parity, T4.2), so an
    event without detail carries {"detail": ""}."""
    payload = dict(payload or {}) or {"detail": ""}
    ev = {"event_id": new_event_id(),
          "engagement_id": engagement_id,
          "type": etype,
          "mission_id": mission_id,
          "actor": actor,
          "ts": (clock() if clock else utc_now_iso()),
          "schema_version": 1,
          "entity": "task" if etype.startswith("TASK_") else "mission",
          "payload": payload}
    if task_id:
        ev["task_id"] = task_id
    return ev


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp — same discipline as journal.utc_now, kept local
    so the mission layer's import surface stays journal + this module."""
    return utc_now()


__all__ = [name for name in dir() if name.startswith("EVENT_")] + [
    "new_mission_event", "utc_now_iso"]

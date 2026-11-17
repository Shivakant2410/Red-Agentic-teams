"""The Commander — the mission's lifecycle authority.

What it IS responsible for: the mission + mission_task state machines
(states.py tables), task creation with budget inheritance validation (C3 rule
4), the journaled task CAS (reserve/abort/dispatch), FENCED worker mutations
(C5: owner + lease token on every completion/failure/evidence/renewal), the
lease sweep with the no-steal liveness rule, and event-sourced rebuild
(`apply_event` mirrors the live mutation path exactly — the swarm registry's
replay discipline).

What it is STRUCTURALLY NOT responsible for (C4): the Commander holds no
AttackTree and no FindingStore reference. It cannot mark a tree node, confirm
a finding, or credit an objective — a task completing is an execution outcome
only; the tree completes through sync() on a CONFIRMED finding and nothing
else. attach_evidence additionally refuses confidence="confirmed" by
construction.

Journal discipline: journal-first (`_append_and_apply` — a failed write leaves
state untouched, identical to HypothesisRegistry), event_id idempotence
(`_applied` set, so replay-into cannot double-apply).
"""
from __future__ import annotations

import datetime as _dt
import threading
from typing import Callable

from ..states import (MISSION_HALTED, MISSION_PLANNED, MISSION_RUNNING,
                      TASK_BLOCKED_DUPLICATE, TASK_CLAIMED, TASK_EXPIRED,
                      TASK_FAILED, TASK_PENDING, TASK_RUNNING, TASK_SUCCEEDED,
                      can_transition)
from ..swarm.journal import EventJournal
from .errors import (InvalidTaskTransitionError, LeaseFencingError,
                     MissionStateError, TaskBudgetError, TaskOwnershipError,
                     UnknownTaskError, ValidationError)
from .events import (EVENT_MISSION_CREATED, EVENT_MISSION_STARTED,
                     EVENT_MISSION_STATE_CHANGED, EVENT_MISSION_HALTED,
                     EVENT_TASK_CLAIM_ABORTED, EVENT_TASK_CLAIMED,
                     EVENT_TASK_BLOCKED, EVENT_TASK_CREATED,
                     EVENT_TASK_DISPATCHED,
                     EVENT_TASK_EVIDENCE, EVENT_TASK_EXHAUSTED,
                     EVENT_TASK_FAILED, EVENT_TASK_LEASE_EXPIRED,
                     EVENT_TASK_LEASE_RENEWED, EVENT_TASK_REARMED,
                     EVENT_TASK_RESULT_REJECTED, EVENT_TASK_SUCCEEDED,
                     new_mission_event)
from .mission import Mission
from .task import MissionTask

CONFIRMED = "confirmed"   # the ONLY vocabulary that may never come from here


def _parse_ts(value: str) -> _dt.datetime | None:
    if not value:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


class Commander:
    """One Commander per mission. `journal` is the mission journal (EventJournal
    with the mission's engagement_id). `roe_caps` carries the engagement-inherited
    ceilings a task carve may never exceed:
      {"max_steps": int, "round_noise_budget": float}."""

    def __init__(self, mission: Mission, journal: EventJournal, *,
                 agents=None, bus=None, clock: Callable[[], _dt.datetime] | None = None,
                 roe_caps: dict | None = None, record_path=None):
        self.mission = mission
        self._journal = journal
        self._agents = agents
        self._bus = bus
        self._clock = clock or (lambda: _dt.datetime.now(_dt.timezone.utc))
        self._caps = dict(roe_caps or {})
        # Optional write-only snapshot (mission.json: mission + task records for
        # dashboards/API). NOT read back by recovery — the journal is the intent
        # authority and replay rebuilds task state; this mirrors the RunManifest
        # vs events.jsonl split.
        self._record_path = record_path
        self.tasks: dict[str, MissionTask] = {}
        self._applied: set[str] = set()
        self._lock = threading.RLock()

    # -- event application (the rebuild path mirrors the live path) ----------

    def apply_event(self, event: dict) -> None:
        """Apply one journaled event to in-memory state. Unknown/malformed
        events raise (replay counts the skip); already-applied event_ids are
        idempotent no-ops."""
        event_id = event.get("event_id") or ""
        if not event_id:
            raise ValueError("event without event_id")
        if event_id in self._applied:
            return
        etype = event.get("type") or ""
        payload = event.get("payload") or {}
        handler = getattr(self, f"_on_{etype.lower()}", None)
        if handler is None:
            raise ValueError(f"unknown mission event type {etype!r}")
        with self._lock:
            handler(event, payload)
            self._applied.add(event_id)

    # -- mission lifecycle ---------------------------------------------------

    def start_mission(self, actor: str) -> Mission:
        return self.set_mission_status(MISSION_RUNNING, actor)

    def set_mission_status(self, status: str, actor: str, reason: str = "") -> Mission:
        with self._lock:
            if not can_transition("mission", self.mission.status, status):
                raise InvalidTaskTransitionError(
                    f"invalid mission transition {self.mission.status} -> {status}")
            etype = EVENT_MISSION_STARTED if status == MISSION_RUNNING \
                else (EVENT_MISSION_HALTED if status == MISSION_HALTED
                      else EVENT_MISSION_STATE_CHANGED)
            payload = {"to_status": status}
            if reason:
                payload["reason"] = reason
            event = self._event(etype, actor=actor, payload=payload)
            self._append_and_apply(event)
            return self.mission

    # -- task creation ---------------------------------------------------------

    def create_task(self, *, title: str, role: str, actor: str,
                    technique: str = "", target: str = "",
                    dependencies=(), max_steps: int = 20,
                    opsec_allowance: float = 0.0, max_attempts: int = 2) -> MissionTask:
        """Create a PENDING task. C3 rule 4 enforced HERE: the carve may never
        exceed the engagement caps (max_steps <= caps['max_steps'];
        opsec_allowance <= caps['round_noise_budget']). The role must be a
        registered agent role. Node tasks (technique+target) get node_id."""
        if not title or not str(title).strip():
            raise ValidationError("task title is required")
        if self._agents is None or not self._agents.has_role(role):
            raise ValidationError(f"role {role!r} is not a registered agent role")
        cap_steps = int(self._caps.get("max_steps", max_steps))
        if max_steps > cap_steps:
            raise TaskBudgetError(
                f"task max_steps {max_steps} exceeds the engagement carve "
                f"cap {cap_steps} (C3: task budgets inherit DOWN from the RoE)")
        cap_noise = float(self._caps.get("round_noise_budget", float("inf")))
        if opsec_allowance > cap_noise:
            raise TaskBudgetError(
                f"task opsec_allowance {opsec_allowance} exceeds the engagement "
                f"round noise budget {cap_noise} (C3)")
        if opsec_allowance < 0:
            raise ValidationError("opsec_allowance must be >= 0")
        if max_attempts < 1:
            raise ValidationError("max_attempts must be >= 1")
        node_id = f"{technique}@{target}" if (technique and target) else ""
        from .task import new_task_id
        task = MissionTask(
            task_id=new_task_id(), mission_id=self.mission.mission_id,
            run_id=self.mission.primary_run_id, title=str(title).strip(),
            role=role, technique=technique, target=target, node_id=node_id,
            max_steps=int(max_steps), opsec_allowance=float(opsec_allowance),
            max_attempts=int(max_attempts),
            dependencies=tuple(dependencies))
        with self._lock:
            for dep in task.dependencies:
                if dep not in self.tasks:
                    raise ValidationError(
                        f"dependency {dep!r} is not a known task")
            event = self._event(EVENT_TASK_CREATED, actor=actor, task_id=task.task_id,
                                payload={"task": task.to_dict()})
            self._append_and_apply(event)
            return self.tasks[task.task_id]

    # -- scheduler-facing reservation edges (the claim trio's step 1) ---------

    def reserve_task(self, task_id: str, *, actor: str, lease_token: int,
                     lease_expires_at: str) -> MissionTask:
        """PENDING -> CLAIMED: the journaled CAS that opens the claim trio."""
        with self._lock:
            task = self._task(task_id)
            if task.status != TASK_PENDING:
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}, not claimable (CAS lost)")
            if not can_transition("mission_task", task.status, TASK_CLAIMED):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; not claimable (CAS lost)")
            event = self._event(
                EVENT_TASK_CLAIMED, actor=actor, task_id=task_id,
                payload={"owner": actor, "lease_token": int(lease_token),
                         "lease_expires_at": lease_expires_at,
                         "from_status": task.status})
            self._append_and_apply(event)
            return task

    def abort_claim(self, task_id: str, *, actor: str, lease_token: int,
                    reason: str = "") -> MissionTask:
        """CLAIMED -> PENDING: the journaled rollback when a later claim-trio
        step loses (design doc C2.3). Fenced: only the holder of the CURRENT
        token may abort its own reservation."""
        with self._lock:
            task = self._task(task_id)
            self._assert_fenced(task, actor, lease_token)
            event = self._event(
                EVENT_TASK_CLAIM_ABORTED, actor=actor, task_id=task_id,
                payload={"reason": reason, "token": int(lease_token)})
            self._append_and_apply(event)
            return task

    def block_task(self, task_id: str, *, actor: str, lease_token: int,
                   reason: str = "") -> MissionTask:
        """CLAIMED -> BLOCKED_DUPLICATE: the hypothesis layer reported this
        investigation as already owned this round."""
        with self._lock:
            task = self._task(task_id)
            self._assert_fenced(task, actor, lease_token)
            if not can_transition("mission_task", task.status,
                                  TASK_BLOCKED_DUPLICATE):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; cannot block")
            event = self._event(EVENT_TASK_BLOCKED, actor=actor, task_id=task_id,
                                payload={"reason": reason})
            self._append_and_apply(event)
            return task

    def mark_running(self, task_id: str, *, actor: str, lease_token: int) -> MissionTask:
        with self._lock:
            task = self._task(task_id)
            self._assert_fenced(task, actor, lease_token)
            if not can_transition("mission_task", task.status, TASK_RUNNING):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; cannot dispatch")
            event = self._event(EVENT_TASK_DISPATCHED, actor=actor, task_id=task_id,
                                payload={"token": int(lease_token)})
            self._append_and_apply(event)
            return task

    # -- fenced worker mutations (C5) ------------------------------------------

    def complete_task(self, task_id: str, *, actor: str, lease_token: int,
                      result: str = "") -> MissionTask:
        """RUNNING -> SUCCEEDED. Fenced twice: owner AND current lease
        token. An execution outcome ONLY — no tree, no finding, no objective
        credit happens here (the Commander holds no references to them, C4)."""
        with self._lock:
            task = self._task(task_id)
            self._fenced(task, EVENT_TASK_SUCCEEDED, actor, lease_token)
            if not can_transition("mission_task", task.status, TASK_SUCCEEDED):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; cannot complete")
            event = self._event(EVENT_TASK_SUCCEEDED, actor=actor, task_id=task_id,
                                payload={"result": result})
            self._append_and_apply(event)
            return task

    def fail_task(self, task_id: str, *, actor: str, lease_token: int,
                  error: str = "") -> MissionTask:
        with self._lock:
            task = self._task(task_id)
            self._fenced(task, EVENT_TASK_FAILED, actor, lease_token)
            if not can_transition("mission_task", task.status, TASK_FAILED):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; cannot fail")
            event = self._event(EVENT_TASK_FAILED, actor=actor, task_id=task_id,
                                payload={"error": error})
            self._append_and_apply(event)
            return task

    def attach_evidence(self, task_id: str, *, actor: str, lease_token: int,
                        kind: str, ref: str, confidence: str = "",
                        detail: str = "") -> MissionTask:
        """Attach an evidence REFERENCE to a task. `confidence` may never be
        'confirmed' — that word belongs to the independent verification
        pipeline alone (C4)."""
        if confidence == CONFIRMED:
            raise ValidationError(
                "task evidence can never be 'confirmed' — only the independent "
                "verification pipeline confirms (C4)")
        if not ref:
            raise ValidationError("evidence ref is required")
        with self._lock:
            task = self._task(task_id)
            self._fenced(task, EVENT_TASK_EVIDENCE, actor, lease_token)
            if task.status not in (TASK_CLAIMED, TASK_RUNNING):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; evidence only on active tasks")
            event = self._event(EVENT_TASK_EVIDENCE, actor=actor, task_id=task_id,
                                payload={"kind": kind, "ref": ref,
                                         "confidence": confidence,
                                         "detail": detail})
            self._append_and_apply(event)
            return task

    def renew_lease(self, task_id: str, *, actor: str, lease_token: int,
                    lease_expires_at: str) -> MissionTask:
        """Extend the CURRENT lease's deadline. The token does NOT change —
        renewals keep the same generation; only reclaim/expiry bumps it."""
        with self._lock:
            task = self._task(task_id)
            self._fenced(task, EVENT_TASK_LEASE_RENEWED, actor, lease_token)
            event = self._event(EVENT_TASK_LEASE_RENEWED, actor=actor,
                                task_id=task_id,
                                payload={"lease_expires_at": lease_expires_at})
            self._append_and_apply(event)
            return task

    def _renew_lease_unfenced(self, task: MissionTask,
                              lease_expires_at: str) -> MissionTask:
        """Supervisor-side renewal (the no-steal sweep). Lease TIME is the
        supervisor's to manage; the fence guards OUTCOMES, not lease clocks."""
        event = self._event(EVENT_TASK_LEASE_RENEWED, actor="lease-sweep",
                            task_id=task.task_id,
                            payload={"lease_expires_at": lease_expires_at,
                                     "supervisor": True})
        self._append_and_apply(event)
        return self._task(task.task_id)

    # -- lease sweep (C5.2/C5.3) -------------------------------------------------

    def sweep_expired(self, *, now: _dt.datetime | None = None,
                      worker_alive: Callable[[str], bool] | None = None,
                      include_leaseless: bool = False) -> list[str]:
        """Expire every CLAIMED/RUNNING task past its lease deadline. For each:
        - a LIVE worker (worker_alive(task_id) is True) is never stolen from —
          the lease is auto-renewed once and an audit note records why (C5.2);
        - otherwise the FENCING TOKEN is bumped (the superseded worker's late
          writes now fail with LeaseFencingError), attempts increment, the task
          goes EXPIRED, and the retry policy re-arms it (PENDING) while attempts
          remain, else fails it as exhausted.
        Tasks without a recorded deadline are skipped in live sweeps (they are
        the legacy/leaseless shape; recovery's reconcile decides them)."""
        now = now or self._clock()
        expired: list[str] = []
        with self._lock:
            for task in sorted(self.tasks.values(), key=lambda t: t.task_id):
                if task.status not in (TASK_CLAIMED, TASK_RUNNING):
                    continue
                deadline = _parse_ts(task.lease_expires_at)
                if deadline is None:
                    continue
                if deadline > now:
                    continue
                expired.append(task.task_id)
                if worker_alive is not None and worker_alive(task.task_id):
                    # No-steal: a live worker keeps its lease (extended by the
                    # sweep — the supervisor manages lease TIME, hence the
                    # unfenced renewal); the token is NOT bumped — its
                    # in-flight writes stay fenced-valid.
                    renewed = (deadline + _dt.timedelta(seconds=900)).isoformat()
                    self._renew_lease_unfenced(task, renewed)
                    continue
                self._expire_one(task, now)
        return expired

    def expire_task(self, task_id: str, *, now: _dt.datetime | None = None) -> MissionTask:
        """Expire ONE task (recovery reconcile's single-task path; same journal
        sequence as the sweep — one code path for the state change)."""
        with self._lock:
            task = self._task(task_id)
            if task.status not in (TASK_CLAIMED, TASK_RUNNING):
                raise InvalidTaskTransitionError(
                    f"task {task_id} is {task.status}; only an active lease "
                    f"can expire")
            self._expire_one(task, now or self._clock())
            return task

    def _expire_one(self, task: MissionTask, now: _dt.datetime) -> None:
        token_after = int(task.lease_token) + 1
        event = self._event(EVENT_TASK_LEASE_EXPIRED, actor="lease-sweep",
                            task_id=task.task_id,
                            payload={"token_after": token_after,
                                     "attempts_after": task.attempts + 1,
                                     "as_of": now.isoformat()})
        self._append_and_apply(event)
        if task.attempts < task.max_attempts:
            rearm = self._event(EVENT_TASK_REARMED, actor="lease-sweep",
                                task_id=task.task_id,
                                payload={"attempts": task.attempts,
                                         "max_attempts": task.max_attempts})
            self._append_and_apply(rearm)
        else:
            exhaust = self._event(EVENT_TASK_EXHAUSTED, actor="lease-sweep",
                                  task_id=task.task_id,
                                  payload={"attempts": task.attempts})
            self._append_and_apply(exhaust)

    # -- reads -------------------------------------------------------------------

    def _task(self, task_id: str) -> MissionTask:
        task = self.tasks.get(task_id)
        if task is None:
            raise UnknownTaskError(f"unknown task {task_id!r}")
        return task

    def task(self, task_id: str) -> MissionTask:
        with self._lock:
            return self._task(task_id)

    def task_view(self, task_id: str) -> dict:
        with self._lock:
            return self._task(task_id).view()

    def tasks_view(self) -> list[dict]:
        with self._lock:
            return [t.view() for t in
                    sorted(self.tasks.values(), key=lambda t: t.task_id)]

    def mission_view(self) -> dict:
        m = self.mission
        return {"mission_id": m.mission_id, "run_id": m.primary_run_id,
                "run_ids": list(m.run_ids), "engagement": m.engagement,
                "ticket": m.ticket, "objective": m.objective,
                "status": m.status, "halt_reason": m.halt_reason}

    def _assert_fenced(self, task: MissionTask, actor: str, lease_token: int) -> None:
        if task.owner != actor:
            raise TaskOwnershipError(
                f"{task.task_id} is owned by {task.owner!r}, not {actor!r}")
        if not lease_token or int(lease_token) != task.lease_token:
            raise LeaseFencingError(
                f"{task.task_id} rejected stale lease token {lease_token!r} "
                f"(current generation {task.lease_token}) — the writer was "
                f"superseded; timeout alone never proves an operation stopped")

    def _fenced(self, task: MissionTask, event_type: str, actor: str,
                lease_token: int) -> None:
        """Fence check with audit: a rejected write is journaled as
        TASK_RESULT_REJECTED (audit-only, no state change) BEFORE the error
        propagates — the superseded worker's outcome is on the record, and the
        current owner's state stands. The audit append is best-effort."""
        try:
            self._assert_fenced(task, actor, lease_token)
        except (TaskOwnershipError, LeaseFencingError):
            try:
                self._append_and_apply(self._event(
                    EVENT_TASK_RESULT_REJECTED, actor=actor,
                    task_id=task.task_id,
                    payload={"rejected_writer": actor,
                             "presented_token": int(lease_token or 0),
                             "current_token": int(task.lease_token)}))
            except Exception:
                pass        # journal down: the rejection still raises
            raise

    # -- journal plumbing ----------------------------------------------------------

    def _event(self, etype: str, *, actor: str, task_id: str = "",
               payload: dict | None = None) -> dict:
        return new_mission_event(
            etype, engagement_id=self._journal.engagement_id,
            mission_id=self.mission.mission_id, actor=actor,
            task_id=task_id, payload=payload, clock=self._clock)

    def _append_and_apply(self, event: dict) -> dict:
        """Journal first, apply second — a failed journal write leaves state
        untouched (the mutation 'didn't happen'; the caller sees the error).
        Identical discipline to HypothesisRegistry._append_and_apply."""
        stored = self._journal.append(event)
        self.apply_event(stored)
        self._emit(stored)
        self._save_record()
        return stored

    def _save_record(self) -> None:
        """Best-effort snapshot of the current mission+task state. A failed
        snapshot write is swallowed (the journal holds the authority; the next
        mutation rewrites the snapshot). ATOMIC: write to a sibling temp file
        and os.replace over the target — a concurrent reader (the API's
        mission poller, the recovery replay) must never observe a truncated
        or empty mission.json mid-write (this snapshot fires on EVERY
        mutation, so a non-atomic write here was the mission-poller race)."""
        if self._record_path is None:
            return
        try:
            import json
            import os
            from pathlib import Path
            target = Path(self._record_path)
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(json.dumps(
                {"schema_version": 2, "mission": self.mission.to_dict(),
                 "tasks": self.tasks_view()}, indent=2), encoding="utf-8")
            os.replace(tmp, target)
        except Exception:
            pass

    def _emit(self, event: dict) -> None:
        """Best-effort telemetry on the EventBus (it swallows sink failures by
        contract). Dotted lowercase names per the bus's existing vocabulary."""
        if self._bus is None:
            return
        etype = str(event.get("type", ""))
        name = {"MISSION_STARTED": "mission.start",
                "MISSION_STATE_CHANGED": "mission.state",
                "MISSION_HALTED": "mission.halt",
                "TASK_CLAIMED": "task.claimed",
                "TASK_DISPATCHED": "task.dispatched",
                "TASK_SUCCEEDED": "task.completed",
                "TASK_FAILED": "task.failed",
                "TASK_RESULT_REJECTED": "task.result_rejected"}.get(etype)
        if name:
            try:
                self._bus.emit(name, mission_id=event.get("mission_id", ""),
                               task_id=event.get("task_id", ""))
            except Exception:      # telemetry must never break the mission
                pass

    # -- per-event handlers (apply path; replay uses the SAME handlers) -------

    def _on_mission_created(self, event: dict, payload: dict) -> None:
        raw = payload.get("mission") or {}
        self.mission.status = raw.get("status", MISSION_PLANNED)

    def _on_mission_started(self, event: dict, payload: dict) -> None:
        self.mission.status = MISSION_RUNNING

    def _on_mission_state_changed(self, event: dict, payload: dict) -> None:
        target = payload.get("to_status", "")
        if not can_transition("mission", self.mission.status, target):
            raise ValueError(
                f"journal inconsistency: mission {self.mission.status} -> {target}")
        self.mission.status = target

    def _on_mission_halted(self, event: dict, payload: dict) -> None:
        self.mission.status = MISSION_HALTED
        self.mission.halt_reason = payload.get("reason", "")

    def _on_task_created(self, event: dict, payload: dict) -> None:
        raw = payload.get("task")
        if not raw:
            raise ValueError("TASK_CREATED without task snapshot")
        task = MissionTask.from_dict(raw)
        if task.task_id in self.tasks:
            raise ValueError(f"duplicate TASK_CREATED for {task.task_id}")
        self.tasks[task.task_id] = task

    def _require_task(self, event: dict) -> MissionTask:
        task_id = event.get("task_id") or ""
        task = self.tasks.get(task_id)
        if task is None:
            raise ValueError(f"event {event.get('type')} for unknown task {task_id!r}")
        return task

    def _on_task_claimed(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_PENDING:
            raise ValueError(f"TASK_CLAIMED on {task.status} task")
        task.status = TASK_CLAIMED
        task.owner = payload.get("owner", "")
        task.lease_token = int(payload.get("lease_token") or 0)
        task.lease_expires_at = payload.get("lease_expires_at", "")
        task.touch()

    def _on_task_claim_aborted(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_CLAIMED:
            raise ValueError(f"TASK_CLAIM_ABORTED on {task.status} task")
        task.status = TASK_PENDING
        task.owner = ""
        task.lease_expires_at = ""
        task.touch()

    def _on_task_dispatched(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_CLAIMED:
            raise ValueError(f"TASK_DISPATCHED on {task.status} task")
        task.status = TASK_RUNNING
        task.touch()

    def _on_task_blocked(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_CLAIMED:
            raise ValueError(f"TASK_BLOCKED on {task.status} task")
        task.status = TASK_BLOCKED_DUPLICATE
        task.owner = ""
        task.lease_expires_at = ""
        task.touch()

    def _on_task_lease_renewed(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        task.lease_expires_at = payload.get("lease_expires_at",
                                           task.lease_expires_at)
        task.touch()

    def _on_task_lease_expired(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status not in (TASK_CLAIMED, TASK_RUNNING):
            raise ValueError(f"TASK_LEASE_EXPIRED on {task.status} task")
        task.status = TASK_EXPIRED
        task.lease_token = int(payload.get("token_after") or task.lease_token + 1)
        task.attempts = int(payload.get("attempts_after") or task.attempts + 1)
        task.owner = ""
        task.lease_expires_at = ""
        task.touch()

    def _on_task_rearmed(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_EXPIRED:
            raise ValueError(f"TASK_REARMED on {task.status} task")
        task.status = TASK_PENDING
        task.touch()

    def _on_task_exhausted(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status != TASK_EXPIRED:
            raise ValueError(f"TASK_EXHAUSTED on {task.status} task")
        task.status = TASK_FAILED
        task.error = payload.get("attempts", "") and \
            f"exhausted after {payload.get('attempts')} attempts"
        task.touch()

    def _on_task_succeeded(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status not in (TASK_CLAIMED, TASK_RUNNING):
            raise ValueError(f"TASK_SUCCEEDED on {task.status} task")
        task.status = TASK_SUCCEEDED
        task.result = payload.get("result", "")
        task.owner = ""
        task.lease_expires_at = ""
        task.touch()

    def _on_task_failed(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        if task.status not in (TASK_CLAIMED, TASK_RUNNING):
            raise ValueError(f"TASK_FAILED on {task.status} task")
        task.status = TASK_FAILED
        task.error = payload.get("error", "")
        task.owner = ""
        task.lease_expires_at = ""
        task.touch()

    def _on_task_result_rejected(self, event: dict, payload: dict) -> None:
        # Audit-only: a fenced stale write. NO state change — the current
        # owner's state stands.
        self._require_task(event)

    def _on_task_evidence(self, event: dict, payload: dict) -> None:
        task = self._require_task(event)
        task.evidence.append({"kind": payload.get("kind", ""),
                              "ref": payload.get("ref", ""),
                              "confidence": payload.get("confidence", ""),
                              "detail": payload.get("detail", ""),
                              "recorded_by": event.get("actor", "")})
        task.touch()

    def _on_tree_released(self, event: dict, payload: dict) -> None:
        # The tree FILE is the effect authority; this event only records the
        # mission layer's hand in the release for cross-referencing.
        return

    def _on_agent_registered(self, event: dict, payload: dict) -> None:
        return

    # replay resilience: unknown types raise ValueError (replay counts the
    # skip) — same contract as the swarm registry's apply_event.

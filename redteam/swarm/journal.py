"""Append-only, per-engagement event journal — the registry's source of lifecycle truth.

Why not redteam/events.py's EventBus: emit() deliberately swallows sink failures (the
right policy for dashboard telemetry, the wrong one for authoritative history — a lost
write would silently desynchronize journal from state), payloads are unvalidated flat
dicts with no identity, and there is no duplicate-event protection. See
docs/adr-001-collective-intelligence-foundation.md §2.3. This journal keeps the good
patterns (JSONL append, monotonic per-journal seq, torn-line-tolerant reads) and adds
the guarantees replay needs:

  - every event carries a UUID `event_id` and a `schema_version`;
  - re-appending a known `event_id` is an idempotent no-op that returns the stored
    event (duplicate delivery can never double-apply);
  - write failures RAISE (lifecycle history may not be lost silently — the registry's
    callers decide how to degrade, and the orchestrator degrades to an audit record);
  - the journal is scoped to ONE engagement and refuses events naming another;
  - seq is assigned under a lock, so concurrent appenders get a gapless order.

Replay (projections.py) reads this file in order and rebuilds registry state through
the same apply path the live registry used, so replay is deterministic by construction.
No external broker: one process, thread-level parallelism — the same concurrency model
AttackTree/FindingStore already assume — is satisfied by one lock and one JSONL file.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import uuid
from pathlib import Path

SCHEMA_VERSION = 1

REQUIRED_EVENT_FIELDS = ("event_id", "engagement_id", "type", "hypothesis_id",
                         "actor", "ts", "payload")


def utc_now() -> str:
    """UTC timestamp, ISO-8601 — the only clock format this package writes."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class JournalError(Exception):
    """Base class for journal failures (write errors, invalid events)."""


class EngagementMismatchError(JournalError):
    """An event naming a different engagement was offered to this journal."""


class EventJournal:
    """Append-only JSONL journal for one engagement's hypothesis lifecycle events."""

    def __init__(self, engagement_id: str, path: str | Path | None = None):
        self.engagement_id = str(engagement_id)
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seq = 0
        self._seen: set[str] = set()
        self._events: list[dict] = []
        if self._path is not None and self._path.exists():
            self._events = self._load()
            self._seq = len(self._events)
            self._seen = {e["event_id"] for e in self._events if "event_id" in e}

    # -- writing -------------------------------------------------------------

    def append(self, event: dict) -> dict:
        """Validate, stamp seq, dedupe by event_id, append, and persist.

        Returns the stored event (the previously-stored one when event_id is already
        known — duplicate delivery is idempotent). Raises EngagementMismatchError for
        foreign-engagement events and JournalError for malformed events or write
        failures; a failed append must leave the journal (and its seq) unchanged.
        """
        self._validate(event)
        with self._lock:
            if event["event_id"] in self._seen:
                stored = next((e for e in self._events
                               if e["event_id"] == event["event_id"]), None)
                if stored is not None:
                    return stored
            stored = dict(event)
            stored["seq"] = self._seq + 1
            self._persist(stored)          # may raise — nothing below runs on failure
            self._seq += 1
            self._events.append(stored)
            self._seen.add(stored["event_id"])
            return stored

    def _validate(self, event: dict) -> None:
        if not isinstance(event, dict):
            raise JournalError("event must be a mapping")
        for field in REQUIRED_EVENT_FIELDS:
            if not event.get(field):
                raise JournalError(f"event missing required field {field!r}")
        if event["engagement_id"] != self.engagement_id:
            raise EngagementMismatchError(
                f"event engagement {event['engagement_id']!r} != journal engagement "
                f"{self.engagement_id!r}")

    def _persist(self, event: dict) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True,
                                    default=str) + "\n")
                fh.flush()
        except OSError as exc:
            raise JournalError(f"journal write failed: {exc}") from exc

    # -- reading -------------------------------------------------------------

    def read_all(self) -> list[dict]:
        """All stored events in append order (a consistent snapshot under the lock)."""
        with self._lock:
            return list(self._events)

    def _load(self) -> list[dict]:
        """Torn-line-tolerant load (same discipline as events.read_events): a writer
        killed mid-flush loses one line, the rest replay. Invalid lines are skipped
        rather than fatal — a corrupt tail must not erase a valid history."""
        out: list[dict] = []
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError:
            return out
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict) and ev.get("event_id"):
                out.append(ev)
        return out

    @property
    def path(self) -> Path | None:
        return self._path


def new_event_id() -> str:
    return uuid.uuid4().hex

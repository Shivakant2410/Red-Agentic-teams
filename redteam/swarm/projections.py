"""Projections — rebuilding registry state from the event journal.

`replay()` is the registry's recovery path: given a journal (live object or JSONL
path), it walks events in append order and applies each through the SAME
`apply_event()` the live registry used, so live state and replayed state cannot
diverge by construction. Guarantees, each tested:

  - determinism: replaying the same journal twice yields identical state;
  - idempotency: duplicate event_ids (replay-fed or re-appended) apply once;
  - resilience: torn lines, missing fields, unknown types, invalid transitions,
    and foreign-engagement events are SKIPPED and counted in a ReplayReport —
    a corrupt tail or one bad line never erases the valid history before it;
  - ordering: journal order (gapless per-journal seq under the append lock) is the
    only order replay honors;
  - restart recovery: a fresh registry + the same file reproduces the run's state.

No broker, no snapshot format, no checkpoints in Phase C1: the journal IS the
checkpoint (JSONL, append-only, human-readable, diffable in a PR review).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .hypotheses import (DEFAULT_LEASE_SECONDS,
                         EngagementMismatchError as RegistryEngagementMismatch,
                         HypothesisRegistry, InvalidEventError, SwarmError)
from .journal import EventJournal, JournalError

# Reasons a replayed event can be skipped, all counted in the report.
SKIP_MALFORMED = "malformed"
SKIP_UNKNOWN_TYPE = "unknown_type"
SKIP_INVALID_STATE = "invalid_state"
SKIP_FOREIGN_ENGAGEMENT = "foreign_engagement"
SKIP_DUPLICATE = "duplicate"


@dataclass
class ReplayReport:
    engagement_id: str
    events_read: int = 0
    events_applied: int = 0
    duplicates_skipped: int = 0
    invalid_skipped: int = 0
    issues: list[dict] = field(default_factory=list)   # {seq, reason, detail, event_id}

    def issue(self, seq: int, reason: str, detail: str, event_id: str = "") -> None:
        self.invalid_skipped += 1
        self.issues.append({"seq": seq, "reason": reason, "detail": detail,
                            "event_id": event_id})

    def summary(self) -> dict:
        return {"engagement_id": self.engagement_id, "events_read": self.events_read,
                "events_applied": self.events_applied,
                "duplicates_skipped": self.duplicates_skipped,
                "invalid_skipped": self.invalid_skipped,
                "issues": list(self.issues)}


def replay(source: EventJournal | str | Path, engagement_id: str,
           lease_seconds: float | None = None) -> tuple[HypothesisRegistry, ReplayReport]:
    """Rebuild a HypothesisRegistry from a journal (object or JSONL file path).

    Returns (registry, report). The registry comes back engagement-scoped with a
    fresh in-memory journal of its own — callers who intend to CONTINUE appending
    should construct the registry with the same file-backed journal instead (see
    `replay_into`). Replay's job is state reconstruction, not continuation.
    """
    registry, report, _ = _replay_common(source, engagement_id, lease_seconds,
                                         journal_out=None)
    return registry, report


def replay_into(source: EventJournal | str | Path, journal: EventJournal,
                lease_seconds: float | None = None) -> tuple[HypothesisRegistry, ReplayReport]:
    """Replay a journal file INTO a file-backed journal (restart recovery that keeps
    appending to the same history: new events get seq after the replayed prefix)."""
    registry, report, _ = _replay_common(source, journal.engagement_id, lease_seconds,
                                         journal_out=journal)
    return registry, report


def _replay_common(source, engagement_id, lease_seconds, journal_out):
    registry = HypothesisRegistry(engagement_id, journal=journal_out
                                  or EventJournal(engagement_id),
                                  lease_seconds=lease_seconds
                                  or DEFAULT_LEASE_SECONDS)
    report = ReplayReport(engagement_id=str(engagement_id))
    seen: set[str] = set()

    events = _read_events(source)
    for ev in events:
        report.events_read += 1
        if not isinstance(ev, dict) or not ev.get("event_id"):
            report.issue(getattr(ev, "seq", 0) if isinstance(ev, dict) else 0,
                         SKIP_MALFORMED, "not a mapping or missing event_id")
            continue
        event_id = ev["event_id"]
        seq = ev.get("seq", 0)
        if event_id in seen:
            report.duplicates_skipped += 1
            continue
        if ev.get("engagement_id") != engagement_id:
            report.issue(seq, SKIP_FOREIGN_ENGAGEMENT,
                         f"event engagement {ev.get('engagement_id')!r} != "
                         f"{engagement_id!r}", event_id)
            continue
        if not ev.get("type") or not ev.get("hypothesis_id"):
            report.issue(seq, SKIP_MALFORMED, "missing type or hypothesis_id", event_id)
            continue
        try:
            registry.apply_event(ev)
        except InvalidEventError as exc:
            report.issue(seq, SKIP_INVALID_STATE, str(exc), event_id)
            continue
        except (RegistryEngagementMismatch, SwarmError, JournalError, TypeError,
                ValueError, KeyError) as exc:      # defensive: replay never raises
            report.issue(seq, SKIP_INVALID_STATE, f"{type(exc).__name__}: {exc}",
                         event_id)
            continue
        seen.add(event_id)
        report.events_applied += 1
    return registry, report, None


def _read_events(source) -> list[dict]:
    if isinstance(source, EventJournal):
        return source.read_all()
    path = Path(source)
    out: list[dict] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"event_id": "", "seq": 0})   # counted as malformed, not fatal
    return out


__all__ = ["replay", "replay_into", "ReplayReport"]

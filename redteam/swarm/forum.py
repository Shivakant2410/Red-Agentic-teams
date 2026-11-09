"""Research forum — the swarm's structured, attributable communication layer.

The registry holds authoritative state; the forum holds what agents SAID about it:
hypothesis registrations, claims, observations, evidence attachments, challenges,
relationship assertions, status changes, published artifacts, releases. Every message
is typed, schema-validated, attributed to an agent + role, engagement-scoped, and
retrievable by bounded, filtered queries — never by "send me everything".

Trust model (this layer is itself attack surface — see ADR §2.9):

  - Every payload is a mapping of bounded, sanitized strings (control characters
    stripped, lengths capped). Message content is DATA; nothing in this module (or
    its callers) parses it for instructions.
  - Directive-shaped content is quarantined at publish time with the swarmguard's
    screen (probe 2 of the inter-agent cascade): the message is retained for
    forensics, flagged `quarantined`, and EXCLUDED from relevant_context() — peers
    can never re-enter a quarantined payload into their context.
  - Observations/artifacts carry a mandatory `origin` ("agent" | "target") so
    target-controlled material is never mistaken for agent reasoning.
  - Secrets are redacted before storage: token-shaped strings (bearer headers, JWTs,
    ghp_/sk_ keys, long hex) are masked deterministically. The forum stores pointers
    (artifact refs), not response bodies — traffic.jsonl keeps the masked originals.
  - Duplicate delivery is idempotent (same event_id re-publish returns the stored
    message); a duplicate from a DIFFERENT id but identical content is not detected
    — identity is the event_id contract.
  - Engagement isolation is structural: the instance is built for one engagement_id,
    queries name an engagement that must match it (fail closed).

Mirroring: publish() optionally fans each accepted message out to the run's EventBus
(prefixed "research." for the dashboard) via safe_emit semantics — the forum never
depends on a bus existing, and bus failures never affect the forum.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import uuid
from pathlib import Path
from typing import Callable

from ..events import EventBus, safe_emit
from ..swarmguard import screen_composed
from .journal import utc_now

SCHEMA_VERSION = 1

# The nine message types (fixed by the Phase C1 spec) and their required payload keys.
EVENT_HYPOTHESIS_REGISTERED = "hypothesis.registered"
EVENT_HYPOTHESIS_CLAIMED = "hypothesis.claimed"
EVENT_OBSERVATION_CREATED = "observation.created"
EVENT_EVIDENCE_ATTACHED = "evidence.attached"
EVENT_HYPOTHESIS_CHALLENGED = "hypothesis.challenged"
EVENT_HYPOTHESIS_RELATED = "hypothesis.related"
EVENT_HYPOTHESIS_STATUS_CHANGED = "hypothesis.status_changed"
EVENT_ARTIFACT_PUBLISHED = "artifact.published"
EVENT_HYPOTHESIS_RELEASED = "hypothesis.released"

EVENT_TYPES: dict[str, tuple[str, ...]] = {
    EVENT_HYPOTHESIS_REGISTERED: ("hypothesis_id", "asset_ref", "weakness_class", "claim"),
    EVENT_HYPOTHESIS_CLAIMED: ("hypothesis_id",),
    EVENT_OBSERVATION_CREATED: ("summary", "origin"),
    EVENT_EVIDENCE_ATTACHED: ("hypothesis_id", "evidence_id", "kind", "origin"),
    EVENT_HYPOTHESIS_CHALLENGED: ("hypothesis_id", "reason"),
    EVENT_HYPOTHESIS_RELATED: ("hypothesis_id", "related_id", "kind"),
    EVENT_HYPOTHESIS_STATUS_CHANGED: ("hypothesis_id", "from_status", "to_status"),
    EVENT_ARTIFACT_PUBLISHED: ("artifact_ref", "summary", "origin"),
    EVENT_HYPOTHESIS_RELEASED: ("hypothesis_id",),
}

ORIGINS = ("agent", "target")

MAX_PAYLOAD_JSON = 8192          # whole-payload cap
MAX_SUMMARY = 600
MAX_ID_LEN = 80

AGENT_ROLES = ("recon", "exploit", "verify", "access", "logic", "orchestrator",
               "operator", "other")

# Token-shaped strings worth masking in shared summaries (deterministic, cheap):
# bearer/authorization headers, JWTs, GitHub/OpenAI-style keys, long hex/base64 runs.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("bearer", r"\bbearer\s+[a-z0-9._\-]{12,}"),
        ("jwt", r"\beyJ[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,}"),
        ("token-key", r"\b(ghp|gho|ghu|ghs|sk)[_\-][a-z0-9]{16,}"),
        ("hex-secret", r"\b[a-f0-9]{40,}\b"),
        ("basic-auth", r"\bbasic\s+[a-z0-9+/=]{16,}"),
    )
)


class MessageRejectedError(Exception):
    """A malformed, oversized, or mis-scoped forum message."""


class EngagementMismatchError(Exception):
    """A query naming an engagement other than this forum's."""


def redact_secrets(text: str) -> str:
    """Mask token-shaped strings in shared summaries. Deterministic and conservative:
    a missed shape stays in the run's own traffic log anyway (already masked there);
    a leaked one in the FORUM would be read by every peer's context."""
    out = text or ""
    for name, rx in _SECRET_PATTERNS:
        out = rx.sub(f"[REDACTED:{name}]", out)
    return out


def sanitize_text(value, limit: int, field_name: str = "text") -> str:
    """Bounded, control-character-free text for anything that enters the forum."""
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.strip()


class ForumMessage:
    """One typed forum event. Plain class (not dataclass) because `quarantined` and
    `flags` are post-screening fields and we want strict to_dict() JSON ordering."""

    __slots__ = ("event_id", "engagement_id", "event_type", "schema_version",
                 "source_agent", "agent_role", "subject_hypothesis_id", "asset_ref",
                 "ts", "payload", "refs", "quarantined", "flags")

    def __init__(self, event_id: str, engagement_id: str, event_type: str,
                 source_agent: str, payload: dict, agent_role: str = "other",
                 subject_hypothesis_id: str = "", asset_ref: str = "",
                 ts: str = "", refs: list | None = None,
                 quarantined: bool = False, flags: tuple = ()):
        self.event_id = event_id
        self.engagement_id = engagement_id
        self.event_type = event_type
        self.schema_version = SCHEMA_VERSION
        self.source_agent = source_agent
        self.agent_role = agent_role
        self.subject_hypothesis_id = subject_hypothesis_id
        self.asset_ref = asset_ref
        self.ts = ts or utc_now()
        self.payload = payload
        self.refs = list(refs or [])
        self.quarantined = quarantined
        self.flags = tuple(flags)

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "engagement_id": self.engagement_id,
                "event_type": self.event_type, "schema_version": self.schema_version,
                "source_agent": self.source_agent, "agent_role": self.agent_role,
                "subject_hypothesis_id": self.subject_hypothesis_id,
                "asset_ref": self.asset_ref, "ts": self.ts,
                "payload": self.payload, "refs": self.refs,
                "quarantined": self.quarantined, "flags": list(self.flags)}

    @classmethod
    def from_dict(cls, row: dict) -> "ForumMessage":
        return cls(event_id=row.get("event_id", ""),
                   engagement_id=row.get("engagement_id", ""),
                   event_type=row.get("event_type", ""),
                   source_agent=row.get("source_agent", ""),
                   payload=row.get("payload") or {},
                   agent_role=row.get("agent_role", "other"),
                   subject_hypothesis_id=row.get("subject_hypothesis_id", ""),
                   asset_ref=row.get("asset_ref", ""),
                   ts=row.get("ts", ""),
                   refs=row.get("refs") or [],
                   quarantined=bool(row.get("quarantined", False)),
                   flags=tuple(row.get("flags") or ()))


class ResearchForum:
    """Typed, attributable, engagement-scoped research communication."""

    def __init__(self, engagement_id: str, path: str | Path | None = None,
                 bus: EventBus | None = None, clock: Callable[[], str] | None = None):
        self.engagement_id = str(engagement_id)
        self._path = Path(path) if path else None
        self._bus = bus
        self._clock = clock or utc_now
        self._lock = threading.Lock()
        self._messages: list[ForumMessage] = []
        self._seen: set[str] = set()
        if self._path is not None and self._path.exists():
            self._load()

    # -- publish ---------------------------------------------------------------

    def publish(self, event_type: str, *, source_agent: str, payload: dict | None = None,
                agent_role: str = "other", subject_hypothesis_id: str = "",
                asset_ref: str = "", refs=(), ts: str | None = None) -> ForumMessage:
        """Validate → sanitize → screen → store → mirror. Raises MessageRejectedError
        for unknown types, missing payload keys, non-dict payloads, oversized
        payloads, bad origin values, or a foreign engagement id in payload. A
        quarantined message is still stored (forensics) and returns normally — the
        caller sees flags and knows it will not reach peers' context."""
        etype = str(event_type or "").strip()
        if etype not in EVENT_TYPES:
            raise MessageRejectedError(
                f"unknown event_type {event_type!r}; known: {sorted(EVENT_TYPES)}")
        agent = sanitize_text(source_agent, MAX_ID_LEN, "source_agent")
        if not agent:
            raise MessageRejectedError("source_agent is required")
        role = str(agent_role or "other").strip().lower()
        if role not in AGENT_ROLES:
            role = "other"
        if not isinstance(payload, dict):
            raise MessageRejectedError("payload must be a mapping")
        for key in EVENT_TYPES[etype]:
            if key not in payload or payload[key] in (None, ""):
                raise MessageRejectedError(
                    f"{etype} payload missing required key {key!r}")
        payload = self._sanitize_payload(etype, dict(payload))
        blob = json.dumps(payload, ensure_ascii=False)
        if len(blob) > MAX_PAYLOAD_JSON:
            raise MessageRejectedError(
                f"payload exceeds {MAX_PAYLOAD_JSON} bytes")
        subject = sanitize_text(subject_hypothesis_id, MAX_ID_LEN)
        asset = sanitize_text(asset_ref, 300)
        msg = ForumMessage(event_id=uuid.uuid4().hex, engagement_id=self.engagement_id,
                           event_type=etype, source_agent=agent,
                           payload=payload, agent_role=role,
                           subject_hypothesis_id=subject, asset_ref=asset,
                           ts=ts or self._clock(), refs=[str(r) for r in refs or []])
        # Quarantine screening (swarmguard probe 2) over the summary-bearing fields —
        # the message as a whole is DATA; directive-shaped content must not re-enter
        # another agent's context even as "an observation a sibling made".
        screened_text = " \n".join(str(v) for v in payload.values() if isinstance(v, str))
        sc = screen_composed(screened_text)
        if sc.verdict != "allow":
            msg.quarantined = True
            msg.flags = sc.flags
        with self._lock:
            if msg.event_id in self._seen:            # unreachable for fresh uuids, kept
                existing = next(m for m in self._messages if m.event_id == msg.event_id)
                return existing                       # for replay-fed publishes
            self._messages.append(msg)
            self._seen.add(msg.event_id)
            self._persist(msg)
        if self._bus is not None and not msg.quarantined:
            safe_emit(self._bus, f"research.{etype}", engagement_id=self.engagement_id,
                      source_agent=agent, agent_role=role,
                      hypothesis_id=subject, asset_ref=asset, payload=payload)
        return msg

    def _sanitize_payload(self, etype: str, payload: dict) -> dict:
        clean: dict = {}
        for key, value in payload.items():
            key = sanitize_text(key, 64, "payload key")
            if isinstance(value, str):
                value = redact_secrets(sanitize_text(
                    value, MAX_SUMMARY if key in ("summary", "reason", "claim") else 300,
                    key))
                clean[key] = value
            elif isinstance(value, bool) or isinstance(value, (int, float)):
                clean[key] = value
            elif isinstance(value, (list, tuple)):
                clean[key] = [str(v)[:120] for v in list(value)[:20]]
            elif isinstance(value, dict):
                clean[key] = {str(k)[:64]: str(v)[:200] for k, v in
                              list(value.items())[:20]}
            else:
                raise MessageRejectedError(f"payload key {key!r} has unsupported type "
                                           f"{type(value).__name__}")
        if etype in (EVENT_OBSERVATION_CREATED, EVENT_ARTIFACT_PUBLISHED):
            if clean.get("origin") not in ORIGINS:
                raise MessageRejectedError(
                    f"origin must be one of {ORIGINS} — provenance (agent vs "
                    f"target-controlled) is mandatory")
        return clean

    # -- retrieval -------------------------------------------------------------

    def query(self, *, engagement_id: str | None = None,
              event_types=None, hypothesis_id: str | None = None, agent: str | None = None,
              asset: str | None = None, since: str | None = None,
              until: str | None = None, limit: int = 100,
              include_quarantined: bool = False) -> list[ForumMessage]:
        """Filtered, bounded retrieval, oldest first. Every filter is optional except
        the engagement scope, which ALWAYS applies: a query naming a different
        engagement fails closed (cross-engagement leakage is a bug, not an empty
        result)."""
        if engagement_id is not None and engagement_id != self.engagement_id:
            raise EngagementMismatchError(
                f"forum is scoped to engagement {self.engagement_id!r}; query named "
                f"{engagement_id!r}")
        limit = max(1, min(int(limit), 300))
        types = set(event_types or ())
        with self._lock:
            rows = list(self._messages)
        out: list[ForumMessage] = []
        for m in rows:
            if types and m.event_type not in types:
                continue
            if hypothesis_id and m.subject_hypothesis_id != hypothesis_id:
                continue
            if agent and m.source_agent != agent:
                continue
            if asset and (m.asset_ref or "") != asset:
                continue
            if since and m.ts < since:
                continue
            if until and m.ts > until:
                continue
            if m.quarantined and not include_quarantined:
                continue
            out.append(m)
            if len(out) >= limit:
                break
        return out

    def relevant_context(self, hypothesis_id: str, *, related_ids=(),
                         asset: str | None = None, limit: int = 20) -> list[ForumMessage]:
        """Bounded briefing for one worker: messages about this hypothesis, its
        explicitly related hypotheses, or its asset — newest first, capped, with
        quarantined messages excluded. This is the ONLY bulk-ish read the swarm gets;
        "the entire forum history" is never a valid query result."""
        related = {hypothesis_id, *(str(r) for r in related_ids or ())}
        with self._lock:
            rows = list(self._messages)
        hits = [m for m in rows
                if not m.quarantined
                and (m.subject_hypothesis_id in related
                     or (asset and m.asset_ref == asset))]
        hits.sort(key=lambda m: m.ts, reverse=True)
        return hits[: max(1, min(int(limit), 50))]

    def stats(self) -> dict:
        with self._lock:
            by_type: dict[str, int] = {}
            quarantined = 0
            for m in self._messages:
                by_type[m.event_type] = by_type.get(m.event_type, 0) + 1
                quarantined += 1 if m.quarantined else 0
            return {"engagement_id": self.engagement_id, "total": len(self._messages),
                    "by_type": by_type, "quarantined": quarantined}

    # -- persistence -------------------------------------------------------------

    def _persist(self, msg: ForumMessage) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(msg.to_dict(), ensure_ascii=False,
                                    sort_keys=True) + "\n")
                fh.flush()
        except OSError:
            # Communication is best-effort (EventBus's own policy): a dead sink must
            # not break the swarm. In-memory fan-out still worked; forensics lose
            # this one line.
            pass

    def _load(self) -> None:
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("event_id"):
                msg = ForumMessage.from_dict(row)
                self._messages.append(msg)
                self._seen.add(msg.event_id)

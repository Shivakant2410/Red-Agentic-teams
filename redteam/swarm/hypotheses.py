"""Hypothesis registry — the run-scoped store of structured security hypotheses.

THE DISTILLATION OF PHASE C1's PRINCIPLE:

    an observation is not a hypothesis; a hypothesis is not a finding; a finding is
    not confirmed until the independent verification pipeline confirms it.

A hypothesis is the swarm's *structured suspicion* about one (asset, weakness) pair:
what is suspected, what must already be true, what behavior is expected if it is real,
how it would be tested, what evidence supports or contradicts it, who is working it,
and where it stands in its lifecycle. It is NOT a finding — a landing finding is
attached as *evidence* and the hypothesis moves to AWAITING_VERIFICATION; only the
independent verification pipeline's verdict, mirrored in via
`record_verification_outcome()`, may set CONFIRMED/REFUTED. Nothing an agent says,
challenges, or reflects can promote a hypothesis, and nothing here promotes a finding:
`FindingStore.promote()` (tools/independent_verify.py) remains the only writer of
finding confidence.

Concurrency contract (mirrors AttackTree/FindingStore discipline — one process,
thread-level parallelism, one lock):

  - every mutation is a compare-and-set under `self._lock`, expressed as ONE domain
    event that is journaled (via swarm/journal.py) and applied through the same
    `apply_event()` path replay uses — live writes and replay cannot diverge;
  - `claim()` is atomic: two workers race, exactly one wins, the loser gets
    AlreadyClaimedError (the registry twin of AttackTree.claim()'s contract);
  - leases bound ownership: an abandoned claim expires and becomes reclaimable, and an
    expired holder's stale write fails the version check instead of overwriting the
    reclaiming worker's state;
  - mutators accept `expected_version` for optimistic concurrency;
  - the instance is engagement-scoped: no engagement's data is reachable through
    another engagement's registry, and no global registry exists.

Everything is append-only: evidence, counter-evidence, links, challenges, and history
are never rewritten or deleted — corrections supersede, they do not overwrite.
"""

from __future__ import annotations

import datetime as _dt
import threading
import uuid
from dataclasses import asdict, dataclass, field
from typing import Callable

from .journal import EventJournal, new_event_id

# -- lifecycle ---------------------------------------------------------------------

PROPOSED = "PROPOSED"
ACTIVE = "ACTIVE"
AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
BLOCKED = "BLOCKED"
STALE = "STALE"

# BLOCKED: a prerequisite another hypothesis must satisfy first (e.g. a session that
# must exist) — workers skip without abandoning the research. STALE: the target
# changed under the hypothesis (endpoint vanished/changed) — marked, never deleted,
# re-activatable if the surface returns. Both are reversible, both audited; neither
# is reachable from PROPOSED (an unadopted suspicion is simply not worked).
VALID_TRANSITIONS: dict[str, tuple[str, ...]] = {
    PROPOSED: (ACTIVE, STALE),
    ACTIVE: (AWAITING_VERIFICATION, BLOCKED, STALE),
    AWAITING_VERIFICATION: (CONFIRMED, REFUTED, ACTIVE),
    BLOCKED: (ACTIVE, STALE),
    STALE: (ACTIVE,),
    CONFIRMED: (),
    REFUTED: (),
}

TERMINAL = (CONFIRMED, REFUTED)

# Finding-store verdicts (verify.py / findings.py vocabulary) mirrored onto hypotheses.
VERDICT_CONFIRMED = "confirmed"
VERDICT_FALSIFIED = "falsified"
_VERDICT_UNPROVEN = ("not_reproducible", "rejected")

EVENT_REGISTERED = "REGISTERED"
EVENT_STATUS_CHANGED = "STATUS_CHANGED"
EVENT_CLAIMED = "CLAIMED"
EVENT_RELEASED = "RELEASED"
EVENT_LEASE_RENEWED = "LEASE_RENEWED"
EVENT_EVIDENCE_ADDED = "EVIDENCE_ADDED"
EVENT_COUNTER_EVIDENCE_ADDED = "COUNTER_EVIDENCE_ADDED"
EVENT_LINKED = "LINKED"
EVENT_CHALLENGED = "CHALLENGED"

EVIDENCE_ORIGIN_AGENT = "agent"      # agent-generated reasoning / tooling output
EVIDENCE_ORIGIN_TARGET = "target"    # target-controlled material — untrusted
EVIDENCE_ORIGINS = (EVIDENCE_ORIGIN_AGENT, EVIDENCE_ORIGIN_TARGET)

# Relationship kinds (relationships.py matches candidates; only explicit link()
# calls make them authoritative).
DUPLICATE_OF = "DUPLICATE_OF"
RELATED_TO = "RELATED_TO"
CONTRADICTS = "CONTRADICTS"
SUPERSEDES = "SUPERSEDES"
RELATIONSHIP_KINDS = (DUPLICATE_OF, RELATED_TO, CONTRADICTS, SUPERSEDES)

MAX_CLAIM_LEN = 2000
MAX_TEST_LEN = 2000
MAX_SUMMARY_LEN = 600
MAX_PRECONDITIONS = 20
DEFAULT_LEASE_SECONDS = 900.0


# -- errors --------------------------------------------------------------------------

class SwarmError(Exception):
    """Base class for all registry errors."""


class UnknownHypothesisError(SwarmError):
    pass


class EngagementMismatchError(SwarmError):
    pass


class InvalidTransitionError(SwarmError):
    pass


class AlreadyClaimedError(SwarmError):
    pass


class OwnershipError(SwarmError):
    pass


class VersionConflictError(SwarmError):
    pass


class ValidationError(SwarmError):
    pass


class InvalidEventError(SwarmError):
    """An event that cannot be applied to current state (replay reports these)."""


# -- model ---------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


@dataclass(frozen=True)
class EvidenceRef:
    """One piece of evidence (or counter-evidence). Provenance is mandatory and
    decided at write time (the memory.py lesson): `origin` distinguishes agent-
    generated material from target-controlled material, and target-derived content
    can never be relabeled. `artifact_ref` points at where the full material lives
    (traffic.jsonl line, events.jsonl seq, finding id, forum event id) — the registry
    stores references and bounded summaries, never raw bodies."""
    evidence_id: str
    kind: str                    # observation | tool_result | finding | peer_trace | artifact | attempt
    origin: str                  # agent | target
    source_agent: str
    artifact_ref: str
    summary: str
    ts: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict) -> "EvidenceRef":
        return cls(**{k: row[k] for k in
                      ("evidence_id", "kind", "origin", "source_agent",
                       "artifact_ref", "summary", "ts")})


@dataclass
class Hypothesis:
    """One structured suspicion. JSON-round-trippable (asdict/from_dict) so replay
    and reports can move it around verbatim."""
    hypothesis_id: str
    engagement_id: str
    asset_ref: str
    weakness_class: str
    claim: str
    preconditions: list[str]
    expected_behavior: str
    proposed_test: str
    evidence_refs: list[dict] = field(default_factory=list)
    counter_evidence_refs: list[dict] = field(default_factory=list)
    created_by: str = ""
    owner: str | None = None
    status: str = PROPOSED
    related_hypotheses: list[dict] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    lease_expires_at: str | None = None
    version: int = 1
    security_boundary: str = ""
    principal: str = ""
    action: str = ""
    history: list[dict] = field(default_factory=list)
    challenged_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, row: dict) -> "Hypothesis":
        fields = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in row.items() if k in fields})


def _clip(value: str, limit: int, field_name: str) -> str:
    """Sanitize a caller-supplied string: str-coerce, strip control characters except
    newline/tab, cap length. Shared text never executes, so the only goals here are
    bounded context windows and honest storage."""
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    if not text.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    return text


def _clip_optional(value: str, limit: int) -> str:
    if value is None:
        return ""
    try:
        return _clip(value, limit, "text")
    except ValidationError:
        return ""


def _norm_preconditions(preconditions) -> tuple[str, ...]:
    if preconditions is None:
        return ()
    if isinstance(preconditions, str):
        preconditions = [preconditions]
    norm = []
    for item in list(preconditions)[:MAX_PRECONDITIONS]:
        text = _clip_optional(str(item), 200).strip().lower()
        if text:
            norm.append(text)
    return tuple(sorted(set(norm)))


# -- registry ------------------------------------------------------------------------

class HypothesisRegistry:
    """Thread-safe, event-sourced, engagement-scoped hypothesis store.

    Construct one per engagement (per run). `journal` (EventJournal) is required so
    every mutation is persisted-by-construction; `clock` is injectable for
    deterministic lease tests; `lease_seconds` is the default claim lease.
    """

    def __init__(self, engagement_id: str, journal: EventJournal,
                 clock: Callable[[], _dt.datetime] | None = None,
                 lease_seconds: float = DEFAULT_LEASE_SECONDS):
        self.engagement_id = str(engagement_id)
        self._journal = journal
        self._clock = clock or _utcnow
        self._lease_seconds = max(float(lease_seconds), 1.0)
        self._lock = threading.RLock()
        self._hyps: dict[str, Hypothesis] = {}
        self._applied: set[str] = set()     # event_ids already applied (idempotency)

    # -- introspection -------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._hyps)

    def stats(self) -> dict:
        with self._lock:
            by_status: dict[str, int] = {}
            for h in self._hyps.values():
                by_status[h.status] = by_status.get(h.status, 0) + 1
            now = self._clock()
            held = sum(1 for h in self._hyps.values()
                       if h.owner and h.lease_expires_at
                       and _parse_ts(h.lease_expires_at) > now)
            return {"engagement_id": self.engagement_id,
                    "total": len(self._hyps), "by_status": by_status,
                    "active_leases": held}

    # -- reads ----------------------------------------------------------------

    def get(self, hypothesis_id: str) -> Hypothesis:
        with self._lock:
            hyp = self._hyps.get(str(hypothesis_id))
        if hyp is None:
            raise UnknownHypothesisError(f"no hypothesis {hypothesis_id!r} in "
                                         f"engagement {self.engagement_id!r}")
        return hyp

    def has_equivalent(self, asset_ref: str, weakness_class: str,
                       include_terminal: bool = False) -> Hypothesis | None:
        """The first non-terminal hypothesis with the same (asset, weakness) signature,
        or None. The swarm's find-or-register hook and the benchmark's dedupe metric
        both key on this; terminal hypotheses never satisfy a new investigation."""
        key = (normalize_asset(asset_ref), normalize_weakness(weakness_class))
        with self._lock:
            for h in sorted(self._hyps.values(), key=lambda x: x.created_at):
                if (normalize_asset(h.asset_ref), normalize_weakness(h.weakness_class)) != key:
                    continue
                if not include_terminal and h.status in TERMINAL:
                    continue
                return h
        return None

    def list(self, *, status: str | None = None, asset_ref: str | None = None,
             weakness_class: str | None = None, owner: str | None = None,
             include_terminal: bool = True, limit: int = 200) -> list[Hypothesis]:
        """Filtered listing, oldest first, bounded (`limit` caps context size — no
        caller ever receives the full history implicitly)."""
        limit = max(1, min(int(limit), 500))
        with self._lock:
            rows = sorted(self._hyps.values(), key=lambda h: (h.created_at, h.hypothesis_id))
        out: list[Hypothesis] = []
        for h in rows:
            if status and h.status != status:
                continue
            if asset_ref and normalize_asset(h.asset_ref) != normalize_asset(asset_ref):
                continue
            if weakness_class and normalize_weakness(h.weakness_class) != normalize_weakness(weakness_class):
                continue
            if owner is not None and h.owner != owner:
                continue
            if not include_terminal and h.status in TERMINAL:
                continue
            out.append(h)
            if len(out) >= limit:
                break
        return out

    def active_for_asset(self, asset_ref: str, limit: int = 20) -> list[Hypothesis]:
        """Non-terminal hypotheses on one asset — the swarm briefing's sibling view."""
        rows = self.list(asset_ref=asset_ref, include_terminal=False, limit=limit)
        return [h for h in rows if h.status != PROPOSED or h.owner]

    def history(self, hypothesis_id: str) -> list[dict]:
        return list(self.get(hypothesis_id).history)

    # -- writes ----------------------------------------------------------------

    def register(self, *, asset_ref: str, weakness_class: str, claim: str,
                 created_by: str, preconditions=(), expected_behavior: str = "",
                 proposed_test: str = "", security_boundary: str = "",
                 principal: str = "", action: str = "") -> Hypothesis:
        """Register a new hypothesis (status PROPOSED). Registration never overwrites
        an existing hypothesis — an equivalent non-terminal one already on record is
        returned untouched, so the caller claims THAT instead of duplicating."""
        if not created_by or not str(created_by).strip():
            raise ValidationError("created_by (source agent) is required")
        payload = {
            "asset_ref": _clip(asset_ref, 300, "asset_ref"),
            "weakness_class": _clip(weakness_class, 100, "weakness_class"),
            "claim": _clip(claim, MAX_CLAIM_LEN, "claim"),
            "preconditions": list(_norm_preconditions(preconditions)),
            "expected_behavior": _clip_optional(expected_behavior, MAX_CLAIM_LEN),
            "proposed_test": _clip_optional(proposed_test, MAX_TEST_LEN),
            "security_boundary": _clip_optional(security_boundary, 100),
            "principal": _clip_optional(principal, 100),
            "action": _clip_optional(action, 100),
        }
        with self._lock:
            existing = self.has_equivalent(payload["asset_ref"], payload["weakness_class"])
            if existing is not None:
                return existing
            event = self._new_event(EVENT_REGISTERED, hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
                                    actor=str(created_by).strip(), payload=payload)
            self._append_and_apply(event)
            return self._hyps[event["hypothesis_id"]]

    def claim(self, hypothesis_id: str, agent: str,
              lease_seconds: float | None = None) -> Hypothesis:
        """Atomically take ownership. Wins iff PROPOSED/ACTIVE and (unowned or the
        lease expired); re-claim by the current owner just renews the lease. Losing
        racers get AlreadyClaimedError — exactly the AttackTree.claim() contract."""
        agent = _require_agent(agent)
        seconds = self._lease_seconds if lease_seconds is None else max(float(lease_seconds), 1.0)
        with self._lock:
            hyp = self.get(hypothesis_id)
            now = self._clock()
            if hyp.owner is not None and hyp.owner != agent:
                if hyp.lease_expires_at and _parse_ts(hyp.lease_expires_at) > now:
                    raise AlreadyClaimedError(
                        f"{hypothesis_id} is owned by {hyp.owner!r} until "
                        f"{hyp.lease_expires_at}")
                if hyp.status in TERMINAL:
                    raise InvalidTransitionError(
                        f"{hypothesis_id} is {hyp.status}; terminal hypotheses are "
                        f"not claimable")
            if hyp.owner == agent:
                event = self._new_event(EVENT_LEASE_RENEWED, hypothesis_id, agent,
                                        {"lease_until": _iso(now, seconds)})
            else:
                if hyp.status not in (PROPOSED, ACTIVE):
                    raise InvalidTransitionError(
                        f"cannot claim {hypothesis_id} from {hyp.status}")
                event = self._new_event(EVENT_CLAIMED, hypothesis_id, agent,
                                        {"lease_until": _iso(now, seconds),
                                         "from_status": hyp.status})
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def release(self, hypothesis_id: str, agent: str, reason: str = "") -> Hypothesis:
        """Give the hypothesis back (status stays ACTIVE — the research stands, the
        lease does not). Only the current owner may release."""
        agent = _require_agent(agent)
        payload = {"reason": _clip_optional(reason, 300)}
        with self._lock:
            hyp = self.get(hypothesis_id)
            if hyp.owner != agent:
                raise OwnershipError(
                    f"{hypothesis_id} is owned by {hyp.owner!r}, not {agent!r}")
            event = self._new_event(EVENT_RELEASED, hypothesis_id, agent, payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def renew_lease(self, hypothesis_id: str, agent: str,
                    lease_seconds: float | None = None) -> Hypothesis:
        agent = _require_agent(agent)
        seconds = self._lease_seconds if lease_seconds is None else max(float(lease_seconds), 1.0)
        with self._lock:
            hyp = self.get(hypothesis_id)
            if hyp.owner != agent:
                raise OwnershipError(
                    f"{hypothesis_id} is owned by {hyp.owner!r}, not {agent!r}")
            event = self._new_event(EVENT_LEASE_RENEWED, hypothesis_id, agent,
                                    {"lease_until": _iso(self._clock(), seconds)})
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def set_status(self, hypothesis_id: str, status: str, agent: str, *,
                   finding_id: str = "", reason: str = "",
                   expected_version: int | None = None) -> Hypothesis:
        """Validated lifecycle transition by the owner (or any agent for STALE/BLOCKED
        flags on unowned hypotheses). CONFIRMED/REFUTED are NOT settable here — they
        mirror the verification pipeline via record_verification_outcome()."""
        agent = _require_agent(agent)
        status = str(status).strip().upper()
        payload = {"to_status": status,
                   "reason": _clip_optional(reason, 300),
                   "finding_id": _clip_optional(finding_id, 64)}
        with self._lock:
            hyp = self.get(hypothesis_id)
            if expected_version is not None and hyp.version != int(expected_version):
                raise VersionConflictError(
                    f"{hypothesis_id}: expected version {expected_version}, "
                    f"current {hyp.version}")
            if hyp.owner is not None and hyp.owner != agent and hyp.status not in TERMINAL:
                if hyp.lease_expires_at and _parse_ts(hyp.lease_expires_at) > self._clock():
                    raise OwnershipError(
                        f"{hypothesis_id} is owned by {hyp.owner!r} (lease live)")
            if status in (CONFIRMED, REFUTED):
                raise InvalidTransitionError(
                    f"{status} is the independent verification pipeline's verdict — "
                    f"mirror it via record_verification_outcome(), never set it directly")
            if status not in VALID_TRANSITIONS.get(hyp.status, ()):
                raise InvalidTransitionError(
                    f"invalid transition {hyp.status} -> {status} for {hypothesis_id}")
            if status == AWAITING_VERIFICATION and not payload["finding_id"]:
                raise ValidationError(
                    "AWAITING_VERIFICATION requires the finding_id that the normal "
                    "pipeline recorded (a hypothesis is not its own proof)")
            event = self._new_event(EVENT_STATUS_CHANGED, hypothesis_id, agent, payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def attach_evidence(self, hypothesis_id: str, evidence: EvidenceRef,
                        by_agent: str) -> Hypothesis:
        return self._attach(hypothesis_id, evidence, by_agent,
                            EVENT_EVIDENCE_ADDED, "evidence_refs")

    def attach_counter_evidence(self, hypothesis_id: str, evidence: EvidenceRef,
                                by_agent: str) -> Hypothesis:
        return self._attach(hypothesis_id, evidence, by_agent,
                            EVENT_COUNTER_EVIDENCE_ADDED, "counter_evidence_refs")

    def _attach(self, hypothesis_id: str, evidence: EvidenceRef, by_agent: str,
                event_type: str, slot: str) -> Hypothesis:
        if not isinstance(evidence, EvidenceRef):
            raise ValidationError("evidence must be an EvidenceRef")
        if evidence.origin not in EVIDENCE_ORIGINS:
            raise ValidationError(
                f"evidence.origin must be one of {EVIDENCE_ORIGINS} — provenance is "
                f"mandatory (agent-generated vs target-controlled)")
        by_agent = _require_agent(by_agent)
        payload = {"evidence": evidence.to_dict()}
        with self._lock:
            hyp = self.get(hypothesis_id)
            # Evidence attachment is working state: only the current owner (or any
            # agent, when the hypothesis is unowned — e.g. PROPOSED or awaiting
            # verification) may curate it. A stale worker whose lease expired and
            # whose hypothesis was reclaimed must not write into the reclaiming
            # worker's record; peers contribute observations through the FORUM, and
            # the owner curates them into evidence.
            if hyp.owner is not None and hyp.owner != by_agent:
                raise OwnershipError(
                    f"{hypothesis_id} is owned by {hyp.owner!r}; evidence is curated "
                    f"by the owner — publish an observation to the forum instead")
            for existing in getattr(hyp, slot):
                if existing.get("evidence_id") == evidence.evidence_id:
                    return hyp            # idempotent attach (duplicate delivery)
            event = self._new_event(event_type, hypothesis_id, by_agent, payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def link(self, hypothesis_id: str, related_id: str, kind: str, by_agent: str,
             note: str = "") -> Hypothesis:
        """Record an authoritative relationship. Candidates from relationships.py are
        NEVER persisted here — a human/agent decision (with attribution) is required,
        and SUPERSEDES must carry a note explaining what made the old one obsolete."""
        kind = str(kind).strip().upper()
        if kind not in RELATIONSHIP_KINDS:
            raise ValidationError(f"kind must be one of {RELATIONSHIP_KINDS}")
        note_text = _clip_optional(note, 300)
        if kind == SUPERSEDES and not note_text:
            raise ValidationError("SUPERSEDES requires a note stating why")
        payload = {"related_id": str(related_id), "kind": kind, "note": note_text}
        with self._lock:
            hyp = self.get(hypothesis_id)
            if str(related_id) not in self._hyps:
                raise UnknownHypothesisError(f"related hypothesis {related_id!r} unknown")
            for rel in hyp.related_hypotheses:
                if rel.get("hypothesis_id") == str(related_id) and rel.get("kind") == kind:
                    return hyp            # idempotent link
            event = self._new_event(EVENT_LINKED, hypothesis_id,
                                    _require_agent(by_agent), payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def challenge(self, hypothesis_id: str, by_agent: str, reason: str) -> Hypothesis:
        """Record dissent. A challenge never changes status and never removes the
        hypothesis — it is added to the record so the verification pipeline (and the
        next worker briefing) sees it."""
        payload = {"reason": _clip(reason, MAX_SUMMARY_LEN, "reason")}
        with self._lock:
            self.get(hypothesis_id)
            event = self._new_event(EVENT_CHALLENGED, hypothesis_id,
                                    _require_agent(by_agent), payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def record_verification_outcome(self, hypothesis_id: str, *, verdict: str,
                                    finding_id: str, by_agent: str = "verify-pipeline",
                                    reason: str = "") -> Hypothesis:
        """THE ONLY PATH TO CONFIRMED/REFUTED — and it is a mirror, not a decision.

        Requires: the named finding was previously attached as evidence to this
        hypothesis, and the verdict is the FindingStore's vocabulary. `confirmed`
        mirrors to CONFIRMED, `falsified` mirrors to REFUTED; not_reproducible/rejected
        return the hypothesis to ACTIVE with the counter-evidence on record (still
        unproven, still re-attemptable). Nothing here touches FindingStore."""
        verdict = str(verdict).strip().lower()
        finding_id = _clip_optional(finding_id, 64)
        if not finding_id:
            raise ValidationError("finding_id is required")
        payload = {"verdict": verdict, "finding_id": finding_id,
                   "reason": _clip_optional(reason, 300)}
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not any(ev.get("kind") == "finding" and ev.get("artifact_ref") == finding_id
                       for ev in hyp.evidence_refs):
                raise ValidationError(
                    f"{finding_id} was never attached to {hypothesis_id} as evidence — "
                    f"verification mirrors only what the pipeline actually produced")
            if verdict == VERDICT_CONFIRMED:
                payload["to_status"] = CONFIRMED
            elif verdict == VERDICT_FALSIFIED:
                payload["to_status"] = REFUTED
            elif verdict in _VERDICT_UNPROVEN:
                payload["to_status"] = ACTIVE
            else:
                raise ValidationError(f"unknown verdict {verdict!r}")
            event = self._new_event(EVENT_STATUS_CHANGED, hypothesis_id,
                                    _require_agent(by_agent), payload)
            self._append_and_apply(event)
            return self._hyps[hypothesis_id]

    def candidate_relationships(self, hypothesis_id: str,
                                matcher=None) -> list:
        """Two-stage relationship candidates for one hypothesis against the rest of
        the registry. Candidates are advisory: nothing is stored, merged, or deleted
        by calling this (see relationships.py)."""
        from .relationships import DeterministicMatcher  # local import: advisory layer
        hyp = self.get(hypothesis_id)
        others = [h for h in self.list(limit=500) if h.hypothesis_id != hyp.hypothesis_id]
        matchers = []
        if matcher is not None:
            matchers.append(matcher)
        if not matchers:
            matchers.append(DeterministicMatcher())
        out = []
        for m in matchers:
            out.extend(m.candidates(hyp, others))
        return out

    # -- event application (the single write path, shared with replay) ----------

    def _new_event(self, etype: str, hypothesis_id: str, actor: str,
                   payload: dict) -> dict:
        return {"event_id": new_event_id(),
                "engagement_id": self.engagement_id,
                "type": etype,
                "hypothesis_id": hypothesis_id,
                "actor": actor,
                "ts": self._clock().isoformat(),
                "schema_version": 1,
                "expected_version": None,
                "payload": dict(payload)}

    def _append_and_apply(self, event: dict) -> dict:
        """Journal first, apply second — a failed journal write leaves state
        untouched (the mutation "didn't happen" and the caller sees the error)."""
        stored = self._journal.append(event)
        self.apply_event(stored)
        return stored

    def apply_event(self, event: dict) -> None:
        """Apply one domain event to state. THE ONLY MUTATOR of `self._hyps`; replay
        calls it directly. Validates against current state (transition table,
        ownership, version) and raises InvalidEventError before mutating anything —
        so a corrupt journal replays as a skipped-event report, not a corrupted
        registry.

        Causality rule: every clock-dependent judgment inside this method uses the
        EVENT's own timestamp, never the wall clock — the event was valid (or not)
        when it was written, and replay must reach the same verdict a live write
        would have. This is what makes a hostile/stale event unappliable at replay
        time (e.g. a CLAIMED racing a lease that was live when the event was
        written) instead of silently becoming an expired-lease reclaim because the
        real clock moved on."""
        with self._lock:
            eid = event.get("event_id")
            if eid and eid in self._applied:
                return          # idempotent: duplicate delivery applies once
            etype = event.get("type")
            hyp_id = str(event.get("hypothesis_id", ""))
            actor = str(event.get("actor", ""))
            payload = event.get("payload") or {}
            if not isinstance(payload, dict):
                raise InvalidEventError("payload must be a mapping")
            ts = str(event.get("ts") or utc_now())
            now_ref = _parse_ts(ts)     # the event's own timeline — replay-safe
            expected = event.get("expected_version")
            if etype == EVENT_REGISTERED:
                if hyp_id in self._hyps:
                    if eid:
                        self._applied.add(eid)
                    return          # idempotent: already applied (duplicate delivery)
                hyp = Hypothesis(
                    hypothesis_id=hyp_id, engagement_id=self.engagement_id,
                    asset_ref=payload.get("asset_ref", ""),
                    weakness_class=payload.get("weakness_class", ""),
                    claim=payload.get("claim", ""),
                    preconditions=list(payload.get("preconditions", [])),
                    expected_behavior=payload.get("expected_behavior", ""),
                    proposed_test=payload.get("proposed_test", ""),
                    security_boundary=payload.get("security_boundary", ""),
                    principal=payload.get("principal", ""),
                    action=payload.get("action", ""),
                    created_by=actor, status=PROPOSED,
                    created_at=ts, updated_at=ts)
                self._hyps[hyp_id] = hyp
                self._finish(hyp, event, ts, actor, f"registered by {actor}")
                return

            hyp = self._hyps.get(hyp_id)
            if hyp is None:
                raise InvalidEventError(f"{etype} for unknown hypothesis {hyp_id!r}")
            if expected is not None and hyp.version != int(expected):
                raise InvalidEventError(
                    f"{etype}: version {hyp.version} != expected {expected}")

            if etype == EVENT_CLAIMED:
                if hyp.owner is not None and hyp.owner != actor:
                    if hyp.lease_expires_at and _parse_ts(hyp.lease_expires_at) > now_ref:
                        raise InvalidEventError(
                            f"CLAIMED lost the race: owned by {hyp.owner!r} (lease "
                            f"live at event time)")
                if hyp.status not in (PROPOSED, ACTIVE):
                    raise InvalidEventError(f"CLAIMED from {hyp.status}")
                if payload.get("from_status") not in (None, hyp.status):
                    raise InvalidEventError("CLAIMED from_status mismatch")
                hyp.owner = actor
                hyp.lease_expires_at = payload.get("lease_until")
                if hyp.status == PROPOSED:
                    hyp.status = ACTIVE
            elif etype == EVENT_LEASE_RENEWED:
                if hyp.owner != actor:
                    raise InvalidEventError(
                        f"LEASE_RENEWED by non-owner {actor!r} (owner {hyp.owner!r})")
                hyp.lease_expires_at = payload.get("lease_until")
            elif etype == EVENT_RELEASED:
                if hyp.owner != actor:
                    raise InvalidEventError(
                        f"RELEASED by non-owner {actor!r} (owner {hyp.owner!r})")
                hyp.owner = None
                hyp.lease_expires_at = None
            elif etype == EVENT_STATUS_CHANGED:
                to_status = payload.get("to_status", "")
                mirror = payload.get("verdict") is not None
                if not mirror:
                    # Direct set_status path: re-validate ownership + the table here
                    # so replay enforces exactly what live writes enforced.
                    if (hyp.owner is not None and hyp.owner != actor
                            and hyp.status not in TERMINAL
                            and hyp.lease_expires_at
                            and _parse_ts(hyp.lease_expires_at) > now_ref):
                        raise InvalidEventError(
                            f"STATUS_CHANGED by non-owner {actor!r}")
                    if to_status in (CONFIRMED, REFUTED):
                        raise InvalidEventError(
                            "CONFIRMED/REFUTED require a verification-mirror event")
                if to_status not in VALID_TRANSITIONS.get(hyp.status, ()):
                    raise InvalidEventError(
                        f"invalid transition {hyp.status} -> {to_status}")
                if to_status == AWAITING_VERIFICATION and not payload.get("finding_id"):
                    raise InvalidEventError("AWAITING_VERIFICATION without finding_id")
                hyp.owner = None
                hyp.lease_expires_at = None
                if to_status == ACTIVE and hyp.status == AWAITING_VERIFICATION:
                    pass          # returned to the workable pool, unproven
                hyp.status = to_status
            elif etype in (EVENT_EVIDENCE_ADDED, EVENT_COUNTER_EVIDENCE_ADDED):
                ev = payload.get("evidence")
                if not isinstance(ev, dict):
                    raise InvalidEventError("evidence payload must be a mapping")
                if ev.get("origin") not in EVIDENCE_ORIGINS:
                    raise InvalidEventError("evidence origin missing/invalid")
                slot = "evidence_refs" if etype == EVENT_EVIDENCE_ADDED else "counter_evidence_refs"
                if any(x.get("evidence_id") == ev.get("evidence_id")
                       for x in getattr(hyp, slot)):
                    return        # idempotent attach
                getattr(hyp, slot).append(dict(ev))
            elif etype == EVENT_LINKED:
                rel = {"hypothesis_id": payload.get("related_id", ""),
                       "kind": payload.get("kind", ""), "created_by": actor,
                       "origin": "agent", "ts": ts, "note": payload.get("note", "")}
                if any(r.get("hypothesis_id") == rel["hypothesis_id"]
                       and r.get("kind") == rel["kind"]
                       for r in hyp.related_hypotheses):
                    return        # idempotent link
                if not rel["hypothesis_id"]:
                    raise InvalidEventError("LINKED without related_id")
                hyp.related_hypotheses.append(rel)
            elif etype == EVENT_CHALLENGED:
                if actor not in hyp.challenged_by:
                    hyp.challenged_by.append(actor)
            else:
                raise InvalidEventError(f"unknown event type {etype!r}")

            if eid:
                self._applied.add(eid)
            self._finish(hyp, event, ts, actor, _describe(etype, actor, payload))

    def _finish(self, hyp: Hypothesis, event: dict, ts: str, actor: str,
                detail: str) -> None:
        if event.get("type") != EVENT_REGISTERED:
            hyp.version += 1
        hyp.updated_at = ts
        hyp.history.append({"ts": ts, "event": event.get("type", ""), "actor": actor,
                            "detail": detail})

    # -- replay support ---------------------------------------------------------

    def load_state(self, rows: list[dict]) -> None:
        """Bulk-load a state snapshot (used by tests and by replay() as the fast
        path when a journal is rebuilt from a checkpoint). Not a mutation path."""
        with self._lock:
            self._hyps = {r["hypothesis_id"]: Hypothesis.from_dict(r) for r in rows}


# -- helpers ---------------------------------------------------------------------------

_TECHNIQUE_WEAKNESS = {
    "auth.test": "authentication",
    "auth.bypass": "authentication-bypass",
    "access.control": "access-control",
    "access.idor": "idor",
    "injection.sqli": "sql-injection",
    "injection.cmd": "command-injection",
    "ssrf": "ssrf",
    "xss.reflected": "reflected-xss",
    "info.sensitive": "information-disclosure",
    "privesc.admin": "privilege-escalation",
    "data.exfil": "data-exposure",
    "session.steal": "session-hijack",
    "internal.access": "internal-access-via-ssrf",
}


def weakness_for_technique(technique: str) -> str:
    """Deterministic weakness_class for a tree technique — the vocabulary the swarm's
    auto-registered hypotheses use, chosen per-technique (never a coarse family) so
    concurrent suppression only fires on genuinely equivalent work."""
    return _TECHNIQUE_WEAKNESS.get(technique, f"technique:{technique}")


def normalize_asset(asset_ref: str) -> str:
    """Signature normalization for an asset: lowercase, scheme stripped, query and
    fragment dropped, trailing slash stripped. Comparison-only — never rewrites the
    stored asset_ref."""
    text = (asset_ref or "").strip().lower()
    for sep in ("?", "#"):
        text = text.split(sep, 1)[0]
    for scheme in ("https://", "http://", "//"):
        if text.startswith(scheme):
            text = text[len(scheme):]
            break
    return text.rstrip("/")


def normalize_weakness(weakness_class: str) -> str:
    return (weakness_class or "").strip().lower().replace(" ", "-")


def _require_agent(agent: str) -> str:
    name = str(agent or "").strip()
    if not name:
        raise ValidationError("agent identity is required for every write")
    return name


def _iso(now: _dt.datetime, seconds: float) -> str:
    return (now + _dt.timedelta(seconds=seconds)).isoformat()


def _parse_ts(value: str) -> _dt.datetime:
    ts = _dt.datetime.fromisoformat(str(value))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts


def _describe(etype: str, actor: str, payload: dict) -> str:
    if etype == EVENT_CLAIMED:
        return f"claimed by {actor} (lease until {payload.get('lease_until')})"
    if etype == EVENT_RELEASED:
        return f"released by {actor}"
    if etype == EVENT_LEASE_RENEWED:
        return f"lease renewed by {actor}"
    if etype == EVENT_STATUS_CHANGED:
        return (f"status -> {payload.get('to_status')}"
                + (f" (verdict {payload.get('verdict')} on finding "
                   f"{payload.get('finding_id')})" if payload.get("verdict") else "")
                + (f"; {payload['reason']}" if payload.get("reason") else ""))
    if etype in (EVENT_EVIDENCE_ADDED, EVENT_COUNTER_EVIDENCE_ADDED):
        ev = payload.get("evidence", {})
        prefix = "counter-evidence" if etype == EVENT_COUNTER_EVIDENCE_ADDED else "evidence"
        return f"{prefix} {ev.get('kind')} ({ev.get('origin')}) by {actor}: {ev.get('summary', '')}"
    if etype == EVENT_LINKED:
        return f"linked {payload.get('kind')} -> {payload.get('related_id')} by {actor}"
    if etype == EVENT_CHALLENGED:
        return f"challenged by {actor}: {payload.get('reason', '')}"
    return f"{etype} by {actor}"

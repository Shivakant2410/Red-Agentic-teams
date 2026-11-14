"""redteam.swarm — the collective-intelligence layer (Phase C1).

One run-scoped package, four capabilities, one principle:

    an observation is not a hypothesis; a hypothesis is not a finding; a finding is
    not confirmed until the independent verification pipeline confirms it.

Modules:

  journal.py       EventJournal — append-only, engagement-scoped lifecycle history
                   (JSONL; idempotent by event_id; write failures raise, never vanish).
  hypotheses.py    Hypothesis model + HypothesisRegistry — thread-safe lifecycle,
                   atomic claims, leases, optimistic versions, evidence, links,
                   challenges, and the verification MIRROR (the only CONFIRMED path).
  forum.py         ResearchForum — typed, attributable, quarantined, redacted,
                   bounded-read communication between specialists.
  relationships.py Two-stage duplicate/relationship matching — candidates only,
                   never authoritative; SUPERSEDES is never machine-generated.
  projections.py   replay()/replay_into() — deterministic state reconstruction from
                   the journal, with a skip-and-report policy for corrupt events.

The ResearchBundle below is the smallest orchestrator-facing facade: it wires the
registry + forum + journal for one engagement, optionally persisting under the run
directory and mirroring forum traffic to the run's EventBus for the dashboard.
Everything here is additive to the existing swarm: when no bundle is constructed,
the swarm behaves exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .forum import ForumMessage, MessageRejectedError, ResearchForum, redact_secrets
from .hypotheses import (AWAITING_VERIFICATION, ACTIVE, BLOCKED, CONFIRMED, DEFAULT_LEASE_SECONDS,
                         PROPOSED, REFUTED, STALE, AlreadyClaimedError, EvidenceRef,
                         Hypothesis, HypothesisRegistry, InvalidTransitionError,
                         OwnershipError, SwarmError, UnknownHypothesisError,
                         ValidationError, VersionConflictError,
                         weakness_for_technique)
from .journal import EventJournal
from .projections import ReplayReport, replay, replay_into
from .relationships import (CONTRADICTS, DUPLICATE_OF, RELATED_TO, SUPERSEDES,
                            DeterministicMatcher, HypothesisSignature,
                            LexicalOverlapMatcher, NullSemanticMatcher,
                            RelationshipCandidate, SemanticMatcher)

__all__ = [
    # facade
    "ResearchBundle",
    # registry
    "Hypothesis", "HypothesisRegistry", "EvidenceRef",
    "PROPOSED", "ACTIVE", "AWAITING_VERIFICATION", "CONFIRMED", "REFUTED",
    "BLOCKED", "STALE",
    "AlreadyClaimedError", "InvalidTransitionError", "OwnershipError",
    "SwarmError", "UnknownHypothesisError", "ValidationError", "VersionConflictError",
    "weakness_for_technique",
    # forum
    "ResearchForum", "ForumMessage", "MessageRejectedError", "redact_secrets",
    # relationships
    "DeterministicMatcher", "LexicalOverlapMatcher", "NullSemanticMatcher",
    "HypothesisSignature", "RelationshipCandidate", "SemanticMatcher",
    "DUPLICATE_OF", "RELATED_TO", "CONTRADICTS", "SUPERSEDES",
    # journal + replay
    "EventJournal", "ReplayReport", "replay", "replay_into",
]


@dataclass
class ResearchBundle:
    """The per-run wiring the orchestrator holds: registry + forum over one journal,
    optionally persisted under the run directory and mirrored to the dashboard bus.

    - run_dir=None  → in-memory only (legacy callers, tests): zero file I/O.
    - run_dir given → research_journal.jsonl + research_forum.jsonl in the run dir,
      AND a killed run's state is RESTORED before the bundle is handed out (review
      fix 2): the journal is replayed through the registry's own apply path, so
      hypotheses, statuses, evidence, relationships, ownership, and still-live
      leases survive a restart. `recovery` carries the ReplayReport (events
      applied / skipped and why) — recovery is observable, never silent. The
      forum restores its own side independently (see ResearchForum._load).
    - bus           → every non-quarantined forum message is also emitted as a
      `research.<type>` event (best-effort; the dashboard sees the swarm think).
    """

    registry: HypothesisRegistry
    forum: ResearchForum
    journal: EventJournal
    recovery: ReplayReport | None = None   # None for in-memory bundles: nothing to replay

    @classmethod
    def for_run(cls, engagement_id: str, *, run_dir: str | Path | None = None,
                bus=None, lease_seconds: float | None = None) -> "ResearchBundle":
        engagement_id = str(engagement_id or "engagement")
        if run_dir is None:
            journal = EventJournal(engagement_id)
            forum = ResearchForum(engagement_id, bus=bus)
            registry = HypothesisRegistry(engagement_id, journal=journal,
                                          lease_seconds=lease_seconds
                                          or DEFAULT_LEASE_SECONDS)
            return cls(registry=registry, forum=forum, journal=journal)
        run_dir = Path(run_dir)
        journal = EventJournal(engagement_id, run_dir / "research_journal.jsonl")
        forum = ResearchForum(engagement_id, run_dir / "research_forum.jsonl",
                              bus=bus)
        # RESTART RECOVERY (fix 2): replay the persisted journal INTO the live,
        # file-backed journal — the registry continues appending after the replayed
        # prefix (new events get seq after it), and any corrupt/foreign/invalid
        # event is skipped and REPORTED, never fatal. Ownership and lease expiry are
        # restored verbatim: a lease still inside its expiry stays owned (stealing
        # it raises AlreadyClaimedError exactly as pre-restart); an expired lease is
        # reclaimable through the normal claim path. Replay uses the SAME
        # apply_event() the live writes used, so recovered state cannot diverge
        # from what the pre-restart run actually recorded.
        registry, recovery = replay_into(journal, journal=journal,
                                         lease_seconds=lease_seconds
                                         or DEFAULT_LEASE_SECONDS)
        return cls(registry=registry, forum=forum, journal=journal, recovery=recovery)

    # -- convenience used by the orchestrator's claim loop --------------------

    def claim_or_register(self, *, asset_ref: str, weakness_class: str, claim: str,
                          agent: str, technique: str = "",
                          expected_behavior: str = "", proposed_test: str = "",
                          lease_seconds: float | None = None):
        """Find-or-register + atomically claim one hypothesis.

        Identity is the registry's FULL identity (asset, weakness, claim,
        preconditions, expected behavior, boundary, principal, action — review fix
        1): an identical re-registration returns the SAME record; a same-asset
        same-weakness suspicion with any differing attribute is a DISTINCT record
        (the relationship layer suggests what looks like a duplicate, registration
        never silently merges). Returns (hypothesis, [registered_event,
        claimed_event]) or (None, ()) when the claim was lost to a concurrent
        worker (AlreadyClaimedError) — the caller treats that exactly like a lost
        AttackTree.claim() race."""
        agent = str(agent)
        hyp = self.registry.register(
            asset_ref=asset_ref, weakness_class=weakness_class, claim=claim,
            created_by=agent, expected_behavior=expected_behavior,
            proposed_test=proposed_test)
        was_new = hyp.version == 1          # captured BEFORE the claim mutates it
        try:
            claimed = self.registry.claim(hyp.hypothesis_id, agent,
                                          lease_seconds=lease_seconds)
        except SwarmError:
            return None, ()
        events = []
        if was_new:
            events.append(self.publish_lifecycle(
                "hypothesis.registered", claimed, agent, role="exploit",
                payload={"hypothesis_id": claimed.hypothesis_id,
                         "asset_ref": claimed.asset_ref,
                         "weakness_class": claimed.weakness_class,
                         "claim": claimed.claim}))
        events.append(self.publish_lifecycle(
            "hypothesis.claimed", claimed, agent, role="exploit",
            payload={"hypothesis_id": claimed.hypothesis_id,
                     "lease_until": claimed.lease_expires_at}))
        return claimed, [ev for ev in events if ev is not None]

    def publish_lifecycle(self, event_type: str, hyp, agent: str, *, role: str,
                          payload: dict | None = None):
        """Mirror a registry lifecycle moment into the forum (typed, attributable).
        Never raises — forum trouble must not break the claim loop."""
        try:
            base = {"hypothesis_id": hyp.hypothesis_id}
            base.update(payload or {})
            return self.forum.publish(event_type, source_agent=agent, payload=base,
                                      agent_role=role,
                                      subject_hypothesis_id=hyp.hypothesis_id,
                                      asset_ref=hyp.asset_ref)
        except Exception:
            return None

    def worker_note(self, hyp, *, related_ids=(), limit: int = 12) -> str:
        """The EVIDENCE-RICH research note injected into a specialist's briefing
        (review fix 4): what the hypothesis claims and requires, what was already
        tried and what it produced (negative results WITH their summaries), what
        evidence/counter-evidence exists (with artifact refs so the worker can pull
        the full material via search_peer_traces), what peers observed (forum
        observations with attribution), challenges and open questions, sibling
        hypotheses, and advisory relationship candidates (DUPLICATE_OF/RELATED_TO/
        CONTRADICTS — suggestions only, never auto-applied). Every line is bounded;
        the whole note is bounded; quarantined forum content is excluded upstream
        (relevant_context). Never raises; empty string when there is nothing to say."""
        try:
            lines: list[str] = []

            def section(build) -> None:
                """Per-section resilience (review fix 4): one failing source
                (e.g. a broken matcher) degrades ITS lines only — the rest of
                the briefing still reaches the worker."""
                try:
                    lines.extend(build())
                except Exception:
                    return

            # The claim's own shape: what is suspected, what must already hold,
            # what behavior is expected — the worker tests THIS, not a paraphrase.
            section(lambda: (["PRECONDITIONS to satisfy first: "
                              + "; ".join(hyp.preconditions[:5])]
                             if hyp.preconditions else []))
            section(lambda: ([f"EXPECTED BEHAVIOR if real: {hyp.expected_behavior[:200]}"]
                             if hyp.expected_behavior else []))
            section(lambda: ([f"PROPOSED TEST on record: {hyp.proposed_test[:200]}"]
                             if hyp.proposed_test else []))
            # Positive evidence: what already supports the suspicion.
            section(lambda: self._evidence_lines(hyp.evidence_refs,
                                                 "SUPPORTING EVIDENCE", 4))
            # Negative results: prior attempts that produced NO proof, with their
            # actual summaries — the worker must not repeat the same requests.
            section(lambda: self._evidence_lines(
                hyp.counter_evidence_refs,
                "NEGATIVE RESULTS (prior attempts, no proof)", 4))
            # Peer observations from the forum: attributable, bounded, newest first.
            def _peer() -> list[str]:
                msgs = self.forum.relevant_context(hyp.hypothesis_id,
                                                   related_ids=related_ids,
                                                   asset=hyp.asset_ref, limit=limit)
                if not msgs:
                    return []
                notes = "; ".join(
                    f"[{m.source_agent}] {str(m.payload.get('summary', ''))[:140]}"
                    f" (ref {m.event_id[:8]})"
                    for m in msgs[:5])
                return [f"PEER OBSERVATIONS: {notes}"]
            section(_peer)
            # Open questions: challenges are recorded dissent the worker must
            # address; AWAITING_VERIFICATION says a finding is in the pipeline.
            def _open_questions() -> list[str]:
                out = []
                if hyp.challenged_by:
                    reasons = "; ".join(
                        h.get("detail", "")[:100] for h in reversed(hyp.history)
                        if h.get("event") == "CHALLENGED")[:300]
                    out.append(f"OPEN QUESTION — challenged by "
                               f"{', '.join(hyp.challenged_by[:3])}: "
                               f"{reasons or 'reasons on record'}")
                if hyp.status == AWAITING_VERIFICATION:
                    out.append("AWAITING VERIFICATION: a finding from this hypothesis "
                               "is in the independent verification pipeline — do NOT "
                               "re-prove or self-confirm it.")
                return out
            section(_open_questions)
            # Siblings: every OTHER non-terminal hypothesis on this asset —
            # including registered-but-unclaimed ones, because knowing about a
            # distinct sibling record is the whole point of full-identity
            # registration (review fix 1): consider a relationship link, not a
            # re-registration.
            def _siblings() -> list[str]:
                sibs = [h for h in self.registry.list(asset_ref=hyp.asset_ref,
                                                      include_terminal=False)
                        if h.hypothesis_id != hyp.hypothesis_id]
                if not sibs:
                    return []
                names = "; ".join(f"{h.weakness_class} [{h.status}]"
                                  + (f" owned by {h.owner}" if h.owner else "")
                                  for h in sibs[:5])
                return [f"SIBLING HYPOTHESES on {hyp.asset_ref}: {names} — "
                        f"do not re-run what another worker already covers."]
            section(_siblings)
            # Advisory relationships: what the deterministic matcher thinks about
            # duplication — candidates only, never auto-applied.
            def _candidates() -> list[str]:
                cands = self.registry.candidate_relationships(hyp.hypothesis_id)
                if not cands:
                    return []
                shown = "; ".join(f"{c.kind} -> {c.other_id} ({c.reason[:80]})"
                                  for c in cands[:4])
                return [f"RELATIONSHIP CANDIDATES (advisory — verify before "
                        f"acting): {shown}"]
            section(_candidates)
            return "\n".join(lines[:16])
        except Exception:
            return ""

    @staticmethod
    def _evidence_lines(refs: list, header: str, cap: int) -> list[str]:
        """Bounded 'HEADER: summary (ref) [...]' lines for one evidence slot."""
        if not refs:
            return []
        shown = "; ".join(
            f"{r.get('summary', '')[:120]} (ref {r.get('artifact_ref', '')})"
            for r in refs[-cap:])
        return [f"{header}: {shown}"]

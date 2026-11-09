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
      so a killed run's hypothesis state replays deterministically.
    - bus           → every non-quarantined forum message is also emitted as a
      `research.<type>` event (best-effort; the dashboard sees the swarm think).
    """

    registry: HypothesisRegistry
    forum: ResearchForum
    journal: EventJournal

    @classmethod
    def for_run(cls, engagement_id: str, *, run_dir: str | Path | None = None,
                bus=None, lease_seconds: float | None = None) -> "ResearchBundle":
        engagement_id = str(engagement_id or "engagement")
        if run_dir is None:
            journal = EventJournal(engagement_id)
            forum = ResearchForum(engagement_id, bus=bus)
        else:
            run_dir = Path(run_dir)
            journal = EventJournal(engagement_id, run_dir / "research_journal.jsonl")
            forum = ResearchForum(engagement_id, run_dir / "research_forum.jsonl",
                                  bus=bus)
        registry = HypothesisRegistry(engagement_id, journal=journal,
                                      lease_seconds=lease_seconds
                                      or DEFAULT_LEASE_SECONDS)
        return cls(registry=registry, forum=forum, journal=journal)

    # -- convenience used by the orchestrator's claim loop --------------------

    def claim_or_register(self, *, asset_ref: str, weakness_class: str, claim: str,
                          agent: str, technique: str = "",
                          expected_behavior: str = "", proposed_test: str = "",
                          lease_seconds: float | None = None):
        """Find-or-register the (asset, weakness) hypothesis, then atomically claim it.

        Returns (hypothesis, [registered_event, claimed_event]) or (None, ()) when
        the claim was lost to a concurrent worker (AlreadyClaimedError) — the caller
        treats that exactly like a lost AttackTree.claim() race. Registration reuses
        an equivalent non-terminal hypothesis instead of duplicating it; a reused
        hypothesis still publishes its claim event (the swarm must see who works it
        now)."""
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

    def worker_note(self, hyp, *, related_ids=(), limit: int = 8) -> str:
        """The bounded research note injected into a specialist's briefing: sibling
        hypotheses on the same asset, prior attempts (counter-evidence), challenges.
        Quarantined forum content is excluded upstream (relevant_context). Never
        raises; empty string when there is nothing to say."""
        try:
            siblings = [h for h in self.registry.active_for_asset(hyp.asset_ref)
                        if h.hypothesis_id != hyp.hypothesis_id]
            lines = []
            attempts = len(hyp.counter_evidence_refs)
            if attempts:
                lines.append(f"PRIOR ATTEMPTS on this hypothesis: {attempts} earlier "
                             f"try/tries produced no proof (see counter-evidence) — "
                             f"read them before repeating the same requests.")
            if siblings:
                names = "; ".join(f"{h.weakness_class} [{h.status}]"
                                  for h in siblings[:5])
                lines.append(f"SIBLING HYPOTHESES on {hyp.asset_ref}: {names} — "
                             f"do not re-run what another worker already covers.")
            msgs = self.forum.relevant_context(hyp.hypothesis_id,
                                               related_ids=related_ids,
                                               asset=hyp.asset_ref, limit=limit)
            if msgs:
                notes = "; ".join(f"{m.source_agent}: {str(m.payload.get('summary', ''))[:120]}"
                                  for m in msgs[:5])
                lines.append(f"RESEARCH CONTEXT: {notes}")
            if hyp.challenged_by:
                lines.append(f"CHALLENGED BY: {', '.join(hyp.challenged_by[:3])} — "
                             f"address the recorded reasons.")
            return "\n".join(lines)
        except Exception:
            return ""

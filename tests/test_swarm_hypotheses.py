"""Phase C1 domain tests — the hypothesis registry (redteam/swarm/hypotheses.py).

Covers the spec's registry block: register, retrieve, lifecycle updates, evidence,
counter-evidence, linking, invalid transitions, history, and engagement isolation.
All timestamps/leases run on an injected clock — fully deterministic, no sleeps.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from redteam.swarm import (ACTIVE, AWAITING_VERIFICATION, BLOCKED, CONFIRMED, PROPOSED,
                           REFUTED, STALE, AlreadyClaimedError, EvidenceRef,
                           EventJournal, HypothesisRegistry, InvalidTransitionError,
                           OwnershipError, UnknownHypothesisError, ValidationError,
                           VersionConflictError, replay, weakness_for_technique)


class FakeClock:
    """Deterministic clock the registry accepts as `clock=` — advance() simulates
    time passing (lease expiry) without a single sleep()."""

    def __init__(self):
        self.t = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)

    def __call__(self) -> _dt.datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += _dt.timedelta(seconds=seconds)


@pytest.fixture()
def clock():
    return FakeClock()


def make_registry(tmp_path, clock, engagement="eng-1", persist=True):
    journal = EventJournal(engagement,
                           tmp_path / "journal.jsonl" if persist else None)
    return HypothesisRegistry(engagement, journal=journal, clock=clock)


def make_hyp(registry, **over):
    params = dict(asset_ref="https://api.example.com/admin",
                  weakness_class="access-control",
                  claim="Admin panel reachable without authentication",
                  created_by="recon-1",
                  preconditions=("no session required",),
                  expected_behavior="admin data returned with status 200",
                  proposed_test="GET /admin unauthenticated; expect 200 + admin marker")
    params.update(over)
    return registry.register(**params)


def ev(eid="ev-1", kind="observation", origin="agent", artifact="traffic.jsonl:12",
       summary="odd 403 body", agent="exploit-w0"):
    return EvidenceRef(evidence_id=eid, kind=kind, origin=origin,
                       source_agent=agent, artifact_ref=artifact,
                       summary=summary, ts="2026-01-01T12:00:00+00:00")


# -- registration & retrieval -----------------------------------------------------------

def test_register_creates_proposed_hypothesis_with_spec_fields(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    for field in ("hypothesis_id", "engagement_id", "asset_ref", "weakness_class",
                  "claim", "preconditions", "expected_behavior", "proposed_test",
                  "evidence_refs", "counter_evidence_refs", "created_by", "owner",
                  "status", "related_hypotheses", "created_at", "updated_at",
                  "lease_expires_at", "version"):
        assert field in h.to_dict(), f"missing spec field {field}"
    assert h.status == PROPOSED
    assert h.owner is None and h.version == 1
    assert h.engagement_id == "eng-1"
    assert h.created_by == "recon-1"
    # IDs stable across reads; timestamps are UTC ISO-8601
    assert reg.get(h.hypothesis_id).hypothesis_id == h.hypothesis_id
    parsed = _dt.datetime.fromisoformat(h.created_at)
    assert parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0


def test_register_requires_identity_and_content(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    with pytest.raises(ValidationError):
        reg.register(asset_ref="https://x.example.com", weakness_class="w",
                     claim="c", created_by="  ")
    with pytest.raises(ValidationError):
        reg.register(asset_ref="", weakness_class="w", claim="c", created_by="a")
    with pytest.raises(ValidationError):
        reg.register(asset_ref="https://x.example.com", weakness_class="w",
                     claim="   ", created_by="a")


def test_get_unknown_raises_and_list_filters(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    with pytest.raises(UnknownHypothesisError):
        reg.get("hyp-doesnotexist")
    a = make_hyp(reg, asset_ref="https://x.example.com/admin", weakness_class="idor")
    b = make_hyp(reg, asset_ref="https://x.example.com/users", weakness_class="idor")
    make_hyp(reg, asset_ref="https://x.example.com/admin", weakness_class="xss")
    assert [h.hypothesis_id for h in reg.list(weakness_class="idor")] == \
        sorted([a.hypothesis_id, b.hypothesis_id])
    assert len(reg.list(asset_ref="https://x.example.com/admin/")) == 2   # normalized asset
    assert len(reg.list(status=PROPOSED)) == 3


def test_registration_reuses_equivalent_non_terminal_hypothesis(tmp_path, clock):
    """find-or-register: a second registration of the same (asset, weakness) returns
    the SAME record — duplication is prevented at the source, never deleted."""
    reg = make_registry(tmp_path, clock)
    a = make_hyp(reg)
    b = make_hyp(reg, claim="worded completely differently but same target and class")
    assert a.hypothesis_id == b.hypothesis_id
    assert len(reg.list()) == 1


def test_weakness_map_is_per_technique(tmp_path):
    """Coarse families would false-positive dedupe; each technique owns its class."""
    assert weakness_for_technique("injection.sqli") != weakness_for_technique("injection.cmd")
    assert weakness_for_technique("access.idor") == "idor"
    assert weakness_for_technique("totally-unknown") == "technique:totally-unknown"


# -- lifecycle ---------------------------------------------------------------------------

def test_full_happy_path_lifecycle(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    claimed = reg.claim(h.hypothesis_id, "exploit-w0")
    assert (claimed.status, claimed.owner) == (ACTIVE, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id, ev(), "exploit-w0")
    # the landing finding goes through the NORMAL pipeline; it is attached here as
    # finding-kind evidence, which is what makes the mirror possible at all
    reg.attach_evidence(h.hypothesis_id,
                        ev(eid="ev-f1", kind="finding", artifact="F-1",
                           summary="high: auth bypass @ /admin"), "exploit-w0")
    await_ = reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0",
                            finding_id="F-1")
    assert await_.status == AWAITING_VERIFICATION
    # Ownership transfers to verification: the worker no longer holds the lease
    assert await_.owner is None
    confirmed = reg.record_verification_outcome(h.hypothesis_id, verdict="confirmed",
                                                finding_id="F-1")
    assert confirmed.status == CONFIRMED
    assert [e["event"] for e in confirmed.history] == \
        ["REGISTERED", "CLAIMED", "EVIDENCE_ADDED", "EVIDENCE_ADDED",
         "STATUS_CHANGED", "STATUS_CHANGED"]


def test_refuted_path_requires_falsified_verdict(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id,
                        ev(eid="ev-f", kind="finding", artifact="F-9"), "exploit-w0")
    reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0", finding_id="F-9")
    out = reg.record_verification_outcome(h.hypothesis_id, verdict="falsified",
                                          finding_id="F-9")
    assert out.status == REFUTED


def test_not_reproducible_returns_hypothesis_to_active(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id,
                        ev(eid="ev-f", kind="finding", artifact="F-9"), "exploit-w0")
    reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0", finding_id="F-9")
    out = reg.record_verification_outcome(h.hypothesis_id, verdict="not_reproducible",
                                          finding_id="F-9")
    assert out.status == ACTIVE


def test_invalid_lifecycle_transitions_rejected(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    # PROPOSED -> CONFIRMED is the self-promotion fantasy; refused
    with pytest.raises(InvalidTransitionError):
        reg.set_status(h.hypothesis_id, CONFIRMED, "recon-1", finding_id="F-1")
    # AWAITING_VERIFICATION cannot be reached from PROPOSED
    with pytest.raises(InvalidTransitionError):
        reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "recon-1",
                       finding_id="F-1")
    claimed = reg.claim(h.hypothesis_id, "exploit-w0")
    # AWAITING_VERIFICATION REQUIRES the finding_id (a hypothesis is not its own proof)
    with pytest.raises(ValidationError):
        reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0")
    # PROPOSED->... already moved; CLAIMED from ACTIVE again is a lease renew, fine —
    # but a direct set to PROPOSED is not in the table
    with pytest.raises(InvalidTransitionError):
        reg.set_status(h.hypothesis_id, PROPOSED, "exploit-w0")
    assert claimed.status == ACTIVE


def test_set_status_cannot_bypass_verification_pipeline(tmp_path, clock):
    """The invariant under test: no agent path sets CONFIRMED/REFUTED directly."""
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id,
                        ev(eid="ev-f", kind="finding", artifact="F-1"), "exploit-w0")
    reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0", finding_id="F-1")
    with pytest.raises(InvalidTransitionError):
        reg.set_status(h.hypothesis_id, CONFIRMED, "verify-pipeline", finding_id="F-1")
    with pytest.raises(InvalidTransitionError):
        reg.set_status(h.hypothesis_id, REFUTED, "verify-pipeline", finding_id="F-1")


def test_verification_mirror_requires_attached_finding(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.set_status(h.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0", finding_id="F-77")
    with pytest.raises(ValidationError):
        reg.record_verification_outcome(h.hypothesis_id, verdict="confirmed",
                                        finding_id="F-OTHER")
    with pytest.raises(ValidationError):
        reg.record_verification_outcome(h.hypothesis_id, verdict="confirmed",
                                        finding_id="F-77")  # attached as finding? no —
    # F-77 was named in set_status but never ATTACHED as finding-kind evidence


def test_blocked_and_stale_are_reversible_side_states(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    assert reg.set_status(h.hypothesis_id, BLOCKED, "exploit-w0",
                          reason="needs a session first").status == BLOCKED
    assert reg.set_status(h.hypothesis_id, ACTIVE, "exploit-w0").status == ACTIVE
    assert reg.set_status(h.hypothesis_id, STALE, "exploit-w0",
                          reason="endpoint vanished").status == STALE
    assert reg.set_status(h.hypothesis_id, ACTIVE, "exploit-w0").status == ACTIVE


# -- evidence ----------------------------------------------------------------------------

def test_evidence_and_counter_evidence_append_only(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id, ev(eid="ev-1"), "exploit-w0")
    reg.attach_counter_evidence(h.hypothesis_id,
                                ev(eid="cev-1", origin="target",
                                   artifact="traffic.jsonl:40",
                                   summary="control also returns 200"), "exploit-w0")
    h2 = reg.get(h.hypothesis_id)
    assert len(h2.evidence_refs) == 1 and len(h2.counter_evidence_refs) == 1
    # provenance is mandatory and preserved verbatim
    assert h2.evidence_refs[0]["origin"] == "agent"
    assert h2.counter_evidence_refs[0]["origin"] == "target"
    # idempotent attach (duplicate delivery)
    reg.attach_evidence(h.hypothesis_id, ev(eid="ev-1"), "exploit-w0")
    assert len(reg.get(h.hypothesis_id).evidence_refs) == 1
    # invalid origin refused
    with pytest.raises(ValidationError):
        reg.attach_evidence(h.hypothesis_id, ev(eid="ev-2", origin="surveillance"),
                            "exploit-w0")


def test_evidence_requires_actor(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    with pytest.raises(ValidationError):
        reg.attach_evidence(h.hypothesis_id, ev(eid="ev-1"), "")


# -- linking & challenges ------------------------------------------------------------------

def test_link_hypotheses_idempotent_and_validated(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    a = make_hyp(reg, asset_ref="https://x.example.com/admin", weakness_class="idor")
    b = make_hyp(reg, asset_ref="https://x.example.com/admin", weakness_class="idor",
                 preconditions=("other precondition",))
    reg.link(a.hypothesis_id, b.hypothesis_id, "RELATED_TO", "exploit-w1",
             note="same object space, different principal")
    reg.link(a.hypothesis_id, b.hypothesis_id, "RELATED_TO", "exploit-w1")
    assert len(reg.get(a.hypothesis_id).related_hypotheses) == 1
    rel = reg.get(a.hypothesis_id).related_hypotheses[0]
    assert rel["kind"] == "RELATED_TO" and rel["created_by"] == "exploit-w1"
    with pytest.raises(UnknownHypothesisError):
        reg.link(a.hypothesis_id, "hyp-nope", "RELATED_TO", "exploit-w1")
    with pytest.raises(ValidationError):
        reg.link(a.hypothesis_id, b.hypothesis_id, "SAME_AS", "exploit-w1")
    # SUPERSEDES must carry a reason — an explicit, auditable decision
    with pytest.raises(ValidationError):
        reg.link(a.hypothesis_id, b.hypothesis_id, "SUPERSEDES", "exploit-w1")


def test_challenge_records_dissent_without_status_change(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    challenged = reg.challenge(h.hypothesis_id, "exploit-w1",
                               "control request returned identical body")
    assert challenged.status == ACTIVE
    assert challenged.challenged_by == ["exploit-w1"]
    assert any(e["event"] == "CHALLENGED" for e in challenged.history)


# -- history & provenance -------------------------------------------------------------------

def test_history_preserves_order_and_actors(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg, created_by="recon-9")
    reg.claim(h.hypothesis_id, "exploit-w2")
    reg.attach_evidence(h.hypothesis_id, ev(eid="ev-1"), "exploit-w2")
    reg.challenge(h.hypothesis_id, "exploit-w3", "nope")
    reg.release(h.hypothesis_id, "exploit-w2", reason="moving on")
    hist = reg.history(h.hypothesis_id)
    assert [e["actor"] for e in hist] == ["recon-9", "exploit-w2", "exploit-w2",
                                          "exploit-w3", "exploit-w2"]
    assert [e["event"] for e in hist] == ["REGISTERED", "CLAIMED", "EVIDENCE_ADDED",
                                          "CHALLENGED", "RELEASED"]
    assert all(e["ts"] == clock().isoformat() for e in hist)   # injected clock, deterministic


def test_json_round_trip_preserves_state(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    reg.attach_evidence(h.hypothesis_id, ev(eid="ev-1"), "exploit-w0")
    row = json.loads(json.dumps(reg.get(h.hypothesis_id).to_dict()))
    from redteam.swarm.hypotheses import Hypothesis
    restored = Hypothesis.from_dict(row)
    assert restored.to_dict() == reg.get(h.hypothesis_id).to_dict()


# -- engagement isolation ---------------------------------------------------------------------

def test_engagement_isolation_structural(tmp_path, clock):
    """Two engagements, two registries, one journal file naming one engagement: no
    cross-engagement retrieval is possible, and the journal refuses foreign events."""
    journal_a = EventJournal("eng-a", tmp_path / "a.jsonl")
    journal_b = EventJournal("eng-b", tmp_path / "b.jsonl")
    reg_a = HypothesisRegistry("eng-a", journal=journal_a, clock=clock)
    reg_b = HypothesisRegistry("eng-b", journal=journal_b, clock=clock)
    a = make_hyp(reg_a)
    b = make_hyp(reg_b)
    assert reg_a.get(a.hypothesis_id).engagement_id == "eng-a"
    assert reg_b.get(b.hypothesis_id).engagement_id == "eng-b"
    with pytest.raises(UnknownHypothesisError):
        reg_a.get(b.hypothesis_id)     # another engagement's hypothesis is invisible
    with pytest.raises(UnknownHypothesisError):
        reg_a.get(a.hypothesis_id.replace("hyp-", "hyp-foreign-"))
    # journal-level refusal: registry A's journal rejects an event stamped eng-b
    from redteam.swarm.journal import EngagementMismatchError
    foreign = {"event_id": "x1", "engagement_id": "eng-b", "type": "REGISTERED",
               "hypothesis_id": "hyp-x", "actor": "a", "ts": clock().isoformat(),
               "payload": {"asset_ref": "x", "weakness_class": "w", "claim": "c"}}
    with pytest.raises(EngagementMismatchError):
        journal_a.append(foreign)


def test_stats_and_listing_bounds(tmp_path, clock):
    reg = make_registry(tmp_path, clock)
    for i in range(12):
        make_hyp(reg, asset_ref=f"https://x.example.com/p{i}")
    assert reg.stats()["total"] == 12
    assert len(reg.list(limit=5)) == 5
    assert reg.stats()["by_status"][PROPOSED] == 12

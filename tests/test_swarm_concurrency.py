"""Phase C1 concurrency tests — atomic claims, leases, stale owners, version races.

The registry is shared by a parallel exploit swarm (ThreadPoolExecutor, same model as
AttackTree/FindingStore), so these failures would be real lost-work bugs: two workers
on one hypothesis, an expired owner silently overwriting a reclaiming worker, or
racing updates tearing the version counter. Deterministic: an injected clock drives
lease expiry — no sleeps, no flakiness.
"""

from __future__ import annotations

import datetime as _dt
from concurrent.futures import ThreadPoolExecutor

import pytest

from redteam.swarm import (ACTIVE, AlreadyClaimedError, EventJournal,
                           HypothesisRegistry, OwnershipError, PROPOSED,
                           ValidationError, VersionConflictError)

from test_swarm_hypotheses import FakeClock, ev, make_hyp, make_registry


def test_two_workers_claim_same_hypothesis_exactly_one_wins(tmp_path):
    """The registry twin of AttackTree.claim()'s contract: N racers, one winner."""
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    barrier_count = 16

    def racer(i):
        try:
            reg.claim(h.hypothesis_id, f"exploit-w{i}")
            return h.hypothesis_id
        except AlreadyClaimedError:
            return None

    with ThreadPoolExecutor(max_workers=barrier_count) as pool:
        results = list(pool.map(racer, range(barrier_count)))
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    assert reg.get(h.hypothesis_id).owner == f"exploit-w{results.index(winners[0])}"
    assert reg.get(h.hypothesis_id).status == ACTIVE


def test_claim_requires_proposed_or_active(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "w0")
    reg.set_status(h.hypothesis_id, "BLOCKED", "w0", reason="waiting")
    with pytest.raises(Exception):
        reg.claim(h.hypothesis_id, "w1")
    reg.set_status(h.hypothesis_id, "ACTIVE", "w0")
    assert reg.claim(h.hypothesis_id, "w1").owner == "w1"   # released by owner? no —
    # BLOCKED->ACTIVE keeps ownership? set_status clears ownership (verification or
    # blocked states are not owned work). Either way the claim here succeeds because
    # the owner was cleared by the BLOCKED transition.


def test_lease_expiry_makes_abandoned_claim_reclaimable(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0", lease_seconds=120)
    clock.advance(60)
    with pytest.raises(AlreadyClaimedError):
        reg.claim(h.hypothesis_id, "exploit-w1")       # lease still live
    clock.advance(61)
    reclaimed = reg.claim(h.hypothesis_id, "exploit-w1")   # lease expired: recoverable
    assert reclaimed.owner == "exploit-w1"


def test_stale_owner_cannot_overwrite_after_reassignment(tmp_path):
    """An expired-lease holder's next write must fail the version/ownership checks —
    never silently overwrite the reclaiming worker's state."""
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0", lease_seconds=60)
    clock.advance(120)
    reg.claim(h.hypothesis_id, "exploit-w1")               # reclaim
    with pytest.raises(OwnershipError):
        reg.attach_evidence(h.hypothesis_id,
                            ev(eid="ev-stale", origin="agent"), "exploit-w0")
    with pytest.raises(OwnershipError):
        reg.release(h.hypothesis_id, "exploit-w0")
    with pytest.raises(OwnershipError):
        reg.renew_lease(h.hypothesis_id, "exploit-w0")
    # the reclaiming worker's state is intact
    assert reg.get(h.hypothesis_id).owner == "exploit-w1"
    assert reg.get(h.hypothesis_id).evidence_refs == []


def test_release_is_owner_only(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    with pytest.raises(OwnershipError):
        reg.release(h.hypothesis_id, "exploit-w5")
    released = reg.release(h.hypothesis_id, "exploit-w0")
    assert released.owner is None and released.status == ACTIVE


def test_concurrent_updates_and_version_conflicts(tmp_path):
    """Optimistic concurrency: only the expected-version writer lands; racers that
    read a stale version get VersionConflictError, and every applied write bumps the
    version exactly once."""
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    stale_version = reg.get(h.hypothesis_id).version

    def attach(i):
        try:
            reg.attach_evidence(h.hypothesis_id,
                                ev(eid=f"ev-{i}", origin="agent"), "exploit-w0")
            return True
        except VersionConflictError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attach, range(8)))
    assert all(outcomes)                       # no expected_version -> lock arbitrates
    hyp = reg.get(h.hypothesis_id)
    assert len(hyp.evidence_refs) == 8
    assert hyp.version == stale_version + 8    # exactly one bump per applied event

    # expected_version pins the write to a state the writer has actually seen
    with pytest.raises(VersionConflictError):
        reg.set_status(h.hypothesis_id, "BLOCKED", "exploit-w0",
                       reason="x", expected_version=1)


def test_concurrent_register_same_identity_deduplicated_different_identity_distinct(tmp_path):
    """Concurrent registration (review fix 1 + fix 6 regression): N workers posting
    the SAME full identity get exactly one hypothesis; N workers posting the same
    asset+weakness with different claims get DISTINCT hypotheses — no silent
    suppression. Near-duplicates surface as advisory DUPLICATE_OF candidates only."""
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)

    def register_same(i):
        return reg.register(asset_ref="https://x.example.com/admin",
                            weakness_class="access-control",
                            claim="admin panel reachable without authentication",
                            created_by=f"exploit-w{i}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        hyps = list(pool.map(register_same, range(8)))
    assert len({h.hypothesis_id for h in hyps}) == 1
    assert len(reg.list()) == 1

    def register_worded(i):
        return reg.register(asset_ref="https://y.example.com/admin",
                            weakness_class="access-control",
                            claim=f"worker {i}'s wording of the same suspicion",
                            created_by=f"exploit-w{i}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        hyps2 = list(pool.map(register_worded, range(8)))
    assert len({h.hypothesis_id for h in hyps2}) == 8
    assert len(reg.list()) == 9
    cands = reg.candidate_relationships(hyps2[0].hypothesis_id)
    assert len(cands) == 7 and all(c.kind == "DUPLICATE_OF" for c in cands)


def test_journal_seq_is_gapless_under_concurrent_writes(tmp_path):
    """Concurrent mutations must get a gapless, ordered journal — replay depends on it."""
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=True)
    hyps = [make_hyp(reg, asset_ref=f"https://x.example.com/p{i}") for i in range(6)]

    def claim(h):
        try:
            reg.claim(h.hypothesis_id, f"w-{h.hypothesis_id[-3:]}")
        except AlreadyClaimedError:
            pass

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(claim, hyps))

    rows = (tmp_path / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    seqs = [json_seq(r) for r in rows]
    assert seqs == list(range(1, len(seqs) + 1))


def json_seq(line: str) -> int:
    import json
    return int(json.loads(line)["seq"])


def test_owner_only_set_status_with_live_lease(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "exploit-w0")
    with pytest.raises(OwnershipError):
        reg.set_status(h.hypothesis_id, "BLOCKED", "exploit-w9", reason="not mine")


def test_claim_after_terminal_is_refused(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    h = make_hyp(reg)
    reg.claim(h.hypothesis_id, "w0")
    reg.attach_evidence(h.hypothesis_id,
                        ev(eid="ev-f", kind="finding", artifact="F-2"), "w0")
    reg.set_status(h.hypothesis_id, "AWAITING_VERIFICATION", "w0", finding_id="F-2")
    reg.record_verification_outcome(h.hypothesis_id, verdict="confirmed", finding_id="F-2")
    with pytest.raises(Exception):
        reg.claim(h.hypothesis_id, "w9")
    assert reg.get(h.hypothesis_id).status == "CONFIRMED"

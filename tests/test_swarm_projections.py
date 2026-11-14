"""Phase C1 projection tests — event-sourced replay, restart recovery, resilience.

Replay guarantees under test: determinism (same journal twice ⇒ identical state),
idempotency (duplicate event_ids apply once), resilience (torn lines, missing fields,
invalid transitions, foreign engagements are skipped and REPORTED, never fatal),
ordering (journal order is the only order), and process-restart recovery from a real
file. No mocks of the journal — real JSONL files throughout.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.swarm import (ACTIVE, AWAITING_VERIFICATION, CONFIRMED, EventJournal,
                           HypothesisRegistry, PROPOSED, replay, replay_into)
from redteam.swarm.journal import JournalError

from test_swarm_hypotheses import FakeClock, ev, make_hyp, make_registry


def build_run(tmp_path, clock, engagement="eng-1"):
    """A run with a real journal file and a realistic event mix."""
    reg = make_registry(tmp_path, clock, engagement=engagement, persist=True)
    a = make_hyp(reg, asset_ref="https://x/admin", weakness_class="access-control")
    reg.claim(a.hypothesis_id, "exploit-w0")
    reg.attach_evidence(a.hypothesis_id, ev(eid="ev-1"), "exploit-w0")
    reg.attach_evidence(a.hypothesis_id,
                        ev(eid="ev-f1", kind="finding", artifact="F-1"), "exploit-w0")
    reg.set_status(a.hypothesis_id, AWAITING_VERIFICATION, "exploit-w0",
                   finding_id="F-1")
    reg.record_verification_outcome(a.hypothesis_id, verdict="confirmed",
                                    finding_id="F-1")
    b = make_hyp(reg, asset_ref="https://x/users", weakness_class="idor")
    reg.claim(b.hypothesis_id, "exploit-w1")
    reg.attach_counter_evidence(b.hypothesis_id,
                                ev(eid="cev-1", kind="attempt"), "exploit-w1")
    reg.release(b.hypothesis_id, "exploit-w1", reason="no proof")
    reg.link(a.hypothesis_id, b.hypothesis_id, "RELATED_TO", "exploit-w2",
             note="same object space")
    reg.challenge(b.hypothesis_id, "exploit-w3", "control held for me")
    return reg, a, b


def snapshot(reg: HypothesisRegistry) -> dict:
    return {h.hypothesis_id: h.to_dict() for h in reg.list()}


# -- determinism & completeness -----------------------------------------------------------

def test_replay_reconstructs_identical_state(tmp_path):
    clock = FakeClock()
    reg, a, b = build_run(tmp_path, clock)
    path = tmp_path / "journal.jsonl"
    assert path.exists() and len(path.read_text().splitlines()) >= 12
    rebuilt, report = replay(path, "eng-1")
    assert report.invalid_skipped == 0 and report.duplicates_skipped == 0
    assert snapshot(rebuilt) == snapshot(reg)
    assert rebuilt.get(a.hypothesis_id).status == CONFIRMED
    assert rebuilt.get(a.hypothesis_id).challenged_by == []   # challenge was on b
    assert rebuilt.get(b.hypothesis_id).challenged_by == ["exploit-w3"]
    assert rebuilt.get(a.hypothesis_id).related_hypotheses[0]["kind"] == "RELATED_TO"


def test_replay_twice_is_deterministic(tmp_path):
    clock = FakeClock()
    build_run(tmp_path, clock)
    path = tmp_path / "journal.jsonl"
    r1, rep1 = replay(path, "eng-1")
    r2, rep2 = replay(path, "eng-1")
    assert snapshot(r1) == snapshot(r2)
    assert rep1.summary() == rep2.summary()


def test_replay_preserves_full_history_and_versions(tmp_path):
    clock = FakeClock()
    reg, a, b = build_run(tmp_path, clock)
    rebuilt, _ = replay(tmp_path / "journal.jsonl", "eng-1")
    orig_a = reg.get(a.hypothesis_id)
    new_a = rebuilt.get(a.hypothesis_id)
    assert new_a.version == orig_a.version
    assert [(e["event"], e["actor"]) for e in new_a.history] == \
        [(e["event"], e["actor"]) for e in orig_a.history]
    assert len(new_a.evidence_refs) == len(orig_a.evidence_refs)


# -- restart recovery ------------------------------------------------------------------------

def test_process_restart_recovers_from_journal_file(tmp_path):
    """The operational scenario: the run died, a new process opens the same journal
    file into a fresh file-backed registry and continues appending."""
    clock = FakeClock()
    reg, a, _ = build_run(tmp_path, clock)
    path = tmp_path / "journal.jsonl"

    fresh_journal = EventJournal("eng-1", path)
    assert fresh_journal._seq == len(fresh_journal.read_all())
    resumed, report = replay_into(path, fresh_journal)
    assert report.invalid_skipped == 0
    assert resumed.get(a.hypothesis_id).status == CONFIRMED
    # the resumed registry keeps writing to the same history, with seq continuing
    c = make_hyp(resumed, asset_ref="https://x/late", weakness_class="xss")
    rows = path.read_text().splitlines()
    seqs = [json.loads(r)["seq"] for r in rows]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_journal_load_survives_torn_tail(tmp_path):
    """A writer killed mid-flush loses ONE line; everything before it replays."""
    clock = FakeClock()
    reg, a, _ = build_run(tmp_path, clock)
    path = tmp_path / "journal.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"event_id": "torn", "engagement_id": "eng-1", "type": "REGI')
    rebuilt, report = replay(path, "eng-1")
    assert rebuilt.get(a.hypothesis_id).status == CONFIRMED
    assert report.issues and report.issues[0]["reason"] == "malformed"


# -- invalid / hostile events ------------------------------------------------------------------

def test_replay_skips_invalid_events_and_reports(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=True)
    a = make_hyp(reg)
    reg.claim(a.hypothesis_id, "exploit-w0")   # live lease — makes x6's claim a real race
    path = tmp_path / "journal.jsonl"
    good_lines = path.read_text().splitlines()

    bogus = [
        json.dumps({"event_id": "x1", "engagement_id": "eng-OTHER", "type": "REGISTERED",
                    "hypothesis_id": "hyp-x", "actor": "a", "ts": clock().isoformat(),
                    "payload": {}}),                                            # foreign
        json.dumps({"event_id": "x2", "engagement_id": "eng-1", "type": "REGISTERED",
                    "actor": "a", "ts": clock().isoformat(), "payload": {}}),   # no hyp id
        json.dumps({"event_id": "x3", "engagement_id": "eng-1", "type": "CLAIMED",
                    "hypothesis_id": "hyp-never-registered", "actor": "a",
                    "ts": clock().isoformat(), "payload": {}}),                 # unknown hyp
        json.dumps({"event_id": "x4", "engagement_id": "eng-1", "type": "STATUS_CHANGED",
                    "hypothesis_id": a.hypothesis_id, "actor": "recon-1",
                    "ts": clock().isoformat(),
                    "payload": {"to_status": "CONFIRMED"}}),                    # self-promotion
        json.dumps({"event_id": "x5", "engagement_id": "eng-1", "type": "WARP_DRIVE",
                    "hypothesis_id": a.hypothesis_id, "actor": "a",
                    "ts": clock().isoformat(), "payload": {}}),                 # unknown type
        json.dumps({"event_id": "x6", "engagement_id": "eng-1", "type": "CLAIMED",
                    "hypothesis_id": a.hypothesis_id, "actor": "intruder-w0",
                    "ts": clock().isoformat(),
                    "payload": {"lease_until": clock().isoformat()}}),          # live-owner race
        "not json at all {{{",                                                  # garbage
    ]
    path.write_text("\n".join(good_lines + bogus) + "\n", encoding="utf-8")

    rebuilt, report = replay(path, "eng-1")
    assert snapshot(rebuilt) == snapshot(reg)      # only the valid events applied
    assert report.events_applied >= 1
    assert report.invalid_skipped == len(bogus)
    reasons = {i["reason"] for i in report.issues}
    assert {"foreign_engagement", "malformed", "invalid_state"} <= reasons
    # the live hypothesis is untouched by the hostile CLAIM: the legitimate owner
    # keeps it and the intruder's event never applied
    assert rebuilt.get(a.hypothesis_id).owner == "exploit-w0"
    assert [e["actor"] for e in rebuilt.get(a.hypothesis_id).history] == ["recon-1",
                                                                          "exploit-w0"]


def test_duplicate_event_ids_apply_once_across_replays(tmp_path):
    clock = FakeClock()
    reg = make_registry(tmp_path, clock, persist=False)
    a = make_hyp(reg)
    reg.claim(a.hypothesis_id, "w0")
    event = reg._journal.read_all()[-1]
    # feed the same event 5 more times through apply_event (at-least-once delivery)
    for _ in range(5):
        reg.apply_event(dict(event))
    assert reg.get(a.hypothesis_id).version == 2       # CLAIMED bumped exactly once
    rebuilt, report = replay(reg._journal, "eng-1")
    assert report.duplicates_skipped == 0
    assert rebuilt.get(a.hypothesis_id).version == reg.get(a.hypothesis_id).version


def test_journal_refuses_malformed_and_foreign_writes(tmp_path):
    clock = FakeClock()
    journal = EventJournal("eng-1", tmp_path / "j.jsonl")
    with pytest.raises(JournalError):
        journal.append({"engagement_id": "eng-1"})     # missing required fields
    with pytest.raises(JournalError):
        journal.append({"event_id": "e", "engagement_id": "eng-9", "type": "T",
                        "hypothesis_id": "h", "actor": "a", "ts": "t", "payload": {}})
    # a failed append leaves the journal unchanged
    assert journal.read_all() == []


def test_replay_missing_file_yields_empty_registry(tmp_path):
    rebuilt, report = replay(tmp_path / "never-written.jsonl", "eng-1")
    assert len(rebuilt) == 0 and report.events_read == 0


def test_registry_state_survives_registry_reconstruction_round_trip(tmp_path):
    """End-to-end: registry → journal file → replay (into a file-backed journal) →
    more events → replay again — the whole run stays reconstructable at every point.
    Continuation goes through replay_into() per the contract: replay() itself is
    reconstruction-only (its registry carries a fresh in-memory journal)."""
    clock = FakeClock()
    reg, a, _ = build_run(tmp_path, clock)
    path = tmp_path / "journal.jsonl"
    mid_journal = EventJournal("eng-1", path)
    mid, _ = replay_into(path, mid_journal)
    c = make_hyp(mid, asset_ref="https://x/late", weakness_class="xss")
    mid.claim(c.hypothesis_id, "w9")
    final, _ = replay(path, "eng-1")
    assert final.get(a.hypothesis_id).status == CONFIRMED
    assert final.get(c.hypothesis_id).status == ACTIVE
    assert final.get(c.hypothesis_id).owner == "w9"

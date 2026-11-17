#!/usr/bin/env python
"""Generate the Phase 2 backward-compatibility golden fixtures.

MUST be run with the PRE-CHANGE code (before the EventJournal schema
generalization in docs/builder01-phase2-mission-design.md C4). It drives a real
HypothesisRegistry through a full lifecycle against a file-backed journal and
records BOTH the journal (golden_swarm_journal.jsonl) and the exact replay
result (golden_swarm_replay.json: report summary + projected registry state).

The compat test (tests/test_mission_journal_compat.py) replays the golden
journal after the schema change and asserts byte-identical behavior against the
recorded expectation — the reviewer's "migration and replay tests BEFORE
changing its schema" requirement.

Also writes an old-format attack_tree.json (the five pre-Phase-2 fields only)
that must load unchanged once AttackNode grows owner/lease fields.

Run:  PYTHONPATH=. python scripts/make_golden_fixtures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

FIXTURES = REPO / "tests" / "fixtures" / "journal"

import datetime as _dt

from redteam.swarm.hypotheses import EvidenceRef, HypothesisRegistry
from redteam.swarm.journal import EventJournal
from redteam.swarm.projections import replay


class _FakeClock:
    """Advancing deterministic clock (the registry's injectable `clock`)."""

    def __init__(self) -> None:
        self._now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)

    def __call__(self) -> _dt.datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += _dt.timedelta(seconds=seconds)


def build_golden_journal(path: Path) -> None:
    """Drive a registry through EVERY journal event type the swarm writes:
    REGISTERED, CLAIMED, LEASE_RENEWED (steal-after-expiry), RELEASED,
    EVIDENCE_ADDED, COUNTER_EVIDENCE_ADDED (challenge), STATUS_CHANGED
    (manual + verification-mirrored CONFIRMED/REFUTED), LINKED."""
    clock = _FakeClock()
    journal = EventJournal("golden-eng", path=path)
    reg = HypothesisRegistry("golden-eng", journal=journal, clock=clock,
                             lease_seconds=900.0)

    hyp1 = reg.register(
        asset_ref="https://target.test/api/users/7",
        weakness_class="idor",
        claim="Object 7 is readable as principal A without ownership check",
        created_by="synthesis",
        preconditions=("authenticated as principal A",),
        expected_behavior="403 or ownership diff",
        proposed_test="two-request differential",
        security_boundary="authorization",
        principal="userA", action="read")
    hyp2 = reg.register(
        asset_ref="https://target.test/admin",
        weakness_class="auth.bypass",
        claim="Admin panel accepts a forged session cookie",
        created_by="synthesis")

    reg.claim(hyp1.hypothesis_id, "exploit-w1")
    for i, (eid, summary) in enumerate((
            ("ev-golden-1", "200 on /api/users/7 as userA; body differs from own object"),
            ("ev-golden-2", "reproduced with cache-buster"),)):
        reg.attach_evidence(
            hyp1.hypothesis_id,
            EvidenceRef(evidence_id=eid, kind="observation", origin="agent",
                        source_agent="exploit-w1", artifact_ref=f"traffic://req-{17 + i}",
                        summary=summary,
                        ts=clock().isoformat()),
            "exploit-w1")
    reg.challenge(hyp1.hypothesis_id, "exploit-w2", "could be caching, recheck")
    reg.attach_evidence(
        hyp1.hypothesis_id,
        EvidenceRef(evidence_id="ev-golden-3", kind="finding", origin="agent",
                    source_agent="verify-pipeline", artifact_ref="F-2026-0001",
                    summary="independent k-of-n reproduction", ts=clock().isoformat()),
        "exploit-w1")
    reg.set_status(hyp1.hypothesis_id, "STALE", "exploit-w1", reason="endpoint moved")
    reg.set_status(hyp1.hypothesis_id, "ACTIVE", "exploit-w1", reason="endpoint restored")
    reg.set_status(hyp1.hypothesis_id, "AWAITING_VERIFICATION", "exploit-w1",
                   finding_id="F-2026-0001")
    reg.record_verification_outcome(
        hyp1.hypothesis_id, verdict="confirmed", finding_id="F-2026-0001",
        by_agent="verify-pipeline", reason="independent re-check reproduced")

    reg.claim(hyp2.hypothesis_id, "exploit-w2")
    reg.attach_evidence(
        hyp2.hypothesis_id,
        EvidenceRef(evidence_id="ev-golden-4", kind="finding", origin="agent",
                    source_agent="verify-pipeline", artifact_ref="F-2026-0002",
                    summary="forged-cookie probe falsified", ts=clock().isoformat()),
        "exploit-w2")
    reg.release(hyp2.hypothesis_id, "exploit-w2", reason="handed back")
    clock.advance(1000.0)                    # past the 900 s lease -> steal is legal
    reg.claim(hyp2.hypothesis_id, "exploit-w1")
    reg.attach_counter_evidence(
        hyp2.hypothesis_id,
        EvidenceRef(evidence_id="ev-golden-5", kind="observation", origin="agent",
                    source_agent="exploit-w1", artifact_ref="traffic://req-42",
                    summary="login wall logged the forged attempt", ts=clock().isoformat()),
        "exploit-w1")
    reg.set_status(hyp2.hypothesis_id, "AWAITING_VERIFICATION", "exploit-w1",
                   finding_id="F-2026-0002")
    reg.record_verification_outcome(
        hyp2.hypothesis_id, verdict="falsified", finding_id="F-2026-0002",
        by_agent="verify-pipeline", reason="forged cookie rejected; login wall intact")

    reg.link(hyp1.hypothesis_id, hyp2.hypothesis_id, "RELATED_TO", "exploit-w1",
             "same auth surface")


def snapshot_state(reg: HypothesisRegistry) -> list[dict]:
    """Deterministic replay-state export (no wall-clock fields)."""
    rows = []
    for h in sorted(reg.list(include_terminal=True, limit=1000),
                    key=lambda x: x.hypothesis_id):
        rows.append({
            "hypothesis_id": h.hypothesis_id,
            "status": h.status,
            "owner": h.owner,
            "version": h.version,
            "lease_expires_at": h.lease_expires_at,
            "finding_id": "",
            "asset_ref": h.asset_ref,
            "weakness_class": h.weakness_class,
            "evidence": [e.get("evidence_id") for e in h.evidence_refs],
            "counter_evidence": [e.get("evidence_id") for e in h.counter_evidence_refs],
            "related": sorted(str(r) for r in h.related_hypotheses),
        })
    return rows


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    journal_path = FIXTURES / "golden_swarm_journal.jsonl"
    if journal_path.exists():
        journal_path.unlink()
    build_golden_journal(journal_path)

    reg, report = replay(journal_path, "golden-eng")
    expectation = {
        "engagement_id": "golden-eng",
        "report": report.summary(),
        "state": snapshot_state(reg),
    }
    out = FIXTURES / "golden_swarm_replay.json"
    out.write_text(json.dumps(expectation, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")

    # Old-format attack tree fixture: EXACTLY the five pre-Phase-2 fields —
    # must load unchanged once AttackNode grows owner/lease_expires_at.
    tree_path = FIXTURES / "golden_attack_tree_old_format.json"
    tree_path.write_text(json.dumps([
        {"technique": "auth.test", "target": "https://target.test/",
         "status": "completed", "findings": "session stored", "bucket": "static"},
        {"technique": "access.idor", "target": "https://target.test/api/users/7",
         "status": "in_progress", "findings": "", "bucket": "rest"},
        {"technique": "injection.sqli", "target": "https://target.test/search",
         "status": "todo", "findings": "", "bucket": "form"},
    ], indent=2) + "\n", encoding="utf-8")

    print(f"journal events : {len(journal_path.read_text().splitlines())}")
    print(f"replay summary : {json.dumps(expectation['report'])}")
    print(f"state rows     : {len(expectation['state'])}")
    print(f"wrote {journal_path.name}, {out.name}, {tree_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

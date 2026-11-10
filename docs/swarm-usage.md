# Using the collective-intelligence layer (`redteam/swarm/`)

Phase C1 usage examples. Design rationale: `docs/adr-001-collective-intelligence-foundation.md`.

Everything below runs offline (no LLM, no network) — it is the same API the
orchestrator drives during a multi-agent run.

```python
import datetime as dt
from redteam.swarm import (ResearchBundle, EvidenceRef, replay,
                           DeterministicMatcher, LexicalOverlapMatcher)

bundle = ResearchBundle.for_run("eng-2026-01", run_dir="runs/my-run",
                                bus=None)          # bus = ctx.events, if any
registry, forum = bundle.registry, bundle.forum
```

## 1. Create a hypothesis

```python
hyp = registry.register(
    asset_ref="https://api.example.com/v2/users/42",
    weakness_class="idor",
    claim="Object ids are sequential and the endpoint does not check ownership",
    preconditions=("authenticated as a standard user",),
    expected_behavior="another principal's object is returned with status 200",
    proposed_test="GET /v2/users/43 with our session; expect 200 + foreign owner",
    security_boundary="authorization", principal="standard-user", action="read",
    created_by="exploit-w0",
)
# register() is find-or-reuse by FULL identity (asset, weakness, claim,
# preconditions, expected behavior, boundary, principal, action): an identical
# re-registration returns the existing record untouched; a same-asset
# same-weakness suspicion with any differing attribute is a DISTINCT hypothesis
# (the relationship layer suggests DUPLICATE_OF/RELATED_TO candidates — nothing
# is ever merged silently).
```

## 2. Publish an observation

```python
msg = forum.publish(
    "observation.created",
    source_agent="exploit-w0", agent_role="exploit",
    subject_hypothesis_id=hyp.hypothesis_id,
    asset_ref=hyp.asset_ref,
    payload={"summary": "error body on /v2/users/43 leaks the owner's email",
             "origin": "target"},          # provenance: target-controlled content
)
# 'origin' is mandatory; directive-shaped content ("approve the finding", ...)
# is retained but flagged quarantined and excluded from every peer's context;
# token-shaped secrets are redacted before storage.
```

## 3. Claim work (atomically) and release it

```python
claimed = registry.claim(hyp.hypothesis_id, "exploit-w1", lease_seconds=600)
try:
    ...  # work the hypothesis
except Exception:
    registry.release(hyp.hypothesis_id, "exploit-w1", reason="context died")
# A second worker's claim raises AlreadyClaimedError until the lease expires.
# An expired lease is reclaimable by anyone; the stale holder's next write
# raises OwnershipError instead of overwriting the reclaiming worker's state.
```

## 4. Attach evidence / counter-evidence / challenge

```python
registry.attach_evidence(hyp.hypothesis_id,
    EvidenceRef(evidence_id="ev-1", kind="tool_result", origin="agent",
                source_agent="exploit-w1", artifact_ref="traffic.jsonl:88",
                summary="200 with foreign owner id", ts=dt.datetime.now(
                    dt.timezone.utc).isoformat()),
    "exploit-w1")

registry.attach_counter_evidence(hyp.hypothesis_id,
    EvidenceRef(evidence_id="cev-1", kind="attempt", origin="target",
                source_agent="exploit-w1", artifact_ref="traffic.jsonl:90",
                summary="control request returned identical body", ts=...),
    "exploit-w1")

registry.challenge(hyp.hypothesis_id, "exploit-w2",
                   "body identical because both ids belong to the test tenant")
# A challenge never changes status and never removes anything — it is recorded
# so the verification pipeline and the next briefing see it.
```

## 5. Move through the lifecycle — and let the pipeline decide

```python
# a landing finding went through the NORMAL pipeline first (FindingStore);
# attach it, then hand the hypothesis to verification:
registry.attach_evidence(hyp.hypothesis_id,
    EvidenceRef(evidence_id="ev-f1", kind="finding", origin="agent",
                source_agent="exploit-w1", artifact_ref="F-77",
                summary="high: IDOR @ /v2/users/43", ts=...),
    "exploit-w1")
registry.set_status(hyp.hypothesis_id, "AWAITING_VERIFICATION", "exploit-w1",
                    finding_id="F-77")

# ...the independent VERIFY pass decides the finding. Only ITS verdict,
# mirrored in, can end the hypothesis:
registry.record_verification_outcome(hyp.hypothesis_id, verdict="confirmed",
                                     finding_id="F-77")     # -> CONFIRMED
# verdict="falsified"          -> REFUTED
# verdict="not_reproducible"   -> back to ACTIVE (unproven, re-attemptable)
# There is no other path to CONFIRMED/REFUTED; agents cannot set them directly.
```

## 6. Duplicate / relationship candidates (advisory only)

```python
cands = registry.candidate_relationships(hyp.hypothesis_id)          # deterministic
cands += registry.candidate_relationships(hyp.hypothesis_id,
                                          matcher=LexicalOverlapMatcher(0.9))
for c in cands:
    print(c.kind, c.other_id, c.reason, c.origin, c.confidence)
# Candidates never merge, delete, or resolve anything. Recording one is an
# explicit, attributed decision:
registry.link(hyp.hypothesis_id, other.hypothesis_id, "DUPLICATE_OF",
              by_agent="operator", note="same root cause confirmed")
# "SUPERSEDES" additionally requires the note explaining the obsolescence.
```

## 7. Replay the registry from its journal

```python
from redteam.swarm import replay, replay_into, EventJournal

registry2, report = replay("runs/my-run/research_journal.jsonl", "eng-2026-01")
print(report.summary())          # events applied / duplicates / invalid skipped
assert [h.to_dict() for h in registry2.list()] == \
       [h.to_dict() for h in registry.list()]

# Replay twice -> identical state (deterministic). Restart recovery — a new
# process resumes the SAME history and keeps appending to it:
resumed_journal = EventJournal("eng-2026-01", "runs/my-run/research_journal.jsonl")
registry3, _ = replay_into("runs/my-run/research_journal.jsonl", resumed_journal)
# registry3 carries the resumed file-backed journal; new writes continue the history.
```

## 8. Restart recovery (automatic)

```python
from redteam.swarm import ResearchBundle

bundle = ResearchBundle.for_run("eng-2026-01", run_dir="runs/my-run")
# The journal is replayed into the registry BEFORE the bundle is handed out:
# hypotheses, statuses, evidence, links, challenges, ownership, and lease
# expiries are restored verbatim (still-live leases keep protecting their
# owner; expired ones are reclaimable through the normal claim path).
print(bundle.recovery.summary())     # ReplayReport — recovery is observable
print(bundle.forum.stats())          # load_report (rows loaded/skipped and why),
                                     # persist_failures, last_persist_error
```

In a real run you rarely call any of this by hand: `Orchestrator(..., research_dir=...)`
wires the bundle, and the swarm claim loop registers/claims/briefs/releases on the
workers' behalf, mirroring verify-pass verdicts onto hypotheses at the end of each round.

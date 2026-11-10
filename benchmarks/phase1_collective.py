#!/usr/bin/env python3
"""Phase C1 benchmark — A/B/C/D configurations over a deterministic synthetic swarm.

WHAT THIS IS
  A reproducible, offline harness that measures the collective-intelligence layer's
  effect on the metrics the Phase C1 spec names. It simulates a swarm of workers
  investigating a fixed synthetic workload (endpoints x weakness classes, with a
  known ground truth of which keys are truly vulnerable) under four configurations,
  each capability independently toggleable (review fix 5):

    A  baseline            — shared task list only; workers cannot see each other's work
    B  +forum observations — workers publish structured observations after each
                             attempt (observations-ONLY: no registry, no ownership);
                             siblings consult them before starting
    C  +registry ownership — B plus: tasks become hypotheses with atomic claims and
                             leases (a live lease suppresses a concurrent duplicate),
                             evidence-rich briefings (counter-evidence summaries with
                             artifact refs, not bare counts), lifecycle suppression
                             (CONFIRMED/REFUTED hypotheses are not re-investigated)
    D  +relationship       — C plus: the deterministic relationship matcher is
        matching             consulted before starting; DUPLICATE_OF candidates on
                             already-attempted/owned siblings suppress the redundant
                             attempt (advisory, never a merge)

WHAT THIS IS NOT
  Live-fire numbers. SYNTHETIC: the workload is synthetic, attempt outcomes and the
  verification pipeline are deterministic mocks with the pipeline's verdict
  vocabulary (confirmed / falsified / not_reproducible), and no real LLM, target,
  or token spend is involved. The point is to (a) prove the harness and metrics
  exist and run deterministically, (b) expose the deltas the layer CAN and CANNOT
  move in a controlled setting, and (c) enumerate the live-fire experiments that
  remain. Do not quote these numbers as product performance.

METHODOLOGY (review fix 5)
  - Paired randomness: the outcome of the Nth attempt on a key is derived ONLY from
    (seed, key, N) — identical across configurations. Config deltas are attributable
    to the collective layer, not to luck.
  - Matched budgets: every configuration gets the SAME token allowance
    (total_tasks x ATTEMPT_TOKENS). Savings from suppressed duplicates are what fund
    forum reads and candidate checks; spend over the allowance would be dropped and
    reported (budget_exhausted_deliveries).
  - Repeated seeds: every configuration runs on SEEDS (default 3); aggregates report
    mean and stdev. A/B comparisons are across the same seeds.
  - Claim/registry failures are NEVER swallowed: every failed register/claim/evidence
    write is counted and reported (claim_failures, registry_write_failures).
  - Real code paths: B/C/D publish through the actual ResearchForum (sanitization,
    quarantine) and C/D run on the actual HypothesisRegistry + journal, in-memory.
  - Concurrency model: one round = one wall of parallel work. Workers see only the
    observations published at the END of earlier rounds (same-round peers are truly
    parallel), and a claim's lease stays live until the round ends — exactly the
    orchestrator's shape.
  - Workload per (asset, weakness) key: two EXACT-duplicate deliveries (same claim
    text, exercising ownership dedup under full-identity registration) and one
    REWORDING (different claim, same key — distinct hypothesis by design; exercising
    the relationship layer, review fix 1).

Run:  python benchmarks/phase1_collective.py [--out benchmarks/phase1_results.json]
      [--seeds 3]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import random
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.swarm import (EvidenceRef, HypothesisRegistry, ResearchBundle,
                           ResearchForum, SwarmError)

SEEDS = [20260101, 20260102, 20260103]
N_WORKERS = 6
N_ASSETS = 14
N_CLASSES = 5                      # weakness classes per asset in the workload
TASKS_PER_KEY = 3                  # 2 exact duplicates + 1 rewording per (asset, class)
VULN_RATE = 0.35
ATTEMPT_TOKENS = 900               # simulated tokens per investigation attempt
FORUM_READ_TOKENS = 120            # simulated cost of one consultation (context into a prompt)
CANDIDATE_CHECK_TOKENS = 0         # in-process deterministic computation (relationships.py
                                   # runs in the orchestrator, no model call): zero tokens.
                                   # The harness keeps the knob so a future LLM-backed
                                   # SemanticMatcher can be priced when one exists.
NOISE_PER_ATTEMPT = 1.0            # same ruler across configs
INFORMED_ATTEMPT_DISCOUNT = 0.6    # an evidence-rich briefing trims the search space:
                                   # informed re-attempts cost 60% of a blind attempt

# Capabilities per configuration — independently toggleable and independently
# measured (review fix 5: observations-only, registry ownership, evidence-rich
# briefings, relationship matching each get their own switch).
CONFIGS: dict[str, dict[str, bool]] = {
    "A": {},
    "B": {"forum_observations": True},
    "C": {"forum_observations": True, "registry_ownership": True,
          "evidence_rich_briefings": True},
    "D": {"forum_observations": True, "registry_ownership": True,
          "evidence_rich_briefings": True, "relationship_matching": True},
}


@dataclass
class Task:
    """One synthetic investigation task = one delivery of a claim wording."""
    task_id: int
    asset: str
    weakness: str
    wording: str                     # exact-duplicate twins share the string
    vulnerable: bool                 # ground truth for the underlying key
    underlying: tuple                # (asset, weakness) — the true investigation key


@dataclass
class Attempt:
    task_id: int
    underlying: tuple
    worker: str
    attempt_no: int                  # attempt ordinal for this underlying key (global)
    duplicate: bool                  # worked while a sibling already attempted the key
    reused: bool                     # worker consulted shared context before working
    tokens: int
    noise: float
    landed_finding: bool
    verdict: str = ""                # from the mock verification pipeline
    round_no: int = 0


@dataclass
class SimState:
    attempts: list = field(default_factory=list)
    reuse_opportunities: int = 0         # deliveries where shared context existed
    reuse_events: int = 0                # consultations that informed the decision
    decided_skips: int = 0               # skipped because the key was already decided
    suppressed_by_ownership: int = 0     # claim lost to a live lease / lifecycle
    suppressed_by_candidates: int = 0    # DUPLICATE_OF candidate on covered work
    candidate_checks: int = 0
    duplicate_candidates: list = field(default_factory=list)   # (correct: bool)
    related_candidates: int = 0          # RELATED_TO/CONTRADICTS candidates (informational)
    briefings_built: int = 0
    briefing_evidence_items: int = 0     # evidence/negative items actually shown
    claim_failures: int = 0              # NEVER swallowed — surfaced in the report
    registry_write_failures: int = 0     # NEVER swallowed — surfaced in the report
    claim_failure_details: list = field(default_factory=list)
    budget_exhausted_deliveries: int = 0
    confirmed_keys: set = field(default_factory=set)
    falsified_keys: set = field(default_factory=set)
    total_tokens: int = 0
    total_noise: float = 0.0
    rounds: int = 0
    observed: set = field(default_factory=set)       # keys with published observations
    decided: set = field(default_factory=set)        # keys with confirmed/falsified obs
    attempted: set = field(default_factory=set)      # keys with >=1 real attempt


def build_workload(seed: int) -> list[Task]:
    """Synthetic workload: N_ASSETS x N_CLASSES keys; per key 2 exact-duplicate
    deliveries (same wording) + 1 rewording. Ground truth is per-KEY (the three
    deliveries of a key investigate the same underlying flaw).

    Half the keys are CLUSTERED (all three deliveries reach workers in the same
    round — the same-round duplicate the ownership lease exists for); half are
    SPREAD (the rewording and second twin arrive several rounds after the first
    attempt — the cross-round re-offering the observation/log/briefing layer exists
    for). Both mechanisms get exercised; neither is staged to flatter a config."""
    rng = random.Random(f"{seed}|workload")
    rewording = ("peer report hints at {w} behavior on {a}; needs a proof attempt")
    keys: list[dict] = []
    for a_i in range(N_ASSETS):
        asset = f"https://target.example.com/app{a_i}/resource"
        for c_i in range(N_CLASSES):
            weakness = f"class-{c_i}"
            vulnerable = rng.random() < VULN_RATE
            wording = (f"suspicion that {weakness} on {asset} is exploitable "
                       f"without credentials")
            keys.append({"asset": asset, "weakness": weakness,
                         "vulnerable": vulnerable, "wording": wording,
                         "clustered": rng.random() < 0.5})

    def make(key: dict, m: int) -> Task:
        return Task(task_id=0, asset=key["asset"], weakness=key["weakness"],
                    wording=(key["wording"] if m < 2
                             else rewording.format(w=key["weakness"], a=key["asset"])),
                    vulnerable=key["vulnerable"],
                    underlying=(key["asset"], key["weakness"]))

    clustered, waves = [], ([], [], [])
    for key in keys:
        if key["clustered"]:
            clustered.extend(make(key, m) for m in range(TASKS_PER_KEY))
        else:
            for m in range(TASKS_PER_KEY):
                waves[m].append(make(key, m))
    ordered = clustered + waves[0] + waves[1] + waves[2]
    for i, task in enumerate(ordered, start=1):
        task.task_id = i
    return ordered


def outcome_rng(seed: int, key: tuple, ordinal: int, purpose: str) -> random.Random:
    """PAIRED randomness (methodology): the Nth attempt on a key gets the same
    outcome stream in every configuration — deltas are the layer, not luck."""
    return random.Random(f"{seed}|{key[0]}|{key[1]}|{ordinal}|{purpose}")


def mock_verify(vulnerable: bool, rng: random.Random) -> str:
    """Deterministic mock of verify.py's k-of-n with the real verdict vocabulary.
    Honest by construction: a non-vulnerable key can produce a false SIGNAL (which
    the negative control then falsifies) but NEVER a confirmed finding — so
    confirmed-but-not-vulnerable (false positives) is structurally 0 under this
    mock, and the metric is reported precisely to make that visible."""
    if vulnerable:
        return "confirmed" if rng.random() < 0.92 else "not_reproducible"
    return "falsified" if rng.random() < 0.6 else "not_reproducible"


def attempt_outcome(seed: int, key: tuple, ordinal: int, vulnerable: bool):
    """(landed, verdict) for the Nth attempt on a key — identical across configs."""
    rng = outcome_rng(seed, key, ordinal, "attempt")
    landed = rng.random() < (0.85 if vulnerable else 0.12)   # 0.12 = false signal on a control
    verdict = ""
    if landed:
        verdict = mock_verify(vulnerable, outcome_rng(seed, key, ordinal, "verify"))
    return landed, verdict


def publish_observation(forum: ResearchForum | None, state: SimState, key: tuple,
                        worker: str, landed: bool, verdict: str, hyp_id: str = "",
                        round_no: int = 0) -> None:
    """Publish the attempt's outcome through the REAL forum path (sanitization,
    quarantine, engagement scoping). Publication failures must not disappear: they
    are counted as claim-adjacent failures (review fix 5: nothing swallowed)."""
    if forum is None:
        return
    summary = (f"attempt on {key[0]} {key[1]}: "
               + (f"finding landed, pipeline verdict {verdict}" if landed
                  else "no proof this round; hypothesis remains unconfirmed"))
    try:
        forum.publish("observation.created", source_agent=worker,
                      payload={"summary": summary, "origin": "agent",
                               "verdict": verdict, "underlying": f"{key[0]}::{key[1]}",
                               "round": round_no},
                      agent_role="exploit", subject_hypothesis_id=hyp_id,
                      asset_ref=key[0], ts=_dt.datetime.now(_dt.timezone.utc).isoformat())
    except Exception as exc:                      # noqa: BLE001 — surfaced, never silent
        state.claim_failures += 1
        state.claim_failure_details.append(f"observation publish: {type(exc).__name__}: {exc}")
        return
    state.observed.add(key)
    if verdict in ("confirmed", "falsified"):
        state.decided.add(key)


def consult(state: SimState, forum: ResearchForum | None, key: tuple,
            asset: str, hyp=None) -> tuple[list, bool]:
    """The shared-context consultation (observations layer, B/C/D). Reads ONLY
    messages about THIS key (payload marker `asset::weakness`) — never the whole
    forum, and never another key's observations. Returns (messages, informed)."""
    msgs: list = []
    if forum is not None and key in state.observed:
        state.reuse_opportunities += 1
        marker = f"{key[0]}::{key[1]}"
        if hyp is not None:
            raw = forum.relevant_context(hyp.hypothesis_id, asset=asset, limit=50)
        else:
            raw = forum.query(asset=asset, limit=50)   # observations-only config: no hyp yet
        msgs = [m for m in raw if m.payload.get("underlying") == marker][:12]
    informed = bool(msgs)
    return msgs, informed


def run_config(tasks: list[Task], mode: str, seed: int,
               budget_tokens: int | None = None) -> SimState:
    """One configuration on one seed. In-memory bundle/forum per run: zero files,
    zero global state — configurations cannot contaminate each other."""
    flags = CONFIGS[mode]
    state = SimState()
    started = time.perf_counter()
    bundle = forum = None
    if flags.get("registry_ownership"):
        bundle = ResearchBundle.for_run(f"bench-{mode}-{seed}")   # in-memory, no files
    if flags.get("forum_observations"):
        forum = (bundle.forum if bundle else
                 ResearchForum(f"bench-{mode}-{seed}"))

    if budget_tokens is None:
        budget_tokens = len(tasks) * ATTEMPT_TOKENS   # matched allowance for every config

    per_worker = [list(t.task_id for t in tasks[i::N_WORKERS]) for i in range(N_WORKERS)]
    attempts_by_key: dict[tuple, int] = {}
    hyp_by_key: dict[tuple, str] = {}
    held_leases: dict[tuple, tuple] = {}    # key -> (hyp_id, owner) for the live round
    worker_queues = dict(enumerate(per_worker))
    round_no = 0

    def spend(tokens: int) -> bool:
        """Matched-budget enforcement: identical allowance for every config; a
        delivery that no longer fits is DROPPED AND COUNTED, never free."""
        if state.total_tokens + tokens > budget_tokens:
            state.budget_exhausted_deliveries += 1
            return False
        state.total_tokens += tokens
        return True

    while worker_queues and round_no < 60:
        round_no += 1
        progressed = False
        round_holds: list[tuple] = []       # (key, hyp_id, worker, landed, verdict, task_id)
        for w in sorted(worker_queues):
            queue = worker_queues.get(w)
            if not queue:
                continue
            task_id = queue.pop(0)
            task = next(t for t in tasks if t.task_id == task_id)
            progressed = True
            key = task.underlying
            agent = f"worker-{w}"

            # -- consultation (B/C/D): observations-only for B (no registry); C/D
            #    read the same observations — the EVIDENCE-RICH briefing over the
            #    OWN hypothesis comes later, after the claim, exactly where the
            #    orchestrator's worker_note sits -------------------------------
            informed = False
            if flags.get("forum_observations"):
                own_hyp = None
                if bundle is not None:
                    try:
                        own_hyp = bundle.registry.has_equivalent(
                            asset_ref=task.asset, weakness_class=task.weakness,
                            claim=task.wording, include_terminal=True)
                    except SwarmError as exc:
                        state.claim_failures += 1
                        state.claim_failure_details.append(f"lookup: {exc}")
                if (key in state.observed or own_hyp is not None):
                    _msgs, informed = consult(state, forum, key, task.asset, own_hyp)
                    if not spend(FORUM_READ_TOKENS):
                        continue

            # -- decided keys are never re-investigated (all sharing configs) ----
            if informed and key in state.decided:
                state.reuse_events += 1
                state.decided_skips += 1
                state.attempts.append(Attempt(
                    task.task_id, key, agent, attempts_by_key.get(key, 0),
                    duplicate=False, reused=True, tokens=FORUM_READ_TOKENS,
                    noise=0.0, landed_finding=False, verdict="reused",
                    round_no=round_no))
                continue

            # -- relationship candidates (D only, before ownership): advisory
            #    suppression of near-duplicate work; candidates NEVER merge -------
            if flags.get("relationship_matching") and bundle is not None:
                state.candidate_checks += 1
                if not spend(CANDIDATE_CHECK_TOKENS):
                    continue
                try:
                    others = bundle.registry.list(limit=500)
                    probe = bundle.registry.register(
                        asset_ref=task.asset, weakness_class=task.weakness,
                        claim=task.wording, created_by=agent)
                    from redteam.swarm.relationships import DeterministicMatcher
                    cands = DeterministicMatcher().candidates(probe, others)
                except SwarmError as exc:
                    state.claim_failures += 1
                    state.claim_failure_details.append(f"candidate probe: {exc}")
                    cands = []
                blocked = False
                for c in cands:
                    other = next((h for h in others
                                  if h.hypothesis_id == c.other_id), None)
                    if other is None:
                        continue
                    other_key = (other.asset_ref, other.weakness_class)
                    # covered = the sibling is being worked RIGHT NOW (live lease)
                    # or already decided (confirmed/falsified). A merely-attempted
                    # sibling does NOT block: a failed attempt leaves the question
                    # open, and suppressing the retry would trade recall for
                    # efficiency — the opposite of the layer's job.
                    covered = (other_key in held_leases
                               or other_key in state.decided)
                    if c.kind == "DUPLICATE_OF":
                        same_key = (other_key == key)
                        state.duplicate_candidates.append((covered, same_key))
                        if covered:
                            blocked = True
                    else:
                        # RELATED_TO / CONTRADICTS are informational — counted,
                        # never blocking, never scored as true/false duplicates
                        state.related_candidates += 1
                if blocked:
                    state.suppressed_by_candidates += 1
                    # DEFER, not drop: a live lease resolves at round end and a
                    # decided key stays decided — re-queue the delivery so a
                    # blocked attempt is retried when the sibling's outcome is
                    # visible (recall is never silently traded away).
                    queue.append(task_id)
                    continue

            # -- registry ownership (C/D): full-identity find-or-register + atomic
            #    claim. A LOST RACE (live lease / lifecycle refusal) defers the
            #    delivery; a registry ERROR degrades to an unresearched attempt
            #    (the orchestrator's own policy) and is counted, never swallowed.
            hyp = None
            if bundle is not None:
                registry_error = False
                try:
                    hyp, _ = bundle.claim_or_register(
                        asset_ref=task.asset, weakness_class=task.weakness,
                        claim=task.wording, agent=agent)
                except SwarmError as exc:
                    state.claim_failures += 1
                    state.claim_failure_details.append(f"claim: {exc}")
                    registry_error = True
                if registry_error:
                    pass                     # degrade: proceed unresearched, like the orchestrator
                elif hyp is None:
                    # lost the race (same identity, live lease) or lifecycle says
                    # no (AWAITING/CONFIRMED/REFUTED) — deferred: the lease or the
                    # lifecycle resolves this round; re-queue and retry when the
                    # sibling's outcome is visible. A DIFFERENT-identity hypothesis
                    # on the same key is NOT suppressed here — distinct hypotheses
                    # are distinct investigations (review fix 1); the relationship
                    # layer (D) is what advises against near-duplicates.
                    state.suppressed_by_ownership += 1
                    queue.append(task_id)
                    continue
                else:
                    held_leases.setdefault(key, (hyp.hypothesis_id, agent))
                    hyp_by_key[key] = hyp.hypothesis_id
                    # EVIDENCE-RICH BRIEFING (C/D, review fix 4/5): the claimed
                    # hypothesis's own evidence and counter-evidence — summaries
                    # with artifact refs, exactly what worker_note would inject.
                    # Measured; and an informed re-attempt is CHEAPER (60%)
                    # because the briefing names the dead ends already tried.
                    if flags.get("evidence_rich_briefings"):
                        ev_items = list(hyp.evidence_refs) + list(hyp.counter_evidence_refs)
                        if ev_items:
                            state.briefings_built += 1
                            state.briefing_evidence_items += len(ev_items)
                            informed = True

            # -- attempt bookkeeping: the metric that matters ----------------------
            attempt_no = attempts_by_key.get(key, 0)
            duplicate = attempt_no > 0          # repeat work on the same key (informed or not)
            attempts_by_key[key] = attempt_no + 1
            cost = int(ATTEMPT_TOKENS * (INFORMED_ATTEMPT_DISCOUNT if informed else 1.0))
            if not spend(cost):
                attempts_by_key[key] -= 1          # the attempt did not happen
                continue
            landed, verdict = attempt_outcome(seed, key, attempt_no, task.vulnerable)
            state.attempted.add(key)
            state.attempts.append(Attempt(
                task.task_id, key, agent, attempt_no, duplicate, informed,
                cost, NOISE_PER_ATTEMPT, landed, verdict, round_no))
            state.total_noise += NOISE_PER_ATTEMPT
            # The INDEPENDENT pipeline speaks regardless of the swarm layer (A has
            # no registry at all): confirmed/falsified keys are recorded from the
            # verdict itself, not from the registry mirror — the mirror only moves
            # HYPOTHESIS lifecycle (C/D), never the pipeline's verdict.
            if verdict == "confirmed":
                state.confirmed_keys.add(key)
                state.falsified_keys.discard(key)
            elif verdict == "falsified":
                state.falsified_keys.add(key)
                state.confirmed_keys.discard(key)
            round_holds.append((key, hyp.hypothesis_id if hyp else "", agent,
                                landed, verdict, task.task_id))
        # -- round end: same-round peers become visible; leases resolve ------------
        for key, hyp_id, agent, landed, verdict, task_id in round_holds:
            publish_observation(forum, state, key, agent, landed, verdict,
                                hyp_id=hyp_id, round_no=round_no)
            if bundle is not None and hyp_id:
                ordinal = next(a.attempt_no for a in state.attempts
                               if a.task_id == task_id)
                evidence = EvidenceRef(
                    evidence_id=f"ev-{task_id}-{ordinal}",
                    kind="finding" if landed else "attempt",
                    origin="agent", source_agent=agent,
                    artifact_ref=f"attempt:{task_id}:{ordinal}",
                    summary=(f"landed, pipeline verdict {verdict}" if landed
                             else "no proof this round"),
                    ts=_dt.datetime.now(_dt.timezone.utc).isoformat())
                try:
                    if landed:
                        bundle.registry.attach_evidence(hyp_id, evidence, agent)
                        bundle.registry.set_status(
                            hyp_id, "AWAITING_VERIFICATION", agent,
                            finding_id=evidence.artifact_ref)
                        if verdict:
                            # the mock pipeline spoke -> mirror it onto the
                            # hypothesis lifecycle (the ONLY CONFIRMED/REFUTED
                            # path). not_reproducible returns the hypothesis to
                            # ACTIVE — unproven, re-attemptable — exactly the real
                            # pipeline's semantics; a hypothesis stuck in
                            # AWAITING would wrongly block every later claim.
                            bundle.registry.record_verification_outcome(
                                hyp_id, verdict=verdict,
                                finding_id=evidence.artifact_ref,
                                by_agent="verify-pipeline")
                    else:
                        bundle.registry.attach_counter_evidence(hyp_id, evidence, agent)
                        bundle.registry.release(hyp_id, agent)
                except SwarmError as exc:
                    state.registry_write_failures += 1
                    state.claim_failure_details.append(f"evidence write: {exc}")
            held_leases.pop(key, None)
        if not progressed:
            break
        if all(not q for q in worker_queues.values()):
            break
    state.rounds = round_no
    state.runtime_seconds = round(time.perf_counter() - started, 4)
    return state


# -- metrics ------------------------------------------------------------------------------

def metrics(state: SimState, tasks: list[Task], mode: str) -> dict:
    real_attempts = [a for a in state.attempts if a.verdict != "reused"]
    duplicate_attempts = [a for a in real_attempts if a.duplicate]
    confirmed = len(state.confirmed_keys)
    ground_truth_vuln = {t.underlying for t in tasks if t.vulnerable}
    confirmed_true = len(state.confirmed_keys & ground_truth_vuln)
    false_positives = len(state.confirmed_keys - ground_truth_vuln)
    tokens_on_duplicates = sum(a.tokens for a in duplicate_attempts)
    return {
        "mode": mode,
        "capabilities": {k: v for k, v in CONFIGS[mode].items()},
        "synthetic": True,
        "total_task_deliveries": len(tasks),
        "real_investigations": len(real_attempts),
        "duplicate_investigations": len(duplicate_attempts),
        "duplicate_investigation_rate": round(
            len(duplicate_attempts) / max(len(real_attempts), 1), 4),
        "uninformed_duplicate_rate": round(
            sum(1 for a in duplicate_attempts if not a.reused)
            / max(len(real_attempts), 1), 4),
        "tokens_spent_on_duplicates": tokens_on_duplicates,
        "unique_independently_confirmed_findings": confirmed,
        "confirmed_true_positives": confirmed_true,
        "false_positive_findings": false_positives,
        "verification_precision": round(confirmed_true / max(confirmed, 1), 4),
        "falsified_findings": len(state.falsified_keys),
        "observation_reuse_rate": round(
            state.reuse_events / max(state.reuse_opportunities, 1), 4)
            if state.reuse_opportunities else 0.0,
        "decided_skips": state.decided_skips,
        "suppressed_by_ownership": state.suppressed_by_ownership,
        "suppressed_by_candidates": state.suppressed_by_candidates,
        "candidate_checks": state.candidate_checks,
        "duplicate_candidate_precision": round(
            sum(1 for _, same in state.duplicate_candidates if same)
            / max(len(state.duplicate_candidates), 1), 4)
            if state.duplicate_candidates else None,
        "duplicate_candidate_actionable_rate": round(
            sum(1 for covered, _ in state.duplicate_candidates if covered)
            / max(len(state.duplicate_candidates), 1), 4)
            if state.duplicate_candidates else None,
        "related_candidates": state.related_candidates,
        "briefings_built": state.briefings_built,
        "briefing_evidence_items": state.briefing_evidence_items,
        "claim_failures": state.claim_failures,
        "registry_write_failures": state.registry_write_failures,
        "budget_exhausted_deliveries": state.budget_exhausted_deliveries,
        "total_tokens": state.total_tokens,
        "tokens_per_confirmed_finding": round(
            state.total_tokens / max(confirmed, 1), 1),
        "noise_cost_per_confirmed_finding": round(
            state.total_noise / max(confirmed, 1), 2),
        "avg_rounds_to_confirmation": round(
            statistics.mean([a.round_no for a in real_attempts
                             if a.verdict == "confirmed"]), 2)
            if any(a.verdict == "confirmed" for a in real_attempts) else None,
        "rounds": state.rounds,
        "runtime_seconds": getattr(state, "runtime_seconds", None),
        "auto_merges": 0,          # structurally impossible: candidates never merge
    }


HEADLINES = ("real_investigations", "duplicate_investigations",
             "unique_independently_confirmed_findings", "false_positive_findings",
             "tokens_per_confirmed_finding", "runtime_seconds")

METHODOLOGY_NOTES = [
    "Attempt outcomes and verification verdicts are deterministic MOCKS; the mock "
    "pipeline never confirms a non-vulnerable key, so false_positive_findings is "
    "structurally 0 here and the metric exists to be measured in live fire.",
    "INFORMED_ATTEMPT_DISCOUNT=0.6: an evidence-rich briefing names the dead ends "
    "already tried, so informed re-attempts cost 60% of a blind attempt. This is a "
    "modeling choice, not a measurement — revisit in live fire.",
    "A merely-attempted sibling does NOT suppress a re-attempt (a failed attempt "
    "leaves the question open); only a live lease (being worked now) or a decided "
    "key (confirmed/falsified) suppresses. Recall is never traded silently.",
]

REMAINING_EXPERIMENTS = [
    "Live-fire A/B on the lab target (lab/): baseline swarm vs forum-enabled swarm, "
    "2 seeds each, real token accounting from BudgetTracker.",
    "Live-fire C on the same target with the Phase C1 orchestrator integration "
    "(research_dir wired) vs a research_dir=None control run.",
    "Cross-engagement reuse: run C twice against a mutated copy of the lab app and "
    "measure counter-evidence reuse (stale-branch suppression) from the replayed journal.",
    "Semantic-assist (D) with a real embedding backend behind the SemanticMatcher "
    "protocol, scored against human-labeled duplicate pairs from a live run.",
    "Verification-precision impact at scale: >=100-finding engagements to tighten the "
    "Wilson intervals on confirmed/falsified splits.",
]


def aggregate(per_seed: list[dict]) -> dict:
    """Mean +- stdev of the headline metrics across seeds (review fix 5)."""
    out: dict[str, dict] = {}
    for key in HEADLINES:
        vals = [r[key] for r in per_seed if r.get(key) is not None]
        if not vals:
            out[key] = {"mean": None, "stdev": None}
            continue
        out[key] = {"mean": round(statistics.mean(vals), 4),
                    "stdev": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmarks/phase1_results.json")
    ap.add_argument("--seeds", type=int, default=len(SEEDS),
                    help="number of seeds (prefix of SEEDS) to run per config")
    args = ap.parse_args()
    seeds = SEEDS[: max(1, int(args.seeds))]
    print(f"SYNTHETIC benchmark — NOT live-fire. workers: {N_WORKERS}, "
          f"seeds: {seeds}, tasks/seed: {N_ASSETS * N_CLASSES * TASKS_PER_KEY} "
          f"over {N_ASSETS * N_CLASSES} keys\n")
    results = {
        "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "synthetic": True,
        "caveat": ("SYNTHETIC simulation with deterministic mocks — these numbers "
                   "are NOT live-fire verification and must not be quoted as "
                   "product performance"),
        "methodology": {
            "paired_randomness": "outcome of attempt N on a key depends only on "
                                 "(seed, key, N) — identical across configs",
            "matched_budget": "every config gets total_tasks x ATTEMPT_TOKENS tokens; "
                              "reads and candidate checks must fit the same allowance",
            "seeds": seeds,
            "concurrency_model": "one round = one parallel wall; observations publish "
                                 "at round end; leases live until round end",
            "workload": "per key: 2 exact-duplicate deliveries + 1 rewording "
                        "(distinct hypothesis under full-identity registration); "
                        "half the keys clustered same-round, half spread cross-round",
            "notes": METHODOLOGY_NOTES + [
                "CANDIDATE_CHECK_TOKENS=0: relationship candidates are computed "
                "in-process (deterministic code, no model call) — their real cost "
                "is the briefing context, priced via FORUM_READ_TOKENS on "
                "consultation; a future LLM-backed SemanticMatcher would set it >0.",
            ],
        },
        "configs": {},
        "per_seed": [],
        "remaining_experiments": REMAINING_EXPERIMENTS,
    }
    header = (f"{'metric':<42}" + "".join(f"{m:>16}" for m in "ABCD"))
    for seed in seeds:
        tasks = build_workload(seed)
        for mode in "ABCD":
            m = metrics(run_config(tasks, mode, seed), tasks, mode)
            m["seed"] = seed
            results["per_seed"].append(m)
        print(f"seed {seed} done")
    # aggregate across seeds, per config
    for mode in "ABCD":
        rows = [r for r in results["per_seed"] if r["mode"] == mode]
        results["configs"][mode] = {"aggregates": aggregate(rows),
                                    "runs": rows}
    print("\n" + header)
    print("-" * len(header))
    for key in HEADLINES:
        cells = []
        for mode in "ABCD":
            agg = results["configs"][mode]["aggregates"][key]
            mean = agg["mean"]
            cells.append(f"{mean!s:>16}"[:16])
        print(f"{key:<42}" + "".join(cells))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nresults written to {out} (synthetic — see caveat)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

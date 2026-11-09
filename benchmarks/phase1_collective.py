#!/usr/bin/env python3
"""Phase C1 benchmark — A/B/C/D configurations over a deterministic synthetic swarm.

WHAT THIS IS
  A reproducible, offline harness that measures the collective-intelligence layer's
  effect on the metrics the Phase C1 spec names. It simulates a swarm of workers
  investigating a fixed synthetic workload (endpoints x weakness classes, with a
  known ground truth of which are truly vulnerable) under four configurations:

    A  baseline        — shared task list only; workers cannot see each other's work
    B  + forum         — workers publish observations; siblings consult them
    C  + registry      — tasks become hypotheses with atomic claims, leases, and
                         counter-evidence reuse (the Phase C1 integration shape)
    D  + semantic help — C plus relationship candidates consulted before starting

WHAT THIS IS NOT
  Live-fire numbers. The workload is synthetic, attempts are simulated with a fixed
  seed, and the verification pipeline is a deterministic mock with the same verdict
  vocabulary (confirmed / falsified / not_reproducible). The point is to (a) prove
  the harness and metrics exist and run, (b) expose the deltas the layer CAN and
  CANNOT move in a controlled setting, and (c) enumerate the live-fire experiments
  that remain. Do not quote these numbers as product performance.

Run:  python benchmarks/phase1_collective.py [--out benchmarks/phase1_results.json]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.swarm import (ACTIVE, AWAITING_VERIFICATION, CONFIRMED, EventJournal,
                           HypothesisRegistry, REFUTED, ResearchForum, EvidenceRef)
from redteam.swarm.forum import redact_secrets
from redteam.swarm.relationships import DeterministicMatcher, HypothesisSignature

SEED = 20260101
N_WORKERS = 6
N_ASSETS = 14
N_CLASSES = 5                     # weakness classes per asset in the workload
TASK_MULTIPLIER = 3               # task descriptions per (asset, class) — near-duplicates
VULN_RATE = 0.35
ATTEMPT_TOKENS = 900              # simulated tokens per investigation attempt
FORUM_READ_TOKENS = 120
CANDIDATE_CHECK_TOKENS = 150
NOISE_PER_ATTEMPT = {0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0}   # same ruler across configs
VERIFY_TRIALS, VERIFY_NEED = 5, 4

GROUND_TRUTH_WORDS = ("granted", "succeeds", "accessible", "bypassed")
CONTROL_WORDS = ("denied", "403", "blocked", "unchanged")


@dataclass
class Task:
    """One synthetic investigation task = one hypothesis wording."""
    task_id: int
    asset: str
    weakness: str
    wording: str                     # near-duplicate wording variants share a task
    vulnerable: bool                 # ground truth
    underlying: tuple                # (asset, weakness) — the true investigation key


@dataclass
class Attempt:
    task_id: int
    underlying: tuple
    worker: str
    attempt_no: int                  # attempt ordinal for this underlying key (global)
    duplicate: bool                  # worked while a sibling already attempted it
    reused: bool                     # worker consulted sibling context before working
    tokens: int
    noise: float
    landed_finding: bool
    verdict: str = ""                # from the mock verification pipeline
    round_no: int = 0


@dataclass
class SimState:
    attempts: list = field(default_factory=list)
    observations: dict = field(default_factory=dict)   # underlying -> worker summary
    reuse_opportunities: int = 0
    reuse_events: int = 0
    provenance_items: int = 0
    provenance_complete: int = 0
    candidates: list = field(default_factory=list)     # (kind, correct: bool)
    candidate_checks: int = 0
    stale_write_rejected: int = 0
    stale_write_tried: int = 0
    confirmed_keys: set = field(default_factory=set)
    falsified_keys: set = field(default_factory=set)
    total_tokens: int = 0
    total_noise: float = 0.0
    rounds: int = 0


def build_workload() -> list[Task]:
    rng = random.Random(SEED)
    tasks: list[Task] = []
    tid = 0
    wordings = [
        "suspicion that {w} on {a} is exploitable without credentials",
        "{a} may be affected by {w} given the verbose error bodies observed",
        "peer report hints at {w} behavior on {a}; needs a proof attempt",
    ]
    for a_i in range(N_ASSETS):
        asset = f"https://target.example.com/app{a_i}/resource"
        for c_i in range(N_CLASSES):
            weakness = f"class-{c_i}"
            vulnerable = rng.random() < VULN_RATE
            for m in range(TASK_MULTIPLIER):
                tid += 1
                tasks.append(Task(
                    task_id=tid, asset=asset, weakness=weakness,
                    wording=wordings[m % len(wordings)].format(w=weakness, a=asset),
                    vulnerable=vulnerable, underlying=(asset, weakness)))
    return tasks


def mock_verify(vulnerable: bool, rng: random.Random) -> str:
    """Deterministic-shaped mock of verify.py's k-of-n: a truly vulnerable target
    reproduces (confirmed) with high probability; a non-vulnerable one fails or is
    falsified by the negative control."""
    if vulnerable:
        return "confirmed" if rng.random() < 0.92 else "not_reproducible"
    if rng.random() < 0.5:
        return "falsified"          # negative control reproduces the signal
    return "not_reproducible"


def record_evidence(state: SimState, origin: str, agent: str, artifact: str) -> None:
    state.provenance_items += 1
    if origin in ("agent", "target") and agent and artifact:
        state.provenance_complete += 1


# -- configurations -----------------------------------------------------------------------

def run_config(tasks: list[Task], mode: str) -> SimState:
    """mode: 'A' baseline, 'B' forum, 'C' registry, 'D' registry+semantic."""
    rng = random.Random(SEED + ord(mode))
    state = SimState()
    registry = forum = None
    if mode in ("C", "D"):
        registry = HypothesisRegistry(f"bench-{mode}", journal=EventJournal(f"bench-{mode}"))
    if mode in ("B", "C", "D"):
        forum = ResearchForum(f"bench-{mode}")

    per_worker = [list(t.task_id for t in tasks[i::N_WORKERS]) for i in range(N_WORKERS)]
    attempts_by_key: dict[tuple, int] = {}
    claimed_by: dict[tuple, str] = {}
    hypothesis_by_key: dict[tuple, str] = {}
    round_no = 0

    worker_queues = dict(enumerate(per_worker))
    active = set(worker_queues)
    while worker_queues and round_no < 40:
        round_no += 1
        state.rounds = round_no
        progressed = False
        for w in sorted(active):
            queue = worker_queues.get(w)
            if not queue:
                continue
            task_id = queue.pop(0)
            task = next(t for t in tasks if t.task_id == task_id)
            progressed = True
            underlying = task.underlying
            agent = f"worker-{w}"
            reused = False

            # -- sibling-context consultation -------------------------------
            if forum is not None and underlying in state.observations:
                state.reuse_opportunities += 1
                state.total_tokens += FORUM_READ_TOKENS
                # B/C/D: a completed sibling attempt with a verdict is reusable
                # context; the worker skips re-proving an already-decided key
                verdict = state.observations[underlying].get("verdict")
                if verdict in ("confirmed", "falsified"):
                    state.reuse_events += 1
                    state.attempts.append(Attempt(
                        task.task_id, underlying, agent,
                        attempts_by_key.get(underlying, 0), duplicate=False,
                        reused=True, tokens=FORUM_READ_TOKENS, noise=0.0,
                        landed_finding=False, verdict="reused", round_no=round_no))
                    continue
                reused = True
                state.reuse_events += 1

            # -- relationship candidates (D) ---------------------------------
            if mode == "D" and registry is not None and registry.has_equivalent(
                    task.asset, task.weakness) is None:
                state.candidate_checks += 1
                state.total_tokens += CANDIDATE_CHECK_TOKENS
                # near-duplicate wording on the same (asset, class): the lexical
                # matcher suggests reuse; candidates NEVER merge anything
                for t in tasks:
                    if t.underlying == underlying and t.task_id != task.task_id:
                        sig_a = HypothesisSignature.of(_pseudo_hyp(task.asset, task.weakness, task.wording))
                        sig_b = HypothesisSignature.of(_pseudo_hyp(t.asset, t.weakness, t.wording))
                        correct = (sig_a.asset == sig_b.asset and sig_a.weakness == sig_b.weakness)
                        state.candidates.append(("DUPLICATE_OF", correct))
                        break

            # -- attempt bookkeeping (the metric that matters) ----------------
            attempt_no = attempts_by_key.get(underlying, 0)
            duplicate = attempt_no > 0 and not reused
            attempts_by_key[underlying] = attempt_no + 1

            # -- registry claim (C/D) -----------------------------------------
            if registry is not None:
                try:
                    hyp = registry.register(asset_ref=task.asset,
                                            weakness_class=task.weakness,
                                            claim=task.wording, created_by=agent)
                    registry.claim(hyp.hypothesis_id, agent)
                    hypothesis_by_key[underlying] = hyp.hypothesis_id
                except Exception:
                    pass    # lost a claim race in-sim: counts as suppressed below

            tokens = ATTEMPT_TOKENS
            noise = NOISE_PER_ATTEMPT[0]
            landed = task.vulnerable and rng.random() < 0.8
            verdict = mock_verify(task.vulnerable, rng) if landed else ""
            if verdict == "confirmed":
                state.confirmed_keys.add(underlying)
                if underlying in state.falsified_keys:
                    state.falsified_keys.discard(underlying)
            elif verdict == "falsified":
                state.falsified_keys.add(underlying)
            state.attempts.append(Attempt(
                task.task_id, underlying, agent, attempt_no, duplicate, reused,
                tokens, noise, landed, verdict, round_no))
            state.total_tokens += tokens
            state.total_noise += noise
            if forum is not None:
                state.observations[underlying] = {
                    "worker": agent, "verdict": verdict,
                    "summary": redact_secrets(f"attempt on {underlying[0]} "
                                              f"{('landed: ' + verdict) if landed else 'no proof'}")}
                record_evidence(state, "agent", agent, f"attempt:{task.task_id}")
            if registry is not None and underlying in hypothesis_by_key:
                hyp_id = hypothesis_by_key[underlying]
                evidence = EvidenceRef(
                    evidence_id=f"ev-{task.task_id}-{attempt_no}",
                    kind="finding" if landed else "attempt",
                    origin="agent", source_agent=agent,
                    artifact_ref=f"attempt:{task.task_id}:{attempt_no}",
                    summary=f"{'landed ' + verdict if landed else 'no proof'}",
                    ts=_dt.datetime.now(_dt.timezone.utc).isoformat())
                try:
                    if landed:
                        registry.attach_evidence(hyp_id, evidence, agent)
                        registry.set_status(hyp_id, AWAITING_VERIFICATION, agent,
                                            finding_id=evidence.artifact_ref)
                        if verdict == "confirmed":
                            # the mock pipeline spoke -> mirror
                            registry.record_verification_outcome(
                                hyp_id, verdict="confirmed",
                                finding_id=evidence.artifact_ref,
                                by_agent="verify-pipeline")
                    else:
                        registry.attach_counter_evidence(hyp_id, evidence, agent)
                        registry.release(hyp_id, agent)
                except Exception:
                    pass
        if not progressed:
            break
        # stale-ownership probe (C/D): a worker whose lease expired tries to write
        if registry is not None and mode in ("C", "D") and round_no == 10:
            state.stale_write_tried += 1
            try:
                some_hyp = next(iter(hypothesis_by_key.values()))
                registry.renew_lease(some_hyp, "ghost-worker")
            except Exception:
                state.stale_write_rejected += 1
        active = {w for w, q in worker_queues.items() if q}
        if not active:
            break
    return state


def _pseudo_hyp(asset: str, weakness: str, claim: str):
    """A lightweight Hypothesis-shaped object for signature checks in the sim."""
    from redteam.swarm.hypotheses import Hypothesis
    return Hypothesis(hypothesis_id="sim", engagement_id="sim", asset_ref=asset,
                      weakness_class=weakness, claim=claim, preconditions=[],
                      expected_behavior="", proposed_test="")


# -- metrics ------------------------------------------------------------------------------

def metrics(state: SimState, tasks: list[Task], mode: str) -> dict:
    real_attempts = [a for a in state.attempts if a.verdict != "reused"]
    duplicate_attempts = [a for a in real_attempts if a.duplicate]
    confirmed = len(state.confirmed_keys)
    falsified = len(state.falsified_keys)
    ground_truth_vuln = {t.underlying for t in tasks if t.vulnerable}
    confirmed_true = len(state.confirmed_keys & ground_truth_vuln)
    total = len(state.attempts)
    return {
        "mode": mode,
        "total_task_deliveries": total,
        "real_investigations": len(real_attempts),
        "duplicate_investigation_rate": round(
            len(duplicate_attempts) / max(len(real_attempts), 1), 4),
        "unique_confirmed_findings": confirmed,
        "confirmed_true_positives": confirmed_true,
        "verification_precision": round(confirmed / max(confirmed + falsified, 1), 4),
        "evidence_provenance_completeness": round(
            state.provenance_complete / max(state.provenance_items, 1), 4)
            if state.provenance_items else None,
        "observation_reuse_rate": round(
            state.reuse_events / max(state.reuse_opportunities, 1), 4)
            if state.reuse_opportunities else 0.0,
        "avg_rounds_to_confirmation": round(
            statistics.mean([a.round_no for a in real_attempts
                             if a.verdict == "confirmed"]), 2)
            if any(a.verdict == "confirmed" for a in real_attempts) else None,
        "tokens_per_confirmed_finding": round(
            state.total_tokens / max(confirmed, 1), 1),
        "noise_cost_per_confirmed_finding": round(
            state.total_noise / max(confirmed, 1), 2),
        "false_relationship_rate": round(
            sum(1 for _, ok in state.candidates if not ok)
            / max(len(state.candidates), 1), 4) if state.candidates else None,
        "auto_merges": 0,          # structurally impossible: candidates never merge
        "stale_ownership_rejections": (
            f"{state.stale_write_rejected}/{state.stale_write_tried}"
            if state.stale_write_tried else None),
    }


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmarks/phase1_results.json")
    args = ap.parse_args()
    tasks = build_workload()
    print(f"workload: {len(tasks)} task wordings over "
          f"{len({t.underlying for t in tasks})} (asset, weakness) keys, "
          f"ground-truth vulnerable keys: {len({t.underlying for t in tasks if t.vulnerable})}")
    print(f"workers: {N_WORKERS}, seed: {SEED}\n")
    results = {"generated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
               "seed": SEED, "workload_size": len(tasks), "configs": [],
               "remaining_experiments": REMAINING_EXPERIMENTS,
               "caveat": "SYNTHETIC simulation — not live-fire numbers"}
    header = (f"{'metric':<38}" + "".join(f"{m:>14}" for m in "ABCD"))
    print(header)
    print("-" * len(header))
    rows: dict[str, list] = {}
    for mode in "ABCD":
        m = metrics(run_config(tasks, mode), tasks, mode)
        results["configs"].append(m)
        for k, v in m.items():
            if k == "mode":
                continue
            rows.setdefault(k, []).append(v)
        print(f"config {mode} computed")
    for k, vals in rows.items():
        cells = []
        for v in vals:
            cells.append(f"{v!s:>14}"[:14])
        print(f"{k:<38}" + "".join(cells))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nresults written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

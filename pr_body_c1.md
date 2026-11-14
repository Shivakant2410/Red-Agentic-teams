# Phase C1 PR body — Collective Intelligence Foundation

Branch: `phase-c1-collective-intelligence` (stacks on `phase-b5-strategy-memory`)
Base: `phase-b5-strategy-memory` — merge after B5, per the standing order B2→B3→B4→B5→C1

## What this adds

The swarm now shares *research*, not just state. `redteam/swarm/` is a run-scoped,
engagement-isolated, thread-safe collective-intelligence layer governed by one
principle: **an observation is not a hypothesis; a hypothesis is not a finding; a
finding is not confirmed until the independent verification pipeline confirms it.**

Four capabilities (ADR: `docs/adr-001-collective-intelligence-foundation.md`):

1. **Hypothesis registry** (`swarm/hypotheses.py`) — first-class, run-scoped store of
   structured suspicions: register / retrieve / filter / lifecycle transitions /
   evidence + counter-evidence (append-only, mandatory `origin: agent|target`
   provenance) / links / challenges / full history. Atomic claims (CAS under lock —
   the `AttackTree.claim()` contract), leases with injectable clock, optimistic
   `expected_version`, stale-owner write rejection. Lifecycle
   `PROPOSED → ACTIVE → AWAITING_VERIFICATION → CONFIRMED / REFUTED` plus reversible
   `BLOCKED`/`STALE`.
2. **Research forum** (`swarm/forum.py`) — nine typed, schema-validated, attributable
   message types; bounded filtered retrieval (never "send everything"); duplicate
   delivery idempotent; **swarmguard quarantine** at publish (directive-shaped peer
   content never re-enters a peer's context) and **secret redaction**; optional
   EventBus mirror for the dashboard.
3. **Relationships & duplicate detection** (`swarm/relationships.py`) — two stages:
   deterministic normalized-signature matching + pluggable `SemanticMatcher` protocol
   (no external service required in C1; a deterministic lexical matcher exercises the
   plumbing). Candidates only — never merge, never delete, never reword;
   `SUPERSEDES` is never machine-generated.
4. **Event replay** (`swarm/journal.py` + `swarm/projections.py`) — append-only JSONL
   journal is the lifecycle source of truth (the `events.py` EventBus stays
   telemetry-only: its emit-swallows-errors policy is wrong for authoritative history
   — documented in ADR §2.3). `replay()` rebuilds state deterministically through the
   same apply path; torn/invalid/foreign events are skipped and reported; restart
   recovery keeps appending via `replay_into()`. Clock judgments use the EVENT's
   timestamp (causal) so a hostile/stale claim can't ride wall-clock drift into an
   expired-lease reclaim.

## Orchestrator integration (additive, smallest surface)

- Every swarm claim becomes a registered, atomically-claimed hypothesis; a lost
  registry claim suppresses the duplicate investigation (same FAILED discipline as
  empty attempts); specialists get a **bounded research briefing** (prior attempts,
  sibling hypotheses, forum context) — wasted attempts become reusable context.
- After every `run_verify_pass`, verdicts are **mirrored** onto hypotheses.
  `CONFIRMED/REFUTED` are reflections of the pipeline, never causes of finding
  confidence — `FindingStore.promote()` remains the only writer.
- Research failures degrade to audit records (`research.error`), never run failures.
- `run.py` passes `research_dir` so a killed run's research state replays from
  `research_journal.jsonl` / `research_forum.jsonl`.
- No new agent tools, no worker-count change, attack-tree selection untouched.

## What was NOT touched (protected behavior)

`attack_tree.py`, `findings.py`, `verify.py`, `falsify.py`, `events.py`,
`swarmguard.py`, `tools/peer_traces.py`, `memory.py`, `reflection.py`,
`knowledge.py` — zero diffs. The only modified files are `orchestrator.py`
(+213 additive lines, 3 lines of logic changed: signature, finding-ID tracking),
`run.py` (+1 line), `pyproject.toml` (+1 package), README/AGENTS/docs.

## Tests

**927 passed** (847 baseline + 80 new), 0 regressions, no pre-existing failures.
New suites: registry (20), concurrency (10, ThreadPoolExecutor + injected clock —
no sleeps), forum (14), relationships (15), replay (10, real JSONL files),
integration (11, FakeClient — no live LLM).

## Benchmark

`benchmarks/phase1_collective.py` — deterministic synthetic A/B/C/D harness
(**clearly labeled as simulation, not live-fire**): duplicate-investigation rate
0.667 (A) → 0.0 (B/C/D); tokens/confirmed-finding 8590.9 (A) → 7759.1 (B); D's
candidate checks cost tokens while producing 0 false relationships and 0 auto-merges.
Results in `benchmarks/phase1_results.json` with the remaining live-fire experiment
list. No improvement claims are made beyond the measured simulation.

## Non-goals respected

No contrarian agents, no dissent budget, no specialist teams, no bandit, no attack-tree
replacement, no LLM-client change, no external vector DB or broker, no LLM auto-merge,
no verification-contract change, no scope change.

## Merge order

B2 (#2) → B3 (#4) → B4 (#5) → B5 (#6) → **this PR**.

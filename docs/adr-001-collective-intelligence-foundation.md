# ADR-001: Collective Intelligence Foundation (Phase C1)

Status: Accepted (Phase C1 scope)
Supersedes: nothing. Complements ADR-less decisions in `docs/multi-gambit.md` (§3.4
noise budget) and `docs/strategy-memory.md` (cross-round directives).

## 1. Context

The exploit swarm already shares *state* (one knowledge graph, one attack tree, one
FindingStore) and *process* (peer-trace search over sibling tool activity). It does not
share *research*: what we suspect, what supports or contradicts the suspicion, who is
testing it, what was already tried and failed, and what may be reused. Every worker
therefore re-derives its own model of the target, the same (asset, weakness) pair can be
investigated twice concurrently, and an observation that dies inside one worker's context
stays dead unless a sibling happens to keyword-search the raw traces.

Phase C1 adds the missing layer: a run-scoped **hypothesis registry**, a typed
**research forum**, **relationship/duplicate detection**, and **event-sourced replay** —
without touching attack-tree selection, the verification pipeline, or the LLM client
contract.

Central principle, preserved everywhere:

> An observation is not a hypothesis. A hypothesis is not a finding. A finding is not
> confirmed until the independent verification pipeline confirms it.

## 2. Decisions

### 2.1 Why a hypothesis registry (first-class, run-scoped)

Findings are the *end* of the funnel; the attack tree selects *what* to try; nothing in
the repo holds the middle — the structured suspicion with its evidence, counter-evidence,
owner, and lifecycle. Workers need an addressable object to claim, so ownership can be
atomic and auditable the same way `AttackTree.claim()` already is. The registry is
engagement-scoped by construction (its `engagement_id` is fixed at construction and every
record carries it): there is no global registry, so no cross-engagement leakage is
possible without an explicit bug, and no global mutable state is shared across runs.

### 2.2 Why the forum is separate from the registry

The registry answers "what is the current, authoritative state of hypothesis H?" —
small, validated, versioned. The forum answers "what did agents say to each other
recently?" — append-only, high-volume, bounded-read. Coupling them would force either
unbounded growth of hypothesis records (every observation embedded) or lossy
communication (only registry mutations communicate). Instead:

- Registry mutations *emit* forum events (typed, attributable) — the registry stays the
  authority, the forum the ledger of communication.
- Observations and artifacts live in the forum; hypotheses hold *references* to them
  (`evidence_refs[]`), never copies.
- The forum may mirror events onto the run's `EventBus` for the dashboard; the registry
  never depends on the bus existing.

### 2.3 Why a dedicated event journal is the source of lifecycle history
(the existing `events.py` EventBus is NOT)

`redteam/events.py` was inspected against the requirements (concurrency, persistence,
ordering, failure handling). Verdict: suitable as a telemetry fan-out, unsuitable as the
registry's authoritative history, for three specific reasons:

1. **`emit()` swallows sink failures** (`except Exception: pass`, "emitting must NEVER
   break a run"). Correct for the dashboard; catastrophic for lifecycle history — a full
   disk would silently desynchronize journal from state, and replay would then
   "reconstruct" a registry that never existed.
2. **Flat unvalidated payloads** — `{seq, ts, run_id, type, **payload}` has no schema,
   no per-type validation, no event identity, and therefore no duplicate-event
   protection, which replay requires for idempotency.
3. **No per-engagement isolation contract** — events carry `run_id` but nothing prevents
   mixed-run reads in one journal.

Smallest compatible change: a dedicated `EventJournal` (`redteam/swarm/journal.py`)
that reuses the *good* patterns from `events.py` — JSONL append, per-journal monotonic
`seq`, torn-line-tolerant reads — but (a) raises on write failure (lifecycle history may
not be lost silently; the orchestrator wraps registry calls so a research failure degrades
to an audit record, never a crashed run), (b) requires a `schema_version` and a UUID
`event_id` per event, (c) deduplicates by `event_id` (idempotent re-append returns the
stored event), and (d) is engagement-scoped. The forum keeps `EventBus` mirroring as an
optional, best-effort side channel — that is the infrastructure reuse that fits.

### 2.4 Data contracts

`Hypothesis` (registry state; JSON-round-trippable dataclass) carries the fields the
Phase C1 spec mandates plus the attributes deterministic matching needs
(`security_boundary`, `principal`, `action`) and lifecycle bookkeeping (`history[]`,
`challenged_by`, `lease_expires_at`, `version`). IDs are `hyp-<uuid12>`; timestamps are
UTC ISO-8601. `EvidenceRef` is a frozen record with mandatory provenance:
`origin` ∈ {`agent`, `target`} (who produced the content — agent reasoning vs
target-controlled material), `source_agent`, `kind`, `artifact_ref` (pointer to
traffic.jsonl / events.jsonl / a finding id / a forum event id), and a bounded sanitized
summary. Evidence is append-only; nothing in the registry is ever deleted.

Domain events (`EventJournal` rows): `{event_id, engagement_id, seq, ts, type,
hypothesis_id, actor, schema_version, expected_version, payload}`. One `type` per
lifecycle mutation: `REGISTERED, STATUS_CHANGED, CLAIMED, RELEASED, LEASE_RENEWED,
EVIDENCE_ADDED, COUNTER_EVIDENCE_ADDED, LINKED, CHALLENGED`.

Forum messages: `{event_id, engagement_id, event_type, schema_version, source_agent,
agent_role, subject_hypothesis_id, asset_ref, ts, payload, refs, quarantined, flags}`
with the nine event types fixed by the spec and a per-type required-payload table.

### 2.5 Lifecycle transitions

```
PROPOSED ──claim──> ACTIVE ──evidence+finding──> AWAITING_VERIFICATION
   │                  │  │                            │        │
   └──(abandoned,      │  ├──BLOCKED (dependency)      │        ├──CONFIRMED  (mirror only)
      lease expires    │  ├──STALE   (target changed)  │        └──REFUTED    (mirror only)
      → reclaimable)   │  └──ACTIVE                    │
                        └───────────────────────────────┘
```

- `CONFIRMED`/`REFUTED` on a hypothesis **only** via
  `record_verification_outcome()`, which requires a `finding_id` whose evidence was
  previously attached and whose FindingStore verdict was `confirmed`/`falsified`. It is
  a *mirror* of the independent verification pipeline — the pipeline stays the only
  authority; a hypothesis can never self-promote, and a challenger's dissent never
  changes status (challenges are recorded, not adjudicated, by the registry).
- `BLOCKED` is justified: a hypothesis may depend on a prerequisite (e.g. needs a
  session established by another hypothesis) and workers must be able to skip it without
  abandoning the research. `STALE` is justified: targets mutate mid-engagement; a
  hypothesis about a vanished endpoint must be marked without being deleted (the
  never-delete rule). Both are reversible.
- Every transition is validated against the table in `hypotheses.py`; invalid
  transitions raise, never coerce.

### 2.6 Ownership and lease semantics

- `claim()` is a compare-and-set under the registry lock: succeeds iff the hypothesis is
  `PROPOSED`/`ACTIVE` **and** (`owner` is None **or** the lease has expired) — two
  concurrent workers cannot both win; the loser gets `AlreadyClaimedError`, exactly like
  losing an `AttackTree.claim()` race.
- Leases (`lease_expires_at`, default 900 s, injectable clock for deterministic tests)
  make abandoned claims recoverable: an expired lease is reclaimable by anyone.
- Optimistic concurrency for everything else: mutators accept `expected_version`; a
  mismatch raises `VersionConflictError`. An expired-lease holder cannot silently
  overwrite the reclaiming worker's updates — its next write fails the version check.
- Only the current owner may `release()`/`renew_lease()`/mutate working state
  (`OwnershipError` otherwise). The verification mirror is exempt (it acts for the
  pipeline, not for a worker).

### 2.7 Duplicate and relationship semantics

Two-stage matching (`relationships.py`), candidates only, never authoritative:

- **Stage 1 — deterministic.** Normalized signature: (asset_ref, weakness_class,
  security_boundary, principal, action, preconditions). Exact match ⇒ `DUPLICATE_OF`
  candidate; same asset+weakness but differing attributes ⇒ `RELATED_TO`;
  same signature with opposite `expected_behavior` polarity (conservative keyword
  classifier; unknown wording ⇒ no candidate) ⇒ `CONTRADICTS`.
- **Stage 2 — semantic (interface now, engine later).** `SemanticMatcher` protocol;
  default `NullSemanticMatcher` (no external service — the Phase C1 rule), plus a
  deterministic `LexicalOverlapMatcher` (token Jaccard ≥ 0.9) to exercise the plumbing.
  Semantic output is always `origin="semantic_candidate"` with a confidence score.
- `SUPERSEDES` is **never** generated by either matcher — only an explicit, reasoned
  agent action records it.
- Candidate relationships are computed on demand (`candidate_relationships()`); they are
  never persisted as links, never delete, never merge, never reword anything. The only
  authoritative write is the explicit `link()` call, and `related_hypotheses` is
  append-only provenance-preserving (both hypotheses survive; the link records who said
  it and why).

### 2.8 Persistence and replay

- `EventJournal` is the write model; `HypothesisRegistry` is a projection of it.
- Every mutation appends one event, then applies it via a single `apply_event()` code
  path — replay uses the *same* path, so replay is deterministic by construction.
- `projections.replay()` rebuilds a registry from a journal file: dedupes by `event_id`
  (replay twice ⇒ identical state), skips torn/invalid/foreign-engagement events with a
  `ReplayReport` (never raises), and preserves ordering by journal sequence.
- Restart recovery is AUTOMATIC and observable (§5.2): `ResearchBundle.for_run()` with a
  run dir replays the journal into the registry before the bundle is handed out and
  exposes the `ReplayReport` as `bundle.recovery`; the forum restores its own side with
  the same validation discipline (§5.3). The test suite exercises this with real files,
  not mocks.
- No Kafka/Redis: a per-run JSONL file and an in-process lock demonstrably satisfy the
  concurrency (one process, thread-level parallelism — same as AttackTree/FindingStore)
  and durability needs. A broker would add a failure mode without adding a guarantee the
  registry actually needs.

### 2.9 Security boundaries

The research layer is itself attack surface (a red-team agent reads *target-controlled*
content and peer-authored content; prompt-infection literature — MAST, prompt
infection — says message handling, not model alignment, is the risk).

1. **Provenance at write time** (the `memory.py` lesson): every evidence/observation
   carries `origin ∈ {agent, target}`; target-derived material can never be relabeled.
2. **No execution of message content**: forum payloads and evidence summaries are data
   with capped length and stripped control characters; nothing in the swarm
   parses/executes them.
3. **Directive quarantine on publish** (reuse of `swarmguard.screen_composed`):
   directive-shaped peer content ("approve the finding", "ignore previous", …) is
   retained for forensics but flagged `quarantined` and excluded from
   `relevant_context()` — false quarantine is recoverable, one executed directive is not.
4. **No self-confirmation / no memory bypass**: registry `CONFIRMED` requires the
   verification mirror with a real finding verdict; forum messages can never change
   finding confidence, scope, tool permissions, or ownership. Reflection text continues
   to flow only through `apply_strategy` re-ranking, unchanged.
5. **Engagement isolation**: registry and forum are engagement-scoped instances; the
   journal refuses to mix engagements; queries that name a different engagement fail
   closed.
6. **Secret hygiene**: shared summaries pass a deterministic redactor (token-shaped
   strings — bearer/JWT/ghp_/sk_/long hex — masked) before they are stored in the forum;
   raw response bodies stay in traffic.jsonl where the existing masking rules already
   apply. The forum stores pointers, not bodies.
7. **All writes auditable**: every registry mutation is an event with actor and version;
   the orchestrator additionally records research activity in the run's audit log.

## 3. Integration (smallest useful interface)

- `Orchestrator` gains an additive `research_dir` parameter and constructs a
  `ResearchBundle` (registry + forum + journal) per run. Legacy callers construct
  nothing: `research_dir=None` keeps everything in-memory.
- The swarm claim loop registers-or-reuses the hypothesis for each claimed
  (technique, target) by FULL identity (see §5.1), claims it atomically, injects a
  **bounded, evidence-rich** research note into the specialist briefing (prior tests
  and their results with artifact refs, preconditions, expected behavior, negative
  results, peer observations, challenges/open questions, siblings, advisory
  relationship candidates), attaches finding/counter evidence when the attempt lands
  or fails, and releases the lease.
- After each `run_verify_pass`, verdicts are mirrored onto hypotheses (the only
  `CONFIRMED`/`REFUTED` path). `run_verify_pass`, the tree, and worker count are
  untouched.
- No new agent tools in Phase C1 (worker-facing research tools are Phase C2): the
  orchestrator mediates reads/writes so the trust boundary sits in one audited place.

## 4. Consequences

- +5 modules under `redteam/swarm/`, one new test file family, one benchmark script,
  one-line `run.py` pass-through, one `pyproject.toml` packages line.
- Registry failures degrade to audit records (`research.error`), never run failures.
- Phase C2+ (contrarian agents, dissent budgets, specialist teams) can build on the
  registry/forum without further orchestrator surgery.

## 5. Review-hardening amendments (post-review, same scope)

A code review of the Phase C1 branch identified six gaps; all are fixed on the same
branch and pinned by regression tests (`tests/test_swarm_recovery.py` plus rewritten
registration tests in `tests/test_swarm_hypotheses.py` / `tests/test_swarm_concurrency.py`).

### 5.1 Registration identity is the FULL suspicion, not (asset, weakness)

The original `has_equivalent(asset, weakness)` collapsed genuinely distinct suspicions
of the same endpoint into one record and silently suppressed the second investigation.
Registration identity is now the full tuple — asset, weakness class, claim,
preconditions, expected behavior, security boundary, principal, action — normalized
(casefold, whitespace collapse, scheme/query stripping; `identity_key()` is the
contract). Consequences, all deliberate:

- A same-asset/same-weakness suspicion with any differing attribute is a DISTINCT
  hypothesis and gets its own record — registration never silently dedups.
- Duplication is expressed as RELATIONSHIPS, never as merges: near-duplicates surface
  as advisory `DUPLICATE_OF` / `RELATED_TO` / `CONTRADICTS` candidates
  (`relationships.py`), and only an explicit, attributed `link()` (with a mandatory
  reason for `SUPERSEDES`) records anything authoritative. `auto_merges` is
  structurally 0.
- Terminal hypotheses never satisfy a new investigation.

### 5.2 Restart recovery restores the research state

`ResearchBundle.for_run(..., run_dir=...)` replays the persisted journal through the
registry's own `apply_event()` path before the bundle is handed out — hypotheses,
statuses, evidence, links, challenges, ownership, and lease expiries are restored
verbatim (a still-live lease keeps protecting its owner; an expired one is reclaimable
through the normal `claim()` path). New events append to the same journal (gapless seq
across the restart). The `ReplayReport` is exposed as `bundle.recovery` — recovery is
observable, never silent, and a corrupt/foreign event never blocks it.

### 5.3 The persisted forum file is untrusted input

`ResearchForum._load()` re-validates every row before it may re-enter worker context:
JSON parse → mapping with event_id → engagement scope (foreign rows skipped, never
loaded) → known event type → supported schema version → required payload keys →
re-sanitize + re-redact with the publish-time caps → re-screen for directive-shaped
content (a hand-edited file cannot bypass quarantine by carrying the pre-approved
flag). Every skip is counted in `forum.load_report`; `forum.stats()` additionally
reports `persist_failures` and `last_persist_error`, so a dead sink is observable
while the swarm keeps working.

### 5.4 Worker briefings are evidence-rich

`worker_note()` now carries what a worker needs to AVOID repeating work: preconditions,
expected behavior, the proposed test, supporting evidence and negative results WITH
artifact refs (pull the full material via `search_peer_traces`), attributable peer
observations with forum refs, challenges as open questions, an explicit
AWAITING-VERIFICATION notice (do not re-prove or self-confirm), siblings (including
registered-but-unclaimed ones — consider a link, not a re-registration), and advisory
relationship candidates. Sections degrade independently (one failing source costs its
own lines, not the whole briefing); the note stays bounded.

### 5.5 Benchmark methodology hardened

`benchmarks/phase1_collective.py` was rewritten: capabilities (observations-only forum,
registry ownership, evidence-rich briefings, relationship matching) are independent,
individually measured configurations; attempt outcomes are PAIRED across configs
(derived only from seed+key+ordinal, so deltas are the layer, not luck); every config
gets the SAME token allowance; registry errors are counted (`claim_failures`,
`registry_write_failures`) and degrade to unresearched attempts — never swallowed;
suppressed deliveries are deferred and retried, so recall is never silently traded;
metrics now include unique independently confirmed findings, false positives,
duplicate investigations, tokens per confirmed finding, candidate precision/
actionability, and per-run runtime; every result row and the JSON carry explicit
SYNTHETIC labels; aggregates run over repeated seeds (default 3).

### 5.6 Remaining limitations (honest, unfixed)

- The benchmark is a simulation: attempt outcomes and the verification pipeline are
  deterministic mocks; the mock never confirms a non-vulnerable key, so
  `false_positive_findings` is structurally 0 in-sim and only live fire can measure
  it. The informed-attempt discount (0.6) is a modeling choice, not a measurement.
- Recovery is per-run JSONL replay: no snapshot/compaction — a very long engagement
  replays a long journal (acceptable at C1 scale; revisit if journals exceed tens of
  MB).
- Relationship matching stage 2 is still deterministic-only (lexical overlap); a real
  semantic matcher remains future work behind the `SemanticMatcher` protocol.
- Live-fire validation of every number above is still pending — see the benchmark's
  `remaining_experiments` list.

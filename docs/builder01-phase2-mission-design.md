# BUILDER 01 — PHASE 2 DESIGN: Mission Coordination Core
## Design addendum resolving the five review clarifications

**Status:** submitted for review — no implementation. Phase 1 audit (`docs/builder01-phase1-architecture-audit.md`, commit `cb612c2`) approved in principle; this document resolves the five clarifications and freezes the Phase 2 scope and test plan.
**Repo state:** branch `phase-e1-agent-hands`, baseline `1122 passed / 0 failed` (`PYTHONPATH=src`).
**Authority rule (restated by reviewer, honored throughout):** `FindingStore`, `AttackTree`, `ScopeGuard`, egress enforcement, `EventBus`, and independent verification remain the authoritative components. Nothing below creates a parallel authority; every mission-layer object *references* an authority.

---

## C1. Identity contract — mission_id / run_id

### C1.1 What identity is today (verified)

| Surface | Identity today | Verified at |
|---|---|---|
| Run directory | The run_id **is** the directory name under `runs_root`; minted by `RunRegistry.new_run_id()` as `{UTC ts}-{objective slug ≤32}` with `-2, -3…` collision suffixes | server.py:102–110 |
| CLI runs | The CLI names `out_dir` directly; same "identity = directory" rule | run.py `RunOptions.out_dir` |
| Events | Bus envelope carries `run_id` (constructor arg to `EventBus`) | events.py:84–90 |
| RunManifest | **Has no run_id field** — identity is implicit in the file's location (manifest.json inside the run dir) | runtime.py `RunManifest` fields |
| Swarm journal | `engagement_id = str(engagement.name) or "engagement"` — the *engagement* (RoE) name, not the run | orchestrator.py:563–565, swarm/journal.py:35–36 |
| Uniqueness oracle | The filesystem: `while (self.runs_root / run_id).exists()` | server.py:107–109 |

So the platform already answers "what is a run" with a directory name, and "what is an engagement" with the RoE name. The mission layer must join this scheme without minting a competing identity authority.

### C1.2 The contract (Phase 2)

1. **`run_id` stays exactly what it is**: the physical run-directory identity. Never renamed, never re-minted, still carried by every bus event envelope and resolved by every existing API route (`/api/runs/{run_id}` = directory lookup). Zero change to existing consumers.
2. **`mission_id` is the logical mission identity, and in Phase 2 `mission_id == run_id` by construction** (one mission = one run directory — Phase 1 decision §10.1 upheld). The Commander does not mint a second ID; it receives the run_id chosen by the existing minting path and adopts it.
3. **`mission.json` stores both fields independently**: `{"mission_id": "<run_id>", "run_id": "<run_id>", "engagement": "<RoE name>", "ticket": "<auth ref>", …}`. Storing them separately (rather than deriving one from the other at read time) means a future multi-run mission (1 mission : N runs) is a schema extension, not an identity migration.
4. **`task_id`** = `task-{uuid4().hex[:12]}`, minted by the Commander. Every task record carries the immutable triple `{task_id, mission_id, run_id}`.
5. **Events**: the bus envelope contract is untouched (`{seq, ts, run_id, type, **payload}`). Mission/task payloads *add* `mission_id` (and `task_id` where applicable). No existing event type gains or loses a field.
6. **Journal**: mission events use the **same `engagement_id` value the swarm journal uses** (`engagement.name`), so one engagement's journals remain cross-referenceable; mission/task IDs live in the payload fields (`mission_id`, `task_id`), and the mission journal is its own file (`mission_journal.jsonl`) — journal *files* are per-concern (research vs mission), journal *identity* is per-engagement.
7. **API**: additive routes resolve missions by the same directory lookup the runs API uses: `GET /api/missions/{mission_id}` ≡ `GET /api/runs/{mission_id}`'s directory. Responses echo `{mission_id, run_id, engagement, ticket}` so a client never has to guess the relationship.

### C1.3 Consistency matrix

| Entity | Minted by | Stamped where | Uniqueness authority | Immutable |
|---|---|---|---|---|
| `run_id` | `RunRegistry.new_run_id()` (server) / CLI `out_dir` (unchanged) | dir name, bus envelope, mission.json `run_id` | filesystem dir collision loop | yes |
| `mission_id` | adopted == run_id (Phase 2) | mission.json `mission_id`, all mission/task payloads, journal events | == run_id's oracle | yes |
| `task_id` | Commander at task creation | task record, journal events, bus payloads | Commander's in-memory set + journal event_id idempotence | yes |
| `hypothesis_id` | HypothesisRegistry (unchanged) | swarm journal, task record evidence refs | registry (existing) | yes |
| `finding_id` | FindingStore (unchanged) | findings.json, task evidence refs | store (existing) | yes |

**Test commitments:** identity tests assert (a) `mission.json.mission_id == mission.json.run_id == directory name`; (b) every mission/task event payload carries a `mission_id` matching the envelope `run_id`; (c) API responses echo the triple; (d) two `execute_run` invocations can never share a mission_id (filesystem oracle).

---

## C2. Atomic task ownership across the claim trio

### C2.1 The three primitives (verified current behavior)

| Primitive | Authority for | Atomicity | Reversibility today |
|---|---|---|---|
| **Mission task record** (new, Phase 2) | intent + lifecycle + evidence refs | CAS on status under the Commander lock; journal-first append | yes — explicit abort events (see C2.3) |
| **`AttackTree.claim()`** | work selection (which (technique, target) may be attacked) | TODO→IN_PROGRESS under RLock, winner-takes-all (attack_tree.py:346–359) | **no** — no un-claim, no owner, no lease; `AttackNode` = `{technique, target, status, findings, bucket}` (attack_tree.py:144–153). states.py:101–102 documents a lease-expiry → TODO release path that was never implemented |
| **`HypothesisRegistry.claim()`** | duplicate-suppression of investigations | wins iff PROPOSED/ACTIVE and (unowned or lease expired); owner re-claim renews; losers get `AlreadyClaimedError` (hypotheses.py:406–436) | yes — `release()` owner-only (438–450) |

**Current swarm order (for contrast):** tree claim first (orchestrator.py:700/706), hypothesis claim second (orchestrator.py:844). A duplicate hypothesis suppresses the investigation (`research.duplicate_suppressed` audit, worker returns) — and the tree node **stays IN_PROGRESS for the rest of the round** because the tree has no release path. That round-local leak is exactly what the lease/release primitives below close.

### C2.2 Phase 2 dispatch order — reversible reservation first

The scheduler dispatches in **reservation-reversibility order** (most reversible first):

1. **Task record CAS** `pending → claimed` (owner = agent_id, lease stamped) + `TASK_CLAIMED` journal event. *Why first:* this is the only primitive with a clean, journaled rollback; it reserves intent before touching any authority.
2. **`AttackTree.claim(technique, target, owner=agent, lease_seconds=T)`** — the selector authority. Failure (another worker won) → rollback step 1.
3. **`claim_or_register`** on the hypothesis registry — the dedup authority. `(None, True)` duplicate → task → `blocked_duplicate` (this round; tree node released per C2.3); `(None, False)` research-layer failure → proceed unresearched (the verified degrade-never-crash contract, orchestrator.py:874–879).
4. **Dispatch** the worker. Ownership is now triple-recorded (task record + tree node + hypothesis), all journaled *before* any offensive action.

### C2.3 Rollback semantics (each step's failure path)

| Failure at | Rollback action | Journal events | Tree/hypothesis state after |
|---|---|---|---|
| step 1 CAS | none needed (CAS failed = no reservation) | none | untouched |
| step 2 tree claim lost | task record CAS `claimed → pending` (attempt unchanged) | `TASK_CLAIM_ABORTED` | task pending; tree node owned by the other worker — untouched |
| step 3 duplicate hypothesis | task `claimed → blocked_duplicate` + **tree `release()`** (new primitive, see below) | `TASK_BLOCKED`, `TREE_RELEASED` | tree TODO; hypothesis owned by other worker — untouched |
| step 3 research-layer error | proceed unresearched (existing degrade) — no rollback | `research.error` audit (existing) | tree IN_PROGRESS under this worker's lease |
| worker crash/timeout | lease expiry sweep (C5) — not a synchronous rollback | `TASK_LEASE_EXPIRED` | tree released by sweep → TODO |

**New AttackTree primitives (the only tree changes in Phase 2, both additive):**
- `claim(technique, target, *, owner="", lease_seconds=None)` — keyword-only owner/lease with defaults; existing positional callers (`orchestrator.py:700/706`) compile and behave byte-identically.
- `release(technique, target, actor)` — IN_PROGRESS → TODO, **owner-only** (mirrors `HypothesisRegistry.release`'s OwnershipError contract). This implements the release path states.py:101–102 has documented since D1. `AttackNode` gains `owner: str = ""`, `lease_expires_at: str = ""` — old attack_tree.json files load via dataclass defaults (the established backward-compat pattern; findings.py:66–68 does the same for `retest_history`).

### C2.4 Crash-recovery matrix (process death between steps)

On mission restart, recovery runs a **pure reconcile function** `reconcile(journal_events, tree_state, task_state) → list[action]` — intent is read from the journal, effect from the tree/store files:

| Crash window | Journal shows | Tree shows | Task record shows | Recovery action |
|---|---|---|---|---|
| before TASK_CLAIMED persists | no claim | TODO | pending | nothing (task never started) |
| after TASK_CLAIMED, before tree claim | TASK_CLAIMED | TODO | claimed | re-dispatch same attempt (tree never claimed → no work lost) |
| after tree claim, before hypothesis claim | TASK_CLAIMED | IN_PROGRESS (leased) | claimed | lease decides (C5): live → resume dispatch; expired → tree release + task expired |
| after hypothesis claim, before dispatch | TASK_CLAIMED + HYP CLAIMED | IN_PROGRESS | claimed | same as above; hypothesis lease expires independently (900 s default) |
| after dispatch, before TASK_COMPLETED | TASK_CLAIMED (+ renewals) | IN_PROGRESS | claimed | lease decides; late completion → SUPERSEDED (C5.3) |
| after TASK_COMPLETED persists | TASK_COMPLETED | IN_PROGRESS or COMPLETED | succeeded | if tree not yet COMPLETED: completion is pending verification — tree completes only via `sync()` on a **confirmed** finding (authority rule); task stays succeeded either way |

**Invariants tested:** (a) at most one live owner per task under N-thread races (1 winner, losers get explicit errors — the `test_swarm_concurrency.py` pattern); (b) no crash window produces two owners; (c) no crash window loses a *confirmed* result (FindingStore is the effect authority); (d) reconcile is deterministic (same inputs → same actions).

---

## C3. Budget taxonomy — four planes, never conflated

The platform already keeps these mechanically separate; the clarification makes the separation contractual. **One task carries three independent budget fields (`execution`, `opsec_allowance`, `attempts`), never one "budget" bag.**

| Plane | Authority (existing class — reused, not reimplemented) | Scope | Exhaustion semantics | Distinct event |
|---|---|---|---|---|
| **Engagement / RoE** | `BudgetTracker` (wall-clock, tokens, STOP kill file → `Halt`) runtime.py:77; `RateLimiter` (RPS + total requests) ratelimit.py; engagement window (config.py `starts/ends`) | whole run, all agents/threads | **HALT** — mission → HALTED; never replanned around, never waived | `mission.halted` (reason: budget/kill/deadline) |
| **Execution (per-task)** | profile `max_steps` (existing per-specialist limit); **new** per-task wall-clock deadline = lease deadline; retry `attempts` (policy, default 2) | one task | **task failed** — may trigger replanning (Phase 4); never touches engagement caps | `task.failed` |
| **OPSEC / noise** | `RunOptions.round_noise_budget` credits (run.py, default 12.0) + `DriftPlusPenaltyScheduler` (orchestrator.py:311) + `technique_cost` (attack_tree.py) | per round, carved per task at claim time | **claim gating** — loud techniques unaffordable this round are simply not dispatched (quiet-only mode); a running task is never killed mid-flight by OPSEC; never a HALT | `opsec.throttled` (credits remaining, deferred techniques) |
| **Verification / proof** | k-of-n trials budget inside the proof tools (verify.py / proof.py — unchanged) | one finding's reproduction | **inconclusive** — finding stays `pending_verification`/`not_reproducible`; only the independent verify pass can promote | existing finding events |

**Non-conflation rules (each enforced by a test):**
1. OPSEC exhaustion can never produce `mission.halted`, and token exhaustion can never produce `opsec.throttled` — the event type identifies the plane, and no payload mixes plane fields.
2. A task's `opsec_allowance` is a *reservation* charged against the round's `round_noise_budget` at claim time and released on failure — it is not seconds, tokens, or requests; those live only in the engagement plane.
3. The engagement plane is read-only to the Commander: `BudgetTracker.check()` raises `Halt` exactly as today; the Commander catches it to set mission HALTED and re-raises nothing that could bypass the kill switch.
4. Per-task execution budgets are carved **down** from what the engagement allows; no task field can exceed the engagement cap (RoE inheritance is a validation rule at task creation).

---

## C4. EventJournal backward compatibility — schema change plan, tests first

### C4.1 Current schema (verified)

- `REQUIRED_EVENT_FIELDS = ("event_id", "engagement_id", "type", "hypothesis_id", "actor", "ts", "payload")` — append-time `_validate` raises `JournalError` on any missing field, `EngagementMismatchError` on foreign engagement (journal.py:35–36, 71–80).
- Append is idempotent by `event_id`; `seq` assigned under lock; persistence `sort_keys` JSONL, write failures raise (`_persist`, journal.py:83–95).
- Replay (`projections.py`) reads raw JSONL: missing/invalid fields → `InvalidEventError` from the registry's `apply_event` → **skipped and counted** (`SKIP_MALFORMED`, `SKIP_UNKNOWN_TYPE`, …), never fatal. Replay validation therefore lives in the *registry*, not the journal.

### C4.2 The change (generalize without breaking)

1. **Core fields shrink to** `("event_id", "engagement_id", "type", "actor", "ts", "payload")`; `hypothesis_id` moves into a **per-type required-field table**:
   - all existing swarm types (`REGISTERED`, `STATUS_CHANGED`, `CLAIMED`, `RELEASED`, `LEASE_RENEWED`, `EVIDENCE_ADDED`, `COUNTER_EVIDENCE_ADDED`, `LINKED`, `CHALLENGED`, `VERIFICATION_RECORDED`) → require `hypothesis_id`;
   - new mission types (`MISSION_*`, `TASK_*`) → require `mission_id` (`TASK_*` also `task_id`).
2. **Behavioral identity for the swarm:** the registry's `_new_event` always stamps `hypothesis_id`, so every swarm append validates exactly as before; on replay, a swarm event missing `hypothesis_id` still fails in `apply_event` → same skip counts. **No swarm write or replay path changes value.**
3. **No migration:** journals are append-only; no record is rewritten, no file converted. `SCHEMA_VERSION` stays 1; mission events may carry an extra `entity` field that readers ignore (events are flat dicts — unknown keys are already tolerated).
4. **Same-class, same-file-pattern:** mission journals instantiate the *same* `EventJournal` class (engagement-scoped, own `mission_journal.jsonl` file) — no second journal implementation.

### C4.3 Compat tests — written and passing BEFORE the schema change (reviewer requirement)

| # | Test | Asserts |
|---|---|---|
| T4.1 | **Golden replay fixtures**: journals captured from the existing swarm test suite (harvested at runtime into `tests/fixtures/journal/`) replay byte-identically — `ReplayReport.summary()` equal pre/post change | no old record changes meaning |
| T4.2 | Old-record rejection parity: an event missing `hypothesis_id` is rejected at append (JournalError) and skipped at replay (SKIP_MALFORMED) identically pre/post | failure modes unchanged |
| T4.3 | Mission events append + replay through the same class; `TASK_*` without `task_id` rejected; with it, accepted | new types validated |
| T4.4 | Mixed journal (swarm + mission events, one engagement) replays; skip counters correct per type | one class serves both |
| T4.5 | Torn last line + duplicate `event_id` idempotence + engagement-mismatch raise — unchanged | core guarantees intact |
| T4.6 | `test_swarm_recovery.py`, `test_swarm_projections.py`, `test_swarm_concurrency.py`, `test_swarm_hypotheses.py` pass **unmodified** (diff-checked) | the tested contract is untouched |

T4.1–T4.2 land first (green against the current code), then the schema change must keep them green — the red/green ordering the reviewer asked for.

---

## C5. Lease ownership and recovery

### C5.1 Ownership model

- **Lease owner = the dispatched agent id** (`exploit-w1` style — the same actor string the hypothesis layer uses), stamped on the task record and (new) on the tree node at claim time.
- **Renewal cadence:** at every agent turn boundary — the hook point the agent loop already crosses per turn (manifest update, budget check). A missed renewal is itself signal: it means the worker is stuck inside one long operation.
- **Lease length:** `task_deadline + 2 × SandboxConfig.command_timeout` (command_timeout defaults to 300 s, config.py:68 → grace ≥ 600 s), bounded below by `DEFAULT_LEASE_SECONDS = 900.0` (hypotheses.py:106). Rationale: the longest single atomic tool call must never be mistaken for a dead worker.
- Renewal and expiry are journaled (`TASK_LEASE_RENEWED` / `TASK_LEASE_EXPIRED`); expiry sweep (`expire_claimed()`) runs at round boundaries and at recovery start — never mid-turn.

### C5.2 Worker still active when the lease expires

- **Same-process** (scheduler and worker share the interpreter): reclaim requires the liveness check `thread.is_alive() == False`. A live worker is **never stolen from**: the sweep emits `task.lease_expired`, auto-renews once, and records an audit entry (`mission.lease_extended`) — the long tool call completes normally.
- **Cross-process** (mission restart): no liveness check is possible; the grace period above is the only guard. After grace, the task is reclaimable and the old worker — if it somehow still runs — hits the **stale-writer wall**: its completion write fails the ownership/version check (the `HypothesisRegistry` behavior at hypotheses.py:483–486, mirrored in the task store) and lands as a SUPERSEDED audit record. It can never overwrite the reclaiming worker's state.

### C5.3 Process dies between execution and journal persistence

Journal-first ordering (`_append_and_apply`: "Journal first, apply second — a failed journal write leaves state untouched", hypotheses.py; the mission task store uses the same order) bounds every window:

| Window | On disk | Recovery behavior |
|---|---|---|
| claim not yet persisted | no TASK_CLAIMED | task never happened — clean |
| claim persisted, work in progress | TASK_CLAIMED (+ renewals) | lease decides: live → IN_FLIGHT_UNKNOWN, wait grace; expired → `TASK_LEASE_EXPIRED`, attempt += 1, re-dispatch per retry policy |
| work done, completion NOT persisted | TASK_CLAIMED, tree IN_PROGRESS | **the effect authorities prevent double-execution**: (a) the tree node is not TODO → `claim()` refuses duplicates (attack_tree.py:354–355); (b) any produced finding is already in `FindingStore` — the effect that matters survives on disk; (c) reconcile marks the task expired and re-dispatches only after tree release; if the tree node went COMPLETED meanwhile (a confirmed finding landed), the re-dispatched task resolves as already-done — **a completed task is never executed twice** |
| completion persisted, tree not yet marked | TASK_COMPLETED | task stays succeeded; tree completes only through `sync()` on a *confirmed* finding (authority rule — the task layer never marks the tree directly) |

**Late-writer discipline:** a superseded worker's late `TASK_COMPLETED` is rejected (ownership check), audited as SUPERSEDED, and **never re-fed to the bandit** — `mark()`'s idempotent re-mark guard (attack_tree.py:240–247) already prevents win inflation on the tree side.

**Test commitments:** injectable clock (the registry's `clock=` pattern) drives: active-worker-no-steal, expired+grace reclaim, late-write-superseded, restart-with-live-lease, restart-with-expired-lease, double-execution prevention when the tree completed under a lost journal, sweep-at-boundary-only.

---

## Phase 2 implementation scope (frozen until approved)

| Deliverable | Files | Notes |
|---|---|---|
| Mission + task lifecycle machines | `redteam/states.py` (add `mission`, `mission_task` machines; writer matrix; EXPORT_VERSION bump) | the ONE lifecycle registry |
| Task model | NEW `redteam/mission/task.py` | `MissionTask` + triple identity + three-plane budget fields |
| Agent registry | NEW `redteam/mission/registry.py` | derived from `SpecialistProfile` + `hands.HANDS` (drift-proof, Phase 1 §7.3) |
| Commander (lifecycle, validation, dispatch orchestration) | NEW `redteam/mission/commander.py` | coordinates; authorizes nothing |
| Scheduler + reconcile | NEW `redteam/mission/scheduler.py` | dependency resolution, claim-trio ordering (C2), leases (C5), **mock executors only** |
| Mission journal | reuse `swarm/journal.py` per C4 | per-type validation table |
| Tree lease + release | `redteam/attack_tree.py` (claim kwargs, `release()`, node fields) | implements the documented states.py:101 path |
| Driver seam | `redteam/run.py` (`RunOptions.driver`, mission dir wiring) | 3-way enum at the existing fork (run.py:510) |
| Control plane | `redteam/server.py` additive `/api/missions*` | runs API byte-identical |
| Tests | NEW `tests/test_mission_*.py` (§ test plan) + compat fixtures | T-series below |

**Explicitly NOT in Phase 2** (later phases, unchanged from Phase 1 §7): real specialist delegation hooks in `orchestrator.py` (Phase 4 — Phase 2 proves coordination with deterministic mock agents, per the brief's "deterministic tests with mock agents and controlled execution"), adaptive replanning (Phase 4), recovery API + dashboard panels (Phase 5), EventJournal schema change (Phase 2 only *adds the compat tests*; the change itself lands with the mission journal in the same PR after T4.1–T4.6 are green).

## Test plan (Phase 2 T-series)

| Series | File | Covers |
|---|---|---|
| T1 | `test_mission_lifecycle.py` | every legal/illegal `mission` + `mission_task` transition; WRITER matrix enforcement; audit of each transition |
| T2 | `test_mission_identity.py` | C1.3 matrix: mission_id==run_id==dir; payload/event/API echo; filesystem uniqueness |
| T3 | `test_mission_ownership.py` | claim-trio ordering, N-thread races → 1 winner, rollback table rows, crash-window reconcile (each C2.4 row = a test), reconcile determinism |
| T4 | `test_mission_journal_compat.py` | C4.3 table, tests-first red/green |
| T5 | `test_mission_leases.py` | C5: injectable-clock expiry, no-steal-of-live-worker, grace reclaim, SUPERSEDED late writes, sweep boundaries |
| T6 | `test_mission_budgets.py` | C3: plane separation (OPSEC throttle ≠ halt; token halt ≠ opsec event; task budget ≤ engagement cap; reservation release on failure) |
| T7 | `test_mission_registry.py` | registry derives from profiles+hands (equality test = drift guard), capability/permission filters, `agent.registered` events |
| T8 | **existing suites unmodified** | `test_server.py`, `test_orchestrator.py`, `test_swarm_*.py`, `test_attack_tree*.py` must pass with zero edits (the compat gate) |

## Open items

None blocking. One note for the record: Phase 2's mock-executor scheduler exercises the full claim-trio + lease + journal machinery deterministically; wiring real specialist dispatch through the existing swarm path is Phase 4 and will re-run T3/T5 against live agents.

*Submitted for review. No code has been written or modified — the working tree contains only this document.*

# BUILDER 01 — PHASE 1: Architecture Audit
## Autonomous Mission Commander over the existing red-team engine

**Status:** submitted for review — no implementation has been done, per the Phase 1 gate.
**Repo state audited:** branch `phase-e1-agent-hands`, HEAD `0c481e9`, working tree clean.
**Baseline suite:** `PYTHONPATH=src python -m pytest tests/ -q` → **1122 passed, 0 failed** (43.3 s; see §2.3 for the collection caveat).

---

## 1. Executive summary — one system or several engines?

**The verdict from the code: one engine core with strong shared authorities, wrapped in layers that were never unified under a mission abstraction, plus one genuinely separate sibling package.**

Concretely:

1. **The core is already ONE system.** `run.py:execute_run()` is the single assembly line both the CLI and the API drive. Six shared authorities have exactly one owner each: `states.py` (every lifecycle vocabulary + transition table + writer matrix), `FindingStore.promote()` (the only path to a confirmed finding), `AttackTree` (the only work selector), `ScopeGuard` + the sandbox egress firewall (the only scope authority), `EventBus`/`events.jsonl` (the only telemetry stream), `EventJournal` + `projections.replay` (the only event-sourced recovery path). The swarm, the class specialists, the hypothesis registry, and the strategist reflection all plug into the same `Orchestrator` loop. This is not several engines sharing a repository — it is one engine whose *command layer* is hard-coded.

2. **What is missing is exactly the Mission Commander layer.** There is no mission entity anywhere (`grep -ri mission redteam/` returns only substring coincidences in `detection_belief.py`). The "plan" is the fixed phase sequence hard-coded in `Orchestrator.run()` (recon → N exploit rounds → logic round). Tasks exist only as attack-tree nodes with a 4-state lifecycle and no leases, timeouts, per-task budgets, or retry policies. "Recovery" exists only for the hypothesis layer. An interrupted run leaves an orphaned `running` manifest that nothing ever resumes.

3. **There is one real fragmentation:** `src/agentic_setup/` is a second package with its own OpenRouter client, its own router, its own benchmark/qualification stack, and its own CLI. It is imported by 12 test files but shares nothing with `redteam/llm/` beyond naming. This is the "separate engines sharing a repository" pattern the mission brief worried about — but it is the benchmark/qualification sibling, not the red-team engine. The Mission Commander must not absorb it; §7.9 proposes the boundary contract.

**Bottom line:** the requested upgrade is an *additive coordination layer* (~7 new modules + 5 touched files + tests), not a rebuild. Every Phase 2–5 capability in the brief has an existing authority to extend; nothing in the brief requires duplicating one. §7 gives the design; §8 gives the file-level change inventory; §10 lists the design decisions that need a reviewer's call before Phase 2 starts.

---

## 2. Repository survey

### 2.1 Scale and layout

| Area | Files | Notes |
|---|---|---|
| `redteam/` core package | 60 modules | agent, orchestrator, specialists, swarm/ (5), tools/ (20+), sandbox/ (5), llm/ (4), llmred/ (7, LLM-as-target), memory_backend/ (3), recon/ (2) |
| `src/agentic_setup/` | 12 modules | **separate package** — benchmark, qualification, tool broker, its own router/CLI |
| `tests/` | 108 files | flat pytest directory mirroring both packages |
| `docs/` | 17 artifacts | ADR-001 (collective intelligence), state-machines.md, multi-gambit.md, synthesis.md, hands-and-skills.md … |
| Dashboard | `dashboard/` | Next.js static export, served by `server.py` at `/` |
| `lab/`, `benchmarks/`, `scripts/` | — | lab target, bench harness (incl. `benchmarks/phase1_collective.py`), live-fire scripts |

### 2.2 Mandated-file inventory (all inspected)

Every file in the brief's mandatory list exists and was read in full: `orchestrator.py` (1289 L), `run.py` (637), `runtime.py` (166), `server.py` (554), `events.py` (152), `attack_tree.py` (397), `objective.py` (225), `findings.py` (191), `swarm/__init__.py` (287), `swarm/hypotheses.py` (920), `swarm/journal.py` (150), `swarm/projections.py` (147), `specialists.py` (247), `config.py` (257), `GEN2-ARCHITECTURE.md` (219), `AGENTS.md` (314).

Files the brief did not name but the import graph made mandatory, also read or structurally inspected: **`states.py`** (421 L — the lifecycle registry, the single most important integration point), `agent.py` (445 — the tool-use loop), `planner.py` (96 — briefing/coverage engine, *not* a task planner), `hands.py` (682 — capability catalog), `offensive.py` (deterministic zero-LLM workflows), `config.py` siblings (`scope.py`, `ratelimit.py`, `credit.py`, `strategy.py`, `reflection.py`, `synthesis.py`, `memory.py`, `access.py`, `killchain.py`), `swarm/forum.py` + `swarm/relationships.py` (structurally), `ROADMAP.md`.

### 2.3 Baseline test run (evidence)

```
$ PYTHONPATH=src python -m pytest tests/ -q --tb=no
1122 passed, 3 warnings in 43.27s
```

**Caveat that must go in any CI/ops doc:** without `PYTHONPATH=src`, 12 collection errors occur (`test_config`, `test_authorization`, `test_benchmark`, `test_cli_agent`, `test_lab_runner`, `test_local_assessment`, `test_models`, `test_openrouter`, `test_qualification`, `test_router`, `test_tool_broker`, `test_usage`) — all `ModuleNotFoundError: No module named 'agentic_setup'`. The src-layout package is not installed in this environment; `pip install -e .` or `PYTHONPATH=src` is required. This is an environment fact, not a code regression.

---

## 3. Architecture map (current state)

### 3.1 Mission entry point (as it exists today)

```
CLI:  redteam/cli.py:main ──consent preflight──┐
                                               ├─► run.execute_run(RunOptions)   ← THE ONE assembly line
API:  server.py POST /api/runs ──RunRegistry───┘        │
      (daemon thread per run, EventBus + HeadlessApprover)
```

`execute_run` (run.py:262) performs, in order: engagement load + window check → **control-plane self-targeting guard** (run.py:288 — a scope including the API's own host:port aborts the run) → audit log (+`AuditBridge`), scope.json freeze, FindingStore, RateLimiter, ScopeGuard → KnowledgeGraph, BanditStore (+EPSS/KEV priors, + federation sync handler), AttackTree, AccessGraph, KillChain, TrafficRecorder, AssetInventory (+ optional asset-feed intersection, fail-closed) → LLM client (`build_llm_client`) → approver → deterministic recon (zero LLM) → evidence proxy → Kali sandbox (`ensure_tools` EXTRA_TOOLS layer → start → egress self-test PASS mandatory) → browser → `ToolContext` → memory (JSON / local semantic / Helix) → `BudgetTracker` + `RunManifest` → **driver** (`Orchestrator` if `multi_agent`, else single `RedTeamAgent`) → verify pass (single-agent only) → memory credit/learn → reports → objective save → summary dict.

**Implication for the Commander:** the mission layer must sit *above* `execute_run` (multi-run campaigns) and/or *inside* it as a driver variant (mission-driven orchestration). Both integration points exist without forking the assembly line — which AGENTS.md explicitly forbids ("New runs must go through run.execute_run — don't fork the assembly logic").

### 3.2 Existing agent lifecycle

`RedTeamAgent.run()` (agent.py:181): budget check per turn → `compact_messages` → LLM call (`role`-routed) → manifest update (module-level lock, swarm-safe) → tool-call dispatch (repetition guard, stall detection with foothold-phase relief, novel-signature tracking) → per-turn briefing injection (objective → access → killchain → planner state → attack tree after `sync()`) → objective autoevaluation → continue-nudges (max 3). Specialist turns end on: no tool calls + objective met / nudges exhausted / stall-out / max_steps / budget halt. In multi-agent mode a specialist's budget end ends only its *turn* (`terminal_on_budget_end=False`); in single-agent mode it halts the run honestly as `halted`.

### 3.3 Existing specialist dispatch mechanism

- **Five base profiles** hard-coded in `orchestrator.py` (RECON/EXPLOIT/ACCESS/LOGIC/VERIFY, lines 108–219): each = name, addon prompt, tool allowlist, model role (PARSE vs PLAN), max_steps.
- **Gen-3 class specialists** (`specialists.py`): `ClassSpecialist(owasp, title, techniques, profile)` for A01/A03/A05/A07/A10; `profile_for(technique)` routes a claimed tree node to its class expert, fallback to generic EXPLOIT, `RED_CLASS_SPECIALISTS=0` A/B switch.
- **Swarm fan-out** (`_run_exploit_swarm`, orchestrator.py:627): `ThreadPoolExecutor(max_workers=min(3, len(actionable)))`; each worker loop claims the next tree node (`AttackTree.claim()` — atomic TODO→IN_PROGRESS), re-ranked by the drift-plus-penalty OPSEC scheduler (`DriftPlusPenaltyScheduler.rank()`, score = Q·cost − V·progress), registers/claims the research hypothesis (`claim_or_register` — a lost registry claim suppresses the duplicate investigation), attaches the synthesis brief, and runs a uniquely-named agent (`exploit-w{id}`).
- **The verify pass** (`run_verify_pass`, orchestrator.py:222): fresh-context VERIFY agent over `FindingStore.pending()`, shared by both drivers, followed by `credit_confirmed_findings` (deterministic creditor) and `_mirror_verification_outcomes` (verdicts mirrored onto hypotheses — reflection, never cause).

### 3.4 Shared state and memory

| Layer | Authority | Scope |
|---|---|---|
| In-process shared brain | `ToolContext` (scope, limiter, audit, findings, approve, sandbox, browser, graph, sessions, skills, access, objective, killchain, events, traffic, inventory) | one run, all specialist threads |
| Per-run durable state | run dir: manifest.json, findings.json, graph.json, attack_tree.json, access.json, killchain.json, inventory.json, traffic.jsonl, scope.json (frozen RoE), objective.json, events.jsonl, audit.log.jsonl (hash-chained), approvals.json, research_journal.jsonl, research_forum.jsonl, reflections.json, strategy.json, report.md/html, proxy.json | one run; stores re-load from disk on construction |
| Cross-run learning | `memory/bandit.json` (BanditStore), `memory/skills.json` (SkillLibrary), `memory/experience.json` (ExperienceStore + semantic backends) | all runs |
| Event-sourced state | `swarm/journal.py` EventJournal → `swarm/projections.py` replay | hypotheses only |

### 3.5 Task execution and completion (today's "task")

The only task unit is the attack-tree node `technique@target`:
- states: `todo → in_progress → completed/failed` (+ failed→todo once per round via `retry_failed()`) — `states.py` `attack_tree_node` machine;
- claim: `AttackTree.claim()` atomic under RLock; **no lease, no timeout** — a killed process leaves nodes stuck `in_progress` forever (states.py:101–103 *documents* a lease-expiry release path that `claim()` never implemented — an aspirational docstring, verified against attack_tree.py:346);
- completion: `sync()` marks COMPLETED only from **confirmed** findings (CWE→technique map), which `_unlock()`s chained follow-ups and feeds the bandit;
- duplicates: within a round prevented by atomic claims + hypothesis full-identity registration; across *runs* prevented by on-disk node status.

### 3.6 Budget and approval management

| Control | Authority | Enforced at |
|---|---|---|
| wall-clock / tokens / kill switch | `BudgetTracker.check()` raises `Halt` (STOP file) | every agent turn + every orchestrator round |
| request rate + total | `RateLimiter` (shared by fetch path AND evidence proxy) | every HTTP + every proxied tool call |
| OPSEC noise budget | `DriftPlusPenaltyScheduler` (per-round allowance, POMDP belief blend) | every swarm claim |
| scope | `ScopeGuard` + sandbox default-DROP egress + canary self-test | network layer, not prompt |
| approvals | `interactive_approver` (CLI) / `HeadlessApprover` (approvals.json, REST resolve, kill-file auto-DENY) — `states.py` approval machine | gated actions (`require_approval_for`) |
| run status | `RunManifest` — `running/completed/halted/error` | agent loop + server watchdog |

### 3.7 Event propagation

`EventBus.emit()` → `events.jsonl` FileSink (single source of truth) + in-process subscribers; monotonic per-run `seq`; `safe_emit` never raises; `read_events(after=cursor)` replay; server serves REST + SSE from the file. Current event vocabulary (verified from emit sites): `run.start/finish`, `phase.change`, `agent.turn`, `tool.call/result`, `finding.recorded/confirmed`, `objective.progress`, `approval.requested/resolved`, `swarm.claim`, `scheduler.state`, `strategy.state`, `reflection`, `bandit.state`, `run.research.summary`, `assets.imported`, `research.<type>` (forum mirror), `llm.rotate` (via AuditBridge). **All mission.* events will be additive; nothing existing gets renamed** (spec non-goal).

### 3.8 Campaign persistence

There is no campaign/mission persistence. Persistence is per-run directory (§3.4), created fresh by `execute_run`. Cross-run continuity exists only through the memory dir (bandit/skills/experience) — which is learning, not campaign state.

### 3.9 Recovery behavior (the sharpest gap)

- **Hypotheses: real recovery exists.** `ResearchBundle.for_run(run_dir=...)` replays `research_journal.jsonl` through the registry's own `apply_event()` (`replay_into`), with a `ReplayReport` counting skipped corrupt events; lease expiry restored verbatim (live leases stay owned; expired ones reclaimable). Deterministic, tested (`test_swarm_recovery.py`, `test_swarm_projections.py`).
- **Everything else: none.** A killed run leaves `manifest.status = "running"` (the server only finalizes `error` if the *thread* raises inside the same process; a dead process leaves a zombie). Findings/graph/tree reload from disk if a *new* run points at the same dir, but no code resumes; `RunManifest`'s docstring says "so an interrupted engagement can resume" — the resume implementation does not exist. Tree nodes stuck `in_progress` have no lease to expire. The brief's requirement G ("detect expired task leases", "avoid executing completed tasks again", "report corrupt recovery data") is satisfied today *only* by the hypothesis layer's patterns — which is precisely the pattern to extend.

### 3.10 Dashboard integration

`server.py` adapts on-disk artifacts into the dashboard's shapes (`run_detail`), serves replay + SSE from events.jsonl, exposes `GET /api/state-machines` (the machine-readable lifecycle export — the AX surface any new mission machine must appear in), traffic/inventory/graph/coverage/bench endpoints, REST approvals, and a POST stop that writes the STOP kill file. Dashboard consumers read **event types and artifact files only** — no engine imports — so additive mission events and a mission.json artifact require zero changes to existing consumers.

---

## 4. Dependency map (verified by import grep)

```
                     ┌────────────────────────── ENTRY ──────────────────────────┐
                     │  cli.py ──────────────┐                                   │
                     │  server.py ───────────┼──► run.execute_run(RunOptions)    │
                     └───────────────────────┴───────────────┬───────────────────┘
                                                             │
      config.py ◄────────────────────────────────────────────┤  (Engagement, RoE, Sandbox)
      scope.py, ratelimit.py, audit.py, findings.py, states.py ◄─ owned constants
                                                             │
  ┌──────────────────────────────── DRIVER ──────────────────▼──────────────────────┐
  │  orchestrator.py ──► agent.py ──► tools/* (ToolContext + registry)               │
  │      │  ├── specialists.py (class routing, imports orchestrator profiles)        │
  │      │  ├── swarm/ (journal→hypotheses→forum→relationships→projections)          │
  │      │  ├── reflection.py → strategy.py → attack_tree.apply_strategy            │
  │      │  └── synthesis.py (evidence join, degrades to audit)                      │
  └──────────────────────────────────────────────────────────────────────────────────┘
                                                             │
  shared authorities used by everything: states.py (lifecycles) · FindingStore
  (promote-only-confirmed) · AttackTree (claim-only-selector) · ScopeGuard+egress ·
  EventBus (telemetry) · EventJournal+replay (hypothesis recovery) · BudgetTracker
```

Notable edges and why they matter:

- `specialists.py` imports `orchestrator.EXPLOIT` (orchestrator.py:71–76 keeps a lazy `profile_for` alias to avoid the cycle) — **the registry must not introduce another import cycle**; new specialist registrations belong beside the existing ones or behind the same lazy-alias pattern.
- `states.py` imports nothing at module load (hypothesis table merged lazily in `machines()`) — the safe home for new mission machines.
- `run.py` imports driver classes lazily inside `execute_run` — a `mission` driver variant plugs in at exactly this seam.
- `server.py` depends only on `run.py` + `events.py` + `runtime.py` — additive mission endpoints keep that discipline.
- `tests/` import `orchestrator` in 9 files and `execute_run` in 6 — public signatures of both are regression-critical (spec test #19–20).
- `benchmarks/phase1_collective.py` imports `swarm` directly — the hypothesis contract is load-bearing beyond the engine.

---

## 5. Existing functionality inventory (mapped to the brief's ten investigation points)

| # Brief asks | Exists today | Where | Verdict |
|---|---|---|---|
| 1. Understand operator-defined mission | Engagement (RoE) + Objective (criterion list, REQUIRED_SOURCE gates) + `objective.autoevaluate()` | config.py, objective.py | **partial** — objective exists; no mission wrapper, no decomposition |
| 2. Decompose into executable tasks | AttackTree seeding (entry techniques per endpoint) + unlocks chaining + synthesis ideas | attack_tree.py:202–229, synthesis.py | **partial** — tasks are implicit tree nodes |
| 3. Select specialist agents | `profile_for(technique)` class routing + hands catalog | specialists.py, hands.py | **yes, static** — no runtime registry/availability |
| 4. Manage task dependencies | Tree `unlocks` graph (confirm → spawn follow-ups) | attack_tree.py:278 | **partial** — chain dependencies only; no explicit task DAG |
| 5. Dispatch & coordinate | Swarm fan-out + atomic claims + peer traces + forum | orchestrator.py:627–809 | **yes, within one round** |
| 6. Track execution/evidence/verification | FindingStore pipeline (tentative→…→confirmed) + hypothesis mirror + audit chain | findings.py, swarm/hypotheses.py | **strong** — the C1 doctrine is enforced in code |
| 7. Detect failures/blocked tasks | FAILED marks + `retry_failed()` per round + hypothesis BLOCKED/STALE states | attack_tree.py:260, hypotheses.py:63 | **partial** — round-granularity only |
| 8. Replan on new evidence | Per-round strategist reflection (re-rank only) + strategy directives w/ TTL + retry_failed + synthesis | reflection.py, strategy.py | **yes, bounded** — but round-cadence, not event-driven |
| 9. Recover interrupted campaigns | Hypothesis journal replay ONLY | swarm/projections.py | **thin** — one layer of three |
| 10. Report progress/completion | run.finish/summary events, report.md/html, objective.json, dashboard | run.py:585–636 | **yes** — per run, not per mission |

**Governance inventory (all authoritative today):** ScopeGuard (SSRF-aware), egress firewall + canary, RateLimiter, BudgetTracker+Halt, HeadlessApprover (fail-closed), control-plane self-targeting guard (run.py:288, server.py:218), asset-feed intersection (never widens scope), kali_exec tamper guards, deterministic creditor (credit.py), REQUIRED_SOURCE credit gates. **The Commander must reuse, never re-implement, this list.**

---

## 6. Gap analysis (spec §3 A–I → current state)

| Spec | Gap | Severity | Existing authority to extend |
|---|---|---|---|
| **A. Mission lifecycle** | No mission entity; `run` machine has 4 states, no PAUSED / WAITING_FOR_APPROVAL / RECOVERING / CANCELLED | **High** | `states.py` (add machines), `runtime.RunManifest` (keep as run authority) |
| **B. Mission decomposition** | No task record with ID/assignee/priority/deps/budget/retry/evidence refs; planner.py is a briefing engine, not a planner | **High** | AttackTree frontier + Objective criteria + synthesis ideas as task *sources* |
| **C. Agent registry** | Profiles are module constants; no registry (availability, permissions, limits, domains); no future-domain adapters | **Medium** | `SpecialistProfile` + `ClassSpecialist` + `hands.HANDS` |
| **D. Task scheduling** | No per-task timeout/lease (tree `in_progress` can strand), no bounded retry policy (implicit FAILED→TODO once/round), no per-task budget | **High** | `AttackTree.claim()` + `HypothesisRegistry.claim()` (both already atomic — do NOT add a third claim mechanism) |
| **E. Evidence-driven coordination** | Strong already; missing: falsified findings don't *trigger* replanning (they only mark tree FAILED); no event-driven coordination loop | **Low** | FindingStore/promote, hypothesis mirror, credit.py |
| **F. Adaptive replanning** | Round-cadence reflection only; budget-change not a replan trigger; replan decisions not persisted as auditable plan diffs | **Medium** | reflection.py + strategy.py (LLM re-rank only — guardrails to preserve) |
| **G. Persistence & recovery** | Mission-level persistence absent; tree claims leaseless; orphaned `running` manifests; no deterministic mission reconstruction | **High** | EventJournal + `replay_into` pattern (extend, don't duplicate) |
| **H. Budget & governance** | Enforcement strong; missing per-task budgets and a mission-level budget view; PAUSE does not exist (STOP = halt only) | **Medium** | BudgetTracker, RateLimiter, approvals — all reused |
| **I. Events & dashboard** | Vocabulary additive-ready (`/api/state-machines`, EXPORT_VERSION); dashboard reads files+events only | **Low** | EventBus (additive types), server.py (additive endpoints) |

Also verified (spec §6 non-goals are currently *satisfied by the codebase as-is*): there is exactly one KnowledgeGraph, one AttackTree, one EventBus, one FindingStore, one verification pipeline; `orchestrator.py` is 1289 lines of layered additions with the serial path intact; nothing needs removing to make room.

---

## 7. Proposed integration design (for review — not implemented)

### 7.0 Design rules (derived from the brief's non-goals + the repo's own conventions)

1. **One authority per concern.** New mission artifacts *reference* run manifests, findings, tree nodes — they never re-own them. The mission machine's WRITER matrix lives in `states.py` beside the others.
2. **The Commander coordinates; it never selects or authorizes.** Task sources remain `AttackTree.actionable()` (the only selector), objective criteria, and the RoE grid. Replanning reorders and instantiates — it never creates targets (same contract as `apply_strategy`).
3. **Reuse the two existing claim primitives** (`AttackTree.claim`, `HypothesisRegistry.claim`) — atomic, tested, journaled. A scheduler that invents a third claim path would be the duplicate-orchestration the brief forbids.
4. **Degrade, never break.** Every mission-layer failure falls back to the existing fixed-phase orchestrator (the repo's established amplifier pattern — reflection, semantic memory, and the gateway all do this).
5. **Events additive, vocabulary exported.** New `mission.*` / `task.*` / `agent.*` types through the existing bus; `states.py` EXPORT_VERSION bump; `/api/state-machines` serves them automatically.

### 7.1 Mission lifecycle (spec A) — mapping onto existing authorities

New machine `mission` in `states.py` (vocabulary from the brief, mapped to what the engine can actually observe):

| Mission state | Established by | Existing signal it derives from |
|---|---|---|
| CREATED | mission file written | — |
| VALIDATING | Commander starts validation | `load_engagement` + window + `check_control_plane_overlap` |
| READY | validation passed, plan materialized | deterministic recon done |
| RUNNING | driver loop active | `RunManifest.status == running` |
| PAUSED | **new** PAUSE control file (STOP-file pattern) checked at round/turn boundaries | `budget.check()` call sites |
| WAITING_FOR_APPROVAL | derived, not written | pending record in approvals.json (the engine thread already blocks there) |
| RECOVERING | journal replay in progress | `ReplayReport` (existing) |
| COMPLETED | objective achieved **and** no pending verification | `Objective.achieved` + `FindingStore.pending()==0` |
| FAILED | plan exhausted / unrecoverable driver error | manifest error + replan budget spent |
| CANCELLED | operator cancel API | new, STOP-file sibling with a reason |
| HALTED | kill switch / budget halt | `Halt` with reason (existing) |

**No duplicate state authority:** `RunManifest` stays the run-process authority (its 4-state machine is unchanged); the mission machine references it. Every mission transition is (a) validated against the `states.py` table, (b) appended to the mission journal, (c) emitted on the bus. PAUSED/WAITING_FOR_APPROVAL/RECOVERING are derived-where-possible and written-where-observed, so a crashed commander still reconstructs state from journal + existing files.

### 7.2 Mission decomposition (spec B) — Task model

New `MissionTask` record (new module `redteam/mission/task.py`) — fields per the brief, but **sourced from existing structures, not invented**:

- `task_id`, `mission_id` — minted by the Commander; referenced in journal + events.
- `description`, `required_capabilities`, `scope_requirements` — from the tree node's technique/target (RoE-checked by construction, since the tree only seeds from scope-validated endpoints) + hypothesis preconditions (already a normalized list).
- `assigned_specialist` — from `profile_for(technique)` + hands trust classes; never a free-text agent name.
- `priority` — tree priority + chain boost + bandit draw (read-only reuse of `actionable()`'s ranking).
- `dependencies` — **derived**: tree `unlocks` (a chained node depends on its parent's completion) + hypothesis BLOCKED prerequisites; stored as explicit IDs once the task is created, so the brief's "structured task plan" is a real record.
- `execution_budget` — per-task OPSEC allowance carved from the round noise budget (scheduler-split), not a new budget currency.
- `status` — new `mission_task` machine: `pending → ready → claimed → running → succeeded/failed/cancelled/expired` (blocked modeled as a `ready` task with unmet deps — matching the hypothesis layer's semantics; `expired` = lease lapsed).
- `evidence_references` — finding IDs + hypothesis IDs + event seqs (references only).
- `verification_status` — derived from the referenced finding's confidence (states.py finding machine) — the Commander **computes** this, never sets it.
- `retry_policy` — `{max_attempts, backoff_rounds}`; replaces the implicit once-per-round FAILED→TODO with an explicit, auditable policy (default `max_attempts=2` preserves current behavior).
- `created_at` / `completed_at`.

**Not a competing planner:** tasks are *materialized views* over the tree + objective + hypotheses. The tree stays the only selector; the task layer adds bookkeeping (ownership, deps, retries, leases, evidence refs) the tree deliberately does not carry.

### 7.3 Agent registry (spec C)

New `redteam/mission/registry.py` — an index **over** the existing profiles, not a replacement:

```
AgentRecord: agent_id, agent_type, description, capabilities (tool_names ∩ registry,
             validated against hands.validate_agent), supported_domains (OWASP class
             / tactic), tools, model_config (role → gateway routing), execution_limits
             (max_steps), availability (constructed | idle | busy | disabled),
             required_permissions (hands trust classes + require_approval_for overlap)
```

- Initial registrants: recon, exploit (+ A01/A03/A05/A07/A10 class experts), verify, access, logic — i.e. the five roles plus the five existing class specialists, ** enumerated from `orchestrator` + `specialists` + `hands` so the registry cannot drift from the profiles** (a registry that diverges from `SpecialistProfile` would be the shelfware AGENTS.md warns about).
- Future domains (cloud/identity/network/LLM-security/prompt-injection): the extension point is exactly `ClassSpecialist` — a new domain ships as technique(s) in the tree vocabulary + proof conditions + a `ClassSpecialist` + registry entry + tests. **No adapter will be claimed integrated until that quartet exists with tests** (spec §3.C is explicit here, and the audit agrees).
- `agent.registered` / `agent.status_changed` events keep the dashboard honest about what *actually* exists.

### 7.4 Task scheduling & delegation (spec D)

New `redteam/mission/scheduler.py`, consuming the existing primitives:

- **Dependency resolution:** ready set = tasks whose deps are all `succeeded` (deps derived from tree unlocks + hypothesis preconditions, §7.2).
- **Selection:** eligible agents = capability ∧ domain ∧ availability ∧ permissions; tie-break by the tree's own ranking (read via `actionable()`), never a second ranker.
- **Ownership:** `AttackTree.claim()` (tree node) + `HypothesisRegistry.claim()` (research twin) + task record CAS — three references, two existing atomic primitives; a task's owner is written once, so duplicate ownership is structurally impossible.
- **Concurrency:** reuse `max_swarm_workers` (3, token-budget-aware per orchestrator.py:513–518) + a new mission-level `max_concurrent_tasks` ceiling.
- **Timeouts/leases:** **add lease support to `AttackTree.claim()`** — states.py:101 already documents "a lease expiry may drop it back to TODO" as the release path; implementing it closes the stranded-`in_progress` hole and satisfies brief §3.G ("detect expired task leases") with a one-primitive change. Hypothesis leases (900 s, clock-injectable, replay-safe) already exist and need nothing.
- **Failures/retries:** worker error or timeout → task `failed` with reason → retry per policy → beyond policy: `blocked` + replan trigger (§7.6).
- **Budgets:** per-task OPSEC carve from `DriftPlusPenaltyScheduler` (the round allowance already exists; the scheduler just subdivides it per task) + `BudgetTracker.check()` per task start (existing Halt semantics = mission HALTED, not task retry).
- **Conflict prevention:** the brief's "prevents conflicting execution" maps to two existing guarantees — atomic tree claims and full-identity hypothesis registration (already suppresses duplicate investigations) — plus one new check: a task is not dispatched while its target has an `AWAITING_VERIFICATION` hypothesis (don't re-prove what the pipeline owns).

### 7.5 Evidence-driven coordination (spec E)

Already the strongest subsystem; the Commander only wires its *outputs* to replanning:

- Observation / hypothesis / finding / pending / confirmed / falsified map 1:1 onto existing authorities: graph nodes → `HypothesisRegistry` → `FindingStore.confidence` funnel → `promote()` → hypothesis mirror (`record_verification_outcome` — the only CONFIRMED path, mirror-not-cause).
- The Commander reads these; it can never write confidence. Confirmed-finding → credit (`credit_confirmed_findings` — deterministic, idempotent) → objective autoevaluation → mission COMPLETED check.
- `ResearchBundle`, `AccessGraph`, `EventJournal`, objective evaluation — all consumed as-is.

### 7.6 Adaptive replanning (spec F)

New `redteam/mission/replan.py` — **deterministic, bounded, explainable**; the LLM strategist (reflection.py) stays exactly what it is (per-round re-rank, amplifier-only):

| Trigger (brief's list) | Deterministic response |
|---|---|
| task succeeded | materialize unlocked follow-ups as new tasks (tree `_unlock` already created the nodes); release deps |
| task failed / retries exhausted | mark dependents blocked; emit `mission.replanning` with the reason; next round the tree's `retry_failed()` + bandit re-rank applies (existing) |
| hypothesis refuted | close equivalent tasks; counter-evidence already recorded by the registry |
| finding independently confirmed | credit → objective progress → if criterion complete, prune tasks serving only that criterion |
| task blocked | escalate to Commander: attempt alternative technique on same target (tree frontier re-query) or skip with reason |
| approval rejected | the gated task is **cancelled, never retried silently** (fail-closed; a denial is not permission) |
| budget change (Halt / noise throttle) | downgrade round scope: shrink concurrency + quiet-technique filter (scheduler's existing Q-throttle does this) |
| objective achieved | stop dispatch; drain verification; COMPLETED |

Every replan = one journaled decision `{trigger, evidence refs, plan delta}` — bounded (a per-round replan budget) and explainable (the journal IS the explanation). **No LLM participation in authorization, scope, or policy** — the reflection guardrails (re-rank only) are preserved untouched.

### 7.7 Mission persistence & recovery (spec G)

- **`mission_journal.jsonl` in the run dir**, written through the existing `EventJournal` pattern (idempotent event_ids, engagement-scoped, write-failures-raise, torn-line-tolerant). **Open decision for review (§10.2):** `EventJournal._validate` currently *requires* a `hypothesis_id` field (journal.py:35). Either (a) generalize the required-field set to `entity_id` with a schema bump (touches the swarm tests), or (b) add a sibling `MissionJournal` class reusing the same base pattern. Recommendation: (a) — one journal authority, the swarm's hypothesis_id becomes entity_id=hypothesis_id; smaller long-term surface, but it touches a tested contract and deserves a reviewer's call.
- **Recovery** = `replay` of the mission journal through the same apply path (the `replay_into` pattern, verbatim) + existing artifact reload (findings/graph/tree already re-load from disk) + tree lease expiry (§7.4) + `ReplayReport` surfaced as `recovery.started/completed` events with the skip counts. Completed tasks are never re-executed (their terminal state replays). Corrupt/incomplete data is reported (skip-and-report policy), never fatal.
- **Run-level recovery** (the orphaned-`running` manifest): the Commander, on restart, finds missions whose manifest says `running` but whose process is gone (no heartbeat in the journal) → transitions them RECOVERING → replays → resumes or closes them honestly. This is new code in the mission layer; `run.py` itself is untouched except for the driver seam.

### 7.8 Budget & governance (spec H)

Everything the brief lists is already enforced by an existing authority (§3.6 inventory). The Commander adds only: per-task budget carve (§7.4), the PAUSE control file (STOP-file pattern, checked at the same `budget.check()` sites), and the governance rule that **a rejected/unavailable approval cancels its task and blocks equivalent re-dispatch within the mission** (denial ≠ permission). ScopeGuard, egress, approvals, kill switch, tool permissions, time limits — reused unchanged; the mission layer has no code path that can reach a target the RoE does not name, because it dispatches only through the existing tool surface.

### 7.9 Events & dashboard (spec I)

- New event types (all additive): `mission.created/validated/started/paused/replanning/completed/failed`, `task.created/assigned/started/completed/failed/blocked`, `agent.registered/status_changed`, `recovery.started/completed`. `approval.requested` already exists (no rename). Emission through the existing `EventBus`/`safe_emit`.
- Server: additive endpoints — `POST /api/missions` (launch a mission = launch a run with `driver="mission"`), `GET /api/missions`, `GET /api/missions/{id}` (mission.json + journal-derived state), `POST /api/missions/{id}/pause|cancel|resume`. Existing `/api/runs*` contract byte-identical (spec test #19).
- Dashboard: new panels subscribe to the same SSE stream; existing panels untouched.
- **The `agentic_setup` boundary:** it is the benchmark/qualification sibling, not a second offense engine. The Commander does not absorb it; its authorization/qualification checks stay the pre-mission gate (the same way the CLI preflight works today). Consolidating the duplicated OpenRouter client/router is **Builder 02 territory**, with a documented recommendation to make `agentic_setup` import from `redteam/llm` rather than maintain a fork.

### 7.10 Before / after

```
BEFORE (today)                                     AFTER (Phase 2–5)
────────────────                                   ────────────────────────────────────
OPERATOR                                           OPERATOR
  │ CLI / POST /api/runs                              │ CLI / MISSION API (+pause/cancel)
  ▼                                                   ▼
execute_run ──► driver?                            MISSION COMMANDER (new, coordinates)
  ├─ single RedTeamAgent                             ├─ VALIDATION (existing guards)
  └─ Orchestrator: FIXED phase sequence              ├─ DECOMPOSITION (tasks ← tree/objective/hyps)
       recon → [exploit swarm → verify               ├─ AGENT REGISTRY (profiles+hands, indexed)
                → access → reflect] × N              ├─ TASK SCHEDULER (deps, leases, retries,
       → logic → credit                                 budgets, over EXISTING claims)
                                                     ▼
                                                 EXISTING EXECUTION ENGINE (unchanged):
                                                   Orchestrator rounds / RedTeamAgent
                                                     ▼
                                                 FINDING & VERIFICATION (unchanged:
                                                   pending → promote → confirmed-only)
                                                     ▼
                                                 SHARED INTELLIGENCE STATE (unchanged:
                                                   graph, tree, hyps, access, killchain)
                                                     ▼
                                                 ADAPTIVE REPLANNING (new, deterministic,
                                                   evidence-triggered, journaled)
                                                     ▼
                                                 MISSION COMPLETION (+recovery, +report)
```

The right-hand column adds ONE coordination layer and touches the engine only at documented seams (driver factory in `execute_run`, lease in `AttackTree.claim`, additive states/events/endpoints).

---

## 8. File-level change inventory (proposed, with rationale)

### 8.1 New modules (why existing abstractions cannot fulfill the role)

| New file | Purpose | Why nothing existing can do it |
|---|---|---|
| `redteam/mission/__init__.py` | package facade (`MissionCommander`, `ResearchBundle`-style wiring) | the mission facade must wire registry+scheduler+journal as one unit, mirroring the swarm's proven facade pattern |
| `redteam/mission/task.py` | `MissionTask` model + `mission_task` lifecycle helpers | `AttackNode` deliberately carries no ownership/deps/retry/evidence refs (attack_tree.py docstrings); adding them there would overload the selector |
| `redteam/mission/registry.py` | `AgentRegistry` over profiles+hands | `SpecialistProfile` is a static dataclass; `hands.HANDS` a static catalog; availability/permission indexing doesn't exist anywhere |
| `redteam/mission/commander.py` | lifecycle machine + validation + delegation + completion | `Orchestrator.run()` hard-codes the phase sequence; the brief forbids rewriting it, so the commander composes it |
| `redteam/mission/scheduler.py` | dependency resolution, dispatch, leases, retries, per-task budgets | the swarm's worker loop is round-scoped and inline; scheduling policy must be a separate, testable unit over the same claim primitives |
| `redteam/mission/replan.py` | deterministic trigger→plan-delta engine | reflection.py is LLM and re-rank-only by contract; deterministic replanning is a different (complementary) authority |
| `redteam/mission/recovery.py` | journal replay + lease expiry + orphaned-manifest detection | swarm/projections.py is hypothesis-specific; mission entities need the same pattern at mission granularity |
| `tests/test_mission_*.py` (≈6 files) | the 20 required test families (§9) | spec-mandated; deterministic mock agents + controlled execution |

### 8.2 Modified files (each with the single reason)

| File | Change | Why |
|---|---|---|
| `redteam/states.py` | add `mission` + `mission_task` machines + writer matrices; `EXPORT_VERSION = 2` | states.py IS the one lifecycle registry (its own header); adding machines anywhere else would recreate the scattered-vocabulary problem it exists to end |
| `redteam/runtime.py` | optionally a `MissionManifest` dataclass (mission.json) beside `RunManifest` | run manifest vocabulary is frozen (4 states, documented terminal-in-place); mission states are a different machine with different writers |
| `redteam/run.py` | `RunOptions.driver: str = "orchestrator"|"single"|"mission"` + mission dir passthrough | the driver seam already exists (`if opts.multi_agent:` fork, run.py:510); a 3-way enum is the minimal, non-forking extension AGENTS.md mandates |
| `redteam/orchestrator.py` | optional hooks: `on_task_started/completed` callbacks + lease-aware claim + PAUSE check in the round loop | the round loop is the execution site; hooks add observability without touching selection logic (non-goal: no rewrite) |
| `redteam/attack_tree.py` | implement the documented-but-missing claim lease (expires → TODO, replay-safe timestamp) | states.py:101 already documents this transition; closing it fixes stranded `in_progress` nodes AND satisfies brief §3.G with one primitive |
| `redteam/swarm/journal.py` | (decision §10.2) generalize `REQUIRED_EVENT_FIELDS` `hypothesis_id → entity_id` | one journal authority; alternative (new MissionJournal) duplicates the validate/dedupe/seq machinery |
| `redteam/server.py` | additive `/api/missions*` endpoints + mission events in SSE (automatic) | server is the control plane; additive-only keeps every existing consumer byte-compatible |
| `redteam/events.py` | **no changes** | the bus is type-agnostic; new types flow through unchanged (spec: do not replace) |
| `dashboard/` | mission panels (new components) | consumers read events/artifacts only; additive |
| `AGENTS.md`, `GEN2-ARCHITECTURE.md`, `docs/state-machines.md` | document the mission layer + new machines | repo convention: every lifecycle documented before code lands |

**Explicitly untouched** (spec non-goals): `findings.py`, `objective.py`, `config.py`, `scope.py`, `sandbox/*`, `tools/*`, `specialists.py`, `swarm/hypotheses.py`, `reflection.py`, the EventBus implementation, the verification pipeline.

---

## 9. Test plan for Phase 6 (mapping the brief's 20 required families)

Deterministic (mock agents, injectable clocks — the registry's `clock=` pattern already supports lease tests):

| Brief # | Family | Target tests |
|---|---|---|
| 1–2 | creation/validation/lifecycle transitions | `test_mission_lifecycle.py` — every legal + illegal edge of both new machines |
| 3 | dependency resolution | unlocks-derived deps + explicit deps + cycle detection |
| 4–5 | registration & selection | registry enumerates profiles+hands (drift-proof); capability/domain/permission filters |
| 6–7 | concurrent ownership, duplicate prevention | N threads claim one task → 1 winner (pattern: `test_swarm_concurrency.py`) |
| 8–9 | timeout/failure, bounded retries | injectable clock lease expiry; retry policy caps attempts |
| 10 | budget exhaustion | per-task carve + mission Halt propagation |
| 11 | approval rejection | denial cancels task; equivalent re-dispatch blocked |
| 12 | kill switch | STOP file → HALTED, pending approvals auto-denied (existing behavior, mission-level test) |
| 13 | evidence-driven replanning | each §7.6 trigger fires exactly its journaled delta |
| 14 | verification integration | confirmed-only completion; commander cannot write confidence |
| 15–17 | restart recovery, lease expiry, no re-execution | journal replay determinism; completed tasks stay terminal; ReplayReport surfaced |
| 18 | event ordering/replay | seq monotonicity + replay-from-file equals live state |
| 19–20 | API compatibility + orchestrator regression | existing `test_server.py`, `test_orchestrator.py`, `test_swarm_integration.py` must pass unmodified |

---

## 10. Decisions needed from review before Phase 2

1. **Mission scope granularity.** Recommendation: one mission == one run directory (one `execute_run`) for Phases 2–4; multi-run campaign aggregation (a mission spanning several `execute_run` invocations) deferred to Builder 02 with a mission-dir convention. Rationale: recovery, events, and approvals are all already per-run-dir; a cross-run mission would need a second persistence root, which the brief says not to introduce without justification.
2. **Journal authority.** Generalize `EventJournal` (`hypothesis_id → entity_id`, schema bump, touch swarm tests) vs. add a sibling `MissionJournal`. Recommendation: generalize (§7.7 rationale).
3. **PAUSE semantics.** Round/turn boundaries only (checked at existing `budget.check()` sites) vs. mid-turn. Recommendation: boundaries only — mid-turn pause strands tool/sandbox state.
4. **Task retry defaults.** `max_attempts=2`, backoff = next round (preserves current behavior exactly); confirm or adjust.
5. **Registry drift-guard.** Registry entries derived from `SpecialistProfile`/`hands` at import time + a test asserting equality with `HANDS` — confirm this is the desired strictness (it makes adding a specialist a 3-file, test-enforced change).

---

## 11. Known limitations of this audit

- `swarm/forum.py`, `swarm/relationships.py`, `offensive.py`, `memory.py`, `llm/*` were read structurally (docstrings + signatures + emit/grep sites), not line-by-line; their contracts cited here come from their own docs plus the callers audited in full. Phase 2 implementation should re-read `offensive.py` in full before wiring the fallback-workflow path.
- The baseline run used `PYTHONPATH=src` without optional extras (Playwright browsers, Docker, HelixDB) — tests that skip on those prongs skip identically in CI; the 1122-pass figure is the honest full-matrix-for-this-environment number.
- Performance/concurrency observations (brief §9.9) are deferred to Phase 6 per the spec's phase order; the audit records only the structural facts (3-worker ceiling rationale at orchestrator.py:513, token-budget coupling, BudgetTracker lock, RLock discipline in tree/findings/registry).

*Submitted for review. No code has been written or modified — the working tree contains only this document.*

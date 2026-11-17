# BUILDER 01 — Phase 3 Implementation Report

## Mission Specialist Executor: connecting the Mission Scheduler to the real autonomous specialists

Branch: `phase-e2-mission-specialist-integration` (from `main` @ `ed199f7`).
Status: implemented, tested, lab-demonstrated. **Not merged; awaiting review.**

---

## 1. Implementation summary

The mission driver's production path no longer runs `MockExecutor`. `run.py`'s
mission branch now constructs the run's **existing** `Orchestrator` over the
shared engagement objects (same tools, ctx, graph, AttackTree, FindingStore,
budget, memory, research bundle), wraps it in a new **`MissionSpecialistExecutor`**
(`redteam/mission/specialist_executor.py`), and passes it to `run_mission_driver()`.
Every scheduler dispatch therefore executes one real `RedTeamAgent` specialist
through a new task-level interface, `Orchestrator.execute_task(task_view,
on_text=None, objective="")`, and the outcome returns to the scheduler as the
existing `ExecutionResult`.

Nothing was rebuilt:

- routing uses the existing profiles (`RECON`/`ACCESS`/`LOGIC`/`EXPLOIT`) and
  the existing class-specialist router `specialists.profile_for()` for exploit
  tasks;
- specialist construction is the existing `_make_specialist()` (hands/skills
  briefing included), extended with an optional `max_steps` override so a
  task's execution-plane carve can tighten — never widen — the profile ceiling;
- verification is the existing `run_verify_pass()` (fresh VERIFY context over
  the shared `FindingStore`), invoked by the mission `verify` role;
- the Phase 2 early return in `execute_run()` is gone: missions now flow
  through the shared run finalization (memory credit/reflection, report.md +
  report.html, objective scoring, audit-chain check, `run.finish` telemetry);
  the classic single-agent and multi-agent drivers are untouched.

The mission scheduler remains the sole owner of the claim trio (task CAS →
`AttackTree.claim` → hypothesis claim → fenced dispatch). The executor claims
nothing, releases nothing, and never calls `_run_exploit_swarm()` or the
`run()` phase sequence.

## 2. Architecture — the actual execution path

```
RunOptions.driver == "mission"  (run.py execute_run)
  └─ shared run assembly (unchanged): engagement, audit, findings, limiter,
     scope, graph, bandit, attack_tree, access, killchain, traffic, inventory,
     client, sandbox/browser, ctx, tools, budget, manifest
  └─ Orchestrator(engagement, tools, ctx, client, graph, attack_tree, memory,
                  noise_*, research_dir=out).with_runtime(budget, manifest)
  └─ MissionSpecialistExecutor(orchestrator, objective, on_text)
      └─ run_mission_driver(..., executor=..., hypotheses=orch._research)
          └─ MissionScheduler.dispatch(task_id)        [claim trio: reserve →
              │                                         tree.claim → hypothesis
              │                                         → fenced RUNNING]
              └─ executor.run(task_view)
                  └─ Orchestrator.execute_task(task_view, on_text, objective)
                      ├─ role routing → existing SpecialistProfile
                      │    (exploit → profile_for(technique), EXPLOIT fallback)
                      ├─ instruction built from the task view only
                      └─ _make_specialist(profile, agent_name="mission-<task_id>",
                                          max_steps=min(task, profile))
                          └─ RedTeamAgent.run(instruction)   [existing loop]
                              └─ existing tools → shared graph/findings/audit
                  └─ ExecutionResult(status, result, error, evidence)
                      (evidence = real finding refs created by the invocation;
                       never confidence="confirmed")
          └─ scheduler fences completion/failure + attaches evidence (unchanged)
  └─ shared finalization: attack_tree.sync(graph, findings), reports,
     objective scoring, memory reflection, run.finish   [no early return]
```

## 3. Files changed

| File | Change |
| --- | --- |
| `redteam/mission/specialist_executor.py` | **new (108 lines)** — `MissionSpecialistExecutor`: task_view → one real specialist invocation → `ExecutionResult`; soft-failure audit mapping (`agent.no_models` / `agent.halt` / `agent.budget_exhausted` → EXEC_FAILED); real-evidence diff over the shared FindingStore |
| `redteam/orchestrator.py` | **+153/−2** — `execute_task()` task-level interface, `_profile_for_task()` (role→existing profile, `profile_for()` for exploit), `_task_instruction()` (concise, task-scoped), `_execute_verify_task()` (existing `run_verify_pass`), read-only `ctx` property, optional `max_steps` parameter on `_make_specialist()`, `_ROLE_TASK_LINES`; **correction**: `access_precondition_reason()` + `_active_foothold()` (the ACCESS foothold gate) enforced in `execute_task()` before any ACCESS construction; **review round 2**: the gate reads PR #13's canonical `revoked_nodes()` — a revoked holding (the retest-fixed bridge's record) contradicts a stale KillChain INITIAL_ACCESS stage and the gate fails closed |
| `redteam/access.py` | **correction follow-up (superseded by the PR #13 integration — see §6b)**: this branch originally added `release()` + `invalidated_holdings()`; per the PR #13 review round-2 decision the structured `revoke()` / `revoked_nodes()` lifecycle is the single source of truth and the duplicate pair was REMOVED in the integration merge |
| `redteam/credit.py` | **correction follow-up (superseded by the PR #13 integration — see §6b)**: this branch originally added `invalidate_holdings_for_fixed_findings()` (evidence-marker matching + `credit.invalidated` events); the integration removes it — the retest bridge `retest.invalidate_after_fix()` (structured `attrs["finding_id"]` match, KG remediation marking, wired into `retest_run()` on FIXED) is the single invalidation authority, and `credit_confirmed_findings()` (PR #13 review round 2) now excludes findings whose latest retest verdict is FIXED so stale proof can never re-create a revoked holding |
| `redteam/server.py` | **review round 2**: the retest endpoint forwards the run's own `ctx.access`/`ctx.graph` to `retest_run` (the retest CLI already did) — a production FIXED verdict now actually revokes the demonstrated holdings through the canonical `invalidate_after_fix` path |
| `redteam/mission/driver.py` | `hypotheses` pass-through to `MissionScheduler` (the orchestrator's own `ResearchBundle` — one duplicate-suppression registry); **correction**: `access_gate` pass-through wired into the scheduler's readiness gate; the no-executor seam is now LOUD (unconditional stderr warning + `say`); summary reports `executor` class name; docstring updated to Phase 3; **review round 2**: the endgame calc is `mission_outcome()` — mission success requires EVERY task `TASK_SUCCEEDED` (failed/cancelled/expired/exhausted ends are MISSION_FAILED; the old calc equated "all terminal" with "all succeeded") |
| `redteam/mission/scheduler.py` | **correction**: duck-typed `prerequisite` readiness hook (task_view → "" \| reason) consulted in `ready_tasks()` — a gated task stays PENDING and is re-examined every round (the existing not-ready semantics); no claim, no lifecycle/status/journal change |
| `redteam/run.py` | mission branch: constructs the shared `Orchestrator` + `MissionSpecialistExecutor`, passes both to the driver, `attack_tree.sync()` after the mission (same sync the orchestrator's verify passes use), falls through to the SHARED finalization (reports, objective scoring, memory reflection — the Phase 2 early return removed); **correction**: passes `access_gate=mission_orchestrator.access_precondition_reason`; `run.start` mode string is driver-aware; final summary carries mission fields (`mission_id`, `mission_status`, `tasks`, `rounds`, `mission_executor`) |
| `tests/test_mission_specialist_executor.py` | **new (38 tests)** — executor contract, routing, shared context, claim ownership, task limits, verification, the ACCESS prerequisite gate (no-foothold blocked/no-invocation, direct-dispatch refusal, demonstrated foothold executes, revoked foothold blocked via the canonical `revoke()`/`revoked_nodes()`, KillChain path + revoked-holding contradiction, non-ACCESS unaffected, mid-mission foothold, driver wiring), the end-to-end FIXED-retest revocation lab (real creditor → real `retest_run` → canonical `invalidate_after_fix` revocation → blocked despite achieved stage → re-demonstration re-opens), and mission-success truthfulness (all-failed/mixed/succeeded e2e, cancelled at the calc seam) |
| `tests/test_mission_lab_e2e.py` | **new (398 lines, 2 tests)** — the controlled lab (below) |
| `docs/builder01-phase3-implementation-report.md` | **new** — this report |

No Phase 2 lifecycle, journal schema, or state machine was changed. No PI,
kernel, dashboard, or swarm files were touched.

## 4. Specialist routing (actual)

| Mission role | Specialist used | Mechanism |
| --- | --- | --- |
| `recon` | `RECON` (`orchestrator.RECON`) | direct profile reference |
| `exploit` | class expert per technique, e.g. `injection.sqli` → `A03.profile` | **existing** `specialists.profile_for(technique)`; unknown technique → generic `EXPLOIT` fallback (existing router behavior, incl. `RED_CLASS_SPECIALISTS=0`) |
| `access` | `ACCESS` | direct profile reference |
| `logic` | `LOGIC` | direct profile reference |
| `verify` | the existing independent verification pass | `run_verify_pass()` (fresh VERIFY specialist over the shared `FindingStore`) |
| unknown | — | fails loud: EXEC_FAILED `"role ... has no specialist routing"` |

Step budget per task: `min(task.max_steps, profile.max_steps)` — the task carve
can only tighten; a task can never widen the specialist ceiling or the
engagement budget (the shared `BudgetTracker` rides through `with_runtime` onto
every specialist; request limits and scope stay with the shared `RateLimiter` /
`ScopeGuard`).

## 5. Shared context (what is reused — one of each, no second authority)

The executor constructs none of these; it holds only the orchestrator. The lab
test asserts object identity (`agent._ctx is ctx`, `agent._graph is graph`,
`agent._attack_tree is tree`, `agent._budget is budget`):

- `ToolContext` (scope, limiter, audit, findings, approvals, traffic, inventory)
- `KnowledgeGraph`, `AttackTree` (work-selection authority; scheduler claims it)
- `FindingStore` (evidence + promotion pipeline)
- `BudgetTracker` (engagement budget — single authority), `RunManifest`
- `AuditLog`, `EventBus` telemetry, engagement memory (`ExperienceStore`) and
  the skills library via the agent loop's own briefings
- `ResearchBundle` (`orchestrator._research`) — now ALSO the scheduler's
  hypothesis-claim authority, so mission node tasks dedupe against the same
  research registry the swarm uses.

## 6. Verification

The mission `verify` role calls `Orchestrator._execute_verify_task()`, which:

1. reads `ctx.findings.pending()` — with nothing pending it returns the honest
   no-op `"verification task complete: no pending findings — nothing to
   verify"` and does not invoke the verifier;
2. otherwise invokes the **existing** `run_verify_pass()` (module-level
   orchestrator function, unchanged) with the shared engagement/tools/ctx/
   client/budget — a FRESH `VERIFY` specialist re-checks every pending finding
   (`verify_finding_independently`), and `FindingStore.promote()` remains the
   only confirmation authority;
3. audits `mission.verify.start/finish` and reports the still-pending count in
   the task result.

The proposing specialist can never self-confirm: its checks only reach
`pending_verification` (existing tool discipline), the executor strips
`confidence="confirmed"` from evidence (and `ExecutionResult` rejects it by
construction), and the verify pass runs in a separate specialist context.

## 6b. Correction (post-review): ACCESS prerequisite gate — a demonstrated foothold is required

The ACCESS specialist's method assumes a foothold to press; mission-plan
dependencies alone do not PROVE access was obtained. The gate reads ONLY the
existing authorities — no new foothold store, graph, state machine, or
authority:

- **Authority**: `Orchestrator.access_precondition_reason(task_view)` (in
  `orchestrator.py`, next to the routing). It returns `""` (proceed) only when
  a valid, demonstrated, ACTIVE foothold exists per the existing evidence: an
  `AccessGraph` node with `held=True` ("demonstrated, not assumed" — the same
  evidence the classic ACCESS loop consumes via `killchain.recommend()`) or —
  when the graph carries no revocation record — a `KillChain`
  INITIAL_ACCESS stage marked `achieved`. A revoked / never-proven foothold
  never satisfies it, and a non-achieved stage (`in_progress`, …) never
  substitutes. The check is access-role-scoped: recon/exploit/logic/verify
  routing is untouched.
- **Revocation vs the KillChain fallback (review follow-up, decided; adapted
  to PR #13's single canonical lifecycle)**: an achieved INITIAL_ACCESS stage
  is a HISTORICAL milestone and does **not** remain sufficient once the
  evidence supporting the foothold is revoked. The intended lifecycle — all on
  the existing authorities, with the SINGLE canonical invalidation path:
  1. *demonstrated* — `access.hold()` (tools, or the creditor
     `credit_confirmed_findings` on a confirmed finding, which stamps
     structured `finding_id` provenance) sets `held=True`; the KillChain may
     journal the milestone;
  2. *revoked* — a retest verdict of FIXED, through retest.py's own
     FIXED-gated `invalidate_after_fix()`, revokes exactly the holdings that
     finding demonstrably supported via `AccessGraph.revoke()` (held=False
     with invalidated_at/invalidation_reason stamped and the evidence
     retained — `node.revoked` / `revoked_nodes()` is the record;
     re-demonstration through `hold()` is the only sanctioned re-activation);
  3. *gate* — active holdings win; a revoked holding CONTRADICTS the
     historical stage, so the gate fails closed (the stage must never stand in
     for a foothold current evidence says is gone) until a foothold is
     demonstrated again; only a graph with NO revocation record (or no graph
     at all — kill-chain-style deployments) may fall back to the achieved
     stage; re-demonstration re-opens the gate for the SAME pending task.
  Wiring (this branch): the retest endpoint in `server.py` now forwards the
  run's own `ctx.access`/`ctx.graph` to `retest_run` (the retest CLI already
  did) — so a production FIXED retest actually revokes the demonstrated
  holdings. No parallel implementation exists: this branch's earlier
  `release()` / `invalidated_holdings()` / credit-mirror helper were REMOVED
  in favor of PR #13's unified `revoke()` / `revoked_nodes()` /
  `invalidate_after_fix()` (the branch is rebased on PR #13's head).
- **Dispatch-time enforcement (the lifecycle representation)**: the scheduler
  gained a duck-typed `prerequisite` hook consulted in `ready_tasks()` (same
  pattern as `worker_alive`/`hypotheses`); `run.py` wires it to the
  orchestrator's gate via the driver's `access_gate` parameter. A
  prerequisite-less ACCESS task is simply NOT dispatchable — it stays
  **PENDING**, re-examined every round, exactly like unsatisfied dependencies
  (the existing not-ready semantics). No claim is made, no specialist is
  constructed, no agent turn runs; when a foothold is demonstrated later in the
  mission, the SAME pending task dispatches. If the mission ends with the task
  still gated, the mission ends `failed` (honest: the access work never became
  possible).
- **Execution-layer enforcement (defense in depth)**: `execute_task()` checks
  the gate for every access task before routing — if reached without a
  foothold (e.g. a direct dispatch), it raises before `_make_specialist()` /
  `RedTeamAgent.run()`; the executor maps that to EXEC_FAILED with the reason
  preserved, and the existing failure path records it. Unreachable through the
  mission path; loud on any bypass.
- No executor-contract, state-machine, or journal-schema change: the gate adds
  a readiness condition, not a new task status (`blocked_duplicate` remains the
  duplicate-suppression case it was in Phase 2).

## 6c. Correction (review round 2): mission success requires every task succeeded

`run_mission_driver`'s endgame calc treated "succeeded", "failed" and
"cancelled" as equivalent terminal states — a mission in which every task
failed (or was cancelled) was recorded MISSION_SUCCEEDED. Intolerable now
that the production mission path dispatches real specialists. The calc is now
`mission_outcome(tasks)` (driver.py): success requires EVERY task to have
reached `TASK_SUCCEEDED`; failed / cancelled / expired / exhausted ends — and
tasks that never became dispatchable — make the mission FAILED, with the
explicit reason recorded on the mission. `TASK_CANCELLED` exists in the
states machine as reserved vocabulary (no producer writes it yet); the calc
is safe against it regardless. Tests cover all-failed, mixed success/failure
and genuinely successful missions end to end through the driver (scripted
executors over the Phase 2 `run(task_view)` seam), and the cancelled case at
the calc seam itself.

Product-scope note (review round 2): this phase is the execution-integration
step — task loading comes from `mission_plan.json` (with a single
coordination self-check default), NOT yet an autonomous planner. It is not
the complete autonomous mission-planning loop; the next milestone connects
objective + recon intelligence + AttackTree priorities to task generation,
specialist execution, result-driven replanning and further exploitation.

## 7. Tests — exact commands and actual results

```
$ PYTHONPATH=src python3 -m pytest tests/test_mission_specialist_executor.py tests/test_mission_lab_e2e.py -q
.................................................................           [100%]
40 passed in 1.38s          (24 original + 12 ACCESS-gate/lifecycle tests
                             + 4 mission-success truthfulness tests)

$ PYTHONPATH=src python3 -m pytest tests/ -q        (full repository regression,
                             branch rebased on PR #13's head — the union suite)
2043 passed, 16 skipped, 3 warnings in 52.55s          (exit 0; verified twice
                             consecutively — one earlier run had a single
                             transient flake in test_mission_api, which passes
                             standalone and never recurred)
```

The branch is rebased on PR #13's head, so the full-suite number is the union
of both branches' suites (PR #13 contributes its own ADR-002/graph/retest
suites). This branch's own contribution over its pre-review state: 24
executor/lab tests + 12 ACCESS-gate/lifecycle tests + 4 mission-success
truthfulness tests, 0 failures. Existing mission suites (lifecycle, identity,
ownership, recovery, leases, budgets, registry, journal compat, API) pass
unchanged — their scripted-executor injection seam is preserved.

Coverage map: (A) executor contract — success/exception/soft-failure mapping,
error preservation, no fabricated evidence, real-ref evidence, confirmed-
confidence stripping; (B) routing — recon/exploit-via-`profile_for`/fallback/
access/logic/verify + unknown-role fail-loud; (C) shared-context object
identity; (D) claim ownership — scheduler claims exactly once, executor never
re-claims, completion/failure paths intact; (E) limits — task carve respected,
profile ceiling never widened, engagement budget/scope ride through; (F) verify
— existing verifier invoked once, honest no-op, promotion through the
pipeline; (G) regression — full suite green.

## 8. Controlled lab run (authorized local fixture only)

`tests/test_mission_lab_e2e.py` binds a throwaway HTTP server on
`127.0.0.1:<ephemeral>` (RoE: `allowed_hosts=["127.0.0.1"]`,
`allow_private_ranges=true`, sandbox/browser off, no external targets). The
app breaks its `/api/orders?id=…` query on an injected quote (error-based SQLi
shape) and stays clean for the benign control. A scripted no-model client
drives the REAL agent loop; every tool call it scripts executes REAL code.

**Lab 1 — staged coordination (`test_lab_recon_then_exploit_then_independent_confirmation`):**

1. mission + tasks created; mission RUNNING
2. scheduler dispatches the recon task → **real RECON specialist** runs →
   real `http_probe` against the lab
3. scheduler dispatches the exploit task → claim trio (tree node claimed
   exactly once — asserted via a counting wrapper) → **real A03 injection
   specialist** runs → real `confirm_finding` (k-of-n = 3/3 trials through the
   scope-checked host fetch) → finding recorded `pending_verification`
4. the scheduler attaches the REAL finding ref as task evidence
   (`{"kind": "finding", "ref": <id>, "confidence": "pending_verification"}`)
5. verify task (dependency satisfied) → **existing `run_verify_pass`** → real
   VERIFY specialist → real `verify_finding_independently` (payload replay
   matches, benign control clean) → **`confidence == "confirmed"`,
   `independent_verdict == "confirmed"`** — decided by the pipeline, not the
   executor
6. `attack_tree.sync()` completes `injection.sqli@<orders URL>` → `completed`
   (C4 chain closed by the confirmation, not by task success)
7. mission status `succeeded` persisted; `mission.json` reloads;
   `recover_mission()` replays the journal with `skipped == 0` and rebuilds all
   three tasks `succeeded`
8. audit shows exactly 3 `agent.start` events (one per mission specialist) and
   the tool sequence `["http_probe", "confirm_finding",
   "verify_finding_independently"]`

**Lab 2 — production path (`test_execute_run_mission_branch_uses_the_real_executor`):**
`execute_run(RunOptions(driver="mission"))` end to end against the same lab:
summary reports `driver="mission"`, `mission_executor="MissionSpecialistExecutor"`,
`mission_status="succeeded"`, `findings=1` (pending — this plan has no verify
task), `audit_intact=true`; the shared finalization produced real
`report.md`/`report.html` (the Phase 2 early return previously skipped all of
this); the exploit task record carries the real evidence ref;
`mission.json` + `mission_journal.jsonl` persisted (2 `TASK_DISPATCHED` events);
the tree node is claimed/held and NOT completed (no verify task in this plan —
task success alone never completes a node).

Observed mission outcome, stated honestly: one finding recorded through the
existing proof pipeline and independently CONFIRMED in Lab 1 (the differential
reproduced k-of-n and the negative control held); in Lab 2 the finding remains
`pending_verification` because that run's plan contains no verify task.

## 9. Limitations (actual, not aspirational)

1. **`opsec_allowance` gates claims, not agent turns.** The task's OPSEC
   credits gate WHICH tasks dispatch (Phase 2 semantics, unchanged); there is
   no per-task spend meter inside a specialist turn. Engagement-level OPSEC
   (round noise budget / drift-plus-penalty) remains the in-turn enforcement
   point.
2. **`verify` re-checks ALL pending findings of the run**, not only those
   produced by the mission — the existing `run_verify_pass` semantics, reused
   verbatim.
3. **Duplicate suppression is registry-wide, not per-mission**: with
   `hypotheses=orch._research` wired, a node task re-issued for a
   already-claimed/registered (technique, target) is blocked or loses the tree
   claim — correct sharing, but a plan that double-books a node will surface
   `tree_claim_lost`/`blocked_duplicate` outcomes.
4. **A fresh specialist per task** (like the swarm's per-round specialists) —
   no worker pooling/persistence across tasks of the same role.
5. **No CLI flag for `driver="mission"` yet** (unchanged from Phase 2:
   programmatic/server entry only).
6. **The lab drives a scripted no-model client.** The agent loop, tool
   dispatch, proof pipeline, and independent verifier are fully real; payload
   *quality* (what a real LLM would try) is not exercised — unit discipline,
   per the tasking.
7. **Lease grace formula** stays as Phase 2 shipped it (900 s floor +
   sweep-based extension); wiring `deadline + 2 × command_timeout`
   automatically from `SandboxConfig` remains future work.

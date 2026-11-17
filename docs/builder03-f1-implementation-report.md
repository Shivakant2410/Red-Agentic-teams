# Builder 03 — Phase F1: the adaptive offensive autonomy engine (Issue #15)

Branch `phase-f1-adaptive-autonomy` (from `main` @ `4b6c39f`, the merge of PRs
#12 and #13). This report documents the closed loop
**plan → execute → observe → re-plan**, what is genuinely autonomous, what
remains scripted, and what still needs real-model validation.

## 1. The vertical slice

The smallest loop that closes the issue's cycle, built ONLY on existing
authorities:

    each round (mission driver, adaptive mode):
      1. OBSERVE   — attack_tree.sync(graph, findings): confirmed findings
                    complete tree nodes and UNLOCK their chained follow-ups;
                    falsified findings fail nodes; newly observed endpoints
                    seed entry techniques. (The same idempotent sync the
                    orchestrator's verify passes have always run.)
      2. PLAN      — planner.offensive_opportunities(): the read-time
                    attack-path projection ranks the tree's actionable()
                    frontier over LIVE intelligence.
      3. SYNTHESIZE — one task per not-yet-tasked frontier node (+ the round's
                    recon / independent-verification tasks), deduped by
                    node_id across ALL task states.
      4. DISPATCH  — the existing claim trio (reserve → tree.claim →
                    hypothesis → fenced execution) — unchanged.
      5. JUDGE     — assess_viability(): operator stop > round cap >
                    objective achieved > grounded exhaustion; the reason is
                    journaled (MISSION_STOPPED) and reported.

## 2. What changed (and what deliberately did not)

| File | Change |
| --- | --- |
| `redteam/planner.py` | **WS1** — `authority_projection()`: the SAME attack-path join the dashboard renders (graph_view), computed read-time over the LIVE authorities; `offensive_opportunities()`: ranks the tree's actionable() frontier with grounded nudges (+30 outstanding objective criterion, +20 held foothold, +15 evidence-backed hypothesis, −15 falsified hypothesis) and EXCLUDES remediated targets (latest retest FIXED — the creditor's currency rule generalized to planning); `remediated_targets()`; `map_surface_needed()`. The tree remains the work-selection authority: the planner ranks candidates the tree itself holds — it never invents work. |
| `redteam/graph_view.py` | The Phase E2 projection's join extracted verbatim into the pure `join_attack_paths()`; `_build_attack_paths` is now a file-reading wrapper. Byte-identical output (9 graph_view tests + the 10-step demo pass unchanged); the planner consumes the same join. |
| `redteam/mission/adaptive.py` | **WS2+WS3+WS5** (new) — `synthesize_round()` (tasks from ranked frontier, node_id dedup, recon/verify coverage, OPSEC-price reservations, one MISSION_SYNTHESIS journal event per round), `assess_viability()` (the honest stop reasons), `mission_briefing()`. Composition only: no store, no registry, no second scheduler. |
| `redteam/mission/driver.py` | The adaptive loop (top-of-round observe+plan, viability judge, round-boundary claim hygiene via the recovery reconcile applied LIVE, MISSION_STOPPED event, adaptive endgame: an achieved objective outranks the task-level calc with both facts recorded when they disagree). Static mode (`adaptive=False`) reproduces the pre-F1 semantics exactly. |
| `redteam/mission/scheduler.py` | **Bug fix (pre-existing on main)**: the C3 OPSEC round budget was never CHARGED — `_opsec_affordable` gated against a permanently-empty ledger, so a 2.0 round budget dispatched every task. The allowance is now charged at claim time (after the reserve CAS) and re-checked at the claim gate itself (a claim that can no longer afford its allowance is refused and stays PENDING for the next round's reset). |
| `redteam/attack_tree.py`, `redteam/access.py`, `redteam/knowledge.py` | Read-only snapshot accessors (`nodes_all()`, `nodes()`, `edges()`) so the projection/planner never reach into private state. |
| `redteam/mission/events.py` | `MISSION_SYNTHESIS`, `MISSION_STOPPED` journal event types. |
| `redteam/run.py` | `RunOptions.mission_adaptive` (default **True** — the production mission path generates work from live intelligence); run.py wires the shared graph/findings/access stores, the engagement Objective, and a stop_check over the budget tracker + STOP kill file into the driver. |
| `tests/test_mission_lab_e2e.py` | One flag added (`mission_adaptive=False`): the test is the static-path compat witness (it pins exactly 2 dispatches). Its assertions are otherwise untouched. |
| `tests/test_adaptive_autonomy.py` | **new (14 tests)** — the issue's 10 required demonstrations + operator stop + never-invents-targets + static compat. |

## 3. The tested multi-step chain (WS4, deterministic lab)

`access.control` (CWE-284) → verified → unlock **privesc.admin** → the
specialist presses the foothold, demonstrates an IDOR as the elevated
principal (CWE-639) AND discovers a new export endpoint (observed into the
shared KnowledgeGraph mid-mission — the next round's plan adds its entry
techniques) → IDOR verified → unlock **data.exfil** → the specialist
demonstrates the sensitive export (CWE-200, `FLAG{abc123}` in evidence) →
verified → the REAL creditor credits the FLAG criterion →
**stop reason: "objective achieved"**. Every state transition rides the
existing authorities; task success never completes a tree node (C4) — only
independent verification does.

## 4. What is genuinely autonomous vs scripted vs needs a real model

**Genuinely autonomous (deterministic machinery, exercised by the tests):**
the loop itself — intelligence refresh, projection ranking, task synthesis,
dedup, budget-gated dispatch, unlock-driven chaining, remediation-aware
exclusion, stop decisions, journal trail, recovery idempotence. Given ANY
outcome stream, the loop adapts without human plan edits: a confirmed finding
opens its chain, a falsified one dies, a discovery re-targets the next round,
an achieved objective stops the mission.

**Scripted in the tests (by design, no-LLM/no-network):** the specialists'
BEHAVIOR. The doubles mutate the real authorities through their production
APIs — recon observes endpoints, exploit stores replayable
`pending_verification` proofs, and verification runs the REAL
`verify(HttpCheck(...))` k-of-n machinery + `FindingStore.promote` + the REAL
creditor over a canned transport. The production verify-role task still runs
`run_verify_pass` (the LLM verifier); the doubles replace only the model.

**Needs real-model validation:** whether free-model specialists actually
(1) return useful prose/evidence the loop can chain on, (2) respect the
task-scoped instructions under real tool surfaces, (3) produce findings whose
CWE mapping steers the tree well, (4) keep within budgets. Also unexercised
with real models: the hypothesis-evidence nudge (needs a live swarm writing
evidence), the bandit blend inside `actionable()` (attached only in swarm
runs), and `mission_plan.json`-free cold starts where recon quality decides
everything.

## 5. Honest limitations

- One task per node per mission: a terminal task freezes its node until NEW
  intelligence changes the tree (a confirmed/falsified finding, a new
  endpoint). There is no timed re-attack of a TODO node whose task failed
  without a finding — deliberate (no repetition without new evidence), but it
  means transient executor failures need a fresh state transition to retry.
- The adaptive endgame overrides the all-tasks-succeeded calc ONLY upward
  (objective achieved → SUCCEEDED with both facts recorded); a mission that
  exhausts paths still reports the task-level outcome.
- `MISSION_SYNTHESIS` / `MISSION_STOPPED` events are planning trail — the
  recovery replay skips-and-counts them (unknown to the commander's state
  applier), which the recovery test pins explicitly.
- OPSEC reservations are per-round and non-refundable mid-round (a blocked or
  aborted claim's credit returns at the boundary reset).
- The planner's nudges are deterministic heuristics, not learned: the bandit
  (when attached) still owns the within-tier reordering inside
  `actionable()`; the strategist's `apply_strategy` nudges compose on top.
- No egress/network changes were needed or made: scope enforcement remains
  entirely with the existing ScopeGuard at the tool layer (verified by the
  no-invented-targets test at the synthesis layer).

## 6. Exact test commands and results (final commit)

    python -m pytest tests/test_adaptive_autonomy.py -q
      → 14 passed in 0.79s
    python -m pytest tests/test_mission_specialist_executor.py \
      tests/test_mission_lab_e2e.py tests/test_mission_recovery.py \
      tests/test_mission_ownership.py tests/test_mission_lifecycle.py \
      tests/test_mission_registry.py tests/test_mission_budgets.py \
      tests/test_mission_leases.py tests/test_mission_api.py \
      tests/test_mission_identity.py tests/test_adaptive_autonomy.py -q
      → 110 passed (mission core + adaptive loop together)
    python -m pytest -q        (full suite)
      → 2058 passed, 16 skipped, 3 warnings, 0 failed in 57.12 s
        (baseline main 4b6c39f: 2044 passed; +14 new tests, 0 changed outcomes;
         the warnings are the pre-existing sklearn SVD numerics)
    python scripts/demo_unified_intelligence.py
      → ALL 10 STEPS ASSERTED (the Phase E2 projection demo, unchanged by the
        join extraction)

Commit SHA: `ed2046e` — the Phase F1 implementation commit (single commit on
`phase-f1-adaptive-autonomy`; this report is a separate commit on top so the
recorded SHA stays stable).

## 7. Merge notes

No second graph/tree/scheduler/bus/store/registry/verifier was created. The
scheduler keeps the claim trio; the AttackTree keeps work selection; the
FindingStore + independent verification keep confirmation; the creditor keeps
collection. CI (`.github/workflows/ci.yml`, carried from the merged PR #13
line) runs the full suite on push — results appear as check runs, not
builder-reported numbers. Do not auto-merge: review the scheduler charge fix
(§2) and the static/adaptive flag semantics first.

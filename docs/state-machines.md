# State Machines Audit — every lifecycle in the platform, made explicit (Phase D1)

Status: Accepted (Phase D1 scope)
Supersedes: nothing. Complements ADR-001 (hypothesis lifecycle) and the
tolerance policy in `redteam/states.py`.

## 1. The ask

> "Find all of the implicit state machines in my app. Make the best decision
> that will elevate all three — UX, DX, AX — without breaking anything."

## 2. Inventory: what the audit found

Eleven state machines run this platform. One was already explicit
(hypotheses, Phase C1). Ten were **implicit**: states existed as bare string
literals scattered across write sites, legal transitions lived in comments (or
nowhere), and every consumer re-hard-coded its own copy of the vocabulary.

| # | Machine | States | Where it lived (implicit era) | Consumers |
|---|---------|--------|-------------------------------|-----------|
| 1 | **run manifest** (`runtime.RunManifest`) | running → completed \| halted \| error | 8 `_update_manifest(...)` call sites in `agent.py` + `server.py`; vocabulary only in a dataclass comment | dashboard `StatusBadge` (4 hard-coded tones), `bench/ladder.py` scoring, `report.py`, SSE `run.finish` |
| 2 | **approval** (`run.py` approvals.json contract) | pending → resolved (+ `approved: bool` dimension) | string checks in `HeadlessApprover` / `resolve_approval` / API | `approvals.json` file contract, `POST /api/approvals/{id}`, dashboard `ApprovalCard` |
| 3 | **finding confidence** (`findings.py`) | tentative, firm, pending_verification, confirmed, falsified, not_reproducible | merge conditionals in `FindingStore.add()`, `promote()`, the re-check guard in `tools/independent_verify.py`, and a tool-schema enum in `tools/workflow.py` | verify worklist, access-graph + objective crediting, `attack_tree.sync()` unlocks + bandit wins, report, dashboard `FindingsTable` |
| 4 | **attack-tree node** (`attack_tree.py`) | todo → in_progress → completed \| failed (→ todo per round) | constants + comments in `mark()` / `retry_failed()` | server bucket counts, `coverage.py` derivation, dashboard `RunDetail.attack_tree` |
| 5 | **kill-chain stage** (`killchain.py`) | not_started → in_progress → achieved | constants in `mark()`; no table | agent briefing, report, dashboard `KillChainList` |
| 6 | **hypothesis lifecycle** (`swarm/hypotheses.py`) | PROPOSED → ACTIVE → AWAITING_VERIFICATION → CONFIRMED/REFUTED (+ BLOCKED/STALE side states) | **already explicit** (`VALID_TRANSITIONS`, event-sourced) — the house pattern this phase extends | forum briefings, projections, phase-1 benchmark |
| 7 | **orchestrator phase** (`orchestrator.py`) | recon → exploit(round) → verify → logic | `_phase(...)` free strings + `phase.change` events | event stream, dashboard `PhaseStepper` |
| 8 | **strategy directive** (`strategy.py`) | active → expired(TTL) / released-on-evidence | TTL arithmetic in `tick()` | reflection digest, attack-tree boosts/penalties |
| 9 | **coverage pair** (`coverage.py`) | tested / attempted / alive_untouched / untouched | derived constants (already documented) | ARTEX coverage map, `/api/runs/{id}/coverage` |
| 10 | **llmred campaign verdict** (`llmred/campaign.py`) | leaked / blocked / undetermined / error | `Verdict` enum (already explicit, separate domain) | llmred reports, bandit rewards |
| 11 | **assessment usage row** (`agentic_setup/usage.py`) | pending → success \| failed | guarded SQL `UPDATE ... WHERE status='pending'` | spend tracking |

Machines 7–11 were **deliberately left implicit** in D1 (see §5); machines 1–5
are now explicit in `redteam/states.py`, and machine 6 is re-exported there
verbatim so there is exactly one place to look.

## 3. Drift the audit caught (each is a bug that already shipped once)

1. **`Finding`'s docstring lied.** It listed five confidence states; the merge
   code in `FindingStore.add()` silently accepts a sixth (`firm`, the agent's
   own k-of-n self-check). The vocabulary was only discoverable by reading the
   merge conditionals. Fixed: `findings.py` now carries the full six-state
   vocabulary with the writer matrix one import away.
2. **A legacy alias only a consumer knew about.** Very old artifacts carry
   `confirmed` in `attack_tree.json` where the tree writes `completed`;
   `coverage.py` had to tolerate it on read. Now documented as
   `states.TREE_LEGACY_ALIASES` — kept OUT of the write vocabulary on purpose.
3. **Four independent copies of the run-status vocabulary.** `agent.py` writes
   it, the dashboard tones it, the bench scores it, the report summarizes it.
   None could see a fifth status coming. Now one table serves all four
   (`states.RUN_*` + the JSON export), with the dashboard's muted-unknown
   rendering retained as the safety net.
4. **A doctrine gap the writer matrix makes nameable** (not fixed in D1 — see
   §5): the `record_finding` tool schema offers the LLM `confidence:
   "confirmed"`, while C1's doctrine says only the independent pipeline may
   set confirmed. First-party deterministic tools legitimately write confirmed;
   the gap is specifically the agent-facing enum. Naming who may write what is
   the prerequisite for gating it without breaking benches that lean on it.

## 4. The decision

**One lifecycle registry** — `redteam/states.py` — owns the vocabulary, the
transition tables, the writer matrix, and a machine-readable export. Runtime
strictness does not change (the "without breaking anything" contract): write
paths keep accepting what they accepted yesterday; the tables are the contract
new code must honor. Three audiences, one source of truth:

- **DX.** Owner modules import their constants (`from .states import TREE_TODO
  as TODO`, ...), so extending a lifecycle is a one-file diff the test suite
  checks end-to-end. The structural tests in `tests/test_states.py` reject
  malformed tables (unknown targets, unreachable terminals, writers inventing
  states) and pin the store's actual merge/promote behavior to the table.
- **AX.** An agent enumerates every lifecycle, legal transition, terminal set,
  and writer without reading source:
  - `python -m redteam.states --json` (works air-gapped, no server);
  - `GET /api/state-machines` (versioned; bump `EXPORT_VERSION` on any change).
  The hypothesis lifecycle stays authoritative in `swarm/hypotheses.py` and is
  re-exported verbatim — one table, zero forking.
- **UX.** The states an operator sees in `events.jsonl`, the coverage map, and
  the dashboard are now *specified*: an unknown status is by definition a bug,
  not a vocabulary extension. The next dashboard/badge/report change diffs
  against the same table the engine writes.

### The finding-confidence funnel (the load-bearing machine)

```
tentative ──agent's own k-of-n──▶ firm ──queue──▶ pending_verification
    │                                │                    │
    │  first-party deterministic proof lands (merge, forward-only)        
    └──────────────▶ CONFIRMED ◀─────┴────────────────────┤
                          │                               │
                 falsified ◀── benign control ──▶ not_reproducible
                 (terminal)        reproduced      (weak verdict, re-checkable)
```

Writers: `agent:record_finding` → {tentative, firm};
`tool:deterministic_proof` → {tentative, firm, confirmed};
`verify:pipeline (promote)` → {confirmed, falsified, not_reproducible};
`store:merge` → forward-only upgrades. Nothing may credit an objective or
access node from anything but `confirmed`.

## 5. Deliberately NOT done in D1 (the breakage boundary)

1. **No runtime rejection of unknown/illegal transitions.** Strict mode is a
   one-flag follow-up once consumers (benches, old artifacts, replay) are
   audited against the tables. Tightening writes today would risk exactly the
   stacked-run regressions this phase promised not to cause.
2. **No change to the `record_finding` agent enum.** The doctrine gap (§3.4)
   is documented and now machine-checkable; gating it changes scoring
   behavior and belongs in its own reviewed change.
3. **Machines 7–11 stay implicit** until one of their promotion triggers hits:
   a second consumer hard-codes the vocabulary (orchestrator phases — the
   dashboard stepper is close), a lifecycle grows a second writer (strategy
   directives), or a bug class appears (usage rows). Explicitness has a cost;
   these machines are single-owner today.
4. **Dashboard still hard-codes the four run tones.** It now has a source of
   truth to fetch (`/api/state-machines`); wiring the Next.js app to it is a
   dashboard-repo change with its own review cycle.

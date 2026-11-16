# M4-PROOF.md — the orchestrator seams, proven on the labs

Run: 2026-11-07, `run_m4.py --with-dvlba`, real HTTP on loopback, one tree.
Companion research: `RESEARCH-M4.md` (web + papers BEFORE code). Exit
criteria mirror ROADMAP G5: same `schema()` + `run(ctx)` contract served by
both paths; both labs green; STOP-halts proven in Phase B and re-asserted
by unit test.

## 1. Exit checks — all PASS

| # | Criterion | Result | Evidence |
|---|---|---|---|
| E1 | Registry path: GV-1..8 verified, 0 decoy FP, 0 LLM calls, markers ≥ 2 | **PASS** | run1: 616 req, 10 findings (all verified), 0 FP, `llm_seam_calls == 0`, markers 2 |
| E2 | Orchestrator path (run2, run1's memory): same 8 GVs — the contract served by both | **PASS** | run2 via `Orchestrator().run()`: 607 req, 10 findings all verified, GV-1..8 |
| E3 | Policy audit present; lab mode denies nothing | **PASS** | `policy_audit.jsonl` in every run dir; run1: **596 audited decisions, 0 denied** |
| E4 | Refusal control (`approvals=none`): writes denied pre-socket, 0 verified findings, run completes | **PASS** | **33 audited denials (traffic-confirmed 33), 0 verified findings, run completed after 15 counted requests** |
| E5 | Verify pipeline report in both paths | **PASS** | `verify_pipeline` in both summaries; downgrades [0, 0] on green labs (honest) |
| E6 | `Orchestrator.schema() == registry._schema()`; file experience store | **PASS** | dict equality; `experience_store == "file-experience-store"` |
| E7 | dvlba B1..B8 + zero unmatched | **PASS** | run1 270 req / run2 181 req, B1–B8, unmatched 0, 0 FP |

Unit suite: **64 passed** (50 pre-existing + 14 new in
`tests/test_m4_seams.py`) — the delegation refactor is behavior-neutral
(freightlane request counts identical to M3: 616/607).

## 2. What the refusal control proves (the charter's owed refusal case)

`docs/competitor-landscape.md` said the project still owes "held-out,
permissioned tasks with known outcomes **and refusal cases**". The
`approvals=none` run is exactly that artifact:

- 33 write-mutant attempts (registrations, logins, creates, redeems) were
  denied at the executor chokepoint — **no socket was ever opened** for
  them (traffic-confirmed: 33 `policy_denied: true` exchange records, and
  the counted request budget spent only 15 on lawful GETs);
- zero findings shipped; the engagement died economically instead of
  burning its budget (the gate does not consume budget on denial);
- the full decision trail is in `m4-results/refusal-control/policy_audit.jsonl`.

This also caught and fixed a real latent bug: techniques compared
`200 <= r["status"] < 300` against a denial exchange whose status was
`None` (TypeError). Denials now carry `status = 0` — the codebase's
existing "no HTTP response" convention — plus `policy_denied: true`.

## 3. Pre-registered prediction scorecard (RESEARCH-M4.md R5)

| # | Prediction | Result |
|---|---|---|
| P1 | GV-1..8 verified through the Orchestrator path, `llm_seam_calls == 0` | **HIT** (both paths actually) |
| P2 | dvlba + freightlane findings exact — no behavior drift | **HIT** (616/607 req, 10 findings, B1–B8; statuses verified/verified-by-transcript only) |
| P3 | `approvals=none`: 0 findings, ≥ 20 denials, completes | **HIT** (0 findings, 33 denials, completed) |
| P4 | schema dict equality between paths | **HIT** |
| P5 | pipeline downgrades reported honestly whatever they are | **HIT** ([0, 0] on green labs; the mechanism is unit-proven on synthetic candidates) |
| P6 | run-2 memory not worse than run-1 | **HIT** (freightlane 607 vs 616 = −1.5%; dvlba 181 vs 270 = **−33%**) |

6/6 — but note P3's honest framing: the refusal run ended at 15 counted
requests because registrations are themselves write mutants; the swarm
stalls early rather than grinding. That is the intended fail-closed
economics, observed, not assumed.

## 4. Artifacts (all under `m4-results/`)

- `run1/`, `run2/` — freightlane through registry / orchestrator path:
  findings.json (v0.7.0-m4), blackboard.json, dispatch_trace.jsonl,
  traffic.jsonl, hypothesis_ledger.json, attack_surface.json,
  **policy_audit.jsonl**, memory/
- `refusal-control/` — the negative control (findings.json shows 0
  findings; policy_audit.jsonl shows every denial with rule + reason)
- `dvlba/run1|run2/` — the B1..B8 regression through the same path
- `M4-SUMMARY.json` — machine-readable exit report (pass: true)

## 5. What M4 does NOT claim

- The Router's dispatch semantics, the ledger spine, the attack graph, and
  all M0–M3 exit criteria are UNCHANGED — M4 wrapped them; it did not
  retune them (request counts identical to M3 are the drift alarm).
- The verify pipeline's downgrade pass fired zero times on green labs —
  its value is conditional (it converts "nothing refuted it" into
  "nothing reproduced it"), unit-proven, and will bite in M5 when LLM
  hypotheses start entering the board.
- The ≥ +20% memory-efficiency exit belongs to M5; M4 only measured the
  non-regression (P6) and got a dvlba −33% preview.

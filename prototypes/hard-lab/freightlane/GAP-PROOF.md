# GAP-PROOF.md — the v1 engine vs Freightlane: live evidence for the roadmap

Experiment executed per `RESEARCH.md` (pre-registered predictions P-A1…P-C2).
Three runs, fresh servers, real HTTP, full traffic transcripts under `results/`.
Every number below is read from the artifacts, not recalled.

## 0. Headline

Cross-lab context: on the **original meridian-vault lab** (Phase D, re-run
fresh after this experiment), v1 standalone statefuzz also scored **0**
findings (64 req), while the ledger-spine engine scored **8/8 verified**
(301 req, run1+run2). Freightlane (below) isolates the *v1-only* baseline:
what the tools do **without** the hypothesis-engine spine.

| Metric | dvlba-shop (baseline, prior phases) | Freightlane (hard lab, this run) |
|---|---|---|
| statefuzz v1: requests → findings | 87 → **8/8 seed classes** | 73 → **0/8 covert** |
| swarm v0.2: requests → findings | 188 → **9 findings, 8 re-verified** | 115 → **1 finding, verified** |
| Autonomous covert-vuln coverage | 100% | **12.5% (1 of 8)** |
| HypothesisLedger markers registered (autonomous) | 1 (pinned async probe) | **0 / 0** |
| False positives on decoys | — | **0** (discipline held) |
| Deferred-window vulns (GV-4/GV-5) | — | **both missed autonomously; both proven in 34 req when the ledger was fed by hand** |

Same engine, same protocol family, same budgets-tier. The collapse is not
machinery failure — it is strategy failure, and every miss is nameable.

## 1. Ground-truth matrix (each miss cites its mechanism; band taxonomy per RESEARCH.md §6)

| ID | Class | Autonomous result | Band | Nameable mechanism (wire-log evidence) |
|---|---|---|---|---|
| GV-7 rerate rounding drift | REPLAY (arithmetic) | **FOUND** `FW-ROUND-DRIFT`, I4, verified by verify-specialist with fresh principals | E | The one bug inside BOTH the stale doc's graph AND the technique's closed vocabulary (`h_arith_cycle` gate + cycle accounting) |
| GV-8 settle from `booked` | SKIP (FSM) | Hidden verb **observed**: `verb-probe POST …/settle → 200` published as OBSERVATION; no wallet check, no FSM hypothesis, no finding | **D: discovered-not-exploited** | `t_hidden_verbs` stops at observation; no follow-through consumer; no ambient I4 wallet watch |
| GV-1 voucher release replay | REPLAY (hidden surface) | missed | C: wholly-invisible | `/api/vouchers` ∉ stale doc → graph has no such resource → `t_hidden_verbs` probes only doc-listed money resources |
| GV-6 voucher consume race | INTERRUPT (race) | missed | C | Same hidden resource; race primitive exists (Phase-B-proven) but nothing aims it |
| GV-2 `recent` global leak + rebook | CROSS-USER | missed | C | `t_cross_tenant` probed exactly `['/api/wallet']` (traffic log) — `"recent"` ∉ `_READBACK_FALLBACK`; rebook verb undocumented |
| GV-3 `rate_cents` mass-assign | NEGATIVE | missed | C | `t_mass_assign` tried exactly the 5 `PRICE_CANDIDATES` (amount_cents, discount_pct, price_cents, unit_cents, unit_price_cents — traffic log); `rate_cents` ∉ list |
| GV-4 payout settle TOCTOU | INTERRUPT (deferred) | missed (gate-starved) | C→E | `h_async_toctou` gate requires a documented transfer verb → absent; scripted probe (Run C) proved it in ~12 req: final balance **−19955** |
| GV-5 cancel-after-settle | SKIP (deferred) | missed (gate-starved) | C→E | `h_terminal_credit`/`h_state_guard` gates require a documented cancel verb → absent; Run C fed the ledger by hand: expected −30000, observed delta **0** → I1 violation flagged |
| D-1 claim decoy | decoy | clean, no FP | — | race + 5 exhaust identities honestly 200/409-mixed → no finding; ~34 requests burned on a decoy (budget misallocation evidence) |
| D-2 negative `weight_kg` | decoy | untested autonomously | — | the NEGATIVE operator exists in statefuzz mutants but is aimed only by dvlba-pinned probes |

## 2. Pre-registered predictions: scorecard (honesty contract)

| Prediction | Verdict |
|---|---|
| P-A1 0 true findings for statefuzz v1 | **HELD** (count band 30–45 missed: actual 73 — honest miss on the request count only) |
| P-A2 markers_registered == 0 | **HELD** (`deferred_phase_requests: 0` in traffic) |
| P-B1 doc accepted at face value, no re-test | **HELD** — recon's earned insight is literally *"machine-readable surface disclosure outperforms blind probing"* — the wrong lesson on a lying target |
| P-B2 exactly the doc-gated generics fire | **HELD** (h_fsm + hidden_verbs, mass_assign, cross_tenant, arith_cycle, quota_race; state_guard/async_toctou/terminal_credit starved) |
| P-B3 exactly 1 true finding (FW-ROUND-DRIFT) | **HELD** (status: verified) |
| P-B4 per-vuln miss taxonomy | **HELD**, incl. the GV-8 discovered-not-exploited band |
| P-B5 no FP on decoys | **HELD** |
| P-B6 request band 200–320 | **MISSED** (actual 115; decoy burn ~30%, not ≥60%) |
| P-C1 ledger flags violations when fed | **HELD** (GV-5 I1 violation; GV-4 negative balance) |
| P-C2 gap is architectural, not implementational | **HELD** — same lab, same ledger, scripted feed → both findings |

Execution incident (recorded for honesty): the first Run B attempt collapsed
because the lab's OpenAPI used a non-canonical schema dialect (no
`properties` wrapper); the swarm's parser read `create_schema: {}` and four
techniques starved **silently** (three 400s each, then `[]`, no diagnostic).
Fixed the lab to canonical O3 (dvlba dialect) and re-ran. Two lessons: the
generic layer degrades silently on dialect drift, and it never re-validates
the doc against live responses (a create that 400s three times is a parse
failure, not a target property).

## 3. What the run adds beyond the grep audit (new live facts)

1. **The engine self-diagnosed one gap**: `skip-statefuzz … statefuzz_run
   probes are dvlba-shaped (generalization gap)` — the spawn seam refused to
   fire on a non-dvlba surface. Good honesty; but it logged and stopped —
   no alternative FSM strategy exists to fall back to.
2. **Band D is real value leakage**: GV-8's settle verb was found in ~1
   request and dropped; the payout credit landed in the wallet during probing
   and no oracle noticed. Discovery without follow-through = 0 findings.
3. **Memory can encode the wrong lesson**: recon's fresh-run insight
   (trust disclosure over probing) is anti-productive on stale-doc targets.
   Insight curation needs a falsification loop, not just outcome weights.
4. **Verify-specialist independence works**: FW-ROUND-DRIFT was re-verified
   with fresh principals (17 verify-phase requests) — the E3 discipline
   transfers; it is the *hypothesis supply*, not the verification, that
   starves.
5. **The HypothesisLedger is starving, not broken** (P-C2): 0 autonomous
   markers vs 2 violations caught when fed. This is the single highest-leverage
   wiring task in the roadmap.

## 4. Difficulty delta, quantified

- Findings per 100 requests: dvlba swarm = 4.8; Freightlane swarm = 0.87.
- Covert coverage: 8/8 → 1/8.
- Time-to-first-finding: dvlba ≈ first dispatch round; Freightlane = exploit
  round 6+ (arith cycle), after ~60 requests of clean-half/decoy spend.
- The lab achieves this with the SAME seed-count (8) and NO exotic tech —
  only stale disclosure, out-of-vocab names, order sensitivity, deferred
  windows, and one hidden race.

## 5. Artifact index (paths relative to `freightlane/`)

- `results/statefuzz-v1/` — findings.json (empty findings), traffic.jsonl, summary.json
- `results/swarm-v1/` — findings.json (FW-ROUND-DRIFT, verified), blackboard.json
  (hypotheses, hidden-settle OBSERVATION, skip-statefuzz CONTROL), dispatch_trace.jsonl, traffic.jsonl
- `results/ledger-probe/` — probe.json (GV-5 ledger violation, GV-4 negative balance), traffic.jsonl
- `results/memory-freightlane-fresh/` — per-specialist namespaces incl. the recon insight
- `target/app.py` — the lab (ground truth in RESEARCH.md §3)

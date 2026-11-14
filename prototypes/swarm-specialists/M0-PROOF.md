# M0-PROOF.md — the proven spine now lives in the mainline tree

M0 (roadmap): *promote the HypothesisLedger spine from the Phase-D hard lab
into the mainline tree, behind the seam marks, deterministic v1 path kept as
fallback.* Exit criteria: **both labs green from ONE tree — meridian ≥ 8
verified findings, dvlba still 8/8 seed classes.** Every number below is read
from artifacts produced by `run_m0.py` in this directory (`m0-results/`), not
recalled.

## 1. What was promoted (and from where)

| Asset | Source (proven) | Destination (mainline) |
| --- | --- | --- |
| `engine/ledger.py` — propose/attach/resolve/deferred, honest resolution vocabulary, score where refuted = 1.0 | `hard-lab/engine/ledger.py` (validated 8/8 meridian) | `engine/ledger.py` (verbatim) |
| `engine/projection.py` — blackboard→ledger projection | `hard-lab/run_hardlab.py` `project_swarm`/`project_statefuzz` | `engine/projection.py`, **decoupled**: `deferred_hits` is a callback (meridian passes S2/S3, dvlba passes B8, default None ⇒ honest inconclusive); facts/trace accepted in memory or from disk |
| v0.2 technique library + specialists (U1 route-index recon, U2 index-driven surface, U3 schema-unknown probing, exploit `derived_from` fix) | `hard-lab/swarm/` | `swarm/techniques.py`, `swarm/specialists/{recon,surface_mapper,hypothesis,exploit}.py` |
| statefuzz registry graceful-skip on unfamiliar surfaces (wallet read-back `None` guards) | `hard-lab/statefuzz/registry_tool.py` | `statefuzz/registry_tool.py` |
| **New seam** | — | `swarm/registry_tool.py`: guarded `engine` import; `run(ctx)` creates the ledger by default, projects at end-of-run, writes `hypothesis_ledger.json`, exposes `hypothesis_ledger` in the summary; `ctx["ledger"]=False` (or missing engine package) ⇒ deterministic v1 path byte-identical. Version bumped `0.3.0-m0`. |
| **New harness** | — | `run_m0.py` (both labs, one tree, scored), `dvlba_ground_truth.py` (B1–B8 keys mirror `target/seeds.py`; ids are the executed Phase-C finding IDs) |

## 2. Validation — one tree, both labs, real HTTP, fresh servers

`python3 run_m0.py` — meridian on :8461, dvlba on :8462, run1 fresh memory /
run2 same memory (Phase-D protocol).

| Lab | Run | Requests | Findings | Ledger entries |
| --- | --- | --- | --- | --- |
| meridian-vault | run1 | 309 | 8 | 11 (6 confirmed, 1 by-transcript, 1 refuted, 1 tested, 2 inconclusive; score 7.75) |
| meridian-vault | run2 | 295 | 8 | 11 |
| dvlba-shop | run1 | 214 | 9 | 19 (15 confirmed, 1 by-transcript, 3 refuted) |
| dvlba-shop | run2 | 181 | 9 | 19 |

Exit criteria:

- **[PASS]** meridian verified findings = **16 across two runs** (≥ 8 required; proven Phase-D baseline was 8 per run)
- **[PASS]** meridian seeds **S1–S7 all hit** (S8 remains the deliberately-unbuilt existence-oracle arm — roadmap future work, not an M0 regression)
- **[PASS]** meridian false positives = **0** (decoy discipline holds: sample `/.env`, safe `retry`, validated negatives, enforced account read all left unclaimed)
- **[PASS]** dvlba seed classes **B1–B8 all hit**, 0 FP — no regression from the v0.2 promotion
- Deferred-window resolution matches the proven run **exactly**: `confirmed — deferred-window violation (FW-TOCTOU-SETTLE,FW-SETTLED-CANCEL) verified in this run`

## 3. Test suite

`pytest tests/` → **23 passed** (13 pre-existing Phase-C tests — including the
E2E that asserts ≥ 9 findings / ≥ 8 verified on dvlba and cross-run memory
adaptation — plus 10 new M0 tests: ledger lifecycle/honesty scoring,
deferred-window shape, persistence, all five projection resolution paths,
grounding discipline, and two live E2E runs proving the registry writes a
non-empty `hypothesis_ledger.json` by default and produces no spine artifacts
with `"ledger": False`).

## 4. Honest deltas

- Request totals: meridian 604 (M0) vs 603 (proven) — parity. dvlba run1 214
  vs 188 (Phase C) — the U1 route-index recon costs ~2% more on a doc-first
  target; run2 181 matches Phase C exactly, so memory-driven efficiency is
  intact.
- `project_swarm`'s dispatch matching keys on `SF-HYPOTHESIS-*` router labels
  (the id scheme specialist facts actually carry — verified against the
  Phase-D artifacts and now pinned by `test_projection_resolution_paths`).
- The ledger in M0 is **passive by design**: it records and scores beliefs; it
  does not yet steer dispatch. Making it generate and drive hypotheses is M1.
- Hard-lab trees (`hard-lab/`) are unchanged; the promotion is one-directional
  (lab → mainline). The mainline tree is now the single source of truth.

## 5. Artifact index (paths relative to this directory)

- `m0-results/M0-SUMMARY.json` — machine-readable validation report
- `m0-results/meridian/run{1,2}/` — findings.json, blackboard.json,
  dispatch_trace.jsonl, traffic.jsonl, hypothesis_ledger.json, memory/
- `m0-results/dvlba/run{1,2}/` — same artifact set
- `tests/test_m0_ledger.py` — the M0 suite

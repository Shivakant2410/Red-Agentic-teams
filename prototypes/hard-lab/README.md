# hard-lab — meridian-vault (Phase D)

A deliberately **hard** local lab for the Red-Agentic-teams offensive engines,
plus the wiring that connects both engines to the unified **HypothesisLedger**
("hypothetical engine"). Built under the project rule: *research first, code
second* — see `RESEARCH.md` (verified sources, [F]/[H]/[U] flags) and
`GROUND_TRUTH.md` (scorer's key, kept out of the target app).

## What was proven (executed, artifacts in `results/`)

| question | answer |
| --- | --- |
| Can the engines crack a lab with no openapi, hidden verbs, multi-step state machines, race windows and cross-account invariants? | **7/8 seeds found, all independently re-verified**, in ~300 requests / ~2.5 s per run |
| Do the engines report decoys? | **0 false positives** against D1–D4 (sample `/.env`, safe `retry` verb, validated negative amounts, enforced account read) |
| Does the standalone statefuzz generalize? | **No — 0 findings / 64 requests**: the measured dvlba-shape gap, reported honestly |
| What did the lab expose as a capability gap? | S8 (403/404 existence oracle) missed — no technique arms status-code enumeration; future `h_oracle_enum` |
| Full belief lifecycle? | `hypothesis_ledger.json`: 23 hypotheses — 12 confirmed, 2 by-transcript, 2 tested(observation), 3 refuted, 4 inconclusive |

## Quick start

```bash
python -m pytest tests/ -q        # lab validity: seeds reproduce, decoys stay safe (13 tests)
python run_hardlab.py 8391        # 2 swarm runs + statefuzz + ledger + scoring + report
```

Artifacts land in `results/`: `report.md`, `hypothesis_ledger.json`,
`scoring.json`, `summaries.json`, per-run `findings.json` + `traffic.jsonl`
(every wire exchange carries seq/ts/phase provenance), `memory/` (persisted
bandits + insights).

## Layout

```
target/app.py        meridian-vault: Flask escrow bank. No openapi; thin /api
                     route index; 422 error contracts; hidden verbs (settle,
                     retry-decoy); async settle worker; seeded bugs S1–S8,
                     decoys D1–D4
engine/ledger.py     unified HypothesisLedger: propose → test → resolve
                     (confirmed / confirmed-by-transcript / tested / refuted /
                     inconclusive), deferred-window semantics from Phase B
swarm/               Phase C specialist swarm (vendored) + 3 target-agnostic
                     upgrades: U1 recon index/route-index; U2 surface from
                     route index; U3 schema-from-errors (422 contracts)
statefuzz/           Phase B FSM fuzzer (vendored); unfamiliar-surface guards
ground_truth.py      scorer: finding → seed HIT / decoy FALSE-POSITIVE
run_hardlab.py       the connector: boots lab → swarm ×2 (shared memory) →
                     statefuzz → ledger projection → scoring → report.md
tests/               acceptance A1/A2: every seed reproducible, every decoy safe
```

## Seed → finding map (executed)

| seed | mechanism | finding | verified |
| --- | --- | --- | --- |
| S1 quota race | global claim quota, 2 ms check-then-act window, 8 distinct principals, last-byte sync | FW-QUOTA-RACE (I5) | by-transcript |
| S2 settle-after-cancel | payout cancel accepted after settlement; wire stands + balance refunded | FW-SETTLED-CANCEL (I1) | verified |
| S3 async TOCTOU | settle debits with no balance re-check; drain inside deferred window | FW-TOCTOU-SETTLE (I4) | verified |
| S4 rounding drift | refund ceil / charge floor on 0.1% proration; +1 cent per cycle | FW-ROUND-DRIFT (I4) | verified |
| S5 reason dedupe | cancel dedupe keyed (vault, reason); mutated reason re-credits | FW-CANCEL-REASON (I1) | verified |
| S6 terminal reopen | resize accepted on canceled vault; residual re-credit | FW-TERMINAL-RESIZE (I2) | verified |
| S7 cross-tenant | global audit leaks vault ids; writes skip owner check; refund pays CALLER | FW-AUDIT-LEAK + FW-DEPUTY-CREDIT (I3) | verified |
| S8 existence oracle | 403 vs 404 account enumeration | miss → future h_oracle_enum | — |

## Discipline inherited from the platform contract

Loopback-only fail-closed scope guards · STOP kill files · request budgets ·
fresh principal per probe · findings carry provenance + verification stamps ·
honest statuses (a refuted belief scores as informative as a confirmed one;
race artifacts consumed by the finder downgrade to transcript-verified).

## Honesty notes

- Loopback races are near-jitter-free; windows are widened application-side
  (RESEARCH.md R5) — easier than production.
- Seeds intentionally intersect the technique library's shape gates so
  hypotheses are *testable*; difficulty lives in multi-step discovery, not
  exotic shapes.
- run2 (same memory) re-found all 8: memory pruned refuted arms
  (`h_idor` 0.36, `h_mass_assign` 0.36) and favored `fetch_route_index`
  (0.60) — on a target where every technique pays off, adaptation shows as
  arm weighting, not request savings.

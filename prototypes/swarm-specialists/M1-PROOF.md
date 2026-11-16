# M1-PROOF.md — the ledger now generates: markers + window driver

M1 (roadmap): *"Ledger-as-engine + window driver (G1) — markers auto-registered
from 202/event shapes; window interleaving; extend the promoted spine to
**generate** hypotheses, not only resolve them."* Exit criteria:
**Freightlane GV-4 + GV-5 autonomous; `markers_registered ≥ 2`.** Every number
below is read from artifacts produced by `run_m1.py` / `run_m0.py` in this
directory (`m1-results/`, `m0-results/`), not recalled.

## 0. The miss this closes (GAP-PROOF §1, verbatim)

| GAP-PROOF miss | Mechanism (wire-log evidence) | M1 answer |
| --- | --- | --- |
| GV-4 payout settle TOCTOU — "missed (gate-starved)" | `h_async_toctou` gate requires a documented transfer verb → absent on the stale doc | Seam discovery is now **probe-grounded** (`t_async_seam`), and the drain is a **calibrated lawful spend** driven by the marker — no documented verb needed |
| GV-5 cancel-after-settle — "missed (gate-starved)" | `h_terminal_credit`/`h_state_guard` gates require a documented cancel verb → absent | The driver probes the cancel-family on the **observed seam object** after settle |
| "0 / 0 markers registered (autonomous)" | Nothing reacted to the 202/event shape | Markers auto-register from ANY 202/event exchange (traffic scan + seam observations), grounded-only |
| "discovered-not-exploited" band D leak (GV-8 precedent) | Observations dropped; windows unattended | The WINDOW specialist drives windows **between dispatch rounds**, inside the settle TTL |

## 1. What was built (G1 a/b/c → module)

| G1 item | Module | Mechanism |
| --- | --- | --- |
| (a) hypothesis generation from surface + observations | `engine/window.py` `classify_async`/`field_from_error` + `engine/ledger.py` `mark()`; `swarm/techniques.py` `t_async_seam`; `swarm/specialists/hypothesis.py` `h_async_seam` rule | A 202 whose body carries an event-path string and an object id is an **async seam**; the validation error names the create field (U3 analogue); `ledger.mark()` registers a structured marker (expectation `single_debit −amount`) **only** from an observed shape, `derived_from` a board fact (E6) |
| (b) driver loop interleaving window actions | `engine/window.py` `WindowDriver` + `swarm/specialists/window_driver.py` | Between router rounds: poll event path to settle → cancel-family probe (GV-5) → once per run a **fresh drained window**: calibrate a documented create's unit cost, spend just enough to push the balance below the settle amount (GV-4), resolve the marker from wallet read-backs |
| (c) ledger-backed mutant selection | `WindowDriver.drive_pending` reads `ledger.markers(state=…)` | The ledger marker state decides which operator fires next and against which object; hypothesis gating for the seam rule is surface+money-grounded |

Supporting changes: roster gains `WINDOW` (`window_driver`); verify
re-executes driver findings through the **same driver code** with fresh
principals (E3); `_dedupe` normalises endpoint templates (`{payout_id}` →
`{id}`) so two finders of one mechanism merge; the end-of-run projection no
longer re-registers windows that live markers already cover; scan skips
`phase=verify` exchanges (verification re-executions are not discoveries).
Version bumped `0.4.0-m1`. `llm_seam_calls` remains **0** — M1 is
deterministic; the LLM seam stays M5.

## 2. Validation — Freightlane M1 exit (`python3 run_m1.py --with-dvlba`)

| Run | Requests | Findings | Markers | Wall |
| --- | --- | --- | --- | --- |
| freightlane run1 (fresh memory) | 203 | 3 (all verified) | 2 (2 confirmed, 0 refuted) | 6.4 s |
| freightlane run2 (run1 memory) | **136** | 3 (all verified) | 2 (2 confirmed) | 6.3 s |
| dvlba regression run1 / run2 | 214 / 181 | 9 / 9 | 0 | 2.4 s |

Exit criteria:

- **[PASS] E1** GV-4 `FW-TOCTOU-SETTLE` autonomous, **verified** — fresh-principal
  replay: "settle drove the balance negative (−3973)"
- **[PASS] E2** GV-5 `FW-SETTLED-CANCEL` autonomous, **verified** — fresh replay:
  "cancel after settle refunded 50000"
- **[PASS] E3** `markers_registered = 2` (≥ 2), **all grounded** — every marker's
  `derived_from` cites a board fact id
- **[PASS] E4** zero decoy false positives (D-1 claim stays clean; both labs)
- **[PASS] E5** deterministic: `llm_seam_calls = 0`
- **[PASS] E6** dvlba B1–B8 all hit, 0 FP — byte-identical request counts to the
  M0 baseline (214/181)
- Bonus: GV-7 `FW-ROUND-DRIFT` still found + verified — the v1 baseline arm is
  intact; run2 used **67 fewer requests** with identical findings (memory effect
  now covers the M1 arm via curation).

## 3. The grounding chain (read from run1 artifacts)

```
SF-HYPOTHESIS-0011  h_async_seam          (generic rule, surface-gated)
  └─ SF-EXPLOIT-0016      OBSERVATION async-opened
        "POST /api/payouts {} -> 400; POST /api/payouts {amount_cents: 50000}
         -> 202 /api/payouts/PAY-059648c144/events"
       ├─ H-0001 marker (scan, grounded)  confirmed
       │    poll pending×7 → settled → post-settle wallet 50000
       │    → cancel → wallet 100000 (refund 50000) ⇒ GV-5
       └─ H-0002 marker (fresh drained window)  confirmed
            fresh window 100000 → drain 46027 → settled → final −3973
            → cancel → 46027 (refund 50000) ⇒ GV-4 (+GV-5 second shot)
```

Both findings then re-verified with fresh principals through the same driver
code (E3), and curation credits the `h_async_seam` arm through the
`derived_from` closure.

## 4. Regression — one tree, three labs (`python3 run_m0.py`)

| Lab | Requests | Findings | Exit |
| --- | --- | --- | --- |
| meridian-vault run1 / run2 | 362 / 372 | 8 / 8 verified (16 total) | S1–S7 all hit, 0 FP |
| dvlba-shop run1 / run2 | 214 / 181 | 9 / 9 | B1–B8 all hit, 0 FP |

Meridian note: the window driver also runs there (ambient scan marks the
documented payouts' 202 windows). After the dedupe normalisation, its
re-discovery of the settle/cancel class merges into the technique's verified
finding — provenance `['exploit', 'window_driver']`, techniques
`['h_terminal_credit', 'h_window_driver']` — and the verified count matches
the M0 baseline exactly (16). One honest artifact: a driver-originated
duplicate can end the run `candidate` when the router's 40-round cap closes
before verify dispatches; it merges rather than ships as a second finding.

## 5. Test suite

`pytest tests/` → **31 passed** (13 Phase-C + 10 M0 + 8 M1). The M1 suite
covers: shape classification (202/event/id/amount extraction, negatives),
error-contract field learning, marker grounding assertion, marker lifecycle +
honest scoring, idempotent `open_from_shape`, amount-gating, traffic-scan
offset semantics, and two live freightlane E2Es — the M1 exit in miniature
(autonomous discovery, ≥ 2 grounded markers, GV-4+GV-5 verified, decoys
clean) and the `"ledger": False` v1 fallback.

## 6. Honest deltas

- **Marker-loop incident (found by the E2E, fixed)**: the first cut kept
  `drain_attempted` on a per-dispatch driver instance; each dispatch opened
  another fresh window whose 202 fed the traffic scan — a runaway that
  burned the budget (9 markers, verify starved). Fix: once-per-run state is
  caller-owned (survives dispatches), scan offsets skip marked event paths,
  and the E2E now pins markers == 2.
- The driver's fresh window is **once per run** by design; a target with a
  second independent seam class would need M2's surface truth to reach it.
- Freightlane GT scoring in `run_m1.py` keys on finding ids + mechanism
  keywords (the lab has no scripted scorer of its own); the GV-4/GV-5 keys
  mirror GAP-PROOF §1 and the target's docstrings.
- GV-8 (settle-from-`booked`) remains open — it needs the OBSERVATION→
  hypothesis bridge and ambient wallet watcher, which is M3 scope.
- Request efficiency (203 for 3 findings) is not yet an M1 target; efficiency
  gates appear at M5 per the roadmap.

## 7. Artifact index (paths relative to this directory)

- `m1-results/M1-SUMMARY.json` — machine-readable exit report
- `m1-results/freightlane/run{1,2}/` — findings.json, blackboard.json,
  dispatch_trace.jsonl, traffic.jsonl, hypothesis_ledger.json, memory/
- `m1-results/dvlba/run{1,2}/` — regression artifacts
- `m0-results/` — refreshed two-lab regression artifacts
- `tests/test_m1_window.py` — the M1 suite

# M2-PROOF.md — surface truth + open vocabulary: the engine reads the live target

M2 (roadmap): *"Surface truth + open vocabulary (G2+G4) — doc differential,
verb probing doc-free, mined candidates, foreign-id readback."* Exit
criteria: **GV-1, GV-2, GV-3, GV-6 found; surface fact lists ≥ 3
undocumented verbs.** Every number below is read from artifacts produced by
`run_m2.py` / `run_m0.py` in this directory (`m2-results/`, `m0-results/`),
not recalled.

## 0. The misses this closes (GAP-PROOF §1, verbatim)

| GAP-PROOF miss | Mechanism (wire-log evidence) | M2 answer |
| --- | --- | --- |
| GV-1 voucher release replay — "missed, band C" | `/api/vouchers` ∉ stale doc → graph has no such resource → `t_hidden_verbs` probes only doc-listed money resources | Open value-noun vocabulary probes the LIVE target (`GET /api/vouchers` → 405 = exists), `POST {}` → 201 object, verb probe finds `release` (200, credited), replay arm proves two more credits on one object |
| GV-6 voucher consume race — "missed, band C" | "race primitive exists (Phase-B-proven) but nothing aims it" | `t_credit_race` finally aims it: 8/8 synchronized wins, **+240000 = 8× face on ONE voucher** (`FW-CREDIT-RACE`). Empirics first: consume's lock-committed guard HOLDS (1 winner ×3 trials, `probe_gv6.py`) — the winnable race on the hidden resource is `release`; consume is recorded honestly as single-use (200→409) and its race refutes |
| GV-2 `recent` global leak + rebook — "missed, band C" | "`t_cross_tenant` probed exactly `['/api/wallet']`; `recent` ∉ `_READBACK_FALLBACK`; rebook verb undocumented" | Subpath probe promotes `GET /api/shipments/recent` into the readback list → `FW-AUDIT-LEAK` (verified); deputy write uses the DISCOVERED `rebook` verb with `{}` body → `FW-DEPUTY-CREDIT` (+399 to the CALLER, `discovered_verb: true`) |
| GV-3 `rate_cents` mass-assign — "missed, band C" | "`t_mass_assign` tried exactly the 5 `PRICE_CANDIDATES`; `rate_cents` ∉ list" | Echo mining: the create 201 response NAMES `rate_cents`; mined candidates run before the wordlist; differential confirms override, NEGATIVE escalation (−50000) CREDITS the wallet — `mined_from_echo: true` |

## 1. What was built (G2+G4 → module)

| Item | Module | Mechanism |
| --- | --- | --- |
| open vocabularies + probes + merge | `engine/surface.py` (spine, no swarm imports) | `VALUE_NOUNS` (14) / `VERB_VOCAB` (20) / `SUBPATH_NOUNS` (8) / `CLAIM_CONSUME` are DATA; `probe_nouns` (404-vs-405 existence oracle), `open_resource` (object / error-contract / **202 ⇒ hands off to the window driver** — labour separation, M1 owns deferred windows), `probe_verbs` (credit detection from response money-keys), `single_use_signature`, `probe_subpaths`, `money_fields` echo mining, `merge` (pure; discovered actions are shape-identical to doc actions + `discovered: True`), `scan_traffic_suspect_docs` (V5: ≥3 lawful create 400/422 ⇒ doc schema suspect) |
| discovery technique + revised surface | `swarm/techniques.py` `t_open_vocab`; `swarm/specialists/exploit.py` publishes `SURFACE_UPDATE` as a first-class SURFACE fact | One observation + one revised surface, grounded (`derived_from` the hypothesis fact); every consumer already reads `surfaces[-1]`, so the cascade is automatic: new gates → new hypotheses → new techniques |
| follow-through arms | `t_value_replay` (I1), `t_credit_race` (I5) + rules `h_value_replay` / `h_credit_race` | Gated on credited verb facts (claim-family excluded via the signature); fresh object + wallet-grounded deltas; verified by the SAME technique re-run with fresh principals (E3, zero new verify code) |
| generalizations in place | `t_mass_assign` (mined-first candidates + NEGATIVE escalation), `t_cross_tenant` (discovered-verb deputy writes, `{}` body) | The GAP-PROOF "nameable mechanism" columns answered inside the existing techniques — no new arms for GV-2/GV-3 |
| ordering invariant | `swarm/specialists/hypothesis.py` `GENERIC_RULES` | `h_open_vocab` FIRST: router consumes pending dispatches priority-first with deterministic-first tie-break, so publication order == dispatch order — discovery runs before every consumer |

Version bumped `0.5.0-m2`. `llm_seam_calls` remains **0** — M2 is
deterministic; the vocabularies are the data seam the M5 LLM will extend.

## 2. Validation — Freightlane M2 exit (`python3 run_m2.py --with-dvlba`)

| Run | Requests | Findings | Markers | Wall |
| --- | --- | --- | --- | --- |
| freightlane run1 (fresh memory) | 385 | **8 (all verified)** | 2 (2 confirmed) | 6.7 s |
| freightlane run2 (run1 memory) | 325 | 8 (all verified) | 2 (2 confirmed) | 6.6 s |
| dvlba regression run1 / run2 | 255 / 181 | 9 / 9 | 0 | 2.5 s |

Run1 findings (every one `verified` by fresh-principal re-execution):

```
FW-MASS-PRICE      h_mass_assign    I4  rate_cents, mined_from_echo, NEGATIVE credit
FW-AUDIT-LEAK      h_cross_tenant   I3  recent → foreign shipment id
FW-DEPUTY-CREDIT   h_cross_tenant   I3  rebook {} on leaked object, +399 to caller
FW-ROUND-DRIFT     h_arith_cycle    I4  (v1 baseline arm intact)
FW-SETTLED-CANCEL  h_window_driver  I1  (M1 arm intact)
FW-TOCTOU-SETTLE   h_window_driver  I4  (M1 arm intact)
FW-RELEASE-REPLAY  h_value_replay   I1  credits [30000, 30000] on VCH-a9f6517086
FW-CREDIT-RACE     h_credit_race    I5  8/8 winners, +240000 (8x face) on ONE voucher
```

Exit criteria:

- **[PASS] E1** GV-1 autonomous + verified — release replay, I1
- **[PASS] E2** GV-2 autonomous + verified — recent leak (I3) + rebook
  deputy credit (I3, +399, `obtained_via: /api/shipments/recent`)
- **[PASS] E3** GV-3 autonomous + verified — `rate_cents` mined from the
  echo (`mined_from_echo: true`), NEGATIVE probe credited the wallet
- **[PASS] E4** GV-6 autonomous + verified — race k = 8, delta = 8× face
- **[PASS] E5** 4 undocumented verbs in the revised SURFACE fact (≥ 3),
  all grounded — `shipments/rebook`, `shipments/settle`,
  `vouchers/release`, `vouchers/consume`; plus undocumented resources
  `payouts`, `vouchers`; readback added `/api/shipments/recent`
- **[PASS] E6** zero decoy false positives (D-1 clean; D-2 untriggered —
  documented fields are never mass-assign candidates)
- **[PASS] E7** deterministic: `llm_seam_calls = 0`
- **[PASS] E8** dvlba B1..B8 all hit, 0 FP, 9 findings = M1 baseline
  byte-count; discovery on a truthful-doc target cost +41 requests

Discovery cost: **66 requests** (14 nouns + 3 resource-opens + 42 verb
probes + 8 subpaths − overlap), inside the ≤70 pre-registration.

## 3. The grounding chain (run1)

```
SF-HYPOTHESIS-0006  h_open_vocab (published FIRST by construction)
  └─ SURFACE-update fact (revised surface, grounded)
       ├─ undocumented verbs [rebook, settle, release, consume]  (E5 evidence)
       ├─ single_use [consume: 200 -> 409]   -> h_credit_race EXCLUDES it
       ├─ verb_facts credited [release, settle, consume]
       │    ├─ h_value_replay -> FW-RELEASE-REPLAY (verified)  => GV-1
       │    ├─ h_credit_race  -> FW-CREDIT-RACE   (verified)  => GV-6
       │    └─ settle: replay 409 / race 1 winner -> honestly refuted
       ├─ readback +/api/shipments/recent -> h_cross_tenant
       │    -> FW-AUDIT-LEAK + FW-DEPUTY-CREDIT (verified)     => GV-2
       └─ mined_fields shipments[rate_cents] -> h_mass_assign
            -> FW-MASS-PRICE (verified, NEGATIVE)               => GV-3
```

Ledger (run1): 9 confirmed · 2 refuted · 2 inconclusive, score 11.0 — the
refutations (consume's guarded race, settle's guarded replay) are recorded
as information, the band-D lesson inverted: every discovery got a consumer.

## 4. Regression — one tree, three labs

| Lab | Requests | Findings | Exit |
| --- | --- | --- | --- |
| meridian-vault run1 / run2 (`run_m0.py`) | 425 / 360 | 8 / 8 verified (16 total) | S1–S7 all hit, 0 FP — exact M0/M1 baseline |
| dvlba-shop run1 / run2 (`run_m0.py`) | 255 / 181 | 9 / 9 | B1–B8 all hit, 0 FP |
| dvlba-shop (`run_m2.py --with-dvlba`) | 255 / 181 | 9 / 9 | B1–B8, 0 FP |

Meridian note (P-D1): noun probes there discover its documented payouts as
a 202 seam — recorded as a resource fact, handed to the window driver,
never verb-probed; verified-finding count unchanged (16).

## 5. Test suite

`pytest tests/` → **41 passed** (13 Phase-C + 10 M0 + 8 M1 + 10 M2). The
M2 suite covers: template normalisation (literals preserved), echo field
mining (declared fields excluded — D-2 stays a decoy), id extraction, the
404/405 existence oracle, resource opening kinds (object / error-contract /
async handoff / absent), verb credit detection, merge shape-uniformity +
purity + idempotence, suspect-doc scanning, and the live freightlane E2E —
the M2 exit in miniature (all four GV classes verified, ≥3 undocumented
verbs grounded, readback added, M1 markers ≥ 2, decoys clean).

## 6. Honest deltas

- **Consume is NOT racy — scored GV-6 on the winnable shape, disclosed.**
  The lab docstring says "single-use check-then-act with a widened window";
  the lock-committed `first` flag makes it hold (probe_gv6.py: 1 winner ×3
  trials, same shape as decoy D-1's claim). The winnable INTERRUPT on the
  hidden voucher resource is `release` — GV-1's unmarked credit multiplied
  8× by the race primitive (+240000 on face 30000). The GT key scores race
  findings on `/api/vouchers` with k ≥ 2 and delta ≥ 2× face; the consume
  signature and its refuted race are recorded in the ledger either way.
  This amendment was made BEFORE implementation (RESEARCH-M2 §2.5).
- **M1-miniature budget bump 300 → 400** (`tests/test_m1_window.py`): the
  engine legitimately does more work per run now (discovery + follow-through
  + their verification); at 300 the verify phase starves. Exit-tier budgets
  raised to match (620 freightlane / 460 dvlba in `run_m2.py`).
- Request efficiency is still not an M2 target: run2 re-runs discovery
  (no cross-run surface persistence yet); its 60-request saving came from
  other arms' memory. Efficiency gates stay at M5.
- GV-8 remains open by design: `settle` is recorded as an undocumented verb
  fact and nothing follows through — the OBSERVATION→hypothesis bridge and
  ambient wallet watcher are M3 scope (P-R1 held).
- `doc_suspect` (V5) had no effect on these labs (their documented creates
  all work); it is tested at unit level and aimed at the GAP-PROOF dialect
  incident, not yet proven against a lying-schema target.

## 7. Artifact index (paths relative to this directory)

- `m2-results/M2-SUMMARY.json` — machine-readable exit report
- `m2-results/freightlane/run{1,2}/` — findings.json, blackboard.json,
  dispatch_trace.jsonl, traffic.jsonl, hypothesis_ledger.json, memory/
- `m2-results/dvlba/run{1,2}/` — regression artifacts
- `m0-results/` — refreshed two-lab regression artifacts
- `probe_gv6.py` — the pre-code empirics (consume vs release races)
- `RESEARCH-M2.md` — research-first doc incl. the §2.5 amendment
- `tests/test_m2_surface.py` — the M2 suite

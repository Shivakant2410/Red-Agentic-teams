# M5-PROOF.md — the offensive core, proven on the labs

Run: 2026-11-07, `run_m5.py` (budget 900 freightlane / 540 dvlba), real HTTP
on loopback, one tree. Companion research: `RESEARCH-M5.md` — written BEFORE
any M5 code per the standing mandate, and re-scoped on the user's call: the
M4 guard direction (policy gates, CaMeL/MAST boundary papers) is ARCHIVED as
plumbing; this milestone spends its entire budget on attack skill — recon,
attack surface mapping, pre-exploitation, post-exploitation. Exit evidence:
`m5-results/M5-SUMMARY.json` (machine-readable, `pass: true`).

## 1. Pre-registered predictions — 5/5 HIT

| # | Prediction (RESEARCH-M5 §5) | Result | Evidence |
|---|---|---|---|
| P1 | authz-matrix OBSERVATION raises an evidence-derived `h_cross_tenant` (derived_from the matrix fact); exploit dispatched on it; cross-tenant class verifies | **HIT** | matrix fact `SF-PREEX-0016` (bola_hits=2) → hypothesis `SF-PREEX-0018`, prior **0.85**, origin=preex → dispatch_trace row: exploit consumed it → GV-2 verified run1 |
| P2 | recon discovers ≥1 endpoint outside PROBE_PATHS and the served disclosure, tagged with origin | **HIT** | derived-content-discovery found `/api/shipments/{shipment_id}/settle` and `/rebook` — **405 error-differential** (route exists, method-walled), probes on wire in phase=recon |
| P3 | pre-ex ≤ 70 requests; total ≤ 1.35× M4 baseline (≤ 832 @ 900) | **HIT** | preex **24** requests; run1 total **693** (M4: 616 → +12.5% for a new capability layer) |
| P4 | ≥1 post-ex amplification ESCALATION with measured aggregate delta across ≥2 victims on a VERIFIED finding | **HIT** | `px_amplify`: 3 victims reached, **aggregate +150,000 cents** (negative-probe variant of FW-MASS-PRICE, +50,000/victim, every delta measured by wallet read-back) |
| P5 | non-regression: GV-1..8 both paths, 0 decoy FPs, dvlba B1..B8 zero unmatched, llm_seam_calls==0, markers≥2, schema identity | **HIT** | GV-1..8 verified run1 (registry) + run2 (orchestrator); FPs 0/0; dvlba B1..B8, unmatched 0; deterministic path 0 LLM calls; markers 2; `Orchestrator.schema() == registry._schema()` |

Memory efficiency preview (M5's own AWM claim): dvlba run2 **209** vs run1
**315** requests (−34%) with identical seed coverage B1..B8.

## 2. What the offensive core adds (technique → live result)

| Layer | Technique (lineage) | Live result on freightlane |
|---|---|---|
| recon | derived content discovery, error-differential (Intigriti tradecraft) | hidden verbs `settle`, `rebook` found unauthenticated via 405-vs-404, ≤16 probes |
| recon | asset-string mining (LinkFinder-style), target-derived param pool | param pool harvested from wire vocabulary; `rate_cents` reaches the pre-ex candidate set |
| pre-ex | per-principal object map (BOLABuster step 1) | `{shipments: {A: [SHP-…], B: [SHP-…]}}` in 6 requests |
| pre-ex | authz matrix with denials recorded (BOLABuster step 2, OWASP API #1) | **2 bola-evidence** rows: cross-principal object read, owner-matched body — GV-8's root class surfaced as EVIDENCE before exploitation |
| pre-ex | hidden-parameter differential (Arjun, target-derived candidates) | honest failure on freightlane's rerate (no differential) — recorded, weights updated |
| post-ex | amplification replay on fresh victims (XBOW variant analysis + BloodHound reachability) | 3/3 victims, +150,000 cents aggregate, variant tagged `negative-probe` |
| post-ex | persistence replay (PentestGPT post-ex phase) | **repeatable double-credit proven**: +50,000 per replay, same-sign deltas |
| post-ex | capability footprint of a foothold session | `accessible: [/api/wallet, /api/shipments/recent]` vs denied — the "what else can this token do" map |

The full evidence loop is closed: recon discovers → surface maps → pre-ex
measures and raises evidence-carrying hypotheses (prior 0.85, `derived_from`
the matrix fact) → exploit consumes them → verify confirms → post-ex
measures blast radius. Every stage's output is the next stage's consumable
input — the Sarraute POMDP mixing claim, now measured.

## 3. Latent bugs the M5 exit caught and fixed

1. **`Env.wallet` cache poisoning** (pre-existing since M3): a failed anon
   balance discovery wrote `balance_path=None` into the cache and the
   `"balance_path" not in cache` guard never retried — every authenticated
   principal after an anon probe got `None`. Discovery failure is now cached
   **per principal**; the next authenticated principal retries.
2. **Amplify's anon-wallet guard**: the early bail probed the wallet as
   `anon` (always 401 on an authed target) and killed amplification before
   any victim was created. Now probes with a registered principal.
3. **Authz-matrix key mismatch**: the matrix read `env.notes["object_map"]`
   while the ladder stores payloads under technique names
   (`px_object_map`) — the matrix starved silently. Fixed.
4. **Recon bandit ordering**: on a fresh bandit, `technique_order` sorted
   alphabetically, so derived techniques ran BEFORE the disclosure ladder
   published the doc they derive from. Fixed with group-aware ordering
   (disclosure → derived → generic; the bandit still orders within groups).
5. **ESCALATION projection rigidity**: the assembler assumed every
   ESCALATION carries a `chain`; post-ex escalations (amplification/
   persistence/footprint) now project under `postex_escalations`.

## 4. What M5 does NOT claim

- The pre-ex matrix finding (cross-principal shipment read) is
  **evidence + raised hypothesis**, not a new GV: freightlane's ground
  truth has 8 planted classes and the run ships exactly those, 0 decoy
  FPs. The BOLA read is the mechanism BEHIND GV-2, surfaced earlier.
- `px_param_probe` honestly failed on freightlane (rerate ignores unknown
  fields — no differential). The failure is recorded in the bandit; the
  technique's value is conditional, like every other arm.
- Request efficiency claims beyond the dvlba −34% preview belong to the
  memory-evolution milestone; M5's gates are coverage and honesty.

## 5. Artifacts (under `m5-results/`)

- `run1/`, `run2/` — freightlane registry / orchestrator paths:
  findings.json (10 findings each, GV-1..8), blackboard.json (preex
  OBSERVATIONs + evidence-raised HYPOTHESES + postex ESCALATIONs),
  dispatch_trace.jsonl, traffic.jsonl, attack_surface.json,
  hypothesis_ledger.json, memory/
- `dvlba/run1|run2/` — B1..B8 regression through the same path
- `M5-SUMMARY.json` — machine-readable prediction scorecard (pass: true)
- Unit suite: **81 passed** (64 pre-existing + 17 new in
  `tests/test_m5_offensive.py` — fake-env technique tests, op recovery,
  candidate derivation, negative-variant replay, per-principal wallet cache)

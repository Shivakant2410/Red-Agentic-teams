# RESEARCH-M2.md — surface truth + open vocabulary (G2+G4)

**Pre-build research, written before a single line of M2 code** (same
discipline as the master RESEARCH.md: no code before the mechanism is named
and the exit is measurable). Every claim about the current engine is read
from the tree at commit `9d7cb60` (M1), not recalled.

## 1. Why M2 exists — the root-cause chain, file and line

GAP-PROOF §1 put four covert classes in band C ("wholly invisible"). The
code read names the single shared cause: **the engine's attack vocabulary is
closed at three layers, and every layer is keyed to the stale document.**

| # | Closed vocabulary | File:line evidence | Covert class it blinds us to |
|---|---|---|---|
| V1 | **Resource nouns**: the only live resource-discovery probe is `ASYNC_SEAM_NOUNS` — 6 nouns (payouts, withdrawals, settlements, refunds, transfers, disbursements) | `swarm/techniques.py:39` | GV-1/GV-6: `/api/vouchers` ∉ list → resource never probed → graph has no such resource |
| V2 | **Verbs**: `VERB_WORDLIST` — 10 verbs (release, settle, capture, approve, confirm, complete, retry, restore, refund, revoke), probed ONLY on doc-listed money resources (`g.get("param") and g.get("create")` from the doc graph) | `swarm/techniques.py:31,724-759` | GV-2: `rebook` ∉ list; GV-6: `consume` ∉ list — even with vouchers in hand the writes are unreachable |
| V3 | **Read-back candidates**: `surface["readback"]` built from `_READBACK_FALLBACK` keywords over DOC paths + doc GETs; on Freightlane it is literally `['/api/wallet']` (traffic log) | `swarm/specialists/surface_mapper.py:14,57`; GAP-PROOF GV-2 row | GV-2 read half: `GET /api/shipments/recent` is undocumented → never a readback candidate → the global leak is unobservable |
| V4 | **Mass-assign fields**: `PRICE_CANDIDATES` — 5 hardcoded names (unit_price_cents, unit_cents, price_cents, amount_cents, discount_pct) | `swarm/techniques.py:33,578` | GV-3: `rate_cents` ∉ list — and `rate_cents` is **in the create 201 response body** (`target/app.py:119`), i.e. the target names its own price field for free and the engine never looks |
| V5 | **Doc = truth**: `_resource_graph()` parses openapi.json and nothing ever compares it with live behaviour; the GAP-PROOF execution incident (non-canonical dialect → `create_schema: {}` → four techniques starve silently) is the recorded failure mode | `swarm/specialists/surface_mapper.py:63-108`; GAP-PROOF §2 incident | Band C generally: whatever the stale doc omits does not exist for the engine |

M1 removed the *deferred-effect* blindness (202/event shapes now generate
markers). M2 removes the *surface* blindness: the same grounded-only
discipline, applied to resources, verbs, read-backs and fields.

**What M2 is NOT**: it is not a crawler and not a bruteforcer. Every probe
is (a) budget-capped, (b) existence-oracled (404 vs 405/4xx — Flask answers
405 for a POST-only route hit with GET, which is a *free resource-existence
oracle*), and (c) recorded as a surface FACT with evidence — a fact the rest
of the swarm reasons over, never a conclusion. Discovery without follow-through
is band D (GV-8's lesson), so every discovery fact must have a named consumer
before we spend the request.

## 2. Mechanism — one spine module, three hypothesis arms

### 2.1 `engine/surface.py` (spine layer — no swarm imports, M0 layering)

Open, extensible vocabularies (data, not logic — the growth path M5's LLM
seam will exploit is "extend the vocab", not "add code"):

- `VALUE_NOUNS` — 14 value-resource nouns (vouchers, coupons, credits,
  payouts, refunds, rewards, points, invoices, receipts, claims, wallets,
  cashback, promos, gift-cards). Superset discipline: `ASYNC_SEAM_NOUNS ⊂`
  the seam nouns stay where they are; M2's probe adds the value nouns.
- `VERB_VOCAB` — 20 write verbs: the M1 wordlist ∪ cancel-family ∪
  claim-family ∪ {rebook, void, fulfill}. Bounded on purpose: each verb
  costs 1 request per probed object.
- `SUBPATH_NOUNS` — 8 collection subpaths (recent, history, events, audit,
  all, list, search, stats). This is `_READBACK_FALLBACK`'s keyword list
  turned from a passive matcher into a live probe.

Primitives (all take the shared executor → budget, STOP file, traffic
provenance apply automatically):

- `probe_nouns(p)` — `GET /api/{noun}` ×14; status != 404 ⇒ resource fact.
- `open_resource(p, path)` — `POST {}` once; 201/200 ⇒ object + echo fields;
  400/422 ⇒ U3 error-contract learning (`field_from_error`); **202 ⇒ hands
  off** — an async seam belongs to the window driver (M1), not to verb
  probing (labour separation, no double-spending the same window).
- `probe_verbs(p, res, oid, known)` — `POST /api/{res}/{oid}/{verb}` ×≤20;
  non-404/405 ⇒ verb fact `{verb, status, credited}` where `credited` reads
  money-ish keys in the response (credited_cents / refund / bonus).
- `single_use_signature(p, res, oid, verb)` — for claim-family verbs only:
  a second identical probe; 200-then-409 ⇒ single-use check-then-act
  signature, recorded as a fact (the race target GV-6 needs).
- `probe_subpaths(p, collections)` — `GET /api/{res}/{sub}` ×≤8 per
  collection, ≤3 collections; 2xx ⇒ readback fact (appended to
  `surface["readback"]` so the EXISTING cross-tenant flow consumes it).
- `mine_fields(resp_body, schema)` — echo mining: money-shaped field names
  in the resource's own 2xx responses that the create schema does not
  declare ⇒ mass-assign candidates, evidence-backed, zero extra requests.
- `merge(surface, discoveries)` — pure function producing the revised
  surface: discovered actions appended to `resource_actions` (shape-identical
  to doc actions, `discovered: True`), readback entries appended,
  `mined_fields` / `discoveries` / `undocumented_verbs` /
  `undocumented_resources` recorded. **The revision is published as a new
  SURFACE fact**; every consumer already reads `surfaces[-1]`
  (`exploit._env`, window driver, verify), so the cascade is free.

### 2.2 Three hypothesis arms (the named consumers)

| New generic rule | Gate (on the surface, grounded) | Technique | Closes |
|---|---|---|---|
| `h_open_vocab` | surface has any resource graph (always true post-map) | `t_open_vocab`: nouns → open → verbs → signature → subpaths → merge → publish ONE observation + SURFACE_UPDATE | V1–V5; produces the **≥3 undocumented verbs** exit evidence |
| `h_value_replay` | a verb fact with `credited=True`, claim-family excluded (they have their own arm) | `t_value_replay`: replay the credited verb ×2 on a FRESH object of the same resource with wallet reads; two more credits on one object ⇒ I1 | **GV-1** (release replay) |
| `h_credit_race` | a credited verb fact NOT marked single-use | `t_credit_race`: FRESH object, last-byte race ×8, k ≥ 2 wins ⇒ I5 | **GV-6** (race primitive finally aimed at the hidden voucher resource) |

Two existing techniques generalize (the GAP-PROOF "nameable mechanism"
columns, answered in place):

- `t_cross_tenant`: write candidates = doc writes ∪ **discovered verb
  actions** (schema-unknown → `{}` body). With `recent` in readback the leak
  half fires unchanged; with `rebook` discovered the deputy write credits the
  caller ⇒ **GV-2** (both halves, existing finding ids FW-AUDIT-LEAK +
  FW-DEPUTY-CREDIT).
- `t_mass_assign`: candidates = **echo-mined fields first**, then the legacy
  5 (never regress); on an override hit, one NEGATIVE escalation probe
  (candidate = −50000) — wallet credit ⇒ evidence upgraded, operators
  +NEGATIVE ⇒ **GV-3**.

Ordering note (verified in code): the router consumes pending dispatches
priority-first, ties by insertion order; HYPOTHESIS facts are published in
`GENERIC_RULES` order and the tie-break is deterministic-first
(`swarm/llm.py:41-47`). Putting `h_open_vocab` FIRST in `GENERIC_RULES`
therefore guarantees discovery runs before the consumers — no accidental
ordering dependence.

## 2.5 Empirical amendment (probe BEFORE code — probe_gv6.py, run before
any M2 technique was written)

The consume endpoint's docstring says "single-use check-then-act with a
widened window". Source reading said the commit is lock-protected
(`first = not consumed` inside LOCK). The lab answered decisively
(last-byte-synced race ×8, 3 trials):

```
consume race trial 0/1/2: wins=[200] delta=30000   → NOT winnable (1 winner)
release #1/#2/#3: 200, +30000 each                 → repeatable (GV-1)
release race:      wins=8 (of 8) delta=240000      → 8× face on ONE voucher
```

Three honest consequences, folded back into the design before implementation:

1. **GV-6 is scored on the winnable shape.** Consume's guard HOLDS under
   race (exactly like decoy D-1's per-account claim — the lab's own
   "properly locked" contrast). What the race primitive unlocks on the
   hidden voucher resource is `release`: GV-1's unmarked credit multiplied
   8× by INTERRUPT (+240000 on face 30000). GT key: race finding on
   /api/vouchers with k ≥ 2 wins and delta ≥ 2×face. The engine still
   RECORDS the consume signature and races it honestly — the ledger
   resolves that attempt as refuted, which is information, not failure.
2. `single_use_signature` (200-then-409 double probe) stays, but only for
   claim-family verbs — its role is classification (exclude the verb from
   race/replay arms), not accusation.
3. P-A2 corrected pre-code: the merged surface opens `h_value_replay` +
   `h_credit_race` (and grounds `h_cross_tenant`'s read half). It does NOT
   open `h_terminal_credit`/`h_state_guard` — payouts is a 202 seam and
   verb-probing hands off to the window driver (labour separation), so no
   discovered cancel verb lands in the doc graph. The driver remains GV-5's
   finder, exactly as in M1.


### 2.4 Honest costs and failure modes (pre-registered)

- Discovery spend on Freightlane ≈ 14 nouns + 2 create-probes + ~35 verb
  probes + 8 subpaths ≈ **60 requests** before any new finding. Pre-registered:
  run1 total ≤ 330 requests (M1 baseline 203 + ~60 discovery + ~40
  follow-through − overlap). Efficiency is NOT an M2 target (roadmap puts
  request-efficiency gates at M5); run2 memory may or may not reuse
  discovery — predicted to re-run it (no cross-run surface persistence yet).
- Verb probing on a 202-async resource is forbidden (window-driver labour
  separation) — `payouts` gets noun-discovered but never verb-probed.
- Probe side effects are lawful own-account operations (create voucher,
  release once). The release probe credits the prober face value — the race
  and replay techniques then prove the *violation* on fresh objects with
  wallet-grounded deltas, and verification re-runs the SAME technique with
  fresh principals (E3, existing machinery, zero new verify code).
- Doc-trust degradation (V5) is scoped minimal in M2: `merge` records
  `doc_suspect` when traffic shows ≥3 lawful create attempts 400/422 on a
  doc-listed create; `Env.create` then prefers the error contract. Full
  doc-vs-live differential storage stays M5+ (needs the ExperienceStore).

## 3. Exit criteria (ROADMAP M2) → machine checks in `run_m2.py`

| # | Criterion | Check |
|---|---|---|
| E1 | **GV-1** voucher release replay autonomous | FW-RELEASE-REPLAY (I1), status verified (fresh-principal re-execution) |
| E2 | **GV-2** `recent` global leak + rebook deputy credit | FW-AUDIT-LEAK (I3, recent) or FW-DEPUTY-CREDIT (I3, shipment/rebook), verified — deputy credit required |
| E3 | **GV-3** `rate_cents` mass-assign | FW-MASS-PRICE with `rate_cents` in evidence, verified, NEGATIVE escalation present |
| E4 | **GV-6** voucher consume race | FW-CONSUME-RACE (I5), verified, ≥2 race wins, wallet delta ≥ 2×face |
| E5 | surface fact lists ≥ 3 undocumented verbs | run1 revised-SURFACE fact `undocumented_verbs` length ≥ 3, each with probe evidence |
| E6 | zero decoy false positives | D-1 (FW-QUOTA-RACE verified = FP) count 0; D-2 untriggered |
| E7 | deterministic | `llm_seam_calls == 0` |
| E8 | regressions from ONE tree | dvlba B1..B8 (this harness) + meridian/dvlba two-lab (`run_m0.py`) all green |

GT keys (lab-harness code, mirrors run_m1.py's convention of keying on the
lab's own docstrings): GV-1 `FW-RELEASE-REPLAY` or (voucher∧release);
GV-2 `rebook`∨(deputy∧shipment)∨(audit-leak∧recent); GV-3 mass-price∧
rate_cents; GV-6 `FW-CONSUME-RACE` or (consume∧race).

## 4. Pre-registered predictions (scorecard to be filled in M2-PROOF.md)

| ID | Prediction |
|---|---|
| P-A1 | t_open_vocab discovers ≥ 4 undocumented verbs on Freightlane (settle, rebook, release, consume — from the target's route table), within ≤ 70 discovery requests |
| P-A2 | ≥ 2 previously-starved hypothesis gates open as a DIRECT consequence of the merged surface (predicted: h_terminal_credit, h_state_guard — via discovered cancel on the seam resource's action graph) |
| P-B1 | E1–E4 all pass on run1 (fresh memory) — the four band-C covert classes fall in one run |
| P-B2 | run2 (memory) re-runs discovery (no cross-run surface persistence) and finds the same GV set with ≤ 10% fewer requests — honest no-claim on efficiency |
| P-C1 | Zero decoy FPs: noun probes hit no decoy route; t_quota_race behaviour unchanged |
| P-C2 | dvlba regression: findings set unchanged (B1..B8), request delta ≤ +80 from discovery probes that find nothing undocumented (dvlba's doc is truthful) |
| P-D1 | Meridian: noun probes discover no undocumented value resources beyond its documented payouts; window-driver marker count unchanged (≤ +1, the same seam re-marked by probe evidence) — any excess is reported as an honest delta |
| P-R1 | Risk: verb probes on shipments hit `settle` (GV-8's verb) — M2 records the FACT and does not follow through; GV-8 remains M3 scope (OBSERVATION→hypothesis bridge + ambient wallet watcher) |

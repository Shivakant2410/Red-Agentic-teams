# ROADMAP.md — research-driven, gap-proof-backed plan for Red-Agentic-teams tooling

Two axes, one discipline: **first research, then code** — every item cites a
verified source (Phase A dossier verdicts, Phase C `RESEARCH.md`
adjudications, or the Freightlane live run in `hard-lab/GAP-PROOF.md`, which
is the *experimental* proof this roadmap is built on). No generic advice.

Evidence tags: `[GP-n]` = GAP-PROOF §, `[V-n]` = hard-lab RESEARCH.md §0
verified priors, `[C-RESEARCH]` = Phase C RESEARCH.md adjudication,
`[A-DOSSIER]` = Phase A research dossier verdict.

---

## Axis 1 — What the tools still need (capability gaps, priority-ordered)

### G1. HypothesisLedger: from passive sink to hypothesis engine (highest leverage)
- **Live proof (cross-lab, both hard labs)**: v1 statefuzz registered **0 markers** and found **0** covert bugs on both labs (Freightlane 73 req, meridian 64 req); the same ledger hand-fed flagged GV-5 (expected −30000, observed 0) and GV-4's negative settle in 34 requests. Decisive: the Phase-D re-run on the original **meridian-vault** lab — v1-style standalone statefuzz **0 findings** vs the **ledger-spine swarm 8/8 verified findings** (301 req, reproduced run1+run2). The spine is already prototyped at `hard-lab/engine/ledger.py`; it is not yet in the mainline `statefuzz-prototype/` / `swarm-specialists/` trees. `[GP-1, GP-3.5]` `[V5]`
- **Work**: (a) hypothesis *generation* from surface + observations ("async
  seam exists → hypothesize settle-time re-check missing; register marker on
  every 202-with-event-path response"); (b) a *driver loop* that interleaves
  window actions (spend/drain/cancel) between marker registration and drain;
  (c) ledger-backed mutant selection (prefer operators that create deferred
  effects).
- **Acceptance**: autonomous Freightlane run finds GV-4 **and** GV-5 with
  `markers_registered ≥ 2`; no marker is registered without a surface or
  observation fact as `derived_from` (grounded-only, `[C-RESEARCH]` E6).

### G2. Surface truth beyond the document (the stale-doc class)
- **Live proof**: recon's earned insight was *"trust disclosure over probing"*
  — anti-productive on a lying target; the doc was never re-tested against
  live behavior; all four doc-absent resources (vouchers, payouts, recent,
  rebook/settle/release/consume verbs) went unseen. `[GP-1, GP-2, GP-3.3]`
- **Work**: (a) doc-vs-live differential probe (for each documented path:
  does it exist, does the schema match the live body?); (b) doc-independent
  verb/param wordlists applied to *every* param resource found live (the
  `settle` verb cost 1 request to find — `[GP-3.2]`); (c) list/readback
  endpoints enumerated as first-class facts (bodies contain foreign ids).
- **Acceptance**: on Freightlane, surface fact contains `/api/vouchers`,
  `/api/payouts`, `/api/shipments/recent` and ≥ 3 undocumented verbs; recon
  insight updated with a falsification clause.

### G3. Follow-through: observation → finding (Band D leak)
- **Live proof**: GV-8's `settle` was observed (200) and dropped; the payout
  credit landed in the wallet during probing and no oracle noticed.
  `[GP-3.2]`
- **Work**: (a) ambient wallet/oracle watcher — every response is followed by
  a money read-back when a balance path is known (I4 ambient); (b) every
  OBSERVATION of a new write verb spawns a hypothesis ("what guard does this
  verb skip?"); (c) the FSM specialist accepts *live-induced* transition
  tables, not only dvlba's scripted walk (`[V3]`).
- **Acceptance**: autonomous run escalates the settle observation to a
  finding (GV-8) with wallet-delta evidence.

### G4. Open-vocabulary candidate generation (closed-wordlist class)
- **Live proof**: mass-assign tried exactly 5 fixed field names, `rate_cents`
  excluded; cross-tenant readback probed exactly `['/api/wallet']`,
  `"recent"` excluded. `[GP-1, GP-3.3]`
- **Work**: (a) price-field candidates mined from live response diffs (which
  int fields move when inputs change), not name lists; (b) readback
  candidates = all GETs whose bodies contain ids not owned by the caller;
  (c) quota/dedupe semantics inferred from 409 bodies *and* their absence
  (no `quota` field ⇒ per-account semantics, not global).
- **Acceptance**: GV-3 found by differential field search within 25 requests;
  GV-2 found via foreign-id enumeration within 30.

### G5. Orchestrator seams (# Seam: → real platform) `[V3]` `[C-RESEARCH]`
- `LocalScopeGuard` → platform ScopeGuard; findings → verify pipeline;
  per-specialist memory → ExperienceStore; approval gate on write mutants.
- **Acceptance**: same `schema()` + `run(ctx)` contract served by both; a
  STOP file halts mid-race (already proven in Phase B).

### G6. LLM seam activation (E6, grounded-only) `[C-RESEARCH]` `[A-DOSSIER]`
- **Live proof**: `llm_seam_calls` exists in the summary; both runs produced
  0 seam calls (deterministic rules only). The Freightlane miss set
  (order-sensitive multi-step chains) is exactly where priors-carrying LLM
  hypotheses are permitted to help — never conclusions. `[GP-1]`
- **Work**: plug the backend; every LLM hypothesis enters the blackboard with
  a prior and MUST be exploited+verified like any other (Huang-consistent).
- **Acceptance**: on Freightlane, ≥ 2 LLM-origin hypotheses reach exploit;
  none ships unverified.

### G7. Memory falsification + cross-domain transfer `[GP-3.3]` `[C-RESEARCH]` E1/E4/E5
- recon's wrong insight persisted unchallenged. Work: insights carry
  falsification probes ("next run: if doc claims X, sample-test X once");
  GEPA-style prompt/strategy evolution layered on namespace outcomes;
  dvlba→freightlane transfer experiment (with poisoning guard 0.5 intact).
- **Acceptance**: second Freightlane run with memory does not re-burn D-1;
  transfer run improves coverage vs fresh without target-controlled
  promotion.

### G8. Regression harness: hard lab as CI
- Freightlane joins dvlba-shop as a permanent target: `run_v1.py`-style
  harness, per-commit run, coverage tracked against the 8-covert ground
  truth (RESEARCH.md §3). Exit criteria per milestone below are measured
  here.

---

## Axis 2 — What must be generalized (measured pin-debt → target)

**Already generic (keep, no work)**: Executor + last-byte race primitive +
STOP/budget/traffic `[V1]`; I1–I5 invariants; HypothesisLedger; chain
builder; blackboard/router/bandit/memory namespaces; per-specialist curation
+ poisoning guard; `schema()`+`run(ctx)` registry contract; fail-closed scope
guard; verify-specialist independence (proven: FW-ROUND-DRIFT re-verified
fresh `[GP-1]`).

**Pinned — generalize, in this order** (each with acceptance test):

| # | Pinned asset | Evidence | Generalization target | Acceptance |
|---|---|---|---|---|
| 1 | statefuzz `model.py` (100%: openapi fetch, register/login, cart/wallet observers, scripted lawful walk) | `[V3]` | live-induced FSM: walk *derived* from the surface graph (create→param→verbs), observers discovered via readback probes | lawful walk completes on Freightlane AND dvlba-shop unchanged |
| 2 | statefuzz 8 probes in `registry_tool.run()` | 8/8 pinned `[V3]`; 0/8 on Freightlane `[GP-0]` | each probe becomes an operator × surface-shape composition driven by hypotheses (G1) | ≥ 5/8 Freightlane covert autonomously; dvlba still 8/8 |
| 3 | swarm `exploit.py`/`verify.py` dvlba test bodies (32+32 strings) | `[V3]` | move to technique-library runners (the v0.2 `techniques.py` pattern) keyed on graph shapes | exploit/verify contain no target-path literals |
| 4 | closed vocabularies (PRICE_CANDIDATES, VERB_WORDLIST, _READBACK_FALLBACK, CLAIM/CANCEL/TRANSFER sets) | `[GP-3.3]` | G4's mined-from-live candidates | Freightlane GV-2/GV-3 found |
| 5 | OpenAPI dialect sensitivity (silent starvation) | execution incident `[GP-2]` | canonical parser + doc-vs-live validation with loud degradation | non-canonical doc ⇒ explicit SURFACE warning fact, not empty creates |
| 6 | artifact assumption (`promo_code` default, quota-disclosure heuristic) | `[V4]` | artifacts schema in ctx + semantics test (global vs per-account) | D-1 classified per-account within 10 requests |

---

## Milestone ordering (each exits on the hard-lab harness)

| Milestone | Scope | Exit criteria (measured on the labs) | Depends on |
|---|---|---|---|
| **M0** (new) Promote the proven spine | Port `hard-lab/engine/ledger.py` (Phase-D, just re-validated: 8/8 on meridian) into the mainline trees behind the existing `# Seam:` marks; keep the deterministic v1 path as fallback | both labs green from ONE tree; meridian ≥ 8, dvlba still 8/8 | — |
| **M1** Ledger-as-engine + window driver (G1) | markers auto-registered from 202/event shapes; window interleaving — extend the promoted spine to *generate* hypotheses, not only resolve them | Freightlane GV-4 + GV-5 autonomous; `markers ≥ 2` | M0 |
| **M2** Surface truth + open vocabulary (G2+G4) | doc differential, verb probing doc-free, mined candidates, foreign-id readback | GV-1, GV-2, GV-3, GV-6 found; surface fact lists ≥ 3 undocumented verbs | M1 helps but not required |
| **M3** Follow-through + ambient oracles (G3) | wallet watcher, OBSERVATION→hypothesis bridge, live-induced FSM | GV-8 found; statefuzz probes replaced by compositions; dvlba still 8/8 | M2 |
| **M4** Orchestrator seams (G5) | ScopeGuard/verify-pipeline/ExperienceStore swap | same contract, both labs green | — |
| **M5** LLM seam + GEPA evolution (G6+G7) | priors-carrying hypotheses, strategy evolution over namespaces | ≥ 2 LLM hypotheses exploited+verified; run-2 memory improves request efficiency ≥ 20% | M1–M3 |
| **M6** Lab #3 + transfer study (G7+G8) | third domain (payments? IoT?) with new covert classes; dvlba→freightlane memory transfer | coverage transfer > fresh-memory baseline; no FP increase | M5 |

**Rationale for the order**: M0 first because the Phase-D re-run just proved the spine is the differentiator on hard labs (0 → 8 findings); M1 converts it from resolver to generator (P-C2); M2/M3 convert the four Band-C misses and one Band-D leak into capability; M4 is mechanical; M5 only pays once deterministic hypothesis supply exists to measure the LLM seam against (`[A-DOSSIER]`: LLM output is a hypothesis with a prior, never a conclusion).

## Honest bounds of this roadmap

- Freightlane is one lab; acceptance numbers may shift on domain #3 — that is
  what M6 measures.
- Run A's request-count prediction missed (73 vs 30–45); counts in this
  roadmap are targets, not guarantees.
- The swarm's request efficiency (115 for 1 finding) is poor by design of the
  lab; efficiency targets appear only at M5.

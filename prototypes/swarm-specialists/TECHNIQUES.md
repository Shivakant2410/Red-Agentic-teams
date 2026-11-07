# TECHNIQUES.md — the techniques and methods in this stack, with lineage

What we actually use, where it lives, and where each idea comes from.
Every "where" is a file in this tree; every claim is checkable against the
artifacts (`M0/M1/M2/M3-PROOF.md`, `GAP-PROOF.md`). Research anchors were
visited 2026-11; links at §B. Companion research doc: `RESEARCH-M3.md`.

## A. Inventory

### A1. Test generation & oracles

| # | Technique | Mechanism | Where | Since | Lineage |
|---|---|---|---|---|---|
| 1 | FSM-inducing stateful fuzzing | build the resource graph from openapi, walk create→param→verb, mutate state transitions | `statefuzz/model.py`, `statefuzz/registry_tool.py` | Phase B | MOREST's operation-dependency testing (Liu et al. 2022) |
| 2 | Metamorphic invariant oracle I1 (conservation/replay) | value that leaves must land; replayed transitions must not re-pay | `statefuzz/invariants.py`, `swarm/techniques.py` | Phase B | Barr et al. 2015 (oracle problem → metamorphic relations) |
| 3 | I2 state-model invariant | transitions outside the induced/declared lifecycle (terminal-state writes, `booked --settle--> credited`) | `invariants.py`, `engine/fsm.py` (M3) | Phase B / M3 | induced transition tables, APIRL (Foley et al. 2025) |
| 4 | I3 tenancy invariant | a fresh principal must not read/monetize another tenant's object | `invariants.py`, `t_cross_tenant` | Phase C | — |
| 5 | I4 money-balance invariant | every pricing/credit path must reconcile at the wallet read-back | `invariants.py`, `engine/window.py` | Phase B | metamorphic: wallet delta vs expectation |
| 6 | I5 single-use invariant | check-then-act artifacts must lose the race to ≥1 winner only | `invariants.py`, `t_credit_race` | Phase B | — |
| 7 | Deferred-window oracle (markers) | a 202 + event-path shape becomes a ledger marker: "this seam will move the balance exactly once" — resolved later from wallet reads | `engine/ledger.py` `mark()`, `engine/window.py` | M0/M1 | our ledger IS a deferred metamorphic oracle (Barr et al. 2015) |
| 8 | Ambient wallet oracle (I4 ambient) | baseline every principal at registration; settle each act at the balance; unattributed deltas escalate | `engine/watch.py`, `Env.register` | **M3** | continuous ASM observation (OWASP); fixes GAP-PROOF band D |
| 9 | Existence oracle (404 vs 405/4xx) | a POST-only route hit with GET answers 405: free resource-existence oracle for probing without side effects | `engine/surface.py` `probe_nouns` | M2 | — |

### A2. Mutation operators (8)

`SKIP / REPLAY / REORDER / PARTIAL / NEGATIVE / CROSS-USER / INTERRUPT / IDEMPOTENCE` — declared in Phase B (`statefuzz/mutants.py`), composed onto surface shapes by the technique library. M3 adds the two missing compositions: **SKIP × induced-FSM** (`t_state_skip`) and **REPLAY × induced-FSM** (`t_fsm_live`'s built-in re-probe) — the "probes replaced by compositions" milestone item.

### A3. Concurrency primitive

Last-byte-synchronized race (`Executor.race`, 8 workers; `t_credit_race`, `t_quota_race`) — Phase B, unchanged since (proven: 8/8 winners, +240,000 = 8× face on ONE voucher).

### A4. Schema & surface learning

| # | Technique | Mechanism | Where | Since |
|---|---|---|---|---|
| 10 | Schema-from-errors (U3) | probe with `{}`; the 422 error document IS the create schema | `swarm/techniques.py` `_learn_contract` | hard-lab |
| 11 | Doc-vs-live differential + open vocabularies | value-noun/verb/subpath vocabularies as DATA (`VALUE_NOUNS` 14, `VERB_VOCAB` 20, `SUBPATH_NOUNS` 8); every fact probe-grounded; discoveries merge shape-identically into the surface graph | `engine/surface.py`, `t_open_vocab` | M2 |
| 12 | Echo mining | the target's own 201 response names its price fields → mass-assign candidates with `mined_from_echo: true` | `engine/surface.py` `money_fields` | M2 |
| 13 | Foreign-id readback mining | readback candidates = GETs whose bodies carry ids not owned by the caller (found `/api/shipments/recent`) | `engine/surface.py` `extract_ids`, `probe_subpaths` | M2 |
| 14 | Single-use signature | second identical probe on claim-family verbs: 200→409 = check-then-act (race candidate) | `engine/surface.py` `single_use_signature` | M2 |
| 15 | Doc-trust degradation (V5) | ≥3 lawful creates answering 400/422 ⇒ that doc create is `doc_suspect` | `engine/surface.py` `scan_traffic_suspect_docs` | M2 |
| 16 | Lifecycle-noun probing + induced transition table | LIFECYCLE_NOUNS walked across one object's states; 409 rows = order constraints; the state echo names states | `engine/fsm.py` `induce` | **M3** |

### A5. Follow-through & guidance (M3's core)

| # | Technique | Mechanism | Where | Lineage |
|---|---|---|---|---|
| 17 | Credit-verb follow-through | a discovered verb that CREDITED the prober is replayed (I1) and raced (I5) on fresh objects | `t_value_replay`, `t_credit_race` | M2, generalized M3 |
| 18 | State-skip probing | terminal verb invoked from the pristine state; gated-sibling 409s prove the lifecycle exists ⇒ I2 finding | `t_state_skip` | **M3** — closed GV-8 |
| 19 | Attack-surface map as artifact | documented/discovered layers + evidence states (probed/refuted/verified/ambient-paid), written every run | `engine/attackgraph.py` | **M3**; OWASP attack-surface analysis; continuous-ASM practice |
| 20 | Runtime attack graph | `acct:any → goal:wallet-credit` edges with {cost, evidence, technique}; `next_actions()` ranks cheapest untested/credit-only edges | `engine/attackgraph.py` | **M3**; Chen et al. 2024 survey (planner over graph ≠ scanner) |
| 21 | Graph-guided agents | ambient-credit ESCALATION (prio 2.5) → graph rebuild → HYPOTHESIS (origin `attack-graph`) through the EXISTING router loop; ≤2/run, deterministic | `swarm/specialists/attack_graph.py` | **M3**; complements the mainline's static TTP tree (`redteam/attack_tree.py`, Nakano et al. 2025: −56% agent queries with structure) |

### A6. Multi-agent architecture

| # | Technique | Mechanism | Where | Since |
|---|---|---|---|---|
| 22 | Blackboard with typed facts + provenance | OBSERVATION/SURFACE/HYPOTHESIS/FINDING/ESCALATION/CONTROL; `derived_from` chains give every finding an audit path | `swarm/blackboard.py` | Phase C (Hearsay-II) |
| 23 | Progress-ledger router | trigger-gated dispatch, priority-first with deterministic tie-break, stall detection (2 escalate / 3 stop), global budget each round | `swarm/router.py` | Phase C (Magentic-One) |
| 24 | Specialist contract | triggers/skills/private-state; machine-checked spec (≤8 skills, dispatch caps); spawn depth ≤1 | `swarm/specialist.py` | Phase C |
| 25 | Independent verification (E3) | a finding is `verified` ONLY by re-executing the SAME code with fresh principals; window findings replay through the driver; races on consumed artifacts get honest `verified-by-transcript` (0.5) | `swarm/specialists/verify.py`, `engine/window.py` `verify_finding` | Phase C |
| 26 | Grounded-only hypothesis rule (E6) | every marker/finding cites a surface or observation fact as `derived_from`; LLM output may only ever enter as a hypothesis with a prior | `engine/ledger.py`, `swarm/llm.py` | Phase C (Huang et al.) |
| 27 | LLM seam placement (max-entropy) | seam 1 hypothesis generation, seam 2 router tie-break — both currently deterministic (`llm_seam_calls == 0` through M3) | `swarm/llm.py` | Phase C |

### A7. Learning: bandits (your MAB/Thompson question, answered concretely)

| # | Technique | Mechanism | Where | Notes |
|---|---|---|---|---|
| 28 | Deterministic greedy-mean bandit (prototype) | Beta(α,β) posteriors per technique; exploit by posterior mean, ties by name; `should_run` skips learned dead-ends; outcomes recorded ONLY from verified evidence (verified 1.0 / transcript 0.5 / candidate 0.25 / refuted→failure) | `swarm/memory.py` + `swarm/registry_tool.py` `_curation_outcomes` | deterministic for reproducibility; Thompson named as the drop-in (M5/GEPA) |
| 29 | Contextual Thompson-sampling bandit (mainline) | Beta(α,β) per (technique, endpoint-shape bucket); cost-aware selection (findings per unit OPSEC noise — the budgeted-MAB objective); posterior discounting for regime change; federated delta-pooled merging; honeypot suspicion cap; EPSS/KEV prior injection (local-only / data-wins / no-certainty) | `redteam/bandit.py`, `redteam/priors.py` | the strategic layer the user built; literature-aligned: EcoFuzz (USENIX Sec 2020) models schedules as adversarial MABs, T-Scheduler (2024) is literally Beta-Bernoulli + Thompson, BandFuzz (2025) allocates between fuzzers by MAB |
| 30 | Bandit-fed arms | M3 adds `h_state_skip` + `h_fsm_live` as new arms — posteriors accumulate automatically through the same curation | `swarm/memory.py` | verified-first rewards keep a decoy-paying arm from rising (D-1 evidence: `h_quota_race` attributed=False deltas) |

**The honest synthesis**: the prototype bandit is tactical (which arm pays on THIS target, deterministic, verified-reward-only); the mainline bandit is strategic (cross-engagement, Thompson, cost-aware, prior-injected). M3's contribution is neither — it is the *evidence graph* that decides WHICH edges deserve an arm pull next (§A5 #20–21), which neither bandit could do because both choose among fixed arms while the graph discovers the edges.

### A8. Memory & curation

| # | Technique | Mechanism | Where | Since |
|---|---|---|---|---|
| 31 | Per-specialist namespaces + insight curation | bandit/insights/history persisted per specialist; only target-agnostic insights survive | `swarm/memory.py`, `_earn_insights` | Phase C |
| 32 | Poisoning guard (A2) | target-controlled content caps at weight 0.5 (recon/surface_mapper) | `_curation_outcomes` | Phase C |
| 33 | Insight falsification need (open) | recon's wrong "trust the doc" insight persisted unchallenged in GAP-PROOF §3.3; falsification probes + GEPA-style evolution are M5 | ROADMAP G7 | — |

### A9. Safety, scope, honesty

| # | Technique | Mechanism | Where |
|---|---|---|---|
| 34 | Fail-closed scope guard | loopback / TEST-NET-1 only; anything else refuses | `swarm/registry_tool.py` `_scope_ok` |
| 35 | STOP kill file + global budget + traffic provenance | every request through one executor with phase+tag | `statefuzz/executor.py` |
| 36 | Fresh principal per probe (D7) | no cross-probe state pollution | `Env.register`, `verify` |
| 37 | Decoy discipline | D-1/D-2 measured as false-positive sinks; M3 added balance-level decoy visibility (the +1,500 racer payout escalation) | labs + `engine/watch.py` |
| 38 | Honest resolution vocabulary | confirmed / confirmed-by-transcript / refuted / inconclusive — refutations score as information (weight 1.0) | `engine/ledger.py` |
| 39 | Pre-registered predictions | every milestone predicts before it runs; scorecards published with misses (M3: P2 count, P5 band) | `RESEARCH-M3.md` §4, `M3-PROOF.md` §5 |

## B. Research bibliography (visited 2026-11)

1. Yue et al., **EcoFuzz** (USENIX Security 2020) — fuzz scheduling as an adversarial MAB. https://www.usenix.org/conference/usenixsecurity20/presentation/yue
2. Luo et al., **T-Scheduler** (2024) — seed scheduling as a Beta-Bernoulli bandit solved by Thompson sampling. (ScienceDirect, 2024)
3. **BandFuzz** (2025) — collaborative fuzzing; MAB-driven resource allocation between fuzzers.
4. Chen et al., **A Survey on Penetration Path Planning in Automated Penetration Testing** (2024) — attack graphs / planning-domain models; the planner is the differentiator.
5. Skandylas et al. (2025), *Automated penetration testing: formalization* — attack automation + attack planning as the two required features.
6. **Automated Penetration Testing with LLM Agents and Classical Planning** (arXiv:2512.11143) — planner/actor decomposition constrains LLM agents.
7. **PentestGPT** (Deng et al.) / **AutoAttacker** — LLM pentest agents; technique knowledge from model memory goes stale — why our graph is induced from live probes.
8. Liu et al., **MOREST** (arXiv:2204.12148) — model-based RESTful testing with execution feedback.
9. **ARAT-RL** (ASE 2023) — RL-prioritized REST API exploration; **APIRL** (Foley et al., AAAI 2025) — deep RL for REST API fuzzing.
10. Barr et al., **The Oracle Problem in Software Testing: A Survey** (IEEE TSE 2015) — metamorphic relations where no direct oracle exists.
11. OWASP **Attack Surface Analysis Cheat Sheet** — map what is exposed before testing it. https://cheatsheetseries.owasp.org/
12. Nakano et al. (arXiv:2509.07939) + **TAP** (arXiv:2312.02119) — cited by the mainline `redteam/attack_tree.py` for structure-constrained agents (−56% queries) and propose→evaluate→prune.

**What we adopt**: adversarial-MAB scheduling (as the mainline bandit's design), Beta-Bernoulli posteriors with verified-only rewards, attack-graph-guided planning (as a RUNTIME induced graph, not a static template), operation-dependency stateful testing (as live FSM induction), metamorphic wallet oracles (I1/I4/I5 + ambient).
**What we reject, with evidence**: LLM-supplied technique knowledge as ground truth (PentestGPT's staleness class — our stale-doc lab exists to prove the failure mode); self-reported confidence as routing signal (E6); insights promoted without falsification (GAP-PROOF §3.3).

## C. Status after M3 (one line each)

- Found autonomously + verified: **all 8 Freightlane covert classes (GV-1…GV-8)** + meridian S1–S7 + dvlba B1–B8 — three labs, one tree, zero decoy FPs, zero LLM calls.
- The band-D leak class is closed mechanically: discovery that moves money now *cannot* pass unobserved (ambient oracle) and feeds guidance (graph) automatically.
- Open by design: efficiency (M5), LLM seam + GEPA (M5), third-domain transfer study (M6), pinned-probe-library deletion (M5, after coverage parity).

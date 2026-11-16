# RESEARCH-M3.md — follow-through, ambient oracles, and the graph that guides

M3 roadmap scope (ROADMAP-statefuzz-swarm, milestone table): *"wallet watcher,
OBSERVATION→hypothesis bridge, live-induced FSM — exit: GV-8 found; statefuzz
probes replaced by compositions; dvlba still 8/8."* Discipline unchanged:
**first research, then code**; every design decision below cites either the
literature (with links), the mainline tree, or a live artifact from M0–M2.

## R0. The gap M3 closes (measured, not recalled)

GAP-PROOF §1, GV-8 row: `settle` from `booked` — **SKIP (FSM)** — *"Hidden
verb observed: verb-probe POST …/settle → 200 published as OBSERVATION; no
wallet check, no FSM hypothesis, no finding. Band D: discovered-not-exploited.
t_hidden_verbs stops at observation; no follow-through consumer; no ambient I4
wallet watch."* M2 closed the four band-C misses but deliberately left GV-8
open (M2-PROOF §6: *"GV-8 remains open by design: settle is recorded as an
undocumented verb fact and nothing follows through — the OBSERVATION→hypothesis
bridge and ambient wallet watcher are M3 scope"*). M2's replay/race arms DID
follow through on settle and honestly refuted both (409-guarded) — the bug is
not repeatability, it is the **skipped lifecycle**: the lab credits
`rate_cents` to a shipment that settled straight from `booked`, while
`deliver` (409 from `booked`) proves the resource HAS state gating.

## R1. What the user's mainline already has (file evidence)

- `redteam/bandit.py` — **contextual Thompson-sampling bandit**: Beta(α,β)
  posteriors per (technique, endpoint-shape bucket); cost-aware selection
  (confirmed findings per unit of OPSEC noise); posterior discounting for
  regime change; federated delta-pooled merging; honeypot suspicion cap;
  EPSS/KEV prior injection with local-only / data-wins / no-certainty
  contracts. This is the strategic layer.
- `redteam/attack_tree.py` — deterministic **MITRE-ATT&CK-style TTP tree with
  an `unlocks` chaining graph** (SQLi → auth bypass → admin → exfil), citing
  Nakano et al. 2025 (arXiv:2509.07939: structured attack trees cut LLM agent
  query count −56%) and TAP (arXiv:2312.02119: propose→evaluate→prune).
- `redteam/graph_view.py`, `killchain.py`, `planner.py` — graph/kill-chain
  consumers on the same data.
- Prototype swarm (`swarm/memory.py`) — deterministic greedy-mean bandit
  (E1) with a flagged Thompson upgrade path; curation weights verified
  outcomes 1.0 / transcript 0.5 / candidate 0.25 / refuted→failure.

**The gap between the two layers**: the mainline tree/graph is *static
knowledge* (hand-authored TTPs); the prototype bandit is *tactical learning*
(which technique pays on this target). Neither is a **runtime attack graph
induced from live evidence that routes the agents mid-run**. That is M3's
contribution, and it is what "attack graph that guides exploit agents" means
here: not another template — an evidence graph built from the run's own
surface facts, wallet observations, induced transitions and ledger
resolutions, whose `next_actions()` ranking is consumed by the swarm when it
stalls or when ambient money moves unexplained.

## R2. Literature anchors (searched 2026-11, links visited)

Selection: find prior art for (a) bandits/Thompson in attack tooling, (b)
attack-graph-guided exploitation, (c) attack-surface mapping as a live
artifact, (d) induced state machines for API testing.

- **MAB / Thompson sampling in fuzzing & testing**
  - Yue et al., *EcoFuzz: Adaptive Energy-Saving Greybox Fuzzing as an
    Adversarial Multi-Armed Bandit*, USENIX Security 2020.
    https://www.usenix.org/conference/usenixsecurity20/presentation/yue —
    models schedule decisions as an adversarial MAB; the fuzzer's *choice of
    next action* is a bandit arm, not a heuristic.
  - Luo et al., *T-Scheduler* (2024) — seed scheduling as a **Beta-Bernoulli
    bandit solved with Thompson sampling**. Direct precedent for the
    mainline's Beta(α,β) posterior design.
  - *BandFuzz* (2025) — collaborative fuzzing where an MAB allocates
    resources BETWEEN fuzzers — the same shape as our router allocating
    budget between technique arms.
  - Verdict [A]: our two-layer design (mainline Thompson bandit over
    technique×bucket; swarm greedy-mean over arms with verified-only
    rewards) is consistent with the SOTA direction; the prototype's
    deterministic ordering stays for M3 reproducibility (exit E: zero LLM
    seam calls), with Thompson as the M5/GEPA drop-in.
- **Attack-graph-guided exploitation**
  - Chen et al., *A Survey on Penetration Path Planning in Automated
    Penetration Testing* (2024) — PT as search/planning over **attack graphs
    or planning-domain models**; the planner, not the scanner, is the
    differentiator.
  - Skandylas et al. (2025), *Automated penetration testing: formalization*
    — attack automation + attack planning as the two required features.
  - *Automated Penetration Testing with LLM Agents and Classical Planning*
    (arXiv:2512.11143) — decomposes pentest agents into planner/actor;
    classical planning constrains the LLM. PentestGPT / AutoAttacker rely on
    LLM-supplied technique knowledge and inherit its staleness — the reason
    M3's graph is **induced from live probes**, not from a model's memory.
  - Verdict [A]: a graph whose edges carry *execution evidence* (probed /
    refuted / verified / paid) and whose planner ranks next actions by
    cost-to-goal is the literature-consistent way to "guide exploit agents".
- **Attack surface mapping**
  - OWASP *Attack Surface Analysis Cheat Sheet* — map what is exposed before
    testing it; ASM industry practice (external continuous discovery) says
    the map must be **continuous**, not one-shot at recon.
  - Our M2 surface truth (engine/surface.py) already produces the live map;
    M3 promotes it to a first-class ARTIFACT with evidence states
    (documented/discovered, probed/refuted/verified, money-ness, single-use
    signatures, induced states) — the map and the graph share one builder so
    they can never disagree.
- **Stateful API testing / induced FSMs**
  - Liu et al., *MOREST: Model-based RESTful API Testing with Execution
    Feedback* (arXiv:2204.12148) — operation dependency graph + feedback;
    ARAT-RL (ASE 2023) and APIRL (AAAI 2025) add RL over the operation graph.
  - Barr et al., *The Oracle Problem* (IEEE TSE 2015) — when no direct
    oracle exists, metamorphic relations carry the check; our wallet-delta
    after state transitions IS the metamorphic oracle (I4 ambient).
  - Verdict [A]: induce the transition table from live 409-gating + state
    read-backs (409 = "this transition is state-guarded" is a free FSM
    oracle), then run the SKIP/REPLAY operators against the induced table —
    the "probes replaced by compositions" exit item.

## R3. Design decisions (each: decision → mechanism → falsifiable test)

- **D1 Ambient wallet watcher (I4 ambient)** — `engine/watch.py`. Effects are
  OBSERVED at the balance, not inferred from response keys: `Env.register`
  adopts each new principal with a baseline wallet read (≤3 per technique act
  — race arms bring their own attribution); after each act the watcher
  settles: delta per adopted principal, attributed iff the act produced a
  FINDING; otherwise an **ambient-credit ESCALATION** fact (the band-D leak
  made visible). Cost pre-registered: ~2 requests per adopted principal.
  Test: t_open_vocab's settle probe credits the prober with no finding →
  exactly one ambient-credit ESCALATION, grounded.
- **D2 State-skip follow-through (GV-8 finding arm)** — `t_state_skip`
  (h_state_skip). Gate: a DISCOVERED verb fact in the terminal family
  (settle/complete/confirm/fulfill/approve/capture/close/terminate) on a
  create-able param resource. Body: create → state read-back → invoke the
  terminal verb from the pristine state → wallet delta → then, on a SECOND
  fresh object, probe LIFECYCLE_NOUNS (pickup/deliver/ship/dispatch/…)
  from pristine: a 409-gated sibling while the terminal verb succeeded from
  the same state = the FSM-skip evidence. No gated sibling ⇒ honest
  OBSERVATION, never a finding. Finding: FW-STATE-SKIP, I2, evidence carries
  from_state, skipped_transition (409 body), wallet trace, induced order.
  Test: freightlane finds GV-8 verified; a target with no lifecycle gating
  yields no finding.
- **D3 Live-induced FSM (compositions)** — `engine/fsm.py` + `t_fsm_live`
  (h_fsm_live). Gate: ≥1 discovered undocumented verb fact on a param money
  resource (zero on truthful-doc targets ⇒ dvlba/meridian untouched —
  regression safety by construction). Body: probe lifecycle nouns, induce
  the transition table by state read-backs (409-gating as the FSM oracle),
  publish the table as an OBSERVATION the attack graph consumes, then run
  REPLAY on state-changing one-shot transitions (second 2xx = I1). The old
  `_t_fsm` skip-CONTROL message now names the composition path; the dvlba
  checkout spawn stays untouched. Honest boundary: the vendored Phase-B
  probe library is shadowed, not deleted — full removal waits until the
  composition path matches its coverage (tracked in M3-PROOF §deltas).
- **D4 Attack surface map + attack graph, one builder** —
  `engine/attackgraph.py` (spine, no swarm imports, zero requests). Surface
  map: resource/action/readback nodes with documented|discovered + evidence
  states. Attack graph: capability/state nodes (any-account → object-state →
  wallet-credit), edges annotated {requests cost, evidence:
  untested|probed|refuted|verified|ambient-paid, technique suggestion}.
  `next_actions()` ranks cheapest untested edges to the money goal; the
  ATTACKGRAPH specialist (stall-escalate or ambient-credit triggered, ≤2
  guided hypotheses per run, priors 0.45, origin "attack-graph") converts
  them into HYPOTHESIS facts the existing router already dispatches — the
  bridge is the router, no new dispatch machinery. Artifacts
  `attack_surface.json` written every run (also in `_assemble` if the
  specialist never fired). Test: after a freightlane run the graph contains
  the settle edge with ambient-paid evidence and the surface map flags ≥3
  undocumented verbs; artifacts exist in every run dir.
- **D5 Replay-arm generalization (follow-through completion)** —
  `t_value_replay`'s validity condition becomes the honest one: two
  consecutive 2xx replays each crediting > 0 (the `c1+c2 ≥ 2×face` clause was
  a severity prior, not validity — rebook's 10 % bonus failed it although the
  credit repeats forever). Candidate iteration collects ≤2 findings (id
  FW-{VERB}-REPLAY). dvlba-safe because its gate needs credited DISCOVERED
  verb facts (zero there). Test: freightlane yields FW-REBOOK-REPLAY
  verified (GV-2 enrichment); dvlba unchanged.
- **D6 Scope** — unchanged contract: loopback/TEST-NET-1 fail-closed, STOP
  kill file, global budget, every request through the shared executor with
  phase+tag provenance, fresh principal per probe (D7 of hard-lab).

## R4. Pre-registered predictions (honesty contract — scored in M3-PROOF)

- **P1** GV-8 found autonomously as FW-STATE-SKIP (I2), verified by
  fresh-principal re-execution, evidence carries wallet delta + a 409-gated
  sibling transition.
- **P2** exactly one ambient-credit ESCALATION in freightlane run1 (the
  open-vocab settle probe credit), grounded on a hypothesis fact; ambient
  cost ≤ 90 requests (adopt + settle reads, cap 3/act).
- **P3** freightlane run1 findings ≥ 9, all verified: the 8 M2 findings PLUS
  FW-STATE-SKIP (FW-REBOOK-REPLAY may add one more — predicted, not
  required); markers ≥ 2; decoys clean; llm_seam_calls == 0.
- **P4** dvlba (--with-dvlba): B1..B8 all hit, zero decoy FPs, no unmatched
  findings (gates closed), requests +≤ 90 vs M2 baseline from ambient reads.
- **P5** meridian regression (run_m0.py): S1–S7 unchanged, 16 verified
  findings, 0 FP; requests +≤ 90 from ambient reads.
- **P6** attack_surface.json + attack_graph.json exist in every run dir;
  the graph's money paths include the settle edge marked ambient-paid.
- **P7** if P2 yields zero ambient escalations, the watcher is mis-wired and
  M3 FAILS its own exit even if GV-8 is found (the leak must be *visible*,
  not merely lucky).

## R5. What M3 does NOT do (bounds)

- No LLM calls (deterministic M3; the graph's suggestion mapping is a static
  technique map — the M5 seam may rewrite priors, never conclusions).
- No cross-run surface persistence (M5 efficiency gate).
- The vendored statefuzz probe library is not deleted (see D3).
- Freightlane stays one lab; the graph builder is domain-agnostic but the
  transfer study is M6.

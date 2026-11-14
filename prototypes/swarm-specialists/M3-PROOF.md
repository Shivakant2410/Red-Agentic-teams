# M3-PROOF.md — follow-through, ambient oracles, and the graph that guides

M3 (roadmap): *"wallet watcher, OBSERVATION→hypothesis bridge, live-induced
FSM — exit: GV-8 found; statefuzz probes replaced by compositions; dvlba
still 8/8."* Every number below is read from artifacts produced by
`run_m3.py` / `run_m0.py` in this directory (`m3-results/`, `m0-results/`),
not recalled. Research first: see `RESEARCH-M3.md` (literature anchors,
design decisions D1–D6, pre-registered predictions P1–P7).

## 0. The miss this closes (GAP-PROOF §1, verbatim)

| GAP-PROOF miss | Mechanism (wire-log evidence) | M3 answer |
| --- | --- | --- |
| GV-8 settle from `booked` — "missed, band D: discovered-not-exploited" | "Hidden verb **observed**: verb-probe POST …/settle → 200 published as OBSERVATION; no wallet check, no FSM hypothesis, no finding. `t_hidden_verbs` stops at observation; no follow-through consumer; no ambient I4 wallet watch" | Ambient watcher baselines every principal at registration and settles each act at the balance: the discovery-phase credit (+60,399 across the ov principal's voucher/shipment probes) is now an ESCALATION fact. The attack graph ranks the credited-but-untested `settle` edge, publishes `h_state_skip` (origin `attack-graph`), and the technique proves the skip: **settle from `booked` → 200, +3,998 to the wallet, state read-back `booked → settled`, against 3 induced 409-gated siblings** (`FW-STATE-SKIP`, verified) |

## 1. What was built (G3 → modules)

| Item | Module | Mechanism |
| --- | --- | --- |
| ambient wallet oracle (I4 ambient) | `engine/watch.py` (spine, no swarm imports) | `Env.register` adopts each new principal with a baseline wallet read (≤3/act — race arms carry their own evidence); after each act one wallet read per adopted principal; delta **attributed** iff the act produced a FINDING, else an `ambient-credit` ESCALATION — the band-D leak made visible. Event trace shared with the graph via `ctx["ambient_events"]` |
| OBSERVATION→hypothesis bridge | `swarm/specialists/attack_graph.py` + exploit act() | ESCALATION (priority 2.5, above the hypothesis engine's 2.0) → graph rebuild → `next_actions()` → HYPOTHESIS facts through the EXISTING router loop (no new dispatch machinery), bounded ≤2 guided hypotheses/run, prior 0.45, deterministic |
| state-skip follow-through (GV-8 arm) | `t_state_skip` (`h_state_skip`) | Gate: DISCOVERED terminal-verb fact. Create → state echo → invoke terminal verb from state0 → wallet delta; second object induces the lifecycle (`engine/fsm`); a 409-gated sibling while the terminal verb succeeded from pristine = the I2 finding. No gated sibling ⇒ honest observation, no finding |
| live-induced FSM (compositions) | `engine/fsm.py` + `t_fsm_live` (`h_fsm_live`) | Gate: ≥1 discovered verb fact (zero on truthful-doc targets ⇒ dvlba/meridian never spend here). Walks LIFECYCLE_NOUNS across one object's states — 409 rows are the order constraints, the re-probe at each new state IS the replay check; publishes the induced table as an OBSERVATION the graph consumes; money verbs excluded (induction never moves value) |
| attack surface map + attack graph, one builder | `engine/attackgraph.py` (spine, zero requests) | Surface map: resource/action/readback nodes with documented|discovered + evidence states. Attack graph: `acct:any → goal:wallet-credit` edges carrying {cost, evidence: untested/probed/credit-only/verified/ambient-paid, technique}. `next_actions()` = cheapest untested|credit-only edges not yet hypothesized. `attack_surface.json` written every run (specialist fires + `_assemble` end-of-run projection) |
| follow-through completion | `t_value_replay` generalized | Validity is now the honest one (two consecutive 2xx replays each crediting > 0); the old `≥2×face` clause was a severity prior, not validity — it hid rebook's repeatable 10% bonus. ≤2 findings/run, per-verb ids |

Version bumped `0.6.0-m3`. `llm_seam_calls` remains **0** — the graph's
technique suggestion map is data; the M5 LLM seam may rewrite priors, never
conclusions.

## 2. The live guidance chain (run1, blackboard fact order)

```
SF-EXPLOIT-0014  SURFACE-update (open vocab: 4 undocumented verbs, credited)
SF-EXPLOIT-0016  ESCALATION ambient-credit: "discovery moved value with no
                 finding: ov-12 +60399"          <- the band-D leak, visible
   round 5: attack_graph (prio 2.5) rebuilds the graph:
     next_actions = [e-follow-shipments-settle  (credit-only, ~24 req)
                     -> technique h_state_skip]
     publishes HYPOTHESIS h_state_skip prior 0.45 origin=attack-graph
   round 6+: exploit tests it:
     settle@booked -> 200 +3998 (wallet-watched), state booked->settled
     induced walk: pickup@picked_up 409, pickup@delivered 409,
                   deliver@delivered 409   (3 gated siblings, 13 probes)
     -> FW-STATE-SKIP (I2, SKIP) -> verify specialist re-executes fresh
     -> VERIFIED. GV-8 closed end-to-end, each hop grounded on the last.
```

The hypothesis engine's own deterministic rule for `h_state_skip` stayed as
the fallback (it lost the race and was deduped) — two independent paths to
the same arm, one evidence graph between them.

## 3. Validation — Freightlane M3 exit (`python3 run_m3.py --with-dvlba`)

| Run | Requests | Findings | Markers | Ambient events | Wall |
| --- | --- | --- | --- | --- | --- |
| freightlane run1 (fresh memory) | 616 | **10 (all verified)** | 2 | 13 (5 unexplained → 3 escalations) | 7.0 s |
| freightlane run2 (run1 memory) | 607 | 10 (all verified) | 2 | 13 | 7.1 s |
| dvlba regression run1 / run2 | 270 / 181 | 9 / 9 | 0 | 0 | 2.5 s |

Run1 findings (every one `verified` by fresh-principal re-execution):

```
FW-STATE-SKIP      h_state_skip    I2  settle from booked, +3998, 3 gated
                                       siblings          => GV-8  (NEW)
FW-REBOOK-REPLAY   h_value_replay  I1  rebook repeatable (+399 x2 on one
                                       object)           => GV-2  (NEW, M3
                                       generalization of D5)
FW-RELEASE-REPLAY  h_value_replay  I1  (M2 arm intact)   => GV-1
FW-CREDIT-RACE     h_credit_race   I5  8/8 winners, +240000 => GV-6
FW-MASS-PRICE      h_mass_assign   I4  rate_cents, mined_from_echo => GV-3
FW-AUDIT-LEAK      h_cross_tenant  I3  recent leak       => GV-2
FW-DEPUTY-CREDIT   h_cross_tenant  I3  rebook deputy, +399 => GV-2
FW-ROUND-DRIFT     h_arith_cycle   I4  (v1 arm intact)   => GV-7
FW-SETTLED-CANCEL  h_window_driver I1  (M1 arm intact)   => GV-5
FW-TOCTOU-SETTLE   h_window_driver I4  (M1 arm intact)   => GV-4
```

**All eight covert classes (GV-1…GV-8) now found autonomously and
verified.** Decoys clean (D-1 unclaimed-as-vuln; D-2 untriggered);
deterministic (`llm_seam_calls == 0`).

## 4. Exit criteria

- **[PASS] E1** GV-8 autonomous + verified — wallet delta +3,998, gated
  siblings x3, `booked --settle--> credited`
- **[PASS] E2** ambient watcher: 5 unexplained deltas escalated, grounded
  (`derived_from` the hypothesis fact)
- **[PASS] E3** `attack_surface.json` exists; 8 money paths incl.
  `e-follow-shipments-settle`; the graph LIVE-guided `h_state_skip`
- **[PASS] E4** M2 regressions: GV-1/2/3/4/5/6/7 all verified, markers ≥ 2
- **[PASS] E5** decoy FPs = 0
- **[PASS] E6** `llm_seam_calls == 0`
- **[PASS] E7** dvlba B1..B8, **zero unmatched findings** (the new arms'
  discoveries-gates stay closed on a truthful-doc target: +15 requests
  only, from ambient reads)

Third lab (P5): `run_m0.py` meridian S1–S7, 16 verified, 0 FP (518/477
requests); dvlba B1–B8 (270/181). Three labs, one tree, all green.

## 5. Prediction scorecard (RESEARCH-M3 §4 — honesty contract)

| Prediction | Verdict |
|---|---|
| P1 GV-8 = FW-STATE-SKIP, verified, wallet delta + 409-gated sibling | **HELD** (evidence exactly as specified) |
| P2 exactly ONE ambient escalation (the open-vocab settle credit) | **MISSED in count, HELD in mechanism** — 3 escalations: open_vocab +60,399 (settle + release + consume probes each paying once), hidden_verbs −3,998 (the hdv principal's create debit), quota_race +1,500 (**the D-1 decoy paying 3 racers — decoy burn now visible at the balance level**, a new band-D-class insight the prediction did not foresee) |
| P3 freightlane ≥ 9 findings all verified; markers ≥ 2; decoys clean; llm 0 | **HELD** (10 findings; FW-REBOOK-REPLAY was predicted-optional) |
| P4 dvlba B1..B8, zero unmatched, +≤90 requests | **HELD** (+15) |
| P5 meridian S1–S7, 16 verified, 0 FP, +≤90 requests | **PARTIAL** — findings/FP held; requests +93 (518 vs 425), 3 over the band |
| P6 artifacts exist; settle edge in money paths | **HELD** — and exceeded: the graph live-guided the finding (not required by P6) |
| P7 zero ambient escalations ⇒ M3 fails | vacuously held (5 unexplained observed) |

## 6. Request-cost accounting (honest)

M2 run1 385 → M3 run1 616 (+231, traffic-level decomposition):

| Cost centre | Requests | Note |
|---|---|---|
| ambient watcher (adopt + settle reads) | +109 | ~18% of the run; continuous observation is the M3 thesis (OWASP/ASM: the map is continuous); settle re-reads of OLD principals are what catch deferred credits across acts — trimming this is an M5 efficiency item, not silent |
| live-FSM arms (walks + state reads + terminal probes) | +48 | `fsm-walk` 36, `fsm-state-read` 10, `terminal-skip` 2 |
| verification of the two NEW findings | +67 | verify re-executes the same techniques fresh (E3): h_state_skip's re-walk + h_value_replay's double replay |
| misc | +7 | — |

Efficiency gates stay at M5 per the roadmap; the ambient cost is
pre-registered, itemized, and buys the only oracle that cannot be lied to
(the balance).

## 7. Honest deltas

- **The pinned probe library is shadowed, not deleted.** `_t_fsm` still
  spawns `statefuzz_spec` on checkout-bearing surfaces (dvlba — its 8/8
  regression depends on it); everywhere else the skip-CONTROL now names the
  live composition path (`h_fsm_live`), which freightlane exercised
  (induced table OBSERVATION, 13-probe walk). Full deletion waits until the
  composition path matches the pinned library's coverage — M5, measured.
- **Graph guidance on this lab suggested exactly one edge.** Every other
  discovered verb was already credited-and-covered by M2 arms, so
  `next_actions` was otherwise empty; the guidance consumer is exercised
  live once (the settle follow-up) and pinned at unit level. A target with
  untested money edges at stall time will exercise it harder — that is an
  M5/M6 measurement, claimed here only where it ran.
- **Ambient attribution is act-granular.** A finding-producing act
  attributes ALL of its adopted principals' deltas (per-principal
  attribution would need per-request wallet scoping — not worth 3× the
  ambient cost). Disclosed in `engine/watch.py`.
- `state_echo` trusts a `status/state/stage` string field; a target whose
  state field is named otherwise yields `state0=None` and the gated-sibling
  evidence still stands (it never depends on the echo).
- Request-efficiency (M5 gate): run2 re-runs discovery; no cross-run
  surface persistence yet.

## 8. Test suite

`pytest tests/` → **50 passed** (13 Phase-C + 10 M0 + 8 M1 + 10 M2 + 9 M3).
The M3 suite covers: watcher attribution (attributed vs unexplained vs
adopt-cap vs no-readback-inert), FSM state echo, the induced walk (409
gating, built-in replay, terminal-verb exclusion — an inducer that probed a
money verb would fail the test), replayable-row detection, attack-graph
build (surface-map layers, credit edges, follow-up edges, next_actions
evidence classes, artifact save), and the live freightlane E2E — the M3
exit in miniature (GV-8 verified with evidence depth, ambient escalation
grounded, graph artifact carries the settle edge, M1/M2 baselines intact).

## 9. Artifact index (paths relative to this directory)

- `m3-results/M3-SUMMARY.json` — machine-readable exit report
- `m3-results/freightlane/run{1,2}/` — findings.json (incl. `ambient_watch`,
  `attack_graph`), blackboard.json, dispatch_trace.jsonl, traffic.jsonl,
  hypothesis_ledger.json, **attack_surface.json**, memory/
- `m3-results/dvlba/run{1,2}/` — regression artifacts (incl.
  attack_surface.json)
- `m0-results/` — refreshed two-lab regression artifacts
- `RESEARCH-M3.md` — research-first doc (literature, D1–D6, P1–P7)
- `tests/test_m3_follow.py` — the M3 suite

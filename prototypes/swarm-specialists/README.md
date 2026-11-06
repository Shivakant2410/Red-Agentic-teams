# swarm — per-state specialist agents for Red-Agentic-teams (Phase C)

The problem you named: one generalist agent does recon reasoning, hypothesis
formation, surface mapping and exploit choice in the same context with the
same tools. This phase replaces that with **one specialist per engagement
state**, coordinated over a blackboard, each with its own skills, its own
technique bandit, its own memory namespace — and the Phase-B statefuzz tool
wired in as the LOGIC specialist's hard skill.

**Built research-first** per your mandate: `RESEARCH.md` answers "how do we
make each agent great, and better over time" from 12 verified sources
(Hearsay-II, MAST, Magentic-One, Anthropic's multi-agent system, Voyager,
ExpeL, GEPA, sleep-time compute, AgentVerse, Huang et al., BFCL, Tian et al.)
with adopt/reject verdicts and a mechanism→module→test traceability table.
Every module below cites its research basis (M1–M8, E1–E6).

## Roster — one specialist per state

| State | Specialist | Triggers on | Skills (scoped, M8) | Owns |
|---|---|---|---|---|
| RECON | `recon` | CONTROL engage | fetch + probe | 4 techniques, bandit-ordered (E1) |
| SURFACE | `surface_mapper` | OBSERVATION openapi | classify_paths | surface graph: endpoints × auth × flows |
| HYPOTHESES | `hypothesis` | SURFACE | generate | 6 rule-based + LLM-seam hypotheses (seam 1, E6) |
| EXPLOIT | `exploit` | HYPOTHESIS open | http/wallet/register | 6 hypothesis tests; **spawns statefuzz** (M4) |
| VERIFY | `verify` | FINDING candidate | fresh_principal | independent re-execution, fresh principals (E3) |
| ACCESS | `access` | finding_verified CONTROL | chain | capability chains → ESCALATION facts |
| LOGIC | `statefuzz_spec` | spawn-only | run_statefuzz | the Phase-B tool, sub-budget isolated |
| WINDOW | `window_driver` | OBSERVATION async-opened / stall | (ledger-driven) | M1: registers 202/event markers, drives deferred windows (GV-4/GV-5) |

## Quickstart

```bash
pip install flask requests pytest
python demo_swarm.py --port 8378     # two runs, shared memory, delta printed
python -m pytest tests/ -q           # 13 tests, ~6s
```

## Executed result (results/)

- **End-to-end findings**: 9 unique business-logic findings covering all 8
  seeded bug classes, every one **provenance-stamped** (`exploit`,
  `exploit/statefuzz_spec`) and **verification-stamped** (8 independently
  re-executed; the race finding honestly downgraded to
  `verified-by-transcript`).
- **Full autonomy demonstrated**: exploit spawned the statefuzz specialist
  mid-engagement (provenance chain `exploit/statefuzz_spec` on its findings).
- **Better over time, proven**: run 2 (fresh server, persisted memory)
  used **181 vs 188 requests** with the **identical 9 findings** — learned
  dead-ends (`/robots.txt`, 6 path probes) skipped via bandit posteriors,
  technique order re-derived, and an earned insight persisted
  ("openapi disclosure outperforms blind path probing").
- 3 critical capability chains: IDOR→cross-user refund (wallet drain),
  IDOR→unpaid ship, refund-caller-bug→unpaid ship.

## Architecture

- **Blackboard** (`swarm/blackboard.py`): typed facts — OBSERVATION, SURFACE,
  HYPOTHESIS, FINDING, ESCALATION, CONTROL — each with provenance chain and
  `derived_from` lineage (Hearsay-II M1, Magentic-One M3). Specialists never
  talk to each other.
- **Router** (`swarm/router.py`): trigger-gated dispatch with a pending
  queue, contract enforcement (skill-surface width, dispatch caps, typed
  triggers — MAST M2), stall detection by counter, global HTTP budget, LLM
  seam only for tie-breaks (E6).
- **Specialist** (`swarm/specialist.py`): the machine-checkable contract —
  triggers, scoped skills, private working state, `spawn()` with depth ≤ 1.
- **Memory** (`swarm/memory.py`): per-specialist namespace — greedy-mean
  bandit over techniques, learned dead-end skipping, insight curation
  (target-agnostic only), **poisoning guard**: read-side techniques cap at
  weight 0.5 because target-controlled content must never fully promote a
  technique (A2).
- **Improvement loop**: run → verify (grounded, E3) → outcome weights
  (verified 1.0 / transcript 0.5 / candidate 0.25 / refuted failure, E4) →
  end-of-run consolidation (E5) → next run starts smarter (E1).

## Integration seams (`# Seam:` in code)

- `MemoryNamespace` → platform ExperienceStore.
- `LLMSeam(backend=...)` → platform LLM; fires at hypothesis generation and
  router tie-breaks only; LLM output is always a *hypothesis with a prior*,
  never a conclusion.
- `run(ctx)` → same `build_registry()` contract as Phase B (`schema()` +
  `run(ctx)`); scope guard is fail-closed (loopback / TEST-NET-1 only);
  STOP kill file honored (`test_stop_file_halts_swarm`).

## Honest engineering log

Bugs the executed runs caught and fixed (all now regression-tested):
router discarded all-but-top candidate per round (hypotheses/findings never
dispatched); verify replayed the lawful action instead of the mutant
(I4 wrongly refuted); `spawn()` double-published sub-specialist facts;
statefuzz's spawn burned the single-use coupon before exploit's race test
(cheap tests now ordered before the heavy sub-specialist); login used the
wrong password convention; weighted-evidence threshold blocked dead-end
skipping; insights were mutated after persistence.

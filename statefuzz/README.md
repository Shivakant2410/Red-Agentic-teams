# statefuzz — Phase B prototype

Working implementation of the state-machine business-logic fuzzer specified
in *The State-Machine Doctrine* (research dossier, Ch. 8–9): an LLM-inferred
app model + metamorphic invariant oracles + illegal-transition mutation +
concurrency injection, built to drop into the **Red-Agentic-teams** registry.

Zero third-party dependencies. Python 3.10+. `pytest` for the test suite.

## Theory → code map

| Dossier concept | Module |
| --- | --- |
| M = (S, s0, Σ, δ, F), abstraction α, delta-hat, LLM labels w/ human-confirm gate | `appmodel.py` |
| Five invariant classes I1 conservation · I2 legality · I3 ownership · I4 arithmetic/ordering · I5 uniqueness/rate (metamorphic oracles) | `invariants.py` |
| Eight transition mutant operators: SKIP, REPLAY, REORDER, PARTIAL, NEGATIVE, CROSS-USER, INTERRUPT (race), IDEMPOTENCE | `mutants.py` |
| IAT executor: budget meter, stop-file, two-principal sessions, synchronized race | `executor.py` |
| Four oracle kinds: immediate metamorphic, differential (vs clean build), data-flow read-back, deferred hypothesis ledger (unique markers) | `oracle.py` |
| Findings as capabilities: preconditions + grants, chain search, compositional severity | `chains.py` |
| Main loop `statefuzz_run(ctx, budget)` with bounded reflection (|Δ| ≤ 25) | `runner.py` |
| Platform ctx: scope guard, approvals, bandit, findings/traffic sinks | `context.py` |
| Registry glue: `statefuzz_run` / `statefuzz_status` / `statefuzz_export` tools with `schema()` + `run(ctx, …)` | `tools.py` |
| Reference target: vuln-bank with 6 seeded logic bugs (bug-masked) | `demo/vuln_bank.py` |

## Quickstart

```bash
python -m pytest statefuzz/tests -q        # 59 tests
python -m statefuzz.demo.run_demo          # vulnerable vs fixed run
```

Demo result (this repo): the vulnerable build yields 19 findings covering
**all five invariant classes** — race double-spend caught by declared-delta
conservation ("balance moved −500, declared −4000 across 8 accepted
responses"), illegal closed→open transition via deposit, cross-user
read/write, negative amounts accepted, idempotency keys applied twice — plus
an impact chain (`cross-user statement read → cross-user transfer`). The fixed
build (same code, `bugs=set()`) yields **0 findings on the same 37 mutants**:
oracle precision, measured.

## Integration with Red-Agentic-teams

```python
from statefuzz import build_statefuzz_tools
registry.extend(build_statefuzz_tools(ctx))     # build_registry contract
```

The tools never open sockets and never bypass platform discipline:

- **Transport** — `ctx.adapter(plan)` is your scoped, recorded fetch path
  (ScopeGuard-wrapped). Every plan is also checked against
  `ctx.allowed_namespace`; violations tear the run down fail-closed
  (`ScopeViolation` → `torn_down`).
- **Approvals** — write-shaped mutants carry `tier="write"`; the runner
  skips any whose technique id is not in `ctx.approvals.granted_techniques`.
  Deny-by-default; `statefuzz_run`'s output lists `awaiting_approval` for the
  orchestrator to escalate. A mutant is never downgraded to pass the gate.
- **Kill switch** — `ctx.stop_file` is checked before every mutant
  (platform STOP semantics).
- **Findings** — emitted through `ctx.findings_sink` in the findings.json
  schema: preconditions + grants + evidence, `status: candidate`, ready for
  the independent verify pipeline (prover registry).
- **Traffic** — every request mirrored to `ctx.traffic` (traffic.jsonl).
- **Bandit / memory** — technique ids (`SF-RACE`, `SF-CROSSUSER`, …) are the
  bandit arms; `ctx.memory_absorb` writes per-mutant yield to the
  ExperienceStore; prior updates are clamped (|Δ| ≤ 25) so reflection can
  reorder, not capture.
- **Race transport** — `timing="race"` fires n plans through a Barrier.
  In production swap the adapter for single-packet sync (last-byte
  alignment / first-sequence-sync); the executor interface is unchanged.
- **LLM** — inject a labeler (`extract_model(spec, traffic, labeler)`) using
  Observation-Confirmation prompting; low-confidence labels hold the
  human-confirm gate. Without one, `heuristic_labeler` runs deterministically.

## Deliberate design limits

- The demo target is in-process; production targets speak HTTP through the
  platform adapter — statefuzz logic is transport-agnostic by construction.
- The deferred oracle needs platform-hosted callback endpoints (marker
  correlator); unconfirmed hypotheses expire **inconclusive**, never promoted.
- SKIP/REORDER mutants only spawn where the model carries
  `requires_requests` / write-transition annotations — the model extractor,
  not the fuzzer, guesses.
- Findings are candidate evidence. Verification, severity sign-off and
  reporting stay with the platform's verify pipeline — statefuzz widens the
  funnel, it does not adjudicate.

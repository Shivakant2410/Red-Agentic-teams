# RESEARCH-M4.md — the orchestrator seams, researched before built

M4 (ROADMAP G5): "`LocalScopeGuard` → platform ScopeGuard; findings → verify
pipeline; per-specialist memory → ExperienceStore; approval gate on write
mutants. Acceptance: same `schema()` + `run(ctx)` contract served by both; a
STOP file halts mid-race." Per the standing discipline (and the user's
explicit instruction), the web + paper research below happened BEFORE any
code. Links visited 2026-11-07.

## R0. The gap M4 closes (measured in code, not recalled)

The three seams are currently **strings and private functions, not
interfaces**:

1. Scope: `_scope_ok(base_url)` (`swarm/registry_tool.py`) returns a bare
   bool from one call site. No per-action gate exists: once the run is
   seeded, ANY specialist can send ANY verb (including state-changing
   writes) until budget or STOP — G5 explicitly names an "approval gate on
   write mutants" and the prototype has none.
2. Verification: the verify specialist runs during the loop, but the
   end-of-run weight pass (`_curation_outcomes`) is a private function that
   trusts whatever status landed on the FINDING fact. A candidate-only
   finding that nothing refuted still pays weight 0.25 "success" into the
   bandit. There is no independent post-pass that can DOWNGRADE.
3. Memory: `MemoryNamespace` is a concrete file-backed class; the seam note
   in its docstring is prose. Nothing can be swapped.
4. No audit surface: policy decisions, approvals, and denials leave no
   artifact a reviewer could replay.

## R1. What the platform already provides (file evidence) — the swap targets are real

| Prototype seam (today) | Platform interface (mainline `redteam/`) | Delta M4 must close |
|---|---|---|
| `_scope_ok()` bool fn | `scope.py`: `ScopeGuard.check()` fail-closed; allowlist AND DNS-resolved-IP check; `ScopeViolation` exception; engagement config | object with allow/deny + reason + audit; per-ACTION checks (verb-level gate), not just per-run |
| verify specialist + `_curation_outcomes` | `verify.py`: `Check` protocol (`run() -> CheckOutcome`), k-of-n reproduction, `VerificationResult` verdicts `confirmed / not_reproducible / rejected` | one independent post-pass speaking a compatible verdict vocabulary that can downgrade |
| `MemoryNamespace` concrete class | `memory.py` + `memory_backend/`: ExperienceStore with pluggable backend (HelixDB graph+vector) | a `ExperienceStore` protocol the file store implements and an in-memory store can implement |
| ad-hoc phase script in `run()` | `orchestrator.py`: deterministic commander ("a disciplined commander, not another LLM"), EXPLOIT→VERIFY rounds, NoiseBudget | an explicit `Orchestrator` object owning pre-flight → gate → loop → verify pass → curation → artifacts |

## R2. Competitor evidence — "is anyone using this?" (web, 2026-11)

| Component | Who | Exact public claim | Source |
|---|---|---|---|
| Deterministic governance/orchestration layer over an agent fleet | XBOW | "a solid layer of governance, orchestration, and validation"; "coordination agents … apply deterministic logic to debrief agents, refine findings, and prioritize next actions"; "It typically takes four agents to deliver a reliable result" | xbow.com blog, "AI Pentesting: Strengths, Gaps, and Validation" (visited 2026-11-07) |
| Per-action check before execution | XBOW | "We ensure that every agent action is checked before execution"; "We give agents only the tools they need for their specific task, nothing more" | same |
| Independent finding validation | XBOW | "validator agents that confirm whether a discovered issue is truly exploitable using controlled, production-safe challenges"; validation "ongoing and frequent" to shrink "room for error and hallucinations" | same |
| Proof-before-report | Horizon3 NodeZero | "proof of actual exploitability"; "verifies that fixes work" (commercial selling point = our E3) | horizon3.ai/nodezero (visited 2026-11-07) |
| PoC-or-it-doesn't-ship | Keygraph PentestGPT | "claims only findings with a working PoC are reported" | docs/competitor-landscape.md row 2 (checked 2026-09-26) |
| Policy at the tool-call boundary | pentestkit (Claude Agent SDK) | "scope-guarded egress", "proof-oriented reports" — vendor claim; their 104/104 benchmark claim is treated as saturated per the XBOW benchmarks README | docs/competitor-landscape.md row 3 |
| Operation-scoped execution | MITRE CALDERA | operations = server-orchestrated ability chains over agents; MITRE's own paper argues for planning INSIDE the acting loop ("Automated Adversary Emulation: A Case for Planning and Acting") | mitre.org PDF; CALDERA docs |

Verdict: the exact M4 triad — deterministic governance + per-action gate +
independent validation — is not exotic; it is what the commercial leader
publicly claims as its architecture, and what the DARPA-AIxCC-era tools
converge on. Nobody credible ships model-self-governed agents.

## R3. Research-paper anchors, per lens

**Policy gate / ScopeGuard** (security-engineer lens first):
- CaMeL — Debenedetti et al., *Defeating Prompt Injections by Design*
  (arXiv:2503.18813, Google/ETH, 2025): extract control+data flow from the
  trusted query; enforce security policies at tool-call boundaries from a
  system layer "even when underlying models are susceptible"; AgentDojo
  77% of tasks WITH provable security vs 84% undefended. The ~7pp utility
  tax is the published price of provable denial. Our `approvals` switch is
  the same shape at a smaller scale: `lab` = capability auto-grant inside
  the audited scope; `none` = deny writes.
- The mathematician's statement of the same thing: the gate is a
  decidable, total check over a small lattice — (principal, mutating?,
  target∈scope) — default-deny, i.e. fail-closed over the permission
  lattice. It requires no probability, no model, and that is the point:
  it is the one component whose correctness must be absolute rather than
  statistical.
- Sarraute et al., *Penetration Testing == POMDP Solving?*
  (arXiv:1306.4714): the OVERALL engagement is a POMDP; but the POMDP
  solver acts inside a boundary it cannot change — the action set available
  to the planner is defined by policy. Our design keeps exactly that
  separation: Router/bandits choose among allowed actions; policy defines
  allowed.

**Verify pipeline** (AI-researcher lens first):
- MAST — Cemri et al., *Why Do Multi-Agent LLM Systems Fail?*
  (arXiv:2503.13657, NeurIPS 2025 spotlight): 14 failure modes in 3
  categories — system design, inter-agent misalignment, **task
  verification** (κ = 0.88 annotator agreement). Verification failure is a
  NAMED first-class category, not an afterthought; our post-pass is the
  corresponding mechanism.
- EnIGMA (arXiv:2409.16165): documents "soliloquizing" — the model
  self-generates hallucinated observations without environment
  interaction. The only counter is re-execution against the environment:
  k-of-n reproducibility (platform `verify.py` semantics), which is what
  the pipeline now enforces end-of-run (a candidate-only finding
  downgrades to `not_reproducible`).
- Mathematician's lens: a verdict is a reproducibility test — binomial
  k-of-n with a stability requirement, not a single observation; and the
  curation weights (verified 1.0 · transcript 0.5 · candidate 0.25 ·
  refuted → failure 1.0) form an evidence-strength scoring rule that the
  bandit consumes (E4). M4 makes that rule executable in exactly one
  place.
- Schwartz & Vassileva, *POMDP + Information-Decay* (ICAPS 2020): the
  environment is non-stationary (defender acts) — verdicts must be
  re-earned per run, never cached across runs (our store keeps technique
  posteriors, never finding verdicts).

**ExperienceStore** (AI-researcher + security-engineer lenses):
- AWM — Wang et al., *Agent Workflow Memory* (arXiv:2409.07429): induce
  reusable workflows from experience, selectively re-provision them;
  +24.6% / +51.1% relative success on Mind2Web / WebArena AND fewer steps.
  This is exactly the shape of our M5 exit criterion (run-2 request
  efficiency ≥ +20%) — AWM is the published existence proof that
  experience-as-workflow (not raw transcripts) is what pays.
- The user's mainline already routes around AWM's known risk (stale or
  poisoned memory): the prototype keeps target-agnostic insights only
  (M7/A3) and caps target-controlled credit at 0.5 (A2) — that is the
  "selectively provide" half of AWM, which is where their ablations say
  the value is.
- pentestkit ships "a persistent shared knowledge base" (vendor claim) —
  with the stale-context risk their own notes flag; our protocol + per-
  namespace posteriors + falsification-due insight rule (open, M5/G7) is
  the hedge.
- Security-engineer lens: the store is EVIDENCE, not state — every record
  carries the outcome weight rule's provenance, and nothing in it can
  grant a capability (policy reads nothing from memory: fail-closed stays
  memory-independent).

**Orchestrator itself**:
- Magentic-One's progress-ledger loop (already the Router, Phase C) and
  MAST's category-1 fix: machine-checkable specs enforced BEFORE dispatch
  (our `_contract_ok`: ≤8 skills, dispatch caps, typed triggers) — the
  failure class is "spec errors", so the spec is enforced, not hoped for.
- HackSynth (arXiv:2412.01778): planner/summarizer module split, "Our
  findings indicate … the importance of robust safeguards" — module
  boundaries beat monolith prompts.
- MITRE (Appelgate et al., *Automated Adversary Emulation: A Case for
  Planning and Acting*): planning must sit inside the acting loop with
  feedback — the Router + attack-graph rebuild (M3) already do this; M4
  adds the governance shell around it.

**What we adopt, explicitly**: deterministic governance shell (XBOW /
CALDERA / Magentic-One), per-action capability gate (CaMeL, at the
executor chokepoint), independent k-of-n validation with a downgrade pass
(platform verify.py + MAST + EnIGMA), experience as protocol-bounded
posteriors + curated insights (AWM + our poisoning guard).
**What we reject, with evidence**: LLM-as-orchestrator (MAST
inter-agent-misalignment category; the commercial leader's coordination
layer is deterministic); auto-approving write mutants for benchmark speed
(the ungoverned-cadence failure XBOW itself warns about); trusting model
self-reports or single observations as verdicts (EnIGMA soliloquizing);
memory that can influence policy (policy must stay memory-independent).

## R4. Design decisions (decision → mechanism → falsifiable test)

- **D1 Policy as an object, enforced at the executor chokepoint.** Every
  wire byte crosses `Executor.request/race/race_multi`, so the gate lives
  there: `policy.check_action(principal, method, path)` BEFORE connect.
  Denial is non-fatal (a synthetic Exchange with `policy_denied: true`,
  recorded to traffic) — one refusal must never kill an engagement, but
  every refusal is audited to `policy_audit.jsonl`. Test: `approvals=none`
  ⇒ zero state-changing requests leave the box, denials counted, run
  completes.
- **D2 One verdict vocabulary, one place.** The pipeline post-pass maps
  findings to `confirmed / verified-by-transcript / not_reproducible /
  refuted` (compatible with the platform's confirmed / not_reproducible /
  rejected); candidate-only ⇒ `not_reproducible`, and a downgraded finding
  cannot ship above informational. Test: synthetic candidate-only finding
  downgrades; verified keeps its verdict.
- **D3 ExperienceStore as a protocol.** `FileExperienceStore` (current
  byte-for-byte semantics: Beta posteriors, insight guard, history) and
  `InMemoryExperienceStore` (embedding/tests) both implement it; the
  orchestrator takes one by injection. Test: swap the store, outcomes land
  in it, lab results unchanged.
- **D4 One contract, two servers.** `Orchestrator.schema()` is the same
  dict as `registry_tool._schema()`; `registry_tool.run(ctx)` now
  DELEGATES to `Orchestrator.run(ctx)` — the registry path and the
  orchestrator path are the same code by construction. Test: dict
  equality + all three labs green through the new path.
- **D5 The refusal case is an artifact.** A `approvals=none` run ships in
  m4-results as the negative control — the "refusal cases" item the
  project charter (docs/competitor-landscape.md) says is still owed.
  Test: 0 findings, denials > 0, run completes inside budget.

## R5. Pre-registered predictions (scored in M4-PROOF)

- P1: Freightlane GV-1…GV-8 all verified through the Orchestrator path;
  `llm_seam_calls == 0`.
- P2: dvlba B1…B8 and meridian S1…S7 exact through the same path —
  findings sets equal to the M3 artifacts (the refactor changes no
  behavior).
- P3: `approvals=none` freightlane run → 0 findings, ≥ 20 audited denials,
  run completes within budget.
- P4: `Orchestrator.schema() == registry_tool._schema()` (dict equality).
- P5: the pipeline report lists the exact count of downgrades and
  verified-by-transcript promotions — honestly reported whatever it is.
- P6: run-2-with-run-1-memory request count is not worse than run-1 (M4
  guards non-regression; the ≥ +20% AWM-shaped claim stays M5's to
  measure).

## R6. What M4 does NOT do (bounds)

No LLM activation (M5), no GEPA strategy evolution (M5), no semantic
memory backend in the prototype (HelixDB stays platform-side; the protocol
is the seam), no OPSEC noise budget (the platform NoiseBudget exists; the
prototype keeps the global HTTP budget), no third lab (M6), and no change
to the Router's dispatch semantics (that machinery is proven; M4 wraps it,
it does not retune it).

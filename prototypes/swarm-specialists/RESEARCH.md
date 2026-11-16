# RESEARCH.md — How to make each specialist agent great, and better over time

**Phase C pre-build research digest** · 2026-11-04 · Verification discipline: `[F]` = fetched and read, `[H]` = headline/abstract or secondary source only, `[U]` = unverified (excluded from conclusions).

Two questions, per the build mandate:
- **Q1.** What makes a *specialist* agent genuinely great at its domain — not a generalist with a persona sticker?
- **Q2.** How does the swarm get **better over time** ("better time to time") without retraining?

Everything below was checked before a single line of the swarm prototype was written; §5 maps every adopted mechanism to the exact module that implements it.

---

## 1. Method

Queries run across arXiv, NeurIPS/OpenReview, vendor engineering blogs (Anthropic, Microsoft Research, Letta), the Berkeley Function-Calling Leaderboard, and primary papers of the named systems. Claims follow the dossier's `[F]/[H]/[U]` rule: numbers are quoted only where the source was actually read; secondary-source numbers are tagged `[H]` and never load-bearing alone.

---

## 2. Q1 — What makes a specialist agent great

**M1. Specialists = knowledge sources on a blackboard, triggered by board state — the 45-year-old proof this works.**
Hearsay-II (Erman et al., 1980) `[F]` — the first blackboard system — split speech understanding among independent *knowledge sources*, each with a **condition→action** contract: a KS fires when the blackboard holds a pattern it recognizes, writes partial results back, and never talks to the others directly. 2,400+ citations; the architecture survived because it makes *incremental, opportunistic* problem-solving debuggable: every contribution lands on a typed board with provenance. Verdict: **adopt as the routing substrate** — specialists declare triggers on typed facts; no specialist calls another directly.

**M2. Specification failures, not model failures, kill multi-agent systems.**
MAST — "Why Do Multi-Agent LLM Systems Fail?" (Cemri et al., 2025, NeurIPS spotlight) `[F]`: 1,600+ annotated traces across 7 frameworks, 14 failure modes in 3 categories, expert κ = 0.88. Secondary analysis `[H]`: ≈41.8% specification & system-design issues, ≈36.9% inter-agent misalignment, ≈21.3% task-verification failures (6.2% premature stop, 8.2% incomplete verification, 9.1% incorrect verification) — i.e. roughly four in five failures are *spec and coordination*, not model capability. Verdict: **adopt machine-checkable specialist contracts** — JSON-schema triggers, typed fact payloads, explicit budgets and stop conditions per specialist; treat specs like API contracts.

**M3. Orchestrator keeps ledgers and detects stalls by counter.**
Magentic-One (Fourney et al., 2024) `[F]`: an Orchestrator with a **task ledger** (facts, guesses, plan) and a **progress ledger** (per-step self-check: on track? stalled? who acts next?), with stall detection via counters and replanning through an outer loop; agents can be added/removed **without retuning**. Competitive on GAIA, AssistantBench, WebArena. Verdict: **adopt ledgers + stall counters** in the router; blackboard = task ledger, router loop = progress ledger.

**M4. Parallel subagents with isolated contexts are the compression win.**
Anthropic's multi-agent research system `[F]`: lead agent spawns subagents that work in **their own context windows** and return distilled findings — the system beat single-agent Opus 4 by **90.2%** on internal research evals, especially on breadth-first, parallelizable work. Explicitly framed: subagents = separation of concerns + context compression. Verdict: **adopt for full-autonomy spawning** — a specialist that spawns a sub-specialist gives it a *narrow task and its own budget*, and consumes only its distilled output (findings), never its raw transcript.

**M5. Dynamic expert recruitment beats fixed crews — but specialists must be robust to bad peer input.**
AgentVerse (Chen et al., ICLR 2024) `[F]`: an **expert-recruitment** stage re-composes the team per task phase; groups beat solo agents (HumanEval pass@1 83.5% → 89.0% with GPT-4). The caution: GPT-3.5 agents *degraded* in group math because they absorbed erroneous peer feedback. Verdict: **adopt per-phase recruitment** (the router only activates specialists whose triggers fired) and **isolate specialists from peer conclusions** — they read typed facts from the board, never other agents' reasoning traces; confidence comes from execution evidence, not peer assertion.

**M6. Skills verified before storage; unverified "learning" is poison.**
Voyager (Wang et al., 2023) `[F]`: an ever-growing **skill library of executable code**, indexed by description embeddings, retrieved top-5, **stored only after self-verification**, refined by an iterative prompting loop over environment feedback and execution errors. Results: 3.3× unique items, tech-tree milestones up to 15.3× faster, and the library transfers zero-shot to a new world; ablating it (19→36 iterations on diamond pickaxe; 3/3→2/3 success) shows the compounding. Verdict: **adopt "verify before promote"** — a technique/skill only counts as *learned* after independent verification (E3); unverified wins are weak evidence (E4).

**M7. Insight extraction from trajectories transfers — if kept abstract.**
ExpeL (Zhao et al., AAAI 2024) `[F]`: gather experiences → extract natural-language **insights** + retrieve successful trajectories; consistent gains, cross-task transfer, matches/beats Reflexion without repeated attempts. Environment-dependence shown: insights mattered most on HotpotQA (36% vs 31% retrieval-only), trajectory recall on ALFWorld (50% vs 55%). Verdict: **adopt insight curation per specialist namespace**, with the security-specific twist of E5 (target-controlled content is untrusted learning material).

**M8. Small, narrowly-scoped tool surface > big general tool belt.**
BFCL V4 `[F]` shows single-turn function calling is effectively saturated while **memory and dynamic multi-step decision-making remain the open failure surface** — and Anthropic's system `[F]` gives subagents *distinct tool sets* as a design principle. Tool-selection errors are exactly MAST's misalignment/verification classes. Verdict: **adopt minimal-scoped skills per specialist** — the statefuzz specialist exposes one tool, recon exposes four, nobody sees another's tools; smaller surface = fewer wrong-tool failures + smaller confused-deputy blast radius.

---

## 3. Q2 — Better over time: the improvement loop

**E1. Experience → posterior → technique ordering (cheapest loop).**
Their platform already runs a contextual bandit for technique selection; the research agrees it's the right first loop: ExpeL `[F]` shows performance compounds purely by accumulating and *recalling* experiences; Voyager's ablation `[F]` shows a learned library beats a fresh agent even on the same model. Verdict: **adopt a per-specialist bandit over its own techniques**, posterior updated at end-of-run from *verified* outcomes (see E3/E4), persisted to the specialist's memory namespace, and reloaded next run.

**E2. Prompt/program evolution with eval gates — the "skill CI" loop.**
GEPA (Agrawal et al., ICLR 2026 Oral) `[F]`: reflective **prompt evolution** from sampled trajectories beats GRPO by **6% average / up to 20% with up to 35× fewer rollouts**, and beats MIPROv2 by 10%+. DSPy's MIPROv2 `[H]` established the optimize-with-metrics pattern GEPA improves on. Verdict: **defer full prompt-evolution to a later phase** (needs an eval corpus per specialist — the Phase-A DVLBA corpus is the seed), but **structure the code so specialist heuristics are swappable strategy objects** today, which is the precondition for running GEPA/DSPy over them tomorrow.

**E3. Reflection must be grounded in external evidence — otherwise it hurts.**
Huang et al., "LLMs Cannot Self-Correct Reasoning Yet" (ICLR 2024) `[F]`: intrinsic self-correction *without external feedback* fails and sometimes **degrades** performance. This is the trap under every "reflect after each step" design. Verdict: **adopt grounded-only reflection**: the verify specialist re-executes findings with fresh principals (independent evidence), and only verified outcomes feed the bandit/insight loop. Un-reflectable facts are left as facts.

**E4. Evidence strength weighting — verified / unverified / refuted.**
Direct consequence of M6+E3: a technique outcome that produced a finding later *refuted* by verify must not be rewarded; unverified wins are weak evidence. Verdict: **adopt outcome weights**: verified = 1.0, unverified = 0.5, refuted = failure (β += 1). Curation runs at end-of-run ("sleep-time consolidation", below), not mid-run — mid-run credit assignment is exactly the noise MAST's verification failures capture.

**E5. Sleep-time consolidation over persistent memory.**
Sleep-time compute (Lin et al., 2025, Letta/Berkeley) `[F]`: offline "thinking" over persisted state cuts test-time compute ~5× at equal accuracy and adds up to 13–18% accuracy when scaled; **requires stateful agents** — insights vanish without persistent memory. Letta ships this as sleep-time agents over MemGPT-style memory `[F]`. Verdict: **adopt end-of-run consolidation**: after each engagement, each specialist's namespace is consolidated (outcomes → posterior updates; candidate insights appended only if target-agnostic), so the *next* run starts smarter — this is the demo-visible "better time to time."

**E6. Calibration: don't route on self-reported confidence.**
Verbalized-confidence research `[H]` (Tian et al. 2023; follow-ups) shows LLM self-confidence is usable but weakly calibrated, and the Nature MI 2026 analysis `[H]` treats verbal vs logit confidence as distinct measures. Verdict: **adopt execution-evidence routing**: the router trusts trigger matches + posterior means, never a specialist's self-declared confidence; where the LLM seam fires (hypothesis generation), its output enters the board as a *hypothesis with a prior*, which exploit must *test* before it can become a finding.

**Anti-patterns excluded (and why):**
- **A1 Ungrounded self-critique loops** — Huang et al. `[F]` shows degradation; also burns budget (Magentic-One needs stall counters precisely because reflection loops stall) `[F]`.
- **A2 Learning from attacker-controlled feedback** — security-specific: target responses (e.g., a 404 body, an openapi doc) can lie. Rule: facts derived from target-controlled content may *create hypotheses* but may **not** directly promote techniques to "learned"; only end-to-end verified outcomes can (poisoning guard, per M6).
- **A3 Memory bloat / cross-target overfitting** — ExpeL's insights are domain-abstract `[F]`; rule: insights must be target-agnostic or namespace-tagged per-target, and the namespace prunes to top-N by posterior evidence.

---

## 4. Synthesis — the specialist swarm for Red-Agentic-teams

**Specialist contract** (kills MAST class 1 by construction — M2): `name`, `states` owned, `triggers: [{fact_kind, predicate, priority}]`, `skills` (minimal, M8), `budget` (facts + HTTP requests), `memory_namespace`, `spawn()` with depth ≤ 1 (M4), stop conditions. Machine-checkable: the router refuses to dispatch a specialist whose contract is violated.

**Blackboard** (M1, M3): typed facts — `OBSERVATION, SURFACE, HYPOTHESIS, FINDING, ESCALATION, CONTROL` — each with `source` provenance chain (`"exploit/statefuzz_spec"` on spawn), `derived_from` ids, confidence. Board = task ledger; router prints it per round (progress ledger) with stall counters (M3).

**Router** (M1, M3, M5, E6): fires specialists by trigger match + priority; tie-breaks by posterior mean (E1); LLM seam only for hypothesis generation and router tie-break at max-entropy points; escalation on 2 consecutive no-output rounds; hard round cap.

**Improvement loop** (E1, E3–E5): run → findings → verify (grounded, E3) → outcome weights (E4) → end-of-run consolidation into per-specialist namespaces (E5) → next run reorders techniques (E1). Demo proves it: **run 2 on the same target is measurably leaner** (fewer dead-end requests, reordered technique execution) purely from run 1's persisted experience.

**Statefuzz as the first hard specialist** (M8): the Phase-B tool becomes the `LOGIC` state's skill, spawned by exploit when the FSM hypothesis is confirmed — real sub-specialist autonomy with real provenance (`exploit/statefuzz_spec`) stamped on every finding.

---

## 5. Traceability — mechanism → module → test

| Mechanism | Source | Module | Test |
|---|---|---|---|
| M1 blackboard triggers | Hearsay-II `[F]` | `swarm/blackboard.py`, `router.py` | `test_router_dispatches_by_trigger` |
| M2 typed contracts | MAST `[F]` | `specialist.py` (contract validation) | `test_contract_violation_refused` |
| M3 ledgers + stalls | Magentic-One `[F]` | `router.py` (`ledger()`, stall counter) | `test_stall_escalates_then_stops` |
| M4 spawn w/ isolation | Anthropic `[F]` | `specialist.py::spawn`, `router.py` | `test_spawn_depth_limit`, e2e `statefuzz spawn` |
| M5 per-phase recruitment | AgentVerse `[F]` | `router.py` (trigger-gated activation) | e2e trace: recon first, logic last |
| M6 verify-before-learn | Voyager `[F]` | `specialists/verify.py` + curation | `test_refuted_finding_penalizes_technique` |
| M7 insight curation | ExpeL `[F]` | `memory.py::curate` | `test_insights_target_agnostic` |
| M8 minimal skill surface | BFCL/Anthropic `[F]` | specialists' `skills` dicts | `test_skill_scope` |
| E1 per-specialist bandit | ExpeL/Voyager `[F]` | `memory.py::MemoryNamespace` | `test_bandit_reorders_after_outcomes` |
| E3 grounded reflection | Huang `[F]` | `verify.py` (fresh principals) | e2e: every finding has verification stamp |
| E4 outcome weights | M6+E3 | `registry_tool.py` (curation step) | `test_outcome_weights` |
| E5 end-of-run consolidation | Sleep-time `[F]` | `registry_tool.py` (post-run) | e2e run-2 leaner than run-1 |
| E6 no self-confidence routing | Tian `[H]` | `router.py` (evidence-based) | `test_no_self_confidence_routing` |
| A2 poisoning guard | M6 + security | `memory.py::record` (weight rule) | `test_poisoning_guard` |

---

## 6. References

1. Erman et al., *The Hearsay-II Speech-Understanding System*, 1980 — `[F]` faculty.chas.uni.edu/~wallingf/teaching/162/readings/hearsay-ii.pdf
2. Cemri et al., *Why Do Multi-Agent LLM Systems Fail?* arXiv:2503.13657, NeurIPS 2025 spotlight — `[F]` arxiv.org/abs/2503.13657; percentages `[H]` futureagi.substack.com analysis
3. Fourney et al., *Magentic-One*, arXiv:2411.04468 — `[F]` arxiv.org/abs/2411.04468 + microsoft.com research article
4. Anthropic, *How we built our multi-agent research system* — `[F]` anthropic.com/research/multi-agent-research-system
5. Wang et al., *Voyager*, arXiv:2305.16291 — `[F]` arxiv.org/abs/2305.16291 + voyager.minedojo.org
6. Zhao et al., *ExpeL*, arXiv:2308.10144, AAAI-24 — `[F]` arxiv.org/abs/2308.10144 (+ html full text)
7. Huang et al., *LLMs Cannot Self-Correct Reasoning Yet*, arXiv:2310.01798, ICLR 2024 — `[F]` arxiv.org/abs/2310.01798
8. Agrawal et al., *GEPA*, arXiv:2507.19457, ICLR 2026 Oral — `[F]` arxiv.org/abs/2507.19457 (v2 abstract)
9. Lin et al., *Sleep-time Compute*, arXiv:2504.13171 — `[F]` arxiv.org/abs/2504.13171 + letta.com/blog/sleep-time-compute
10. Chen et al., *AgentVerse*, arXiv:2308.10848, ICLR 2024 — `[F]` alphaxiv.org/abs/2308.10848
11. Patil et al., *Berkeley Function-Calling Leaderboard V4* — `[F]` gorilla.cs.berkeley.edu/leaderboard.html (accessed 2026-11)
12. Tian et al., *Just Ask for Calibration*, EMNLP 2023 — `[H]` (search snippets only)
13. Phase A dossier (this project): 12-system survey, DVLBA corpus, S8/S9 theory — prior verified base for statefuzz-as-specialist.

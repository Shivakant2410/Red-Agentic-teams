# PI Gap Research — what is still missing in prompt injection (2026-11)

Grounded gap analysis for the `redteam/pi` capability: the field's current state
(OWASP LLM01:2026, ATLAS 2026.07, 2025-2026 arXiv literature) checked against
what this repo actually implements, file:line by file:line. Not generic: every
gap below names the external evidence, the exact repo state, and the build.

## Method

1. Repo ground truth re-verified at commit `9e17408` (all 7 pi commits landed:
   oracles → app_target → techniques → runner/bench → integration → docs →
   RESISTED-gate test). Working tree is mode-only diffs; no code changes.
2. Local paper corpus re-inventoried (`/work/papers`, 23 files). Only 10 are
   PI-core: Greshake 2302.12173, Liu 2306.05499, GPTFuzzer 2309.10253,
   HarmBench 2402.04249, InjecAgent 2403.02691, Spotlighting 2403.14720,
   AgentDojo 2406.13352, AgentPoison 2407.12784, PI 2.0 2507.13169, GAPo
   (gap.txt). The rest are pentest/agent-exploit papers (VulnBot, PentestEval,
   ToolRL, healthcare scheduling — the last is off-topic entirely).
3. Web research on the 2025→2026 field shift (sources listed at the end).
4. Every claim about the repo was verified with grep/read on the current tree.

## Executive verdict

The implemented spec already matches or beats the 2024-2025 state of the art on
verdict discipline (earned RESISTED), deterministic oracles, and provenance.
What is missing is the **2026 shift**: the field stopped treating prompt
injection as a per-interaction event and moved to **persistent agent state**
(memory, cross-session, tool metadata) and **adaptive attackers**. Against that
shift the repo has three structural holes and eight coverage gaps. The single
sharpest finding: **`CanaryStage.PERSISTED` is a dead enum stage** — defined,
ordered, probed, and structurally unreachable, because the victim app has no
memory surface and no technique targets one.

## What changed in the field since our spec was written

| Shift | Evidence | Our spec's assumption |
|---|---|---|
| Formal impossibility result | Abdelnabi & Bagdasarian, "AI Agents May Always Fall for Prompt Injections" (arXiv 2605.17634, May 2026): contextual-integrity framing; data-instruction separation cannot distinguish legitimate in-data instructions from injected ones; 3 attack classes: misrepresent flows / manipulate norms (slow-burn) / mix flows | Our spec treats separation-style defenses as the "hardened" pole and measures benign completion — but with instruction-free benign docs (see G5) |
| Adaptive attackers beat static sets | Swept AI + UMich, "Evaluation of Prompt Injection Defenses" (arXiv 2604.23887, Apr 2026): agentic adaptive attacker, 20,000+ attacks, 9 defense configs — every model-reliant defense broke; only deterministic application-code output filtering held (0/15,000); "short-run evaluations are misleading". NIST CAISI: adaptive attacks raised one agent's success 11%→81%. OWASP LLM01:2026 prevention: "test against adaptive attackers, reject static-only attack-success claims" | Our runner is a fixed grid — selection over a static registry, no generation loop |
| Cross-session stored PI (XSPI) | "What If Prompt Injection Never Left?" (arXiv 2606.04425, Jul 2026): XSPI — stored-XSS analog; instructions persist in memories/filesystems/tools and fire in later sessions. MemHarmBench (arXiv 2611.01700, Nov 2026). eTAMP (arXiv 2604.02623): cross-session, cross-site poisoning via environment alone. Systematic memory-poisoning study (arXiv 2606.04329): "existing prompt injection defenses fail to cover memory poisoning" | Our spec has the PERSISTED canary stage but no scenario that can reach it |
| OWASP LLM01:2026 published | New scenarios #6 (steganographic multimodal), #7 (zero-click document-borne agentic exfiltration), #8 (agentic destructive command execution), #9 (trusted-backend MCP injection); new preventions: Rule of Two, memory writes as privileged ops, MCP package pinning/signing/auditing, adaptive-attacker testing. Also LLM02:2026 split (PI vs sensitive-info disclosure) | Our metadata pins OWASP LLM01:2025 only |
| MCP/tool-metadata as injection surface | arXiv 2603.22489 (Mar 2026): client-side PI via tool descriptions; MCP-SafetyBench (>80% host-side ASR); tool poisoning framed as supply-chain attack on the context window | No tool-description channel exists in the delivery registry |
| Attack-space taxonomy realignment | PIAtlas (arXiv 2610.24999, Oct 2026): 20+ datasets use incompatible vocabularies; datasets organized by delivery vector/goal/generation under-cover; "adaptive attackers favor mechanisms curated benchmarks underrepresent"; 6 classes by subversion mechanism + PICorpus | Our families A-E are organized by delivery vector — exactly the organization PIAtlas flags |
| Fixture-vs-live honesty | RAS-Eval: under real execution failure modes double (16→32) and task completion drops 36.8%; AgentDyn: CaMeL utility 0% under environment change, SecAlign 80%→53.35%, PromptGuard2 passes 27.15% of attacks; WASP "security by incompetence" (86% partial) | Our bench is fixture-only by design; honest contract exists (pi/__init__.py:15-18) but numbers carry no degradation bound |

## Gap register

### G1 — PERSISTED canary stage is dead (P0, spec-internal contradiction)
- **Field:** XSPI, MemHarmBench, eTAMP, memory-poisoning study, AgentPoison
  (already cited in our provenance!), OWASP LLM01:2026 scenario #4 + prevention
  "treat agent memory writes as privileged operations".
- **Repo state:** `oracles.py:36-38,74-82` defines PERSISTED and its ordering;
  `runner.py:266-269` runs a persistence probe (`runner.py:175-177`) into a
  fresh session on the same app. But `app_target.py` has **no memory surface**
  (grep: zero hits for memory/note/store), and no technique in `techniques.py`
  plants into persistent state (grep: zero hits). The probe asks the model to
  recall; the fixture has nothing to recall from. The stage ladder
  EXPOSED→PERSISTED→RELAYED→EXECUTED is 3/4 live.
- **Build:** (a) `LLMAppConfig` gains a memory store with write + recall paths;
  (b) family B gains a two-phase technique (plant into memory in session 1,
  pivot in session 2) — requires a two-visit protocol in `_run_cell`, not the
  fixed probe string; (c) hardened app models OWASP 2026 prevention: memory
  writes containing instructions require approval (a new `IOPolicy` flag);
  (d) bench reports per-stage coverage so dead stages are visible.

### G2 — Static technique grid; no adaptive attacker loop (P0)
- **Field:** arXiv 2604.23887 (static sets overestimate defense; only
  deterministic app-code boundaries held), arXiv 2606.26479 (adaptive eval of
  out-of-band defenses; white-box GCG still untested anywhere), NIST CAISI
  11%→81%, OWASP LLM01:2026 prevention #5 (test adaptively, disclose defense
  spec to testers).
- **Repo state:** `runner.py:203-208` — `cells = [(t, mode) for t in
  self.techniques for mode in self.cfg.defense_modes]`: fixed enumeration, no
  feedback, no generation. The bandit lives in `llmred/campaign.py` but pi does
  not use it, and even that is selection-only. GPTFuzzer is in our provenance
  but we carry its payloads, not its mutator.
- **Build:** `adaptive: true` mode in `PIEngagementConfig`: attacker loop
  consumes oracle verdicts + failure reasons and mutates payload templates via
  deterministic operators (rephrase / encode / nest / authority-claim /
  split-across-channels); `defense_spec_visible` flag implements the OWASP 2026
  disclosure requirement. Deterministic (seeded) so bench stays reproducible.

### G3 — MCP / tool-description poisoning channel absent (P1)
- **Field:** OWASP LLM01:2026 scenario #9 (trusted-backend injection through
  MCP: GitHub issues, support tickets, npm), prevention #4 (pin, sign, audit
  tool descriptions for hidden instructions), arXiv 2603.22489,
  MCP-SafetyBench, tool poisoning as context-window supply-chain attack.
- **Repo state:** delivery registry `techniques.py:48-67` has 7 channels
  (user_message, rag_document, web_page, email, tool_output, search_result,
  plan_field). None is tool metadata. The forbidden-tool oracle tests the
  *call* side; the *source* (a trusted-looking tool description) is unmodeled.
  Rug-pull (description changes between approval and call) is unmodeled too.
- **Build:** `tool_description` channel; a fixture tool whose description
  carries the payload; a rug-pull variant using a stateful tool registry
  (description v1 approved → v2 poisoned before first call). The call-side
  oracle already exists — only the channel is new.

### G4 — Encoding coverage: A6 is base64/rot13; field moved to unicode smuggling (P2)
- **Field:** OWASP LLM01:2026 explicitly names "multilingual, encoded,
  low-resource-language payloads" as classifier evasion; Unicode-tags (U+E0000)
  and zero-width smuggling are established in real incidents (Copilot exfil);
  steganographic injection (scenario #6).
- **Repo state:** `techniques.py:228-241` — A6 wraps payloads in base64/rot13
  only; canary matching sees through those same encodings (oracles.py). No
  unicode-tags, no zero-width, no code-mixed-language variant.
- **Build:** extend A6 payload templates with tag-encoded and zero-width
  variants; extend `is_canary_shaped`/`canary_hits` to decode U+E0000 runs —
  deterministic, small, and it keeps the "detection must see through the same
  encodings" contract stated in A6's own description.

### G5 — Benign control is instruction-free; the exact case defenses break on is untested (P0)
- **Field:** arXiv 2605.17634's core impossibility: a defender that tightens
  norms blocks *legitimate* in-data instructions; AgentDyn shows defenses'
  utility collapsing (CaMeL 0% under environment change) — over-blocking is
  the field's measured failure mode.
- **Repo state:** `bench.py:15-17,46-49` measures benign completion; runner
  controls check benign task completion — but the benign document contains no
  instructions, so a defense that ignores all document content earns RESISTED
  trivially. This is precisely the blind spot the impossibility result names.
- **Build:** second control type: benign doc containing a *legitimate
  contextual instruction the agent should honor* ("format the notes as a
  numbered list"). New metric `legit_instruction_compliance`; earned-RESISTED
  requires it alongside benign completion. Cheap, deterministic, and it turns
  the 2026 impossibility result into a runnable test.

### G6 — RELAYED evidence under-typed; exfiltration channels unmodeled (P2)
- **Field:** OWASP LLM01:2026 scenario #7 (zero-click document-borne agentic
  exfiltration); markdown-image / DNS / outbound-request exfil channels.
- **Repo state:** `oracles.py:38-39` defines RELAYED as canary moving through
  model output, but evidence is not typed per channel (echo vs file-write vs
  outbound request); the fixture app has no outbound-request recording surface.
- **Build:** typed relay evidence enum; fixture app records outbound requests;
  a payload variant demanding a canary-carrying request to a
  canary-tokened-destination (`{canary}.exfil.invalid`), so RELAYED evidence is
  channel-specific and the negative control proves the destination was never
  contacted.

### G7 — Multimodal: honest skip, but skips are not evidence-linked; fun-tuning vector missing (P2)
- **Field:** Invisible Injections (Jul 2025): 24.3% ASR across GPT-4V/Claude/
  LLaVA; AgentTypo adaptive typographic injection; AudioHijack (2026):
  inaudible audio-borne instructions; steganographic injection vs 8 VLMs;
  OWASP 2026 scenario #6. Fine-tuning API as gradient oracle ("fun-tuning") is
  a new named vector.
- **Repo state:** family D = capability-gated skip records (design decision #5)
  — correct for an offline fixture, but skip records carry no pointer to the
  external evidence they stand in for, and the live-model lane
  (`OpenAIToolLoop`) has no documented multimodal extension point.
- **Build:** skip records gain `evidence` (paper + reported ASR + why the
  fixture cannot represent it) and `live_lane` pointer; fun-tuning enters the
  registry as a gated-skip technique with provenance. No faked multimodal
  fixtures.

### G8 — Standards metadata pinned to 2025 (P0, cheap)
- **Field:** OWASP LLM01:2026 published (GenAI-LLM-Top10 2026/final); ATLAS
  verified current through data release 2026.07 — T0051 .000/.001/.002
  (direct/indirect/triggered) unchanged, so no ATLAS drift, but the OWASP
  anchor is stale and the new scenarios/preventions are unmapped.
- **Repo state:** `techniques.py` + ROADMAP anchor "OWASP LLM01:2025";
  ATLAS T0051/T0054 anchors verified/inferred split exists.
- **Build:** dual-pin OWASP 2025+2026 with per-technique scenario mapping
  (A→direct-user scenarios, B→#4/#7/#9, D→#6, E→#8); Rule-of-Two statement
  into `app_target` defense-config docs (it is essentially what `IOPolicy`
  enforces — say so in the anchor text).

### G9 — Delivery-vector taxonomy vs PIAtlas construction-mechanism taxonomy (P1)
- **Field:** PIAtlas (arXiv 2610.24999): benchmarks organized by delivery
  vector under-cover the mechanisms adaptive attackers actually favor; 6
  subversion-mechanism classes; PICorpus release.
- **Repo state:** families A-E are delivery-organized — the exact organization
  PIAtlas flags. We cannot currently answer "which subversion mechanisms have
  zero techniques here?"
- **Build:** add a `piatlas_class` field to `PITechnique`; a coverage audit
  (CLI flag on bench) prints per-mechanism counts and names the empty ones;
  map PICorpus records to technique IDs as the mapping source. This is the
  audit that would have surfaced G1/G3/G5 on its own.

### G10 — Fixture numbers carry no honesty bound (P1, cheap)
- **Field:** RAS-Eval (failure modes double, completion −36.8% under live
  execution); AgentDyn (defense utility collapses under environment change);
  benchmark saturation/contamination concerns (AgentDojo lineage).
- **Repo state:** `bench.py` emits fixture metrics; `pi/__init__.py:15-18`
  declares the offline contract — but the bench output itself does not carry
  the caveat, has no held-out payload split, and no environment-mutation axis.
- **Build:** bench output gains (a) an `honesty` block (fixture-only flag,
  payload-library-public note, saturation warning), (b) a held-out split of
  the payload library (obfuscated variants not in the public registry) so
  contamination cannot self-score, (c) an environment-shift axis: same
  defense config, mutated env fixture — the deterministic analog of what
  AgentDyn does live.

### G11 — No multi-turn escalation techniques (P2)
- **Field:** arXiv 2605.17634 attack class 2 ("manipulating norms — slow-burn
  recalibration over time"); GAPo stealthy generation; temporal evasion
  benchmark (arXiv 2605.22321).
- **Repo state:** every technique renders one payload and gets one reply
  (`runner.py:270-273`); no thread-level protocol.
- **Build:** family E gains a two-turn technique (turn 1: benign-seeding
  document establishing a "format convention"; turn 2: pivot referencing it);
  `_run_cell` gains a thread protocol (list of sends per technique). Combined
  with G1's two-phase protocol, one mechanism serves both.

## Where we are already ahead (do not churn)

1. **Earned RESISTED with benign + negative controls** — directly counters the
   "static benchmark / always-refuse looks safe" trap the 2026 papers measure.
2. **Deterministic oracles + judge-annotate-only** — matches arXiv 2604.23887's
   conclusion that security boundaries belong in application code, not the
   model being attacked.
3. **Defense differential + benign completion as first-class metrics** — most
   published benchmarks still omit one of the two.
4. **Versioned payload registry with provenance** — answers the reproducibility
   critique in the benchmark-measurement literature.
5. **Honest capability-gated skips** instead of faked modality coverage.

## Prioritized build order

| P | Gap | Why first |
|---|---|---|
| P0 | G1 dead PERSISTED stage | spec-internal contradiction; the field's #1 2026 shift |
| P0 | G5 instruction-bearing benign control | turns the impossibility result into a runnable test; guards against RESISTED inflation |
| P0 | G8 standards dual-pin | trivial cost, metadata correctness |
| P1 | G2 adaptive attacker mode | OWASP 2026 prevention requirement; the biggest metric-credibility lever |
| P1 | G3 MCP/tool-description channel | new named scenario; channel-only change, oracle already exists |
| P1 | G9 PIAtlas mechanism mapping + coverage audit | would have caught G1/G3/G5 mechanically |
| P1 | G10 bench honesty block + held-out split | cheap; publishes what our numbers actually measure |
| P2 | G4 unicode/multilingual encodings | small extension of A6 + canary decoder |
| P2 | G6 typed RELAYED / exfil channels | evidence typing + fixture outbound surface |
| P2 | G7 evidence-linked skips + fun-tuning vector | honesty infrastructure for the live lane |
| P2 | G11 multi-turn threads | shared protocol with G1 |

## Sources

External (opened/retrieved 2026-11-11):
- arXiv 2605.17634 — AI Agents May Always Fall for Prompt Injections (CI impossibility)
- arXiv 2604.23887 — Evaluation of Prompt Injection Defenses in LLMs (adaptive attacker, 20k+ attacks)
- arXiv 2606.26479 — Adaptive Evaluation of Out-of-Band Defenses (Progent, CaMeL/FIDES/RTBAS/FORGE context)
- arXiv 2606.04425 — What If Prompt Injection Never Left? (XSPI)
- arXiv 2611.01700 — MemHarmBench (cross-session PI benchmark, Nov 2026)
- arXiv 2604.02623 — eTAMP (environment-injected cross-session memory poisoning)
- arXiv 2606.04329 — Systematic study of memory poisoning (defenses fail to cover it)
- arXiv 2610.24999 — PIAtlas / PICorpus (attack-space decomposition)
- arXiv 2603.22489 — MCP client threat modeling (tool-description PI)
- arXiv 2509.05883 — Multimodal PI attacks and defenses
- OWASP GenAI-LLM-Top10 2026/final/LLM01_PromptInjection.md (scenarios #6-#9, Rule of Two, adaptive-testing prevention)
- MITRE ATLAS T0051.001 (D3FEND mirror) + atlas-data release 2026.07 (no sub-technique drift)
- aminrj.com benchmark measurement review (AgentDojo/ASB/InjecAgent/WASP/MCP-SafetyBench/RAS-Eval/AgentDyn conditions table)
- Secondary: cipherssecurity.com impossibility writeup, securelayer7 exfil overview, NIST CAISI adaptive-attack statistic (via stingrai.com stats roundup)

Internal: commits 715f444..9e17408; local corpus `/work/papers` (PI-core list above).

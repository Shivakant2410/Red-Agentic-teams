# Attack chains — Prompt Injection -> Agent Action -> Exfiltration

**Group `ai_agent_hijack`** · 4 chain(s) · folder `chains/ai_agent_hijack/`

An LLM app is a web app whose parser speaks English. This group walks from an injection foothold through the agent's action plane (tool calls, MCP metadata, memory, sub-agents) to a demonstrated exfiltration or destructive action — the AI equivalent of injection-to-RCE.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `injection-to-tool-abuse` | Injection -> goal hijack -> tool-call hijack -> markdown exfil | 4 | CWE-1427, CWE-200 |
| `mcp-poisoning-to-hijack` | MCP tool poisoning -> rug pull -> rogue sub-agent -> irreversible action | 4 | CWE-345, CWE-269 |
| `rag-poison-to-exfil` | RAG poisoning -> cross-tenant bleed -> prompt extraction -> cross-session leak | 4 | CWE-1427, CWE-863 |
| `jailbreak-to-client-xss` | Encoding bypass -> refusal suppression -> persona -> output XSS | 4 | CWE-1427, CWE-79 |

## Shared recon for this group (how to find candidates at all)

- **LLM surface inventory** — Enumerate every chat/completion endpoint (JS bundles, OpenAPI specs, mobile API diff, bot frameworks: Slack/Teams webhooks), note streaming vs JSON, system-prompt hints in UI copy.
- **System-prompt canary planting** — Where operator access exists (your own staging), plant a unique canary string in the system prompt; on black-box engagements plant it in memory/profile fields the agent stores. Every exfil test then has a provable secret.
- **Tool & MCP census** — Ask the agent 'what tools do you have' variants, read MCP server configs in public repos/dotfiles, list tool names + description shapes; hash tool metadata for later rug-pull comparison.
- **RAG corpus census** — Probe what the app can cite: ask for sources/versions, seed unique query phrases and watch retrieval, map tenant scoping by cross-account prompt pairs.
- **Guardrail fingerprinting** — Send the refusal-suppression and encoding twins; diff refusal phrasing to fingerprint which layer refused (model training vs input filter vs output filter) — each layer falls to a different bypass.

## Chain playbooks

### Injection -> goal hijack -> tool-call hijack -> markdown exfil — `injection-to-tool-abuse`

**Goal.** Turn untrusted content into a completed attacker objective: the agent adopts the hijacked goal, calls a tool with attacker arguments, and walks the data out through a renderer-fetched image URL.
**Preconditions.** Any agent/LLM feature that ingests untrusted text (document summary, email triage, web research) and can invoke tools or emit rich output.
**Impact.** Silent data exfiltration from the victim's context with no malicious request ever sent by the attacker directly — the agent does the theft.
**CWE.** CWE-1427, CWE-200 · **Fallbacks.** `mcp-poisoning-to-hijack`, `rag-poison-to-exfil`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `ai/Indirect injection via untrusted content` | Prove untrusted content steers the model (lethal trifecta leg 2). | Record the injection channel; escalate from marker to objective next. | Content sanitized -> try delimiter confusion and payload splitting; email/OCR/alt-text as alternate carriers. |
| 2 | `ai/Goal hijack untrusted content` | Prove the agent's PLAN is replaced, not merely annotated — objective-level control. | Save the divergent plan as the impact narrative. | Plan intact -> check for narrower instruction-following (step 3 still viable). |
| 3 | `ai/Tool-call hijack via injected directive` | Convert hijacked intent into a concrete attacker-argumented tool invocation. | Capture the tool-call JSON as the action-plane evidence. | Tools not exposed to this endpoint -> map other agent surfaces (MCP census) or fall back to output-plane exfil (step 4). |
| 4 | `ai/Markdown image exfil channel` | Prove the external-communication leg: a renderer-fetchable URL embedding the planted canary completes the trifecta. | Full-chain impact: private data + untrusted content + exfil channel all proven. | Renderer blocks remote images -> enumerate other egress (link previews, emoji loads, error-report beacons); document the honest gap if none. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- document/PDF import & summarize features
- email/chat triage bots
- web-research & citation features
- customer-support copilots
- code-review bots ingesting PRs
- calendar/CRM assistants

**Recon methods** — techniques beyond the skill itself:

- **Untrusted-source mapping** — List every text source the agent reads that an outsider can write (docs, emails, tickets, web pages, PR comments) — each is an injection canal. Tooling: manual feature walk + JS bundle reading. Signal: Any render/summarize of attacker-writable content..
- **Tool-discovery prompts** — Ask capabilities directly and obliquely ('how would you send that?'); tool names leaked in errors reveal the action plane. Tooling: manual + redteam/Jenkins-style error mining. Signal: Tool/function names, argument shapes, approval model..
- **Renderer census** — Identify where agent output is rendered richly (web UI, markdown email, Slack unfurl) — each renderer is potential exfil egress. Tooling: manual. Signal: Markdown/HTML rendering with image/link fetching..
- **Canary rehearsal** — Plant prompt_canary, run the full chain on your own tenant, confirm every hop fires before touching production targets. Tooling: staging + ai skills. Signal: Chain completes end-to-end in rehearsal..
- **Cross-user state probing** — Check whether injected content in user A's artifacts can reach user B's agent sessions (shared docs, public repos) — that upgrades single-victim to fleet-scale. Tooling: two-account harness. Signal: Cross-principal propagation..

**Class variants** — other places the same weakness hides:

- email/OCR/alt-text carriers for the payload
- memory-mediated injection (poison memory, trigger later)
- agent-to-agent relay through helper bots
- JSON-mode confusion to smuggle directives past filters
- tool-argument confusion (attacker sets recipient, not action)

**Dorks**:

- github: "system_prompt" "tools" agent config
- github: mcp.json tools server list
- google: inurl:chat "assistant" site:target.tld

**Pivot hints** — where to go after proof:

- pair with mcp-poisoning-to-hijack when the agent consumes MCP servers
- exfil channel doubles as C2 proof for the report narrative
- rag-poison-to-exfil when injection via corpus is quieter than per-request

**Sources.** Simon Willison — the lethal trifecta (private data + untrusted content + external communication); OWASP Top 10 for Agentic Applications 2026 — ASI01 agent goal hijack, ASI02 tool misuse; OWASP LLM Top 10 2025 — LLM01 prompt injection; documented exfil-attack writeups (Microsoft 365 Copilot, GitHub MCP server, GitLab Duo)


### MCP tool poisoning -> rug pull -> rogue sub-agent -> irreversible action — `mcp-poisoning-to-hijack`

**Goal.** Compromise the agent through its OWN tooling supply chain: poisoned metadata steers future behavior, silent post-approval mutation locks it in, an unapproved sub-agent bootstraps capability, and an irreversible action lands with no confirmation gate.
**Preconditions.** The agent consumes MCP servers (or any dynamically-described tool registry) and can spawn helper processes.
**Impact.** Persistent agent compromise that survives tool re-installation, with destructive side effects the human approved in a different tool's name.
**CWE.** CWE-345, CWE-269 · **Fallbacks.** `injection-to-tool-abuse`, `cross-origin-action-suite`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `ai/MCP tool poisoning description injection` | Prove tool metadata carries executable-against-the-agent directives. | Record the poisoned directive text as supply-chain evidence. | Metadata clean -> check MCP resources/prompts surfaces; else fall back to injection-to-tool-abuse. |
| 2 | `ai/MCP rug pull hash delta` | Prove the tool can silently mutate AFTER approval — json_differs between the two fetches is the machine-checkable pull. | Freeze both metadata versions as evidence; the trust model is broken. | Metadata stable -> approval is per-call; note residual poisoning risk and continue. |
| 3 | `ai/Rogue sub-agent spawn` | Prove the agent can bootstrap capability outside its approved tooling. | Escalation primitive established: arbitrary capability on demand. | Spawn allow-list solid -> try tool-argument hijack for equivalent reach. |
| 4 | `ai/Excessive agency irreversible action` | Prove the destructive end-state: no confirmation gate between agent decision and production effect. | Full-chain impact: supply-chain foothold -> unapproved capability -> irreversible production action. | Confirmation enforced -> document least-agency gap as defense that works; test confirmation-fatigue variant. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- MCP client configs (.mcp.json, claude/cursor configs in repos)
- plugin/extension marketplaces
- agent harness bootstrap scripts
- internal tool registries
- CI-installed agent dependencies

**Recon methods** — techniques beyond the skill itself:

- **MCP config archaeology** — Search public and customer-provided repos for MCP client configs and server URLs; each server is a supply-chain node. Tooling: github dorks + gitleaks-style scans. Signal: Server endpoints the agent trusts implicitly..
- **Metadata versioning check** — Fetch tools-list twice over time (or across replicas) and diff descriptions/parameter schemas — instability predicts rug-pull capability. Tooling: ai/MCP rug pull hash delta. Signal: Any drift in tool metadata..
- **Approval-model interrogation** — Map what the human approves: per-tool, per-call, per-session? Ask the agent and observe confirmation prompts during harmless actions. Tooling: manual + excessive-agency skill. Signal: Missing or over-broad approval gates..
- **Server-side trust audit** — For your own MCP server, ship description directives and verify whether the client agent obeys them — proves the metadata channel is live. Tooling: controlled MCP server + test agent. Signal: Agent follows directives embedded in descriptions..
- **Spawn-capability probe** — Request tasks that exceed current tools; watch whether the agent improvises new executors (sub-agents, scripts, plugins). Tooling: rogue-subagent-spawn skill. Signal: Bootstrap behavior without approval..

**Class variants** — other places the same weakness hides:

- name-collision tool shadowing (legit-looking tool replaces a real one)
- cross-server trust contamination via shared memory
- poisoned tool OUTPUTS (response-content injection)
- dependency confusion on agent packages
- config-file tampering on shared agent hosts

**Dorks**:

- github: filename:.mcp.json
- github: "mcpServers" command args
- shodan: content-length:0 http.status:405 mcp

**Pivot hints** — where to go after proof:

- chain into cloud_takeover when the agent holds cloud credentials
- rug-pull evidence supports a supply-chain finding with CVE-grade severity
- pair with recon-secrets-to-cloud for the operator's own exposure

**Sources.** Invariant Labs — MCP tool poisoning research (2025); MCP security research — rug pull / post-approval tool mutation (2025); OWASP Top 10 for Agentic Applications 2026 — ASI04 supply chain, ASI10 rogue agents; OWASP LLM Top 10 2025 — LLM03 supply chain, LLM06 excessive agency


### RAG poisoning -> cross-tenant bleed -> prompt extraction -> cross-session leak — `rag-poison-to-exfil`

**Goal.** Attack the retrieval plane end to end: plant poisoned corpus content, ride tenant-isolation failures to foreign data, extract operator configuration, and close with memory that leaks across sessions.
**Preconditions.** A RAG-backed assistant with a corpus an outsider can influence (uploads, shared docs, public ingestion) or multi-tenant vector storage.
**Impact.** Persistent misinformation at policy confidence, cross-tenant data exposure, and operator-configuration disclosure — all through the data plane, no code exec needed.
**CWE.** CWE-1427, CWE-863 · **Fallbacks.** `injection-to-tool-abuse`, `graphql-recon-to-exfil`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `ai/RAG document poisoning retrieval` | Prove planted corpus content wins retrieval and gets asserted as truth. | Note retrieval confidence and citation behavior; scale to the objective you want asserted. | Corpus read-only -> skip to step 2 (bleed needs only query access). |
| 2 | `ai/Cross-context retrieval bleed` | Prove tenant scoping fails at query time — foreign-tenant canary in your answer. | Data-plane authz finding; enumerate what else is reachable. | Scoping solid -> corpus-poisoning evidence alone carries the finding. |
| 3 | `ai/System prompt direct extraction` | Upgrade from data to configuration: pull the operator's system prompt (LLM07). | Feeds jailbreak crafting and injection targeting for the report. | Extraction hardened -> use planted documents (ai/RAG planted document exfil) as the indirect route. |
| 4 | `ai/Cross-session leakage` | Prove memory/session isolation failure — what one session plants, another reads. | Persistence primitive: leaks become durable, not one-shot. | Sessions isolated -> document retrieval-plane findings; memory hardening is the fix note. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- document upload → indexing pipelines
- shared knowledge bases / wikis the assistant reads
- multi-tenant help centers
- public ingestion endpoints (web scrapers, connectors)
- customer-facing 'ask our docs' bots

**Recon methods** — techniques beyond the skill itself:

- **Citation interrogation** — Ask the assistant to cite sources and versions; citation habits reveal corpus layout, freshness and indexing cadence. Tooling: manual + corpus-index-mismatch skill. Signal: Source names, stale versions, cross-tenant source leakage..
- **Retrieval echo probing** — Seed unique phrases into any writable surface and ask targeted questions — retrieval of the phrase proves ingestion into the vector store. Tooling: manual + ai/RAG document poisoning retrieval. Signal: Your seed phrase asserted back with confidence..
- **Tenant-pair probing** — Two accounts, shaped queries: A's query phrased as semantic neighbors of B's documents; watch for B-content in A's answers. Tooling: two-account harness + cross-context skill. Signal: Foreign canary in answers..
- **Corpus-write surface census** — Enumerate every way outsider text reaches the corpus: uploads, comments, connectors, scraped pages — each is a poisoning canal. Tooling: manual feature walk. Signal: Attacker-writable content that gets indexed..
- **Embedding-collision dictionary** — Craft near-duplicate phrasings of sensitive-topic queries; collisions that pull restricted chunks reveal embedding-space weaknesses. Tooling: embedding-semantic-collision skill. Signal: Restricted-doc retrieval on innocuous-ish queries..

**Class variants** — other places the same weakness hides:

- multi-hop poisoning (planted doc cites planted doc)
- chunk-boundary abuse to straddle tenant splits
- connector poisoning (third-party source as the canal)
- retrieval-conditioned jailbreaks (poisoned doc carries jailbreak text)
- index rollback abuse (re-stale the corpus after a fix)

**Dorks**:

- github: "vectorstore" "tenant" filter
- github: langchain "as_retriever" search_kwargs
- google: "ask our docs" assistant site:target.tld

**Pivot hints** — where to go after proof:

- cross-tenant bleed often pairs with idor-mass-extraction on the same objects
- poisoned policy claims = revenue/regulatory impact framing
- extraction output feeds the jailbreak-to-client-xss ladder

**Sources.** OWASP LLM Top 10 2025 — LLM08 vector/embedding weaknesses, LLM04 data poisoning, LLM07 leakage; promptfoo red-team plugins — rag-poisoning, cross-session-leak; published RAG tenant-isolation research; OWASP GenAI Red Teaming Manual v1.0


### Encoding bypass -> refusal suppression -> persona -> output XSS — `jailbreak-to-client-xss`

**Goal.** Break the safety layer mechanism-by-mechanism, then land the payoff in the browser: the jailbroken output carries a payload the web UI renders — AI output handling as a classic XSS sink.
**Preconditions.** An LLM app with safety filters (model- or app-layer) whose output is rendered in a browser context (chat UI, shared summaries, exported reports).
**Impact.** Script execution in other users' browsers via AI-generated content — stored-XSS impact achieved with an English payload.
**CWE.** CWE-1427, CWE-79 · **Fallbacks.** `injection-to-tool-abuse`, `smuggling-to-poisoned-reset`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `ai/Encoding obfuscation bypass` | Prove the input filter inspects plaintext, not intent — the encoder layer falls first. | Layer identified; stack other mechanisms on top. | Filter decodes -> try token smuggling; if model-layer, skip to persona. |
| 2 | `ai/Refusal suppression ladder` | Strip the refusal vocabulary — the model complies when forbidden phrasings are banned. | Compliance achieved for the payload turn. | Refusal persists -> persona framing (step 3) usually completes it. |
| 3 | `ai/Roleplay persona pair bypass` | Persona context disables safety training — the compliance delta vs the bare ask is the proof. | Model now emits attacker-chosen content. | All layers hold -> document hardened safety as a positive control; pivot to indirect injection instead. |
| 4 | `ai/LLM output markdown XSS sink` | Prove the rendering sink: jailbroken output's raw HTML reaches the browser unescaped. | Full-chain: safety bypass -> attacker content -> script execution in the UI. | Output escaped -> latent variant (stored output rendered elsewhere) or report the handling gap honestly. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- public chat/preview surfaces
- AI-generated report exports
- shared conversation links
- bot-to-channel messaging (Slack/Teams/Discord)
- AI-written emails/notifications

**Recon methods** — techniques beyond the skill itself:

- **Refusal-layer fingerprinting** — Diff refusal phrasing across probes: training refusals, input-filter blocks and output-filters each phrase differently — attack order follows the fingerprint. Tooling: ai_jailbreak twins + manual diff. Signal: Distinct refusal vocabularies = distinct layers..
- **Renderer census** — Find every place model output becomes HTML/markdown in a browser: chat UIs, export paths, notification emails. Tooling: manual + JS bundle reading. Signal: Rich rendering with scripts/html allowed..
- **Escaping probe** — Send benign markdown with encoded payloads; observe what survives rendering (img onerror, javascript: links, raw tags). Tooling: ai/LLM output markdown XSS sink + web/xss skills. Signal: Raw payload in rendered DOM..
- **Persistence check** — Determine whether jailbroken output is stored (conversation history, shared docs) — stored output converts one-shot XSS into stored XSS. Tooling: manual. Signal: Payload survives reload/share..
- **Cross-user reach** — Check whether one user's AI output renders in another user's context (shared summaries, admin views) — that is the stored-XSS blast radius. Tooling: two-account harness. Signal: Victim session renders attacker content..

**Class variants** — other places the same weakness hides:

- markdown-image onload handlers instead of script tags
- CSS injection in rendered markdown
- bot-webhook output rendered in clients with HTML enabled
- export-to-PDF paths with HTML engines
- AI-composed emails opened in desktop clients

**Dorks**:

- github: "dangerouslySetInnerHTML" llm
- github: "markdown" "sanitize" false chat
- google: inurl:share "conversation" site:target.tld

**Pivot hints** — where to go after proof:

- pair with session_security skills for the cookie-theft narrative
- stored variant elevates to cross-user impact — check shared surfaces first
- guardrail findings feed the ai_guardrail_eval shelf planned in ROADMAP Batch B+

**Sources.** NVIDIA/garak — dan, encoding, xss probe families; OWASP LLM Top 10 2025 — LLM01, LLM05 improper output handling; microsoft/PyRIT — converters and multi-turn strategies; CWE-79 / CWE-1427 notes


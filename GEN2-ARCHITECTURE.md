# Gen-2 Architecture — from a CLI agent to an observable, multi-provider red-team platform

Gen-1 was a strong single-process CLI: a hand-rolled tool-use loop, a deterministic
5-specialist orchestrator (recon → exploit swarm → verify → access → logic), OpenRouter
free-model rotation, a network-layer-scoped Kali sandbox, and a proof-first finding
pipeline. What it could not do: use more than one LLM vendor, show a human what it was
doing while it did it, learn between rounds, or be driven by anything other than a
terminal. Gen-2 removes exactly those four ceilings without weakening a single safety
rail. This document describes what was added, how it fits together, and which invariants
were deliberately kept.

## What Gen-2 adds

| Capability | Gen-1 | Gen-2 |
|---|---|---|
| LLM providers | OpenRouter free pool only | Any mix of OpenAI-compatible endpoints (OpenAI, Z.ai, Groq, Ollama, vLLM, …) + native Anthropic, role-routed with cross-provider failover |
| Observability | files appearing in the run dir | Typed event stream (`events.jsonl`) → REST replay + live SSE → real-time dashboard |
| Control plane | CLI only | Headless FastAPI server; the CLI and the API drive the *same* `execute_run()` |
| Adaptation | static technique priority + bandit across runs | LLM strategist reflects after every swarm round and re-ranks the attack tree |
| Approvals | stdin prompt | stdin (CLI) or file-backed REST approvals that block the agent until a human decides |
| Memory | JSON + HelixDB (Docker) | JSON + local zero-dependency semantic backend (Helix still available) |
| Toolset | k-of-n proof tools, templates | + `jwt_inspect` (deterministic) and `nuclei_scan` (leads-only scanner) |

## Module map (new or changed in Gen-2)

```text
redteam/
  llm/
    providers.py      ProviderConfig + OpenAICompatProvider + AnthropicProvider
    gateway.py        LLMGateway: role routing, round-robin failover, 429 cooldowns
    openrouter.py     Gen-1 client, unchanged; still the default with no providers config
  events.py           EventBus + FileSink + read_events (replay) + safe_emit
  reflection.py       strategist reflection: deterministic digest -> JSON critique -> tree nudges
  run.py              RunOptions + execute_run(): the ONE run assembly line (CLI + server)
  server.py           FastAPI control plane: lifecycle, SSE, approvals, static dashboard
  tools/
    jwt.py            jwt_inspect — deterministic JWT checklist, offline, leads only
    nuclei.py         nuclei_scan — sandbox-first scanner, JSONL parse, leads only
  memory_backend/
    local_semantic.py LocalSemanticBackend + HashingEmbedder (zero dependencies)
dashboard/            Next.js mission-control (static export, served by server.py)
```

## The shared run executor (`run.py`)

Gen-1 assembled runs inside `cli.main`. Gen-2 extracts that into `execute_run(RunOptions)`.
Every variation between "human at a terminal" and "API-driven headless run" is a dataclass
field, not a code path fork:

- `approve` — `interactive_approver()` for the CLI, `HeadlessApprover` for the server.
- `events` — `None` (CLI, zero overhead) or a constructed `EventBus` (server).
- `quiet` / `on_text` — console output vs. silence.

`execute_run` performs: engagement load + window check → guards/stores → LLM client via
`build_llm_client` → deterministic recon → sandbox/browser → ToolContext → memory →
driver run → (single-agent) independent verify pass → memory credit/learn → reports.
It returns a summary dict and raises `RunSetupError`/`ConfigError`/`RuntimeError` for
setup failures. Both entrypoints therefore stay thin: the CLI adds preflight consent and
arg parsing; the server adds run-id allocation and thread launching.

## Multi-provider LLM gateway (`llm/gateway.py`)

Configuration is additive and backward-compatible: an empty `llm.providers:` list yields
the byte-identical Gen-1 `OpenRouterClient`; listing providers yields the `LLMGateway`.

- `ProviderConfig` accepts shortcut kinds (`openai`, `anthropic`, `zai`, `groq`,
  `ollama`, `openrouter`) that fill default base URLs and `api_key_env`s, plus
  allow/deny model lists, `prefer_free`, `require_tool_support`, and a `priority`.
- Candidate ordering interleaves providers round-robin by priority (A's best, B's best,
  A's second, …) so no single vendor's outage or rate limit can stall a run while still
  respecting your preference order.
- Two consecutive 429s demote a (provider, model) pair to the back of the queue
  (thread-safe — the exploit swarm shares one gateway).
- `role_models` pins strong models to reasoning-heavy roles (`plan`, `poc`); a pin may be
  `"provider:model"` or bare `"model"`, with the normal pool as fallback.
- Anthropic is translated natively (system as top-level field, tool_use/tool_result
  blocks) rather than forced through OpenAI shapes.

Role routing semantics are unchanged from Gen-1: parsing/triage stay cheap, only
reasoning pays.

## Event bus and the observability contract (`events.py`)

Every meaningful step emits a flat JSON event `{seq, ts, run_id, type, **payload}`:

```text
run.start · phase.change · agent.turn · tool.call · tool.result · finding.recorded ·
finding.confirmed · objective.progress · approval.requested · approval.resolved ·
swarm.claim · reflection · llm.rotate · run.finish
role ∈ recon|exploit|access|logic|verify|single|orchestrator
```

Design rules that make this safe to bolt onto an attacking agent:

1. **`events.jsonl` is the single source of truth.** The server serves replay and
   live-tail from the file (`read_events(after=cursor)`), never from memory — the API
   stays correct across restarts and decoupled from the engine's threads.
2. **Emission never raises.** `EventBus.emit` swallows sink failures; `safe_emit` is the
   tool-level wrapper for optional buses. A full disk degrades telemetry, never the run.
3. **Telemetry is thread-safe.** Sequence numbers are monotonic under the swarm's
   concurrency (tested with 4 threads × 200 events).
4. **LLM clients stay telemetry-blind.** `AuditBridge` mirrors selected audit records
   (`llm.rotate`) onto the bus, so providers needed no changes.

## Reflection loop (`reflection.py` + `orchestrator.py`)

After each orchestrator round, a strategist-role LLM call receives a **deterministic
digest** (objective progress, confirmed/pending/dead findings, tree state, kill chain,
prior reflections, failure signals) and returns strict JSON: assessment, what worked,
what failed, techniques to prioritize/deprioritize, focus for the next round.

Hard guardrails:

- The reflection can only **re-rank existing attack-tree nodes** (`+25` prioritize,
  `-25` deprioritize) — it can never create targets, authorize gated actions, or
  override the chain-boost ordering. Hallucinated techniques are ignored by
  `attack_tree.apply_strategy`.
- Reflection is an amplifier, not a dependency: any failure (bad JSON, no budget,
  disabled, LLM error) returns `None` and the run continues with the deterministic plan.
- One call per round, on the strong role, gated by remaining token budget.

## Approvals without a terminal (`HeadlessApprover`)

`request_approval` in a headless run appends a pending record to `approvals.json`, emits
`approval.requested`, and blocks the agent thread polling for resolution. The operator
resolves it via `POST /api/approvals/{id}`; the engine thread sees the file flip and
emits `approval.resolved` — the event stream stays single-writer. A STOP kill file
auto-denies pending approvals (fail closed) and halts the run. File writes are atomic
(rename) under a module lock; resolving an unknown/resolved id is a 404.

## Server (`server.py`)

`python -m redteam.server --runs-root runs --port 8000` starts the control plane:

- `POST /api/runs` validates the engagement *before* spawning anything (bad RoE → 400,
  inactive window → 400), pre-creates the manifest, and launches `execute_run` in a
  daemon thread with its own `EventBus` + `HeadlessApprover`.
- `GET /api/runs/{id}` adapts on-disk artifacts (manifest, findings, objective,
  killchain, graph, attack tree, reflections) into the dashboard's response shape.
- `GET /api/runs/{id}/stream` is SSE (`event: run_event`, 15 s pings) that drains the
  event file and closes itself once the manifest leaves `running` and the file is
  drained.
- Static dashboard export is mounted at `/`; CORS is open for local development.
- A crashed run is finalized: the thread wrapper rewrites the manifest as `error` with
  the reason and emits `run.finish` — no client ever watches a zombie run.

## New tools and the proof-first discipline

Both tools exist to *feed* the existing proof pipeline, not to bypass it:

- **`jwt_inspect`** — decodes a JWS and applies a fixed checklist (alg=none, attacker-
  controlled jku/x5u/kid headers, missing/expired exp, long lifetimes, sequential sub,
  PII in payload). Deterministic, offline, zero LLM cost; every entry is a LEAD with a
  `verify_hint` describing what a human-grade proof looks like. Signatures are never
  echoed back into the transcript.
- **`nuclei_scan`** — runs nuclei through the Kali sandbox when available (so the
  egress firewall still governs every request), falls back to a local binary, and
  refuses anything out of scope. JSONL matches are parsed into leads and folded into
  the knowledge graph; the tool's own output states that a nuclei match alone is not a
  finding.

The promotion path is unchanged and enforced by code: lead → `verify_vulnerability`
(k-of-n + negative control) → `verify_finding_independently` (fresh context) → only
then does anything count toward the objective.

## Local semantic memory (`memory_backend/local_semantic.py`)

`LocalSemanticBackend` implements the same additive protocol as the Helix backend
(`load`/`save` plus optional `semantic_recall_lessons`/`learn_pattern`/`recall_patterns`)
with one JSON file and no services:

- Embeddings come from the on-device sentence-transformer when it is installed; otherwise
  a built-in `HashingEmbedder` (stopword-filtered content words + char trigrams,
  sublinear tf, blake2b buckets, normalized) gives deterministic lexical-semantic recall
  with zero downloads.
- Embeddings are persisted alongside rows, so restarts don't re-embed; `load()` strips
  the internal column so `Lesson(**row)` keeps working.
- If the embedder fails at runtime, semantic methods return `[]` and the store behaves
  exactly like the plain JSON backend — additive capability, never load-bearing.

`--semantic-memory` now means the local backend; `--helix-memory` keeps the Docker path
for those who want true deep-semantic recall.

## Invariants kept from Gen-1

- Network-layer scope enforcement (sandbox egress firewall + browser interception +
  SSRF-aware ScopeGuard) — unchanged; nuclei goes through it.
- Proof-first promotion: nothing counts until independently verified.
- Deterministic-first: recon, parsers, digest, and checklists run without an LLM;
  models amplify, they don't gatekeep.
- Zero-config backward compatibility: no new config → Gen-1 behavior.
- Telemetry and reflection can degrade but never break a run.
- The audit chain stays append-only and verified (`execute_run` returns
  `audit_intact`).

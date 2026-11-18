# Red-Team Agent — Kali sandbox + Playwright, multi-provider LLMs, live mission control

An agentic red-team assistant for **authorized** web-application / API security testing.
Instead of a handful of narrow tools, the agent gets two full execution surfaces:

- **A Kali Linux sandbox in Docker** — the whole offensive toolset (nmap, ffuf, sqlmap,
  nikto, gobuster, curl, nuclei, …) available via `kali_exec`.
- **Playwright browser automation** — a real headless browser for anything that needs a
  DOM and JavaScript.

Model backends: **OpenRouter** (free-pool rotation, the zero-config default) or the
multi-provider gateway (**OpenAI, Anthropic, Z.ai, Gemini, Groq, Ollama, vLLM** —
role-routed with cross-provider failover). Runs are observable in real time from the
bundled **mission-control dashboard**.

> **Authorized use only.** Run this only against systems you own or have **written
> permission** to test (a signed SOW/engagement, or a bug-bounty program within its
> published scope), or an isolated lab. The engagement file is your authorization
> boundary.

## Prerequisites

| Requirement | Why |
| --- | --- |
| Python ≥ 3.10 | the engine (`pip install -e ".[dev]"`) |
| Docker, running | the Kali sandbox container (skip if you use `--no-sandbox`) |
| Node.js ≥ 18 | only for building the dashboard UI |
| One LLM API key | `OPENROUTER_API_KEY` by default; see [Models & providers](#models--providers) |

## Quickstart (CLI)

```bash
pip install -e ".[dev]"                 # engine + server deps + test deps
python -m playwright install chromium   # one-time, for the browser tools
export OPENROUTER_API_KEY=sk-or-...      # your OpenRouter key

cp config/engagement.example.yaml config/engagement.yaml
# edit it to your signed scope: name, window (starts/ends), allowed hosts/ports

python -m redteam.cli \
  --engagement config/engagement.yaml \
  --objective "Map the API surface and test authentication and access controls" \
  --out runs/acme-2026-09-26
```

The first run builds the Kali image (large, one-time). You confirm scope at the preflight
prompt and approve sensitive actions as they come up. Every flag:

`--multi-agent` (orchestrator + specialist swarm), `--max-steps N`, `--source-dir DIR`
(local source tree for whitebox runs), `--asset-feed feeds.csv` (seed the asset
inventory), `--semantic-memory` / `--helix-memory` (cross-run recall), `--events`,
`--no-traffic-bodies`, and — isolated labs only — `--no-sandbox`, `--no-browser`,
`--yes-to-all`.

For a target to practice against, the repo ships isolated lab apps in `lab/` (deliberately
vulnerable, bound to 127.0.0.1); `scripts/run_live_mission.py` boots one end to end.

## Running with the dashboard (recommended)

The CLI and the API drive the **same** `execute_run()`. To run from the browser:

```bash
npm --prefix dashboard install && npm --prefix dashboard run build   # one-time UI build
python -m redteam.server --runs-root runs --port 8000
```

Then open `http://127.0.0.1:8000`:

- **Launch runs from the browser** — engagement path, objective, budgets, and the
  **model provider / model** for the run. The launch panel's **EXECUTION MODE**
  selector picks the driver: a **classic run** (`POST /api/runs`, the orchestrator
  swarm) or an **adaptive mission** (`POST /api/missions`, the mission coordination
  driver over the same specialists/verifier — it claims tasks from the live
  AttackTree frontier and replans between rounds; an explicit static plan is
  strictly opt-in). The RoE is validated before anything starts.
- **Watch the attack live**: every agent turn, tool call/result, finding, phase
  change, model rotation, and reflection streams over SSE into the run-detail page
  (`/runs?id={run_id}` — survives refresh and direct navigation; unknown ids get a
  clear not-found state). Mission runs additionally show the coordination panel:
  mission status, current task + specialist, task lifecycle, the verification
  split, and the mission-journal tail.
- **Approve sensitive actions** in one click (`request_approval` blocks the agent until
  you decide; a STOP kill file auto-denies and halts — fail closed).
- **Stop runs and read reports**: objective score, kill chain, attack tree, per-round
  strategist reflections, wire-level traffic, asset inventory.

Server flags: `--host`, `--port`, `--runs-root` (default `./runs`), `--dashboard`
(defaults to `<repo>/dashboard/out` when it exists — build the UI once and it is served
automatically).

## Models & providers

**Default:** OpenRouter's free pool with live discovery and rotation — zero config.

**Per run, from the dashboard:** the launch form's MODEL PROVIDER section picks the
backend (**OpenAI / Z.ai / Gemini / OpenRouter / Ollama / Groq / Anthropic** or *engine
default*), the model (free text with per-provider presets — `glm-5.3`, `gpt-sol`,
`gemini-argon`, …), an API key for the run, and an optional `base_url` override (vLLM /
LM Studio / a private proxy). The typed key is a **run-scoped credential**: it travels
in memory on that run's options and is resolved into that run's provider sessions at
construction — never written to the process environment, engagement YAML, manifests,
events, or logs, so concurrent runs with different keys cannot cross-use them. Omit the
key to use preconfigured env credentials. The selection is materialized as an effective
`engagement.yaml` inside the run dir and surfaced as an `llm.selected` event, so every
artifact records the exact model config the run used. `GET /api/llm/providers` lists
the supported kinds and whether each key env var is set (presence only).

**Per engagement, in YAML:** route roles across providers with failover by adding a
`providers:` block to the engagement's `llm:` section:

```yaml
llm:
  providers:
    - kind: openai          # shortcut: fills base_url + OPENAI_API_KEY
      models_allow: [gpt-4.1-mini]
      priority: 1
    - kind: anthropic       # native /v1/messages translation
      priority: 2
    - kind: ollama          # local models, zero cost
      base_url: http://127.0.0.1:11434/v1
      priority: 3
  role_models: {plan: "openai:gpt-4.1", poc: "anthropic:claude-sonnet-4-5"}
```

Candidates interleave round-robin by priority; two consecutive 429s demote a pair to the
back of the queue. With no `providers:` block, behavior is byte-identical to the default.

| Kind | Base URL (default) | Key env var |
| --- | --- | --- |
| `openrouter` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` |
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| `zai` | `https://api.z.ai/api/paas/v4` | `ZAI_API_KEY` |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta/openai` | `GEMINI_API_KEY` |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` |
| `groq` | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` |
| `ollama` | `http://127.0.0.1:11434/v1` | — (local, no key) |

Any OpenAI-compatible endpoint (vLLM, LM Studio, a proxy) works via a custom
`base_url`.

## HTTP API

Everything the dashboard does is plain HTTP (same origin):

```bash
# classic run with an explicit provider/model choice
curl -X POST localhost:8000/api/runs -H 'content-type: application/json' -d '{
  "engagement_path": "/abs/path/to/engagement",
  "objective": "Map the API surface and test authentication",
  "multi_agent": true, "max_steps": 40,
  "llm": {"provider": "zai", "model": "glm-5.3", "api_key": "..."}
}'

# adaptive mission (same llm contract; plan omitted = dynamic AttackTree frontier)
curl -X POST localhost:8000/api/missions -H 'content-type: application/json' -d '{
  "engagement_path": "/abs/path/to/engagement",
  "objective": "Reach the admin console and prove data access",
  "max_steps": 40
}'

curl -s localhost:8000/api/runs | jq '.runs[0]'
curl -s localhost:8000/api/missions | jq '.missions[0]'
curl -s localhost:8000/api/missions/<id> | jq '{status, halt_reason, tasks}'
curl -s localhost:8000/api/llm/providers | jq
curl -s localhost:8000/api/runs/<id>/events | jq '.events[-1]'
curl -s localhost:8000/api/runs/<id>/traffic  | jq '.traffic[-1]'   # wire evidence
curl -s localhost:8000/api/runs/<id>/inventory | jq '.summary'      # attack surface
```

Full lifecycle: `POST /api/runs`, `GET /api/runs`, `GET /api/runs/{id}` (includes
`driver`), `GET /api/runs/{id}/events`, `GET /api/runs/{id}/stream` (SSE), `GET
/api/runs/{id}/approvals`, `POST /api/approvals/{id}`, `POST /api/runs/{id}/stop`,
`GET /api/runs/{id}/report`, `GET /api/runs/{id}/traffic`, `GET
/api/runs/{id}/inventory`, `POST /api/missions`, `GET /api/missions`,
`GET /api/missions/{mission_id}`, `GET /api/llm/providers`, `GET /api/health`.
The dashboard's run-detail route is `/runs?id={run_id}`.

## Safety model: how "give it all of Kali" stays scoped

When the agent can run arbitrary tools, you can't enforce scope by inspecting commands —
so scope is enforced at the **network layer**:

- **Sandbox egress firewall** — the Kali container runs `default-DROP` on OUTPUT; only
  IPs/CIDRs derived from the RoE are reachable. The entrypoint installs the rules before
  any tool runs and the container **refuses to start** if it can't (fail closed). An
  egress self-test probes an address that must never be in scope (TEST-NET-1) and tears
  the sandbox down if the probe succeeds — a "ready" log line alone is not trusted.
- **No self-unlocking** — tools run as non-root, all capabilities dropped except
  `NET_ADMIN`/`NET_RAW`, `no-new-privileges` set, and `kali_exec` refuses commands that
  touch iptables/ipset/routing/`sudo`/namespaces.
- **Browser scope interception** — every request the browser makes (page + every
  subresource) is checked against the scope guard; out-of-scope requests are aborted.
- **Approval gates** — destructive/DoS-shaped commands require an interactive "yes".
- Plus a **rate limit + request budget**, an **append-only JSONL audit log**, and an
  **engagement window** the agent won't run outside of.

## What a run produces

Everything lands in the run directory (`--out` / the server's `runs-root`):

- `report.md` / `report.html`, `findings.json` — the deliverables
- `audit.log.jsonl` — append-only audit trail of every action and decision
- `events.jsonl` — the live telemetry the dashboard consumes (replay reads the same bytes)
- `traffic.jsonl` — wire evidence of every in-scope exchange (credential headers masked
  both ways, bodies truncated, droppable with `--no-traffic-bodies`)
- `inventory.json` — attack-surface map (host → port → service/banner/title), built
  passively from every response and actively by `surface_scan`
- `engagement.yaml` (server-launched runs with a model override) — the exact model config
  the run executed with
- `attack_tree.json`, `objective.json`, mission/research journals — planning and swarm state

## Repository layout

```text
redteam/
  config.py          RoE + LLM config (OpenRouter default / multi-provider gateway) + sandbox
  scope.py           ScopeGuard — SSRF-aware target boundary
  ratelimit.py       Token-bucket limiter + request budget
  audit.py           Append-only JSONL audit log
  findings.py        Finding model + JSON store
  report.py          Markdown + HTML report
  agent.py           OpenAI-style tool-use loop
  orchestrator.py    Multi-agent swarm: recon -> exploit -> verify -> access -> logic
  run.py             execute_run() — the ONE run assembly line shared by CLI and API
  cli.py             Terminal entrypoint: preflight, console output, interactive approvals
  server.py          Headless control plane (FastAPI): run lifecycle, SSE, approvals,
                     static dashboard hosting
  events.py          EventBus + JSONL sink: the live telemetry the dashboard consumes
  traffic.py         TrafficRecorder — per-run wire evidence, credentials masked
  inventory.py       AssetInventory — attack-surface map built from every response
  importers/assets.py  Asset-feed sync (CSV/JSON/JSONL) — fail-closed intersection with RoE
  llm/               OpenRouter default, multi-provider gateway, role-routed failover
  sandbox/           Kali container: egress firewall, self-test, lifecycle
  tools/             kali_exec, browser_*, verification, probing and inspector tools
  swarm/             Hypothesis registry + research forum (collective intelligence)
  memory.py          ExperienceStore — persistent cross-run tradecraft lessons
  memory_backend/    Semantic recall: local (zero deps) and HelixDB (Docker, opt-in)
  reflection.py      LLM strategist self-critique between orchestrator rounds (re-rank only)
  states.py / hands.py  Lifecycle registries and declared agent capabilities (introspectable)
  attack_tree.py / bandit.py  Technique ranking + learned win rates across runs
dashboard/           Next.js mission-control UI (static export, served by server.py)
lab/                 Isolated, deliberately vulnerable practice targets (127.0.0.1)
config/              engagement.example.yaml — the RoE template
scripts/             Live-fire demos, smoke tests, lab helpers
docs/                Design docs, ADRs, research notes
tests/               pytest suite (CI runs `python -m pytest -q`)
```

## Optional capabilities (all degrade gracefully)

| Capability | How | What it does |
| --- | --- | --- |
| Semantic memory | `--semantic-memory` (local) / `--helix-memory` (Docker) / `pip install -e ".[semantic-memory]"` | Cross-run recall by meaning, plus app-shape patterns ("two-step login", "sequential IDs") |
| Strategist reflection | automatic in `--multi-agent` | A strong-role LLM re-ranks existing attack-tree techniques between rounds; it can never create targets or authorize gated actions |
| Learned technique ranking | on by default (`bandit.py`) | Thompson-sampling bandit learns per-(technique, endpoint-shape) win rates across runs; persisted to `memory/bandit.json` |
| Hypothesis registry | automatic in `--multi-agent` | The swarm shares research: atomic claims, leases, typed forum, duplicate matching; an observation is not a finding — only the verify pipeline confirms |
| Asset-feed sync | `--asset-feed feeds.csv` | Seeds the inventory from ScopeSentry-style feeds; strictly intersected with the RoE — a feed can never widen scope |

Design details: `docs/adr-001-collective-intelligence-foundation.md`,
`docs/synthesis.md`, `GEN2-ARCHITECTURE.md`, `ROADMAP.md`.

## Tests

```bash
pip install -e ".[dev]"   # once: adds pytest + httpx (testclient)
python -m pytest -q       # full python suite (engine, server, credentials, …)

npm --prefix dashboard install
npm --prefix dashboard test           # dashboard component suite (vitest)
cd dashboard && npx tsc --noEmit && cd ..   # dashboard type check

# browser E2E (drives a real FastAPI server + built UI through the full
# operator workflow with a deterministic fake engine; needs chromium):
npm --prefix dashboard run build
python -m pytest tests/test_dashboard_e2e.py -q
```

## Notes & limits

- **Wildcard scope + sandbox:** the egress firewall opens by IP/CIDR and can't
  pre-resolve `*.example.com`. To reach wildcard subdomains from Kali tools, also list
  the covering CIDR in `scope.allowed_hosts`. The browser tool handles wildcards fine
  (it checks each request's host by name).
- **Free models vary:** not every free model supports tool calling; the router filters
  for `supported_parameters: tools` and rotates on rate-limits/outages. Availability of
  free models changes constantly — that's why discovery is live, not hardcoded.
- **Add a tool** by implementing `schema()` + `run(ctx, ...)` in `redteam/tools/` and
  registering it in `build_registry`; the capability ladder lives in
  `docs/tool-integration-plan.md`, the phase inventory in `docs/tool-inventory.md`.

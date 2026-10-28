# Red-Team Agent — Kali sandbox + Playwright, multi-provider LLMs, live mission control

An agentic red-team assistant for **authorized** web-application / API security testing.
Instead of a handful of narrow tools, the agent gets two full execution surfaces:

- **A Kali Linux sandbox in Docker** — the whole offensive toolset (nmap, ffuf, sqlmap,
  nikto, gobuster, curl, nuclei, …) available via `kali_exec`.
- **Playwright browser automation** — a real headless browser for anything that needs a
  DOM and JavaScript.

Model backends: **OpenRouter** (free-pool rotation, the zero-config default) or the
**Gen-2 multi-provider gateway** (OpenAI, Anthropic, Z.ai, Groq, Ollama, vLLM — role-routed
with cross-provider failover). Runs are observable in real time from the bundled
**mission-control dashboard** (see Gen-2 below).

> **Authorized use only.** Run this only against systems you own or have **written
> permission** to test (a signed SOW/engagement, or a bug-bounty program within its
> published scope), or an isolated lab. The engagement file is your authorization
> boundary.

## How "give it all of Kali" stays safe

When the agent can run arbitrary tools, you can't enforce scope by inspecting commands.
So scope is enforced at the **network layer**:

- **Sandbox egress firewall** — the Kali container runs `default-DROP` on OUTPUT. Only
  IPs/CIDRs derived from the RoE (`redteam/sandbox/egress.py`) are reachable; the
  entrypoint installs the rules before any tool runs and the container **refuses to
  start** if it can't (fail closed). Off-scope hosts are simply unreachable. On top of
  that, `KaliSandbox.start()` runs an **egress self-test**: it probes a destination that
  should never be in scope (TEST-NET-1) and tears the sandbox down if that probe
  succeeds, rather than trusting the entrypoint's "ready" log line alone — a log line
  only proves the script ran, not that the firewall rules actually took effect.
- **No self-unlocking** — tools run as a non-root user, the container drops all
  capabilities except `NET_ADMIN`/`NET_RAW`, sets `no-new-privileges`, and `kali_exec`
  refuses commands that touch iptables/ipset/routing/`sudo`/namespaces.
- **Browser scope interception** — every request the browser makes (page + every
  subresource) is checked against the scope guard; out-of-scope requests are aborted.
- **Approval gates** — destructive/DoS-shaped commands require an interactive human "yes".
- **Rate limit + request budget**, **append-only JSONL audit log**, and an
  **engagement window** the agent won't run outside of.

## Layout

```text
redteam/
  config.py          RoE + LLM config (OpenRouter default / multi-provider gateway) + sandbox
  scope.py           ScopeGuard — SSRF-aware target boundary
  ratelimit.py       Token-bucket limiter + request budget
  audit.py           Append-only JSONL audit log
  findings.py        Finding model + JSON store
  report.py          Markdown + HTML report
  agent.py           OpenAI-style tool-use loop (owned explicitly)
  orchestrator.py    Multi-agent swarm: recon -> exploit -> verify -> access -> logic
  run.py             execute_run() — the ONE run assembly line shared by CLI and API
  cli.py             Terminal entrypoint: preflight, console output, interactive approvals
  server.py          Headless control plane (FastAPI): runs lifecycle, SSE, approvals,
                     static dashboard hosting
  events.py          EventBus + JSONL sink: the live telemetry the dashboard consumes
  traffic.py         TrafficRecorder — per-run wire evidence (traffic.jsonl), credential
                     headers masked both ways, bodies truncatable/droppable
  inventory.py       AssetInventory — attack-surface map (host -> port -> service/
                     banner/title), built passively from every response + surface_scan
  importers/assets.py  ScopeSentry-style asset-feed sync (CSV/JSON/JSONL) — FAIL-CLOSED:
                     feed entries outside the RoE are dropped; the feed can never widen scope
  reflection.py      LLM strategist self-critique between orchestrator rounds (re-rank only)
  llm/openrouter.py  Free-model discovery + rotation/fallback (default backend)
  llm/providers.py   OpenAI-compatible + Anthropic providers (Gen-2)
  llm/gateway.py     Multi-provider role-routed gateway with cross-provider failover
  memory.py          ExperienceStore — persistent cross-run tradecraft lessons
  memory_backend/    Semantic recall backends: local_semantic.py (zero dependencies,
                      JSON + on-device/hashing embeddings) and HelixDB (Docker, opt-in)
  sandbox/           Kali container: egress firewall, self-test, lifecycle
  tools/             kali_exec, browser_*, record_finding, request_approval,
                     verify_vulnerability, verify_finding_independently, jwt_inspect,
                     nuclei_scan (leads only), template/skill tools, postex, ...
dashboard/           Next.js mission-control UI (static export, served by server.py)
config/engagement.example.yaml
GEN2-ARCHITECTURE.md Gen-2 design doc — how the pieces fit and which invariants hold
ROADMAP.md           Gap analysis vs CAI / PentestGPT / Nebula + the path forward
tests/
```

## Setup

```bash
pip install -e .                        # requests, pyyaml, playwright
python -m playwright install chromium   # one-time, for the browser tools
export OPENROUTER_API_KEY=sk-or-...      # your OpenRouter key
cp config/engagement.example.yaml config/engagement.yaml   # edit to your signed scope
# Docker must be installed and running for the Kali sandbox.
```

## Run

```bash
python -m redteam.cli \
  --engagement config/engagement.yaml \
  --objective "Map the API surface and test authentication and access controls" \
  --out runs/acme-2026-09-26
```

First run builds the Kali image (large, one-time). You confirm scope at the preflight
prompt and approve sensitive actions as they come up. Outputs land in `--out`:
`report.md`, `findings.json`, `audit.log.jsonl`, `screenshots/`.

Flags: `--no-sandbox`, `--no-browser`, `--yes-to-all` (isolated labs only), `--multi-agent`
(orchestrator + specialist swarm), `--semantic-memory` (local, zero-dependency semantic
recall), `--helix-memory` (HelixDB backend, needs Docker), `--events` (write the live
event stream to the run directory).

## Gen-2: dashboard + headless control plane

The CLI and the API drive the **same** `execute_run()`. To run with the live dashboard:

```bash
pip install "fastapi>=0.110" "uvicorn[standard]"   # server deps
npm --prefix dashboard install && npm --prefix dashboard run build   # one-time UI build
python -m redteam.server --runs-root runs --port 8000
```

Then open `http://127.0.0.1:8000`:

- **Launch runs** from the browser (engagement path, objective, swarm mode, budgets) —
  the RoE is validated before anything starts.
- **Watch the attack live**: every agent turn, tool call/result, finding, phase change,
  model rotation, and reflection streams over SSE into the mission-control page.
- **Approve sensitive actions** in one click (`request_approval` blocks the agent until
  you decide; a STOP kill file auto-denies and halts — fail closed).
- **Stop runs, read reports**, and inspect the objective score, kill chain, attack tree,
  and per-round strategist reflections.

The API (same origin as the dashboard): `POST /api/runs`, `GET /api/runs`,
`GET /api/runs/{id}`, `GET /api/runs/{id}/events`, `GET /api/runs/{id}/stream` (SSE),
`POST /api/runs/{id}/stop`, `GET /api/runs/{id}/report`, `GET /api/runs/{id}/approvals`,
`POST /api/approvals/{id}`, `GET /api/health`. Telemetry lives in each run directory as
`events.jsonl` — replay, live-tail, and post-mortems all read the same bytes the engine
wrote. See **GEN2-ARCHITECTURE.md** for the full contract and design rules.

### Multi-provider LLM gateway (optional)

By default the agent uses OpenRouter's free pool exactly as before. To route roles
across providers with automatic failover, add a `providers:` block to the engagement's
`llm:` section:

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

Candidates interleave round-robin by priority (A best, B best, A second, …); two
consecutive 429s demote a pair to the back of the queue. With no `providers:` block,
behavior is byte-identical to Gen-1.

### Strategist reflection (multi-agent mode)

After every orchestrator round, a strong-role LLM receives a deterministic digest of
the run (objective progress, findings, tree state, failure signals) and returns a
JSON critique. It may only **re-rank existing attack-tree techniques** (+25/-25) — it
cannot create targets, authorize gated actions, or override the proof pipeline. Any
failure skips reflection silently; the deterministic plan always stands.

## Attack-surface evidence (ARTEX-inspired)

Three capabilities ported from ARTEX (mhtsec/ARTEX — an autonomous pentesting platform;
note it was recently abused in the wild, which is exactly why our ports keep the
authorization-first discipline):

- **Traffic recording** (`traffic.py`) — every in-scope exchange on the shared fetch
  path (probes, proofs, verify passes, surface sweeps) lands in `traffic.jsonl` as
  wire evidence: method, URL, status, timing, headers both ways. Credential-adjacent
  headers (Authorization, Cookie, Set-Cookie, API keys) are masked in BOTH directions;
  bodies are truncated (16 KB) and can be dropped entirely with `--no-traffic-bodies`.
  Scope-denied attempts are recorded too — the log shows the boundary holding.
  Served at `GET /api/runs/{id}/traffic?after=<seq>` with the same cursor contract
  as the event stream.
- **Asset inventory** (`inventory.py` + `surface_scan`) — a per-run map of which
  in-scope hosts answered, on which ports, with which server banner, page title, and
  auth challenge. It builds itself passively from every response, and the RECON
  specialist's `surface_scan` tool fills it actively by knocking once on every
  host:port the RoE already allows (never widens scope, never records findings,
  stops honestly at budget exhaustion). Served at `GET /api/runs/{id}/inventory`.
- **Asset-feed sync** (`importers/assets.py`) — `--asset-feed feeds.csv` (or JSON /
  JSONL, ScopeSentry-style columns `host|domain|ip, port, scheme, service`) seeds the
  inventory before the run starts. It is an INTERSECTION, not a merge: each record is
  re-checked against the RoE by the ScopeGuard itself, out-of-scope entries are
  dropped and counted with samples, and `scope.check()` still refuses them afterwards.
  The server validates the feed at launch (400 on unreadable files).

```bash
# operator view of what the team actually put on the wire
curl -s localhost:8000/api/runs/<id>/traffic | jq '.traffic[-1]'
curl -s localhost:8000/api/runs/<id>/inventory | jq '.summary'
```

## Semantic memory (optional)

`memory.py`'s `ExperienceStore` persists cross-run tradecraft (which CWE classes proved
out, which proof oracles work) as flat JSON by default, recalled by tag/keyword overlap.
Two semantic backends upgrade recall from shared vocabulary to *meaning* — "broken
object reference" matching a lesson phrased around "IDOR" — and add a second kind of
fact, **app-shape patterns** ("this app uses a two-step login," "sequential numeric IDs,
worth enumerating"), distilled from each run's knowledge graph so a brand-new target
isn't started blind:

- **`--semantic-memory` (local, default):** one JSON file, embeddings from the on-device
  `all-MiniLM-L6-v2` when installed, otherwise a built-in hashing embedder (stopword-
  filtered words + character trigrams). Zero dependencies, zero Docker, deterministic.
- **`--helix-memory` (opt-in):** HelixDB graph+vector backend in Docker with a persistent
  named volume (see the notes in `memory_backend/helix_server.py`). Deepest semantic
  quality; needs Docker.

```bash
python -m redteam.cli ... --semantic-memory      # no extra install
pip install -e .[semantic-memory]                # optional: real transformer embeddings
python -m redteam.cli ... --helix-memory         # Docker path
```

Both paths degrade gracefully: if the embedder or the container fails, the store falls
back to plain tag-matched memory and the run continues.

## Learned technique selection (bandit, optional)

`attack_tree.py` ranks techniques (SQLi, IDOR, XSS, ...) for the swarm to try next by a
fixed, hand-set priority table — the same order against every target, with no memory of
what's actually confirmed before. `bandit.py` adds a contextual multi-armed bandit
(Thompson sampling) that learns a per-(technique, endpoint-shape) win rate across runs and
nudges that static order, without ever overriding the priority tiers outright (chained
follow-ups always still outrank fresh entry techniques).

The "context" is a coarse, reusable endpoint-shape bucket (`numeric-id`, `auth-wall`,
`workflow-shaped`, ...) — the same vocabulary `memory_backend/app_patterns.py` already
derives for cross-run pattern recall. The reward is 1.0 when a technique confirms on that
shape, 0.0 when the swarm marks it `FAILED` having found nothing — both already happen in
`attack_tree.py`'s existing control flow; the bandit just tallies them instead of
discarding them. Learned win rates persist to `memory/bandit.json`, so technique selection
keeps specializing across engagements, not resetting every run.

This is wired on by default (`cli.py` always attaches a `BanditStore` to `AttackTree`) and
needs no flag — with no evidence yet, it samples around neutral and leaves the static
order effectively unchanged; it only pays off once there's a track record to learn from.

## Tests

```bash
pytest -q
```

## Notes & limits

- **Wildcard scope + sandbox:** the egress firewall opens by IP/CIDR and can't
  pre-resolve `*.example.com`. To reach wildcard subdomains from Kali tools, also list
  the covering CIDR in `scope.allowed_hosts`. The browser tool handles wildcards fine
  (it checks each request's host by name).
- **Free models vary:** not every free model supports tool calling; the router filters
  for `supported_parameters: tools` and rotates on rate-limits/outages. Availability of
  free models changes constantly — that's why discovery is live, not hardcoded.
- Add a tool by implementing `schema()` + `run(ctx, ...)` in `redteam/tools/` and
  registering it in `build_registry`.

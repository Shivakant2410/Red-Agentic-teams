# Red-Team Agent — autonomous offensive operations on authorized targets

An agentic red-team system that attacks web applications, APIs, and LLM surfaces
end to end: it reconnoiters with stopping rules, builds an asset graph, plans an
attack tree, executes the chain through a full Kali toolset and a real browser,
exploits, proves every finding independently, and reports — against targets you
are authorized to test.

The product is the attack. Containment and audit exist so real teams can deploy
it; they are plumbing, not the pitch (`docs/offense-core.md` settles this
positioning module by module).

## What the agent does to a target

**1. Recon until the math says stop, not until the wordlist ends.**
Content discovery runs on frequency-ordered priors (Nmap/SecLists-derived, 9
buckets, 143 seeded paths) with a STADS missing-mass stop rule: a Beta-posterior
bucket model plus Good–Turing species discovery (`recon/discovery.py`) decides
when further probing buys nothing — the agent stops when the estimated unseen
mass collapses, exactly like serious fuzzers do. Recursion into confirmed
directories is budget-aware; soft-404 baselines keep the statistics honest.

**2. Maps what the org is building in secret.**
The asset radar (`recon/assetgraph.py` + `tools/asset_radar.py`) is a
competitive-intel instrument, not an asset list: CT-freshness diffing catches
certificates issued in the last 45 days before the product is announced;
codename extraction triangulated across independent sources ranks each leaked
label strong/likely/watchlist; codename-seeded DNS permutations verify
environment fanout; version-ahead-of-live edges (`/api/v3` referenced while
`/api/v1` is deployed) expose the roadmap the production site won't admit to;
feature-flag leaks and staging-mirror inference fill in the rest. Output is a
typed-edge graph (announces/projects/resolves_to/references/precedes/mirrors)
with a ranked `secret_builds()` report — leads, never findings.

**3. Plans like an attacker, learns like one too.**
`attack_tree.py` ranks techniques per endpoint shape; a Thompson-sampling bandit
learns win rates across engagements and specializes selection over time
(`memory/bandit.json` persists). In swarm mode the orchestrator runs the chain —
recon → exploit → verify → access → logic — with specialists, distilled skills,
and a strategist reflection pass that may only re-rank the tree.

**4. Executes with the whole offensive toolset.**
`kali_exec` puts nmap, ffuf, sqlmap, gobuster, nikto, nuclei and the rest of
Kali inside a sandboxed container; a Playwright browser handles anything needing
a DOM; `spa_recon` extracts the API surface of login-gated SPAs; `jwt_inspect`
runs the deterministic JWT checklist; `postex.py` carries post-exploitation;
`llmred/` runs structured attack campaigns against LLM targets.

**5. Proves everything, claims nothing it can't show.**
Findings enter `pending_verification` and only become CONFIRMED after an
independent re-check in a fresh context. Nothing credits the objective from a
scanner match or a model's claim; the creditor converts confirmed findings into
objective credit only when proof is on the wire. False-positive discipline is
what makes an autonomous attacker trustworthy, so it is architecture, not a
filter.

**6. Compounds across engagements.**
`memory.py` persists tradecraft (which CWE classes proved out, which oracles
work), app-shape patterns, and per-shape bandit win rates — the system attacks
the next target class better, not just the next run. Local semantic recall is
zero-dependency; HelixDB is opt-in.

## Authorization & containment (plumbing that makes it deployable)

Authorized use only — a signed SOW/engagement, a bug-bounty program within its
published scope, or an isolated lab. The engagement file is the boundary, and it
is enforced without trusting the model:

- **Egress firewall** — the Kali container runs `default-DROP` on OUTPUT; only
  IPs/CIDRs derived from the RoE are reachable, rules install before any tool
  runs, and a TEST-NET-1 self-test tears the sandbox down if a probe escapes.
- **No self-unlocking** — non-root user, all capabilities dropped except
  `NET_ADMIN`/`NET_RAW`, `no-new-privileges`, and `kali_exec` refuses
  iptables/routing/sudo/namespace commands.
- **Browser scope interception** — every page and subresource request is checked
  against the scope guard; out-of-scope requests abort.
- **Approval gates** — destructive/DoS-shaped commands require an interactive
  human "yes"; a STOP kill file auto-denies and halts (fail closed).
- **Rate limit + budget**, **append-only hash-chained JSONL audit**, **engagement
  window** the agent won't run outside of, and **swarm envelope integrity +
  quarantine** on the multi-agent bus.
- **Asset-feed sync is an intersection, never a merge** — out-of-scope entries
  are dropped and counted; the feed cannot widen scope.

## Layout

```text
redteam/
  recon/             offense-core: discovery.py (frequency priors + STADS stop rule),
                     assetgraph.py (competitive-intel radar), passive.py, static_source.py
  attack_tree.py     technique ranking + Thompson-sampling bandit (learned win rates)
  bandit.py          contextual bandit store
  orchestrator.py    multi-agent swarm: recon -> exploit -> verify -> access -> logic
  killchain.py       attack-chain state
  llmred/            LLM-target attack campaigns: strategies, multiseed, objectives,
                     detectors, regression
  agent.py           OpenAI-style tool-use loop (owned explicitly)
  run.py             execute_run() — the ONE run assembly line shared by CLI and API
  cli.py             Terminal entrypoint: preflight, console output, interactive approvals
  findings.py        Finding model + JSON store (pending_verification -> CONFIRMED)
  verify.py          Independent proof pipeline (fresh-context re-check)
  credit.py, proof.py, falsify.py   objective credit from confirmed proof only
  access.py, capabilities.py, objective.py   held access, capability accounting, scoring
  inventory.py       Attack-surface map (host -> port -> service/banner/title)
  memory.py          ExperienceStore — cross-run tradecraft + app-shape patterns
  memory_backend/    Semantic recall: local_semantic.py (zero deps) / HelixDB (opt-in)
  bandit memory      memory/bandit.json — per-(technique, endpoint-shape) win rates
  skills.py, specialists.py   distilled technique packs + specialist swarm
  reflection.py      strategist self-critique between rounds (re-rank only)
  intel/             EPSS + KEV snapshots for exploit prioritization
  tools/             kali_exec, browser_*, nuclei_scan (leads only), jwt_inspect,
                     spa_recon, postex, surface, asset_radar, http, authsession,
                     logic, template/skill tools, ...
  traffic.py         per-run wire evidence (traffic.jsonl) — masked, cursor-served
  graph_view.py      layered attack graph: asset -> endpoint -> access -> finding
  scope.py           ScopeGuard — SSRF-aware target boundary (hygiene)
  sandbox/           Kali container: egress firewall, self-test, lifecycle (hygiene)
  ratelimit.py       Token-bucket limiter + request budget (hygiene)
  audit.py           Append-only hash-chained JSONL audit log (hygiene)
  swarmguard.py      Bus envelope integrity + content quarantine (hygiene)
  events.py          EventBus + JSONL sink — the live telemetry the dashboard consumes
  server.py          Headless control plane (FastAPI): runs lifecycle, SSE, approvals,
                     static dashboard hosting
dashboard/           Next.js mission-control UI (static export, served by server.py)
config/engagement.example.yaml
docs/offense-arsenal.md   skills-first build order with per-technique adoption evidence
docs/offense-core.md      positioning: offense-core / offense-enabling / hygiene
GEN2-ARCHITECTURE.md Gen-2 design doc — how the pieces fit and which invariants hold
ROADMAP.md           gap analysis vs CAI / PentestGPT / Nebula + the path forward
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

## Mission control (dashboard + headless control plane)

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
- **Approve sensitive actions** in one click, **stop runs, read reports**, and inspect
  the objective score, kill chain, attack tree, wire traffic
  (`GET /api/runs/{id}/traffic`), the surface inventory, and the layered attack graph
  (`GET /api/runs/{id}/graph`).

Full API: `POST /api/runs`, `GET /api/runs`, `GET /api/runs/{id}`,
`GET /api/runs/{id}/events`, `GET /api/runs/{id}/stream` (SSE),
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

## Build order: what gets more offensive next

`docs/offense-arsenal.md` §7 is the active roadmap. Week 1 is shipped (recon:
frequency priors, STADS stop rule, asset radar). Next: stage-machine planning
(§5.4), cheapest-path consumers over the radar's typed edges (§3.1), bandit-armed
payload scheduling (§4.1), then TAP/MAP-Elites loops and postex validation +
recovery (§4.2–§5.3). Every technique in the arsenal carries per-technique
adoption evidence from real tools and papers; the math-arsenal guard sections
are deferred behind the offense build.

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

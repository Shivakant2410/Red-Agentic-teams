# AGENTS.md

Reference for coding agents working in this repo. Read this instead of re-exploring the
tree each session.

## What this is

`redteam-agent` (pyproject name) — an **authorized**-use red-team agent for web-app/API
security testing. Two execution surfaces given to the LLM: a Kali Linux Docker sandbox
(`kali_exec`: nmap, ffuf, sqlmap, nikto, gobuster, curl, ...) and Playwright browser
automation. Model backends: OpenRouter free-pool rotation (zero-config default) or the
Gen-2 multi-provider gateway (`llm/gateway.py` + `llm/providers.py` — OpenAI/Anthropic/
Z.ai/Groq/Ollama/vLLM, role-routed with cross-provider failover; an empty `llm.providers`
config falls back to byte-identical Gen-1 behavior). Scope is enforced at the network
layer (egress firewall + SSRF-aware scope guard), not by trusting the model to behave —
see README.md "How 'give it all of Kali' stays safe".

Python >= 3.10. Entry points: `redteam = "redteam.cli:main"` (`python -m redteam.cli`)
and the headless control plane `python -m redteam.server` (FastAPI + the Next.js
dashboard in `dashboard/`; see GEN2-ARCHITECTURE.md for the API contract).

## Two top-level packages

- **`redteam/`** — the actual agent: config/scope/sandbox/tools/CLI/orchestration. This
  is where almost all work happens.
- **`src/agentic_setup/`** — a separate, smaller layer: authorization/qualification
  checks, a local (non-sandbox) assessment path, benchmark running, usage tracking, a
  tool broker, and its own router/CLI. Check which package a task actually touches
  before editing — don't assume `redteam/` when the ask is about benchmarking,
  qualification, or usage accounting.

## Layout (`redteam/`)

```
config.py            RoE + LLM (OpenRouter) + sandbox settings, validated
scope.py              ScopeGuard — SSRF-aware target boundary
ratelimit.py          Token-bucket limiter + request budget
audit.py              Append-only JSONL audit log
findings.py           Finding model + JSON store
proof.py              Proof-of-exploitation requirements (not just a claimed finding)
verify.py             Verification pass over findings
falsify.py            Falsification checks
report.py             Markdown/HTML report builder
agent.py              OpenAI-style tool-use loop (hand-rolled, not a framework)
orchestrator.py       Coordinates planner/agent/skills across an engagement run
planner.py            Objective -> plan of actions
attack_tree.py         Attack tree modeling; optional BanditStore (bandit.py) learns
                       per-(technique, endpoint-shape) win rates across runs to nudge
                       the static priority table instead of overriding it
bandit.py              Contextual multi-armed bandit (Thompson sampling) over
                       attack_tree.py's technique choices; persists to
                       memory/bandit.json, same cross-engagement pattern as memory.py
killchain.py           Kill-chain stage tracking
knowledge.py / retrieval.py   Knowledge base + retrieval for the agent
memory.py              Cross-run memory (see memory/experience.json)
recon/                 Deterministic (zero-LLM-cost) recon: passive.py (robots.txt/
                       sitemap.xml/API-schema fetches) and static_source.py (route
                       extraction from a local source tree) — run once before any
                       LLM call (see cli.py's run_deterministic_recon)
objective.py           Objective modeling/scoring integration
secrets.py             Secret handling/redaction
session.py             Session state
skills.py              Skill library loading
runtime.py             Shared runtime wiring
run.py                 execute_run(RunOptions) — the ONE run assembly line shared by
                       cli.py and server.py; do NOT re-assemble runs elsewhere
events.py              EventBus + JSONL sink (events.jsonl per run) + read_events
                       replay; emission never raises (safe_emit for optional buses)
traffic.py             TrafficRecorder: per-run wire evidence (traffic.jsonl) recorded
                       at the tools/http.py chokepoint; credential headers masked BOTH
                       ways, bodies truncated/droppable; record() never raises and
                       only successful writes increment .count
inventory.py           AssetInventory: host->service surface map (inventory.json),
                       passive fingerprints from every response + surface_scan /
                       asset feeds; atomic saves, RLock (swarm-safe)
importers/assets.py    Asset-feed sync (CSV/JSON/JSONL): an INTERSECTION with the RoE
                       via scope.check — dropped records are counted, scope is NEVER
                       widened; raise ValueError on unreadable feed files
tools/surface.py       surface_scan: knocks once on every allowed host x port (capped
                       at 64 pairs), fills the inventory, NEVER records findings,
                       stops honestly on budget exhaustion
reflection.py          Per-round strategist self-critique; re-ranks attack_tree only
server.py              FastAPI control plane: POST/GET /api/runs, SSE stream, REST
                       approvals (run.py: HeadlessApprover/resolve_approval), static
dashboard hosting
cli.py                 Entrypoint: preflight, sandbox/browser lifecycle, approvals
parsers.py             Output parsing helpers
llm/
  openrouter.py        Free-model discovery + rotation/fallback (default backend)
  providers.py         OpenAI-compatible + native Anthropic providers
  gateway.py           LLMGateway: role routing, round-robin failover, 429 cooldowns
  routing.py            Model routing logic
sandbox/
  Dockerfile            Kali rolling + tools + firewall deps
  entrypoint.sh         Installs the egress allowlist, then idles (fail closed)
  egress.py             RoE scope -> allowed CIDRs
  docker_kali.py        Build/start/exec/stop the container
tools/
  kali.py                kali_exec (firewall-tamper + destructive guards)
  browser.py             browser_navigate/content/click/fill/screenshot
  workflow.py            record_finding, request_approval
  jwt.py                 jwt_inspect — deterministic JWT checklist (offline, leads only)
  nuclei.py              nuclei_scan — sandbox-first scanner; matches are LEADS only
  independent_verify.py  verify_finding_independently — the ONLY tool that may promote
                         a finding to confirmed
  access.py / access_tools.py   Access-control testing helpers
  authsession.py         Auth session handling for tools
  confirm.py             Interactive approval gating
  http.py                HTTP tool
  postex.py              Post-exploitation tooling
  skill_tools.py         Tools for invoking the skill library
  template_search.py     Template/finding search
  verify_tool.py         Verification tool wrapper
memory_backend/
  local_semantic.py      LocalSemanticBackend + HashingEmbedder — zero-dependency
                         semantic memory (JSON file; on-device transformer when
                         installed, hashing n-gram fallback otherwise)
  helix_backend.py       HelixDB backend (Docker, opt-in via --helix-memory)
bench/
  runner.py / scoring.py / objective_scoring.py / targets.py   Benchmark harness
importers/
  nuclei.py              Import Nuclei scan results as findings
```

`config/engagement.example.yaml` — template RoE file; copy to `config/engagement.yaml`
(gitignored) and fill in the signed scope before running anything for real.

`docs/journey.html`, `docs/_journey_artifact.html`, `docs/competitor-landscape.md` —
in-repo HTML/markdown records, not code.

`memory/experience.json` — persisted cross-run agent memory (data file, not docs).

`.state/` — runtime state (`catalog.json`, `usage.sqlite3`); not source.

`lab/` — standalone Docker lab target (`Dockerfile`, `probe.py`, `server.py`) used for
testing against an isolated target, separate from the sandbox/.

## Src layout (`src/agentic_setup/`)

```
authorization.py   Engagement authorization checks
qualification.py   Target/engagement qualification logic
benchmark.py       Benchmark execution
local_assessment.py  Non-sandbox local assessment path (530 lines — largest file here)
lab_runner.py      Drives the lab/ target
router.py          Model routing (separate from redteam/llm/routing.py)
openrouter.py      OpenRouter client (separate from redteam/llm/openrouter.py)
tool_broker.py     Tool brokering layer (586 lines — second largest)
usage.py           Usage tracking
models.py          Shared models
config.py          load_local_environment() — reads .env via python-dotenv
cli.py             Separate CLI entrypoint for this package
```

Note the naming overlap with `redteam/llm/`: `agentic_setup` has its own
`openrouter.py`/`router.py` — they are not the same code, don't conflate them when
searching.

## Tests

`tests/` mirrors both packages in one flat directory (pytest, `pytest -q`). ~40 test
files, ~20k total lines across the repo. Look for an existing `test_<module>.py` before
assuming behavior isn't covered.

## Conventions / things not obvious from a quick grep

- Scope enforcement is deliberately **not** "inspect the command string" — it's
  network-layer (default-DROP egress + ScopeGuard) because the model can run arbitrary
  Kali tools. Don't add scope checks inside `tools/kali.py` as the primary control;
  the firewall (`sandbox/egress.py`, `sandbox/entrypoint.sh`) is the control.
- `kali_exec` refuses commands touching iptables/ipset/routing/sudo/namespaces — no
  self-unlocking from inside the sandbox.
- Destructive/DoS-shaped actions require interactive human approval
  (`tools/confirm.py`, `tools/workflow.py: request_approval`) unless `--yes-to-all`
  (isolated labs only — never suggest this flag for a real engagement).
- Wildcard scope (`*.example.com`) works for the browser tool (checks request host by
  name) but **not** for Kali tools (firewall is IP/CIDR-based) — covering CIDR must
  also be listed in `scope.allowed_hosts`.
- To add a new agent tool: implement `schema()` + `run(ctx, ...)` in `redteam/tools/`
  and register it in `build_registry` (see `redteam/tools/__init__.py`).
- **Gen-2 additions to respect:**
  - New runs must go through `run.execute_run(RunOptions)` — the CLI and API share it;
    don't fork the assembly logic. Headless runs get telemetry via an `EventBus` in
    `RunOptions.events` and approvals via `HeadlessApprover`; CLI passes `None` and
    `interactive_approver`.
  - Emit telemetry with `safe_emit(ctx.events, "type", ...)` from tools; the catalog
    and role enum are in worklog/GEN2-ARCHITECTURE.md. Emission must never raise.
  - Reflection (`reflection.py`) may only re-rank existing attack-tree nodes via
    `attack_tree.apply_strategy` — never create targets or authorize actions.
  - Scanner output (`nuclei_scan`) and deterministic checklists (`jwt_inspect`) produce
    LEADS with verify hints; they must never record findings directly.
  - FastAPI request models must live at module level in `server.py` (closure-local
    pydantic models break schema generation with `from __future__ import annotations`).
- Free OpenRouter model availability changes constantly — `llm/openrouter.py` does
  live discovery filtered on `supported_parameters: tools`, never hardcode a model list.
- Findings require **proof**, not just a label (`proof.py`) — recent commit history
  ("Require proof, not a label, to credit a privilege objective") tightened this; don't
  relax finding-credit logic without checking `proof.py`/`verify.py`/`falsify.py`.
- A proven-proof skill library is intentionally excluded from version control (see
  `.gitignore` / commit "Exclude proven-proof skill library from version control") —
  don't assume a missing skill dir is a bug.

## Running it

```bash
pip install -e .
python -m playwright install chromium
export OPENROUTER_API_KEY=sk-or-...
cp config/engagement.example.yaml config/engagement.yaml   # edit to signed scope
python -m redteam.cli --engagement config/engagement.yaml \
  --objective "..." --out runs/<name>
pytest -q
```

Headless/dashboard mode (Gen-2):

```bash
pip install "fastapi>=0.110" "uvicorn[standard]"
npm --prefix dashboard install && npm --prefix dashboard run build
python -m redteam.server --runs-root runs --port 8000   # dashboard at http://127.0.0.1:8000
```

Docker must be running for the Kali sandbox. First run builds the (large) Kali image.

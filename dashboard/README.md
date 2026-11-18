# Red Teams — Mission Control

Static Next.js dashboard for the autonomous red-team agent server (Gen-2).
Talks to the FastAPI server whose routes and request models live in
`redteam/server.py` (`LaunchBody`, `MissionBody`, the run/mission/LLM
endpoints). No server features are used — this is a pure client-side app
exported to static files.

## Quick start

### Production (recommended): let FastAPI serve the dashboard

```bash
npm install
npm run build          # static export → dashboard/out/
```

Then start the FastAPI server; it serves `dashboard/out` at `/` and the API
under `/api` (same origin, so no CORS or API base config is needed).

### Standalone dev against a running API server

```bash
npm install
NEXT_PUBLIC_API_BASE=http://localhost:8000 npm run dev   # dashboard on :3000
```

- `NEXT_PUBLIC_API_BASE` — origin prefix for **all** fetch/SSE calls.
  Default `""` = same origin (the FastAPI case). It is baked in at dev/build
  time, so set it before starting `npm run dev` (or before `npm run build` if
  you build for cross-origin hosting).
- CORS: the dev contract allows all origins, so `:3000 → :8000` works while
  developing.

## Execution modes

The launch panel's **EXECUTION MODE** selector picks the driver:

- **Classic run** → `POST /api/runs` — the existing orchestrator swarm
  (recon → exploit → verify → access → logic rounds). Exposes `multi_agent`
  and `source_dir`.
- **Adaptive mission** → `POST /api/missions` — the mission coordination
  driver over the SAME specialists/verifier: it claims tasks from the live
  AttackTree frontier, verifies independently, and replans between rounds.
  Exposes `asset_feed`; `multi_agent` does not apply.
  The **explicit plan** field is strictly opt-in (collapsed by default, must
  parse as a JSON array of tasks) — an EMPTY plan (the default) runs the
  dynamic frontier; the server never fabricates a static plan.

Both responses carry `mission_id` and `run_id` (same value today, separate
logical fields) plus `driver`; the dashboard navigates to `/runs?id={run_id}`,
where the header badge shows the driver and mission runs get the **ADAPTIVE
MISSION** panel: mission/run identity, mission status, current task +
specialist, task lifecycle chips and recent tasks (technique → target ·
status), the verification split (confirmed = independent-verifier authority
only), stop reason, and the mission-journal tail. Fields the API does not
expose (e.g. remaining budget) render an explicit unavailable state.
Classic runs keep the existing mission-control experience unchanged.

## Model & provider selection

The launch panel's **MODEL PROVIDER** section sends an optional `llm` override
— identical contract on BOTH `POST /api/runs` and `POST /api/missions`:

```json
{ "provider": "zai", "model": "glm-5.3", "api_key": "...", "base_url": "" }
```

- `provider` — a kind the engine understands: `openai | zai | gemini | openrouter |
  ollama | groq | anthropic`, or anything else **when `base_url` is also sent**
  (the `openai_compat` escape hatch: vLLM, LM Studio, a private proxy).
- `model` — pins the run's rotation to this model id via `llm.providers[].models_allow`;
  empty = the provider's natural rotation. The field is free text with per-provider
  presets as suggestions (OpenAI `gpt-sol`, Z.ai `glm-5.3` / `glm-5.2`,
  Gemini `argon` / `hydrogen`, ...).
- `api_key` — a **run-scoped credential**: carried in memory on THIS run's
  server-side options and resolved into that run's provider sessions at
  construction. It is never written to the process environment, the engagement
  YAML, manifests, events, logs, or responses — concurrent runs with different
  keys cannot cross-use them. Omit it to use preconfigured env credentials
  (`OPENAI_API_KEY`, `ZAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`,
  `GROQ_API_KEY`, `ANTHROPIC_API_KEY`). Ollama needs no key.
- The server materializes the override as `engagement.yaml` inside the run dir
  (the engine runs that copy; the key is NOT in it) and emits an `llm.selected`
  event into the feed, so every artifact records the exact model config the
  run used.
- `GET /api/llm/providers` returns the catalog: supported kinds, the standard
  key env var per kind, and whether that env var is currently set (presence
  only — never the key).

### Preflight (especially for Ollama)

Once a provider is selected, a **PREFLIGHT** button appears next to the section
header. It calls `POST /api/llm/preflight` and renders the server's check list
inline — `PASS`/`FAIL` per check, never a bare "ok" badge:

1. `reachable` — the AGENT SERVER can reach the endpoint (the browser is not
   involved; containers must use `host.docker.internal`, not `localhost`);
2. `model_found` — the endpoint's live catalog serves that model id;
3. `tool_call_ok` — a harmless synthetic request comes back WITH a tool call
   (models without tool-calling support fail here with that stated plainly);
4. `args_parsed` — the tool-call arguments parse as JSON (the same parse the
   agent loop performs every turn).

The preflight never contacts the engagement target. Alongside it, the model
field's suggestions merge with ids discovered live from the endpoint
(`GET /api/llm/models` — silent fallback to presets when the endpoint is
unreachable). Until the preflight is green, expect a local model to either not
start at all or to drive no tools.

## Testing

```bash
npm test               # vitest + testing-library component suite (src/**/*.test.tsx)
npx tsc --noEmit       # type check
npm run build          # static export must always succeed
# from the repo root:
#   python -m pytest tests/test_dashboard_e2e.py   # Playwright browser E2E
#                                                     (needs dashboard/out + chromium)
```

The component suite mocks the api client and navigation; the browser E2E
drives a REAL FastAPI server with a deterministic fake engine through the
complete operator workflow (both drivers, live events, stop, report, mission
panel, refresh recovery).

## Notes

- `next.config.ts` sets `output: "export"`, `trailingSlash: true`
  (so a plain static file server can serve `/runs/`) and
  `images.unoptimized: true`. There are no API routes, rewrites, or server
  components with runtime behavior — `npm run build` must always succeed.
- Live events: `EventSource` on `/api/runs/{id}/stream?after={cursor}`
  with automatic fallback to polling `/api/runs/{id}/events?after={cursor}`
  every 2 s and SSE retry every 5 s. Cursor = last event `seq`.
- Polling cadence: run detail 5 s; mission detail 5 s while the mission is
  live (one final fetch on end); runs overview 5 s while any run is active
  (15 s idle — ONE authoritative poll owns the list; a successful launch
  dispatches a `run:launched` window event so a mounted overview refreshes
  immediately); pending approvals 5 s while the run is live.
- Poll failures never blank the screen: hooks keep the last good data and
  surface the error inline.

## Structure

```
src/
├── app/
│   ├── layout.tsx        # fonts (Inter + JetBrains Mono), metadata, war-room theme
│   ├── page.tsx          # "/" runs overview: health dot, stat cards, runs table, launch panel
│   └── runs/page.tsx     # "/runs?id=..." mission control (Suspense-wrapped client page)
├── components/           # hand-rolled components (no UI kit)
│   ├── EventFeed.tsx     # live feed: type filters, auto-scroll pause, connection state
│   ├── EventRow.tsx      # per-event-type rendering for the full contract catalog
│   ├── MissionControl.tsx# single-run console (stats, stepper, approvals, stop)
│   ├── MissionPanel.tsx  # adaptive-mission visibility (driver, tasks, verification split)
│   └── ...               # StatusBadge, StatCard, PhaseStepper, ObjectiveProgress,
│                         # FindingsTable, KillChainList, ReflectionsFeed, ApprovalCard,
│                         # JsonView, RunsTable, LaunchRunPanel, Bits (primitives)
└── lib/
    ├── api.ts            # fetch wrapper + API_BASE + typed endpoint helpers
    ├── useRunStream.ts   # SSE → polling fallback hook with cursor tracking
    ├── usePoll.ts        # resilient polling hook
    ├── types.ts          # contract types (RunSummary, RunDetail, RunEvent, …)
    └── format.ts         # ages, durations, HH:MM:SS, token counts
```

## Theme

Dark war-room palette per spec: bg `#0B0E14`, panels `#11151C`,
borders `#1E2430`, text `#E6E9EF`, muted `#8A94A6`, red `#FF3B5C`,
green `#2DD4A7`, amber `#F5A623`, blue `#5B9DFF` (plus purple `#A78BFA`,
cyan `#22D3EE`, orange `#FB923C` for role/severity chips).

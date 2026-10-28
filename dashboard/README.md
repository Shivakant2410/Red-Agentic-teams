# Red Teams — Mission Control

Static Next.js dashboard for the autonomous red-team agent server (Gen-2).
Talks to the FastAPI server defined by the **BINDING API contract** in
`/home/z/my-project/worklog.md`. No server features are used — this is a
pure client-side app exported to static files.

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

## Notes

- `next.config.ts` sets `output: "export"`, `trailingSlash: true`
  (so a plain static file server can serve `/runs/`) and
  `images.unoptimized: true`. There are no API routes, rewrites, or server
  components with runtime behavior — `npm run build` must always succeed.
- Live events: `EventSource` on `/api/runs/{id}/stream?after={cursor}`
  with automatic fallback to polling `/api/runs/{id}/events?after={cursor}`
  every 2 s and SSE retry every 5 s. Cursor = last event `seq`.
- Polling cadence: run detail 5 s; runs overview 5 s while any run is active
  (15 s idle); pending approvals 5 s while the run is live.

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

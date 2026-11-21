# RECON — the reconnaissance specialist after the 2026-11-18 upgrade

RECON is a first-class autonomous recon workstation, not an LLM that receives a
recon prompt and calls disconnected tools. It maps the authorized attack
surface with a real instrumented browser, queries an intercepting proxy's
captured history DURING the run, runs passive and controlled active discovery,
corroborates what it finds, and hands structured evidence to EXPLOIT / LOGIC /
VERIFY. This document describes the current capability set, the evidence
architecture, and the honesty rules.

## Architecture: agent → browser → EvidenceProxy → target

```
RECON specialist (Orchestrator profile, 30 tools, 30 steps)
  ├─ Playwright browser (headless chromium, host-side)
  │    ├─ global route guard  → ScopeGuard.check() on EVERY request; out-of-scope aborted
  │    ├─ request/response/console/pageerror capture → bounded ring (agent-queryable)
  │    └─ ALL traffic routed through EvidenceProxy when the proxy runs
  ├─ EvidenceProxy (run-scoped, stdlib, no Docker required)
  │    ├─ plain HTTP forward + HTTP CONNECT; MITM with run CA or HONEST blind tunnel
  │    ├─ scope check BEFORE dialing (403, never forwarded, denial recorded)
  │    └─ every exchange → traffic.jsonl (source=proxy / proxy-mitm / proxy-tunnel)
  ├─ shared fetch path (http_probe etc.) → scope + traffic + detection filter
  └─ ObservationLog (observations.jsonl) → mirrors into KnowledgeGraph
```

Evidence dedupe: when the browser routes through the proxy, the controller
skips direct traffic recording (the proxy's wire row IS the evidence, source
`proxy`/`proxy-mitm`); without a proxy the controller records directly
(source `browser`). No exchange is double-counted.

TLS honesty: `proxy_status` reports whether HTTPS was DECRYPTED (MITM with
the run CA — browser↔proxy leg accepts the run CA; proxy↔target leg still
verifies upstream certificates against the system trust store) or only
TUNNELED (metadata rows, status 0, no body). A passthrough row never claims
decrypted content. Certificate-pinned targets: the MITM leg fails loudly.

The proxy starts for every browser run (`use_browser`), not only sandbox runs
(`run.py`); without it the browser is still scope-guarded and records its own
wire rows.

## Tool surface (RECON profile)

| Phase | Tools |
|---|---|
| A understand | `proxy_status` (listener, TLS mode, capture counters) |
| B passive | `passive_recon` (DNS A/AAAA/CNAME + MX/NS/TXT when dnspython installed, TLS certificate metadata + SANs, robots.txt, sitemap.xml, security headers, cookie flags, technology fingerprints; CT logs only with `RED_CT_LOGS=1`) |
| C active mapping | `surface_scan`, `host_probe`, `port_scan` (RoE-validated port specs) |
| D browser | `browser_navigate/_content/_click/_fill/_screenshot` + read-back: `browser_requests` (list what was ACTUALLY sent incl. XHR/fetch and blocked attempts), `browser_inspect_request` (one exchange in full, sanitized), `browser_console` (console errors + page errors), `spa_recon` (SPA API walk) |
| E API/content | `content_discovery`, `crawl`, `param_discovery`, `http_probe`, `graphql_inspect`, `jwt_inspect` + `proxy_history/_filter/_inspect` (re-read the capture) + `proxy_replay` (re-send ONE captured exchange: scope-checked, budgeted, audited, recorded `source=replay`; no new targets through it) |
| F corroborate | `crosscheck_lead` (second-method verdicts → observation validation states) |
| G handoff | structured `recon_handoff.json` + `observations` query tool |

`observations` (the query tool) is the agent's memory: every recorded claim
with its source tool, mode, timestamp and validation state — check BEFORE
re-running any discovery tool.

## Observation format and validation lifecycle

Every observation carries: stable `obs_id`, type (endpoint/parameter/
technology/host/domain/service/form/api_spec/header/console_error/asset),
target, method, scheme/port, source tool, source specialist, timestamp,
mode (`passive` = no target contact · `light` = metadata-class wire touch ·
`active`), evidence refs, confidence, validation state, bounded metadata
(credential-shaped keys withheld by name).

Validation states (honest by default — a tool's raw output never auto-confirms):

```
discovered → awaiting_corroboration → corroborated | contradicted
                                    → unverifiable | stale
```

- a SECOND DISTINCT source tool observing the same key → `corroborated`
  (mirrors KnowledgeGraph.observe's own rule);
- `crosscheck_lead` verdicts land via `mark_validation()` — the audit record
  stays the legal trail, the log is the working state;
- a corroborated lead is STILL a lead: promotion to a finding happens only in
  the proof pipeline (`verify_finding_independently`), never here;
- duplicates merge by (type, target, method) WITHOUT losing provenance (every
  sighting kept); a contradicted lead that re-observes honestly returns to
  `discovered`.

Everything mirrors into the shared KnowledgeGraph (host/service/endpoint/
parameter/technology/domain kinds) so EXPLOIT/LOGIC/VERIFY read the same
state — the log is the provenance layer, not a second store of truth.

## Workflow (phases A–G) and handoff

The profile instructions encode the phase plan (A understand → B passive → C
initial active mapping → D browser → E API/content → F corroborate → G
handoff). Phase G writes `<run>/recon_handoff.json` (artifacts-only: graph
counts, inventory, validation stats, unverified leads, untested endpoints) and
prefixes the task result with a compact handoff payload so downstream
specialists get structured coverage — completion reflects produced coverage
and outstanding work, never exhausted LLM steps.

## Mission reliability (2026-11-18 fixes)

- A failed initial recon task no longer orphans the mission: the scheduler
  requeues recon tasks on execution failure (`TASK_REQUEUED`, bounded by
  `max_attempts=2` for dynamic recon; `TASK_EXHAUSTED` on the final failure).
- Stop reasons are honest: when the recon prerequisite never succeeded the
  driver reports `recon_failed` / `recon_incomplete` — never
  `frontier_exhausted` (the frontier was never evaluated).

## Security controls (unchanged and verified)

ScopeGuard checks every fetch, every browser request (route guard), every
proxy dial and every replay; port_scan validates explicit ports against the
RoE fail-closed; the shared RateLimiter gates the fetch path, probe, surface,
SPA walk, browser navigation, proxy exchanges and replays; private ranges
require explicit RoE opt-in; headers are masked at the recorder
(Authorization/Cookie/Set-Cookie/…), credential-shaped metadata keys are
withheld by name, bodies are size-clipped; kali_exec stays approval-gated;
external CT lookups are opt-in (`RED_CT_LOGS=1`) and off by default.

## Live view (any.run-style)

The browser controller refreshes `<run>/recon_live/latest.jpg` (JPEG frame)
and `events.jsonl` (navigate/click/fill/screenshot feed) on every action. The
server serves:

- `GET /api/runs/{run_id}/recon/live` — one JSON snapshot: base64 frame,
  activity feed, network tail (with per-source counts), observation counts;
- `GET /live/{run_id}` — a self-contained viewer (no build step): live frame,
  activity, network and observation tables, progress footer; polls at 1.5 s,
  responsive down to phone widths.

## Tests

- `tests/test_recon_integration.py` (13): observation lifecycle/merge/hygiene,
  proxy tools over a REAL EvidenceProxy (history/inspect/filter, replay
  recorded+audited, honest no-proxy status), passive_recon over a real local
  site (robots/sitemap/headers/tech leads with provenance, out-of-scope
  refusal), crosscheck→validation states, recon handoff persistence, live
  snapshot + endpoints.
- `tests/test_browser_recon.py` (2, REAL chromium, skip when absent): network
  capture incl. XHR/fetch and blocked attempts, console errors, redaction,
  traffic.jsonl integration, observation provenance, live artifacts,
  out-of-scope navigation denied before dial.
- `tests/test_mission_recon_retry.py` (3): failed initial recon recovers;
  exhausted retries → `recon_failed`; non-recon failures stay terminal.
- Existing suites: `test_spa_recon.py` (real browser walks), `test_evidence_proxy.py`
  (12 proxy tests), `test_hands.py` + `test_mission_registry.py` (profile/hand sync).

## Remaining limitations

- DNS MX/NS/TXT need `dnspython` (stdlib covers A/AAAA/CNAME); certificate
  parsing needs `cryptography` (shipped with the proxy's MITM support).
- Crawl/ffuf/katana/arjun run host-side without sandbox egress confinement in
  native mode (documented; scope-checked at target level, binary request
  rates clamped) — budget accounting for their sub-requests is per-invocation.
- Proxy MITM requires a client that accepts the run CA (the browser does when
  routed; pinned clients fail loudly by design).
- No WebSocket frame capture beyond the spa_recon walk's OPEN events.

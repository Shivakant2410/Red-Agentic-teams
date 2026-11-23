# ARTEX Session Bridge — human-assisted auth for Red-Agentic-teams

A Chrome/Edge (Manifest V3) extension that closes the loop the platform's
ARTEX architecture is named for: **bind every finding to CA-traced proxy
traffic + verbatim response quotes — and let the HUMAN complete the auth
steps (2FA / SSO / captcha) in their real browser, then hand the surviving
session to the agent.** Human-assisted auth beats Playwright-only auth: it is
the operator's own browser profile, their real IdP session, no bot detection
to defeat.

## What it captures (and what it does not)

| Captured | How | Where it lands |
|---|---|---|
| Session cookies of the active site | `chrome.cookies` → one `Cookie` header | `<run>/ingest/sessions.jsonl` (auth-header-filtered) |
| Request/response headers of browsed traffic | `chrome.webRequest` (observe-only) | `traffic.jsonl` rows, `source=extension`, scope-labeled |
| Response **bodies** | **not captured** — MV3 without the debugger API cannot read them | the agent's own in-scope probes capture bodies via the evidence proxy |

The agent never receives passwords or OTP codes — only the session that the
human produced by completing the login themselves.

## Install (load unpacked)

1. Chrome: `chrome://extensions` → Developer mode → **Load unpacked** →
   select this `extension/` directory. Edge: `edge://extensions` → same flow.
2. Start a run (classic or mission) and keep the control-plane server
   reachable — the default pairing target is `http://127.0.0.1:8000`
   (loopback; the server must not be exposed beyond the operator's machine).
3. Copy the **run id** from the dashboard into the popup, open the target
   site in the active tab, complete the login (2FA/SSO/captcha) yourself.
4. Press **Share session for this site**. The popup posts the session +
   recent traffic to `POST /api/traffic/ingest`.
5. In the run, the RECON/ACCESS specialist calls **`ingest_sessions`** and
   the session becomes usable exactly like a `set_session` session
   (`as_session=<label>`), with source recorded honestly as
   `extension_ingest` and audit entries carrying header names only.

## Server-side honesty rules (redteam/server.py)

- Rows are **evidence only** — never forwarded anywhere.
- The run's **frozen scope.json** decides labeling: in-scope rows are
  extension traffic; out-of-scope rows (e.g. SSO IdP redirects) are recorded
  as **denied** so the chain stays visible without pretending it was
  authorized testing traffic.
- **Sessions fail closed** without a frozen scope; auth-header-filtered;
  values stored only in the run dir, never echoed into transcripts,
  audit logs, or reports.
- Every ingest batch is appended to `<run>/ingest/audit.jsonl`.

## Files

- `manifest.json` — MV3, minimal permissions (`webRequest`, `cookies`,
  `storage`, `tabs`).
- `background.js` — bounded (500-entry) request/response-header ring.
- `popup.html` / `popup.js` — pairing UI + the two ingest actions.

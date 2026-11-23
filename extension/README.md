# Red-Agentic Traffic Capture (browser extension)

Stream the traffic of a **human-driven** session into a Red-Agentic run's
evidence store. This is the clean answer to the auth flows that cannot be
automated headlessly — 2FA, email OTP, CAPTCHA, Cloudflare Turnstile, complex
SSO. A human logs in and clicks through the app normally; the extension records
the resulting HTTP exchanges and ships them to the server, where they land in
the **same `traffic.jsonl`** the MITM proxy and in-process fetch write. The
planner and workers then see real authenticated endpoints, headers, tokens and
API shapes — no headless auth, no scraping stdout.

## Server setup (once)

The ingest endpoint is authenticated with a shared token and is off unless it is
set. On the machine running the server:

```bash
export RED_INGEST_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(24))')"
# start the server as usual (it reads the token from the environment)
python -m redteam.server --host 127.0.0.1 --port 8000 --runs-root runs
```

Keep that token value — you paste it into the extension popup.

## Load the extension

1. Chrome/Edge → `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode**.
3. **Load unpacked** → select this `extension/` directory.

## Capture a session

1. Launch (or already have) a run; note its **run id** (e.g.
   `20261123-…-vinted-warmed`).
2. Open the target site in a tab and log in / solve any challenge **as a human**.
3. Click the extension icon → fill **Server URL** (`http://127.0.0.1:8000`),
   **Ingest token** (`RED_INGEST_TOKEN`), **Run id** → **Start capture**.
4. Browse the key workflows. The popup shows a live `N sent` counter.
5. **Stop** when done. The exchanges are now in the run's traffic store for the
   agent to reason over.

## What it captures (and does not)

- Text-based HTTP(S) exchanges: method, URL, status, request/response headers
  and bodies. Response bodies are read via the Chrome debugger protocol.
- **Skipped**: binary assets (images, fonts, audio, video, stylesheets) and any
  body over 256 KiB — evidence is the API surface, not the pixels.
- Batches of up to 50 exchanges are POSTed to `/api/traffic/ingest`.

## Scope & safety

The extension records whatever tab you point it at — only capture sessions on
**in-scope** targets, and only ever log in with **test accounts you own** (e.g.
an `@bugcrowdninja.com` account for a Bugcrowd program), never a real user's.
Captured bodies may contain session tokens: the traffic store masks the same
fields as every other record, but treat a run's evidence as sensitive.

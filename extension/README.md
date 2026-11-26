# gnhf evidence capture (Chrome / Edge, Manifest V3)

The human-assisted half of the ARTEX loop: some evidence only exists after a
**human** solves a 2FA / OTP / captcha step in their own browser. Playwright-only
auth loses exactly that step; this extension records it and binds it to the run.

## What it records (and what it never touches)

- Page **URL** and **title**
- **Field names** of inputs on the page (name / id / autocomplete / aria-label)
- Booleans: **otp_observed**, **captcha_observed**
- NEVER input **values** — the collect function uses `getAttribute()` only.
  The OTP the operator typed never leaves their machine. This is the same
  masking discipline the traffic recorder applies to `Authorization` /
  `Cookie` headers, applied at the source.

## Install (unpacked)

1. Chrome / Edge → `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode**
3. **Load unpacked** → select this `extension/` directory

## Use

1. In the popup: set **Control plane** (default `http://127.0.0.1:8000`) and
   the **run id** of the armed run (visible in the dashboard URL / `/api/runs`).
2. Walk the authenticated step in your browser as the human in the loop.
3. Click **Capture this page's shape** while on the post-2FA page.
4. The capture is POSTed to `POST /api/traffic/ingest`, scope-checked against
   the run's `engagement.yaml`, and stored as a `kind=extension_session` row in
   the run's `traffic.jsonl` — visible via `/api/runs/{id}/traffic` and bound
   into POE grading.

Out-of-scope captures are **rejected (HTTP 400)** — an out-of-scope capture is
a leak, not evidence.

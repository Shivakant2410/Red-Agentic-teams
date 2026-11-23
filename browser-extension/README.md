# Chrome / Edge Auth Flow Telemetry

This Manifest V3 extension sends **metadata-only** authentication-flow events to a local Red Agentic Teams run.

## What it records

- OTP challenge detected
- OTP form submitted (event only)
- CAPTCHA widget detected
- Login/authentication page detected
- Page origin/path, challenge kind, and a bounded field/widget count
- Browser HTTP request/response metadata: method, resource type, status, tab/frame and request ID

## What it never records

- OTP digits or other input values
- Passwords
- CAPTCHA response tokens
- Cookies or authorization headers
- Request or response bodies
- Request/response headers or cookies
- URL query strings or fragments

The extension does not bypass, solve, or automate OTP/CAPTCHA challenges. A human completes those steps in the browser.

Chrome/Edge request broad HTTP(S) host access plus the `webRequest` metadata
permission so the extension can observe requests from tabs. Use a dedicated
assessment browser profile. The local ingest API persists events only when the
host, scheme and port match the active engagement scope; unrelated pages are
rejected.

## Configure

1. Start the control plane (default: `http://127.0.0.1:8000`).
2. Start an authorized run. The run writes a random token to `runs/<run_id>/traffic_ingest.token` with owner-only file permissions where supported.
3. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge), enable Developer mode, and choose **Load unpacked**. Select this directory.
4. Open the extension's **Options** and set the control-plane URL, run ID, and token from that run's token file.
5. Browse the authorized target. Events appear in the run's `traffic.jsonl` with source `browser-extension`.

The ingest endpoint is loopback-only, requires the per-run token, and enforces the run's allowed hosts, schemes and ports. It strips URL query strings and fragments before persistence.

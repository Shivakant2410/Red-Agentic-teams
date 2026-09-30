"""Shared, scope-enforced HTTP fetch used by confirm_finding and the chained-attack tools.

One place that turns a request spec into (status, body, elapsed[, headers]) and always
scope-checks first. Uses the sandbox's firewalled curl when a sandbox is running, else a
host-side request (for localhost/benchmark targets the container can't reach). Keeping
this single path means every tool inherits the same scope guard and the same behavior.
"""

from __future__ import annotations

import re
import time

import requests

from . import ToolContext

_MARKER = "__RT_STATUS__"

# Hard ceiling on how much of a response body we will hold in memory. A target can
# return an arbitrarily large body (or stream forever); reading it unbounded lets the
# target exhaust our memory. Bodies are evidence, not payloads, so a cap is free.
MAX_RESPONSE_BYTES = 256 * 1024
TRUNCATION_MARKER = " [truncated]"


def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _host_request(req: dict):
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    headers = req.get("headers") or {}
    body = req.get("body")
    start = time.monotonic()
    try:
        # stream=True so we can stop reading instead of buffering a huge body first.
        r = requests.request(method, url, headers=headers, data=body,
                             timeout=20, allow_redirects=False, stream=True)
        raw = r.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True) or b""
        truncated = len(raw) > MAX_RESPONSE_BYTES
        text = raw[:MAX_RESPONSE_BYTES].decode(r.encoding or "utf-8", errors="replace")
        if truncated:
            text += TRUNCATION_MARKER
        return r.status_code, text, time.monotonic() - start, dict(r.headers)
    except requests.RequestException:
        return 0, "", time.monotonic() - start, {}


def _sandbox_request(ctx: ToolContext, req: dict):
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    headers = req.get("headers") or {}
    body = req.get("body")
    parts = ["curl", "-s", "-S", "-k", "-i", "-X", _shq(method)]
    for k, v in headers.items():
        parts += ["-H", _shq(f"{k}: {v}")]
    if body is not None:
        parts += ["--data-binary", _shq(body)]
    parts += ["-w", _shq(f"\\n{_MARKER}%{{http_code}} %{{time_total}}"), _shq(url)]
    res = ctx.sandbox.exec(" ".join(parts))
    out = res.stdout
    status, elapsed = 0, 0.0
    idx = out.rfind(_MARKER)
    head_and_body = out
    if idx != -1:
        m = re.match(r"(\d+)\s+([\d.]+)", out[idx + len(_MARKER):].strip())
        if m:
            status, elapsed = int(m.group(1)), float(m.group(2))
        head_and_body = out[:idx]
    # Split -i output into headers and body at the first blank line.
    resp_headers: dict = {}
    body_text = head_and_body
    if "\r\n\r\n" in head_and_body or "\n\n" in head_and_body:
        sep = "\r\n\r\n" if "\r\n\r\n" in head_and_body else "\n\n"
        head, _, body_text = head_and_body.partition(sep)
        for line in head.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                resp_headers[k.strip()] = v.strip()
    if len(body_text) > MAX_RESPONSE_BYTES:
        body_text = body_text[:MAX_RESPONSE_BYTES] + TRUNCATION_MARKER
    return status, body_text, elapsed, resp_headers


def _check_scope_recording_denial(ctx: ToolContext, req: dict) -> None:
    """Scope-check a request and AUDIT the refusal before raising.

    A blocked request is evidence in its own right: it shows the boundary held, and a
    client reviewing the audit log can see exactly what was attempted and stopped. Letting
    the denial exist only as a string returned to the model loses that record."""
    from ..scope import ScopeViolation
    try:
        ctx.scope.check(req["url"])
    except ScopeViolation as exc:
        ctx.audit.record("tool.denied", tool="http", method=(req.get("method") or "GET"),
                         url=req.get("url"), outcome="scope-denied", reason=str(exc))
        raise


def fetch_once(ctx: ToolContext, req: dict):
    """Single scope-checked request -> (status, body, elapsed, headers)."""
    _check_scope_recording_denial(ctx, req)
    if ctx.sandbox is not None:
        return _sandbox_request(ctx, req)
    return _host_request(req)


def make_fetch(ctx: ToolContext, req: dict):
    """A re-runnable fetch() -> (status, body, elapsed) for the verification engine."""
    _check_scope_recording_denial(ctx, req)

    def fetch():
        status, body, elapsed, _ = (_sandbox_request(ctx, req) if ctx.sandbox is not None
                                    else _host_request(req))
        return status, body, elapsed
    return fetch

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


def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _host_request(req: dict):
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    headers = req.get("headers") or {}
    body = req.get("body")
    start = time.monotonic()
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             timeout=20, allow_redirects=False)
        return r.status_code, r.text or "", time.monotonic() - start, dict(r.headers)
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
    return status, body_text, elapsed, resp_headers


def fetch_once(ctx: ToolContext, req: dict):
    """Single scope-checked request -> (status, body, elapsed, headers)."""
    ctx.scope.check(req["url"])
    if ctx.sandbox is not None:
        return _sandbox_request(ctx, req)
    return _host_request(req)


def make_fetch(ctx: ToolContext, req: dict):
    """A re-runnable fetch() -> (status, body, elapsed) for the verification engine."""
    ctx.scope.check(req["url"])

    def fetch():
        status, body, elapsed, _ = (_sandbox_request(ctx, req) if ctx.sandbox is not None
                                    else _host_request(req))
        return status, body, elapsed
    return fetch

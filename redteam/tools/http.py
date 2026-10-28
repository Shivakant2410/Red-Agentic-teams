"""Shared, scope-enforced HTTP fetch used by confirm_finding and the chained-attack tools.

One place that turns a request spec into (status, body, elapsed[, headers]) and always
scope-checks first. Uses the sandbox's firewalled curl when a sandbox is running, else a
host-side request (for localhost/benchmark targets the container can't reach). Keeping
this single path means every tool inherits the same scope guard and the same behavior.

ARTEX-port hook: this is ALSO the single telemetry chokepoint. Every in-scope
exchange is (a) recorded into the run's TrafficRecorder (secret-masked wire evidence,
see traffic.py) and (b) passively fingerprinted into the AssetInventory (server
banner, page title) — zero extra requests, the surface map builds itself while the
team works. Scope-DENIED attempts are recorded too: a blocked request is evidence
that the boundary held. Telemetry failures are swallowed — recording must never
break a request mid-proof.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

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
    the denial exist only as a string returned to the model loses that record. The
    attempt is also mirrored onto the traffic log (operator-facing wire evidence)."""
    from ..scope import ScopeViolation
    try:
        ctx.scope.check(req["url"])
    except ScopeViolation as exc:
        method = (req.get("method") or "GET")
        ctx.audit.record("tool.denied", tool="http", method=method,
                         url=req.get("url"), outcome="scope-denied", reason=str(exc))
        traffic = getattr(ctx, "traffic", None)
        if traffic is not None:
            traffic.record_http(method=method, url=req.get("url", ""), status=0,
                                elapsed_ms=0, tool="http", error=f"scope-denied: {exc}",
                                req_headers=req.get("headers"), req_body=req.get("body"))
        raise


def _passive_observe(ctx: ToolContext, req: dict, status: int,
                     resp_headers: dict, body: str) -> None:
    """Fingerprint the responding host into the AssetInventory (passive — this runs
    AFTER a real exchange, makes no requests of its own). Best-effort by design."""
    inventory = getattr(ctx, "inventory", None)
    if inventory is None or not status:
        return
    try:
        parsed = urlparse(req.get("url", ""))
        host = parsed.hostname
        if not host:
            return
        scheme = (parsed.scheme or "http").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        inventory.observe_http(host, port, scheme, status, headers=resp_headers,
                               body=body, source="http")
    except Exception:
        pass  # a fingerprinting surprise must never break a proof in flight


def fetch_once(ctx: ToolContext, req: dict, tool: str = "", session: str = ""):
    """Single scope-checked request -> (status, body, elapsed, headers).

    tool/session label the exchange in the traffic log (best-effort identity for
    the operator; they change nothing about how the request is made)."""
    _check_scope_recording_denial(ctx, req)
    start = time.monotonic()
    if ctx.sandbox is not None:
        result = _sandbox_request(ctx, req)
    else:
        result = _host_request(req)
    status, body, _elapsed, headers = result
    _record_traffic(ctx, req, status, time.monotonic() - start, headers, body,
                    tool=tool, session=session)
    _passive_observe(ctx, req, status, headers, body)
    return result


def _record_traffic(ctx: ToolContext, req: dict, status: int, elapsed: float,
                    resp_headers: dict, resp_body: str, tool: str, session: str) -> None:
    traffic = getattr(ctx, "traffic", None)
    if traffic is None:
        return
    try:
        traffic.record_http(method=(req.get("method") or "GET"), url=req.get("url", ""),
                            status=status, elapsed_ms=round(elapsed * 1000),
                            tool=tool, session=session,
                            req_headers=req.get("headers"), req_body=req.get("body"),
                            resp_headers=resp_headers, resp_body=resp_body)
    except Exception:
        pass  # telemetry must never break a run (same rule as the EventBus)


def make_fetch(ctx: ToolContext, req: dict, tool: str = ""):
    """A re-runnable fetch() -> (status, body, elapsed) for the verification engine.
    Each re-run is traffic-recorded too — k-of-n proof attempts are evidence."""
    _check_scope_recording_denial(ctx, req)

    def fetch():
        start = time.monotonic()
        if ctx.sandbox is not None:
            status, body, elapsed, headers = _sandbox_request(ctx, req)
        else:
            status, body, elapsed, headers = _host_request(req)
        _record_traffic(ctx, req, status, time.monotonic() - start, headers, body,
                        tool=tool or "verify", session="")
        _passive_observe(ctx, req, status, headers, body)
        return status, body, elapsed
    return fetch

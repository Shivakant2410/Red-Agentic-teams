"""http_probe — cheap, scope-enforced, session-aware HTTP exploration.

Live-fire gap this closes: the exploit agent kept misusing confirm_finding to LOOK
AROUND (check a response, validate a captured token, walk an ID space) — burning
k-of-n verification budget, spawning dead findings that the verify pass then had to
reject, and polluting the finding pipeline with probes. Exploration and PROOF are
different jobs and now they have different tools:

  - http_probe  = one raw request, whatever headers/session the operator's agent
                  chooses, result echoed back for reasoning. NEVER records a finding.
  - confirm_finding / verify_vulnerability = reproduce a HYPOTHESIS k-of-n and record
                  it into the verification pipeline.

Everything still flows through the shared fetch path (tools/http.py), so a probe
inherits the same scope guard, the same audit-on-denial, and the same sandbox/host
routing as every other network tool. Session material comes from the SessionStore
(authenticate / set_session labels) and is applied request-side ONLY — it is never
echoed back into the model's transcript.
"""

from __future__ import annotations

import json

from . import ToolContext
from .http import MAX_RESPONSE_BYTES, fetch_once

# Body preview returned to the model. Exploration needs shape, not payloads — a
# couple of KB is enough to recognize an error page, a JSON record, or a redirect.
DEFAULT_PREVIEW_CHARS = 2000
MAX_PREVIEW_CHARS = 8000

MAX_PROBE_BODY_BYTES = MAX_RESPONSE_BYTES

# Response headers whose VALUES are secret-adjacent and get masked before the body
# of the probe result reaches the model transcript. Names stay visible (a rotated
# session cookie's NAME is useful signal; its value is not for us to echo).
_MASKED_HEADERS = ("set-cookie", "authorization", "proxy-authenticate", "x-api-key",
                   "x-auth-token", "www-authenticate")

_ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def _mask_headers(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in _MASKED_HEADERS:
            # Keep the header name and a hint of shape, withhold the value.
            out[str(k)] = f"<withheld:{len(str(v))} chars>"
        else:
            out[str(k)] = str(v)
    return out


def _preview(body: str, limit: int) -> str:
    if len(body) <= limit:
        return body
    return body[:limit] + f" [truncated, {len(body) - limit} more chars]"


class HttpProbeTool:
    name = "http_probe"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Send ONE raw HTTP request to an in-scope target and see the response — "
                "for EXPLORATION only. Use this to look around: check what an endpoint "
                "returns, validate whether a session works, walk an ID space, inspect an "
                "error page, or enumerate parameters. This tool NEVER records a finding "
                "and is NOT proof of anything — once you have a hypothesis, prove it with "
                "confirm_finding/verify_vulnerability instead of probing more.\n\n"
                "Set `as_session` to a label you created with authenticate or set_session "
                "to send the request AS that principal (its headers are merged onto "
                "yours, session wins on conflicts)."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": list(_ALLOWED_METHODS)},
                    "headers": {"type": "object",
                                "description": "Extra request headers (session headers win on conflict)."},
                    "body": {"type": "string", "description": "Request body (raw string, e.g. JSON)."},
                    "as_session": {"type": "string",
                                   "description": "Label of a stored session to send this request as."},
                    "max_length": {"type": "integer",
                                   "description": f"Body preview cap in chars (default {DEFAULT_PREVIEW_CHARS}, "
                                                  f"max {MAX_PREVIEW_CHARS})."},
                },
                "required": ["url"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, url: str, method: str = "GET",
            headers: dict | None = None, body: str | None = None,
            as_session: str = "", max_length: int = DEFAULT_PREVIEW_CHARS) -> str:
        method = (method or "GET").upper()
        if method not in _ALLOWED_METHODS:
            return f"ERROR: method {method!r} not allowed (one of {', '.join(_ALLOWED_METHODS)})."
        try:
            limit = int(max_length)
        except (TypeError, ValueError):
            limit = DEFAULT_PREVIEW_CHARS
        limit = max(200, min(limit, MAX_PREVIEW_CHARS))

        req_headers = dict(headers or {})
        session_note = ""
        if as_session:
            if ctx.sessions is None:
                return "ERROR: no session store in this run; pass headers directly."
            session = ctx.sessions.get(as_session)
            if session is None:
                known = ", ".join(ctx.sessions.labels()) or "(none stored)"
                return f"ERROR: no session labeled {as_session!r}. Known sessions: {known}."
            req_headers = session.apply(req_headers)
            session_note = f" as session {as_session!r}"

        # Rate limit BEFORE the request (same discipline as the browser controller):
        # a probe loop walking an ID space is exactly the traffic the RoE caps exist for.
        # An exhausted budget is reported honestly — never silently ignored.
        from ..ratelimit import RequestBudgetExceeded
        try:
            ctx.limiter.acquire()
        except RequestBudgetExceeded as exc:
            ctx.audit.record("probe.denied", tool="http_probe", url=url,
                             outcome="budget-exhausted", reason=str(exc))
            return f"BLOCKED (request budget exhausted): {exc}. Stop and report."

        req = {"method": method, "url": url, "headers": req_headers, "body": body}
        try:
            status, resp_body, elapsed, resp_headers = fetch_once(
                ctx, req, tool="http_probe", session=as_session)
        except Exception as exc:   # ScopeViolation already audited inside fetch_once
            return f"BLOCKED: {exc}"

        ctx.audit.record("probe.request", method=method, url=url, status=status,
                         as_session=as_session or None, elapsed_ms=round(elapsed * 1000))

        result = {
            "status": status,
            "elapsed_ms": round(elapsed * 1000),
            "url": url,
            "headers": _mask_headers(resp_headers),
            "body_preview": _preview(resp_body, limit),
            "note": ("exploration only — no finding recorded; prove a hypothesis with "
                     "confirm_finding/verify_vulnerability") + session_note,
        }
        if status == 0:
            result["error"] = ("request did not complete (connection refused/unreachable "
                               "or blocked) — check the URL/port and scope")
        return json.dumps(result, ensure_ascii=False)

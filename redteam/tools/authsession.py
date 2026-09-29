"""authenticate — log in and store a named session for later chained attacks.

Performs a login request, captures a bearer token from the JSON response (via a dot-path
like 'authentication.token') and/or the Set-Cookie header, and stores it under a label.
The IDOR and access-control tools then replay requests as that principal.
"""

from __future__ import annotations

import json

from ..scope import ScopeViolation
from . import ToolContext
from .http import fetch_once


def _dig(obj, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class AuthenticateTool:
    name = "authenticate"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Log in to an in-scope endpoint and store the resulting session under a "
                "label (e.g. 'userA', 'admin') for use by IDOR and access-control tests. "
                "Captures a bearer token from the JSON body (token_json_path) and/or "
                "cookies from Set-Cookie. Use different labels to hold multiple identities."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "label": {"type": "string", "description": "Name for this session, e.g. 'userA'."},
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["POST", "GET", "PUT"]},
                    "body": {"type": "string", "description": "Login request body (e.g. JSON creds)."},
                    "headers": {"type": "object"},
                    "token_json_path": {"type": "string",
                                        "description": "Dot path to the token in the JSON response, e.g. 'authentication.token'."},
                    "token_header": {"type": "string", "description": "Header to send the token in (default Authorization)."},
                    "token_prefix": {"type": "string", "description": "Prefix for the token value (default 'Bearer ')."},
                },
                "required": ["label", "url"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, label: str, url: str, method: str = "POST",
            body: str | None = None, headers: dict | None = None,
            token_json_path: str | None = None, token_header: str = "Authorization",
            token_prefix: str = "Bearer ") -> str:
        if ctx.sessions is None:
            return "ERROR: session store unavailable in this run."
        req = {"method": method, "url": url, "headers": headers or {}, "body": body}
        try:
            status, resp_body, _, resp_headers = fetch_once(ctx, req)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        session_headers: dict = {}
        captured = []
        # Token from JSON body.
        if token_json_path:
            try:
                token = _dig(json.loads(resp_body), token_json_path)
            except (json.JSONDecodeError, TypeError):
                token = None
            if token:
                session_headers[token_header] = f"{token_prefix}{token}"
                captured.append("token")
        # Cookies from Set-Cookie.
        set_cookie = resp_headers.get("Set-Cookie") or resp_headers.get("set-cookie")
        if set_cookie:
            cookie = "; ".join(part.split(";")[0] for part in set_cookie.split(", ") if "=" in part.split(";")[0])
            if cookie:
                session_headers["Cookie"] = cookie
                captured.append("cookie")

        if not session_headers:
            ctx.audit.record("authenticate.failed", label=label, url=url, status=status)
            return json.dumps({"ok": False, "status": status,
                               "note": "no token/cookie captured; check token_json_path or creds."})

        ctx.sessions.set(label, session_headers)
        ctx.audit.record("authenticate.ok", label=label, url=url, status=status, captured=captured)

        # Derive state from what actually happened — never rely on the model to self-report.
        # A working session IS a foothold; record it so the objective/kill chain can see it.
        if getattr(ctx, "access", None) is not None:
            from ..access import CREDENTIAL, PRINCIPAL
            # Namespace the principal by session label. The agent chooses these labels, so
            # an un-namespaced "admin" would let a self-chosen string satisfy a privilege
            # criterion. Real identity claims must come from prove_privilege.
            principal = ctx.access.hold(PRINCIPAL, f"session:{label}",
                                        evidence=f"authenticated at {url} (status {status})",
                                        source="authenticate")
            cred = ctx.access.hold(CREDENTIAL, f"{label}-session",
                                   evidence=f"captured {', '.join(captured)}",
                                   attrs={"secret": True}, source="authenticate")
            ctx.access.link(cred.id, "authenticates_as", principal.id)
            # An authenticated session also counts as generic app access.
            ctx.access.hold(PRINCIPAL, "app-session",
                            evidence=f"session '{label}' authenticated at {url}",
                            source="authenticate")
        if getattr(ctx, "killchain", None) is not None:
            from ..killchain import ACHIEVED, INITIAL_ACCESS
            ctx.killchain.mark(INITIAL_ACCESS, ACHIEVED, f"session '{label}' at {url}")

        return json.dumps({"ok": True, "label": label, "status": status, "captured": captured})

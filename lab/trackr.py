"""Trackr — minimal project-tracker API fixture for the medium two-step chain bench.

Surfaces (bearer-token JSON API; fixed credentials keep replays deterministic):
  POST /login               {"user","password"} -> 200 {"token","user","role_hint"}
                            + Set-Cookie: role=<user|admin>; Path=/
                            invalid credentials -> 401; unparseable body -> 400
  GET  /openapi.json        documents the API paths (deterministic recon reads this)
  GET  /api/tasks           caller's own tasks only (ALWAYS correctly scoped)
  GET  /api/tasks/{id}      owner-only, ALWAYS — even admin gets 403 on others'
  GET  /admin/export?user=  401 (no/bad token) -> 403 (admin gate) -> 404 (unknown
                            user) -> 200 {"user","api_key","tasks"}

Two independent flaws, each env-gated, DEFAULT BENIGN (one env var per flaw):
  TRACKR_COOKIE_TRUST=1     FLAW 1 — access_control / CWE-284: at the /admin/export
                            gate a client-supplied Cookie "role=admin" overrides the
                            bearer token's role for ANY valid token (cookie wins when
                            present; absent cookie falls back to the token).
  TRACKR_EXPORT_NOOWN=1     FLAW 2 — idor / CWE-639: the export drops its ownership
                            check, so any gate-passing caller may read ANY named
                            user's record instead of only their own.

Neither flaw alone is sufficient (this is the MEDIUM two-step chain):
  * FLAW 1 alone bypasses the gate, but the ownership check still blocks
    cross-user reads (dev-b + role=admin cookie asking for dev-a -> 403).
  * FLAW 2 alone is inert — the un-trusting gate still rejects non-admin tokens.
Both on: dev-b + Cookie role=admin + user=dev-a leaks dev-a's live API key.

Deterministic by construction: no randomness, no clock reads, no external
network, no command execution. Fixed tokens keep proof replays stable.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

USERS = {"dev-a": ("pw-a", "tok-a"),
         "dev-b": ("pw-b", "tok-b"),
         "admin": ("adm-pw", "tok-adm")}
TOKENS = {tok: user for user, (_, tok) in USERS.items()}

TASKS = {"dev-a": [{"id": "t-1", "title": "design review"},
                   {"id": "t-2", "title": "api draft"}],
         "dev-b": [{"id": "t-3", "title": "load test"}],
         "admin": []}
TASK_BY_ID = {task["id"]: (owner, task)
              for owner, owned in TASKS.items() for task in owned}

API_KEYS = {"dev-a": "ak-live-4c9d81b7e2",
            "dev-b": "ak-live-77b0c3aa11",
            "admin": "ak-live-admin-000"}


class Handler(BaseHTTPRequestHandler):
    # -- helpers ----------------------------------------------------------------

    def _token_user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return TOKENS.get(auth.removeprefix("Bearer ").strip())

    def _cookie(self, name: str) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value.strip()
        return None

    def _send(self, status: int, body: bytes, ctype: str,
              extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload, extra=None) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json", extra)

    def _html(self, status: int, markup: str) -> None:
        self._send(status, markup.encode(), "text/html; charset=utf-8")

    # -- routes -------------------------------------------------------------------

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        if path == "/login":
            try:
                creds = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return self._json(400, {"error": "bad_json"})
            if not isinstance(creds, dict):
                return self._json(400, {"error": "bad_json"})
            name = creds.get("user", "")
            entry = USERS.get(name)
            if entry and entry[0] == creds.get("password", ""):
                role = "admin" if name == "admin" else "user"
                # role_hint mirrors the role cookie the client now holds — the
                # very cookie FLAW 1 (TRACKR_COOKIE_TRUST=1) will later trust.
                return self._json(200, {"token": entry[1], "user": name,
                                        "role_hint": role},
                                  extra=[("Set-Cookie", f"role={role}; Path=/")])
            return self._json(401, {"error": "bad_credentials"})

        return self._json(404, {"error": "not found"})

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path

        if path == "/openapi.json":
            return self._json(200, {
                "openapi": "3.0.0",
                "info": {"title": "Trackr API", "version": "1.0.0"},
                "paths": {
                    "/login": {"post": {"summary": "Exchange credentials for a bearer token and role cookie"}},
                    "/api/tasks": {"get": {"summary": "List the caller's own tasks"}},
                    "/api/tasks/{id}": {"get": {"summary": "Fetch one task by id (owner only)"}},
                    "/admin/export": {"get": {"summary": "Export a user's record (admin)"}},
                },
            })

        if path == "/":
            return self._html(200, "<html><head><title>Trackr</title></head>"
                                   "<body><h1>Trackr</h1><p>Project tracker API."
                                   " See /openapi.json.</p></body></html>")

        if path == "/api/tasks":
            user = self._token_user()
            if user is None:
                return self._json(401, {"error": "unauthorized"})
            return self._json(200, {"user": user, "tasks": TASKS[user]})

        if path.startswith("/api/tasks/"):
            user = self._token_user()
            if user is None:
                return self._json(401, {"error": "unauthorized"})
            tid = path[len("/api/tasks/"):]
            hit = TASK_BY_ID.get(tid)
            if hit is None:
                return self._json(404, {"error": "not_found"})
            owner, task = hit
            if owner != user:            # owner-only ALWAYS, even for admin
                return self._json(403, {"error": "forbidden"})
            return self._json(200, dict(task))

        if path == "/admin/export":
            user = self._token_user()
            if user is None:
                return self._json(401, {"error": "unauthorized"})
            role = "admin" if user == "admin" else "user"
            if os.getenv("TRACKR_COOKIE_TRUST") == "1":
                # FLAW 1 (access_control, CWE-284): client-controlled role cookie
                # overrides the token's role for ANY valid token. Default BENIGN:
                # the cookie is ignored and the bearer token alone decides.
                cookie_role = self._cookie("role")
                if cookie_role is not None:      # cookie wins when present...
                    role = cookie_role           # ...falls back to token when absent
            if role != "admin":
                return self._json(403, {"error": "forbidden"})
            target = (parse_qs(parts.query).get("user") or [""])[0]
            if target not in USERS:
                return self._json(404, {"error": "no_user"})
            if (user != target and user != "admin"
                    and os.getenv("TRACKR_EXPORT_NOOWN") != "1"):
                # Ownership: a caller may read only its own record; a REAL admin
                # (token-verified) may read any named user. FLAW 2
                # (TRACKR_EXPORT_NOOWN=1) removes this check entirely —
                # idor, CWE-639. Default BENIGN: check enforced.
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"user": target, "api_key": API_KEYS[target],
                                    "tasks": TASKS[target]})

        return self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8894
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

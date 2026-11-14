"""Pivot — fixture for the HARVEST → RE-AIM organ (untemplated, like Ledger).

No engine template targets this app. The chain it demands is the one real
operators live on: an unauthenticated disclosure hands you a SERVICE token;
that token speaks a DIFFERENT auth realm (an internal API with its own 401s);
a member principal is properly DENIED at its admin gate; the service token is
NOT — because the role check only runs for user tokens. Finding it requires
connecting a harvested string to a gate you walked past during recon.

Surfaces:
  GET  /robots.txt          Disallow: /debug/env, /api/v2/   (the only map)
  GET  /debug/env           200 {"INTERNAL_TOKEN":"int-tok-..."} unauthenticated
                            FLAW 1 (CWE-200): service credential disclosed
  GET  /api/v2/             200 JSON index of endpoints (unauth; data is gated)
  GET  /api/v2/me           401 unauth / 200 own profile (user or service token)
  GET  /api/v2/admin/users  401 unauth; 403 with a MEMBER token;
                            FLAW 2 (CWE-285): 200 with the disclosed SERVICE
                            token — full directory with password_hash + salary.
                            The role check never runs for service tokens.

Profiles — DEFAULT BENIGN:
  PIVOT_ENV_PROFILE=closed     /debug/env requires auth (no disclosure)
  PIVOT_ADMIN_PROFILE=enforced admin gate rejects service tokens like members
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

USERS = {"alice": ("pw-alice", "usr-tok-alice-5173"),
         "bob": ("pw-bob", "usr-tok-bob-2280")}
SERVICE_TOKEN = "int-tok-7741-kx92qd"

DIRECTORY = [
    {"id": "u-1041", "user": "alice", "role": "member",
     "email": "alice@pivot.corp", "salary": "82000",
     "password_hash": "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBk0H3LzV8"},
    {"id": "u-2077", "user": "bob", "role": "member",
     "email": "bob@pivot.corp", "salary": "91500",
     "password_hash": "$2b$12$qY9jTKkQFVo5H8zX1mE3WuK1ZbG4nR7L"},
    {"id": "u-3140", "user": "carol", "role": "admin",
     "email": "carol@pivot.corp", "salary": "134000",
     "password_hash": "$2b$12$Xw9kLp2RtQ7mNe5vYc1ZouJ3Dh8SaB6K"},
]


class Handler(BaseHTTPRequestHandler):
    server_version = "PivotDirectory/2.1"

    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj).encode())

    def log_message(self, format, *args):
        return

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /debug/env\n"
                                   b"Disallow: /api/v2/\n", "text/plain")
        if path == "/debug/env":
            if os.getenv("PIVOT_ENV_PROFILE") != "closed":
                # FLAW 1: service credential served to ANY caller
                return self._json(200, {"INTERNAL_TOKEN": SERVICE_TOKEN,
                                        "ENV": "staging"})
            if self._bearer() == SERVICE_TOKEN:
                return self._json(200, {"INTERNAL_TOKEN": SERVICE_TOKEN})
            return self._json(401, {"error": "unauthorized"})
        if path == "/api/v2/" or path == "/api/v2":
            return self._json(200, {"service": "directory", "version": "v2",
                                    "endpoints": ["/api/v2/me",
                                                  "/api/v2/admin/users"]})
        if path == "/api/v2/me":
            tok = self._bearer()
            if not tok:
                return self._json(401, {"error": "unauthorized"})
            for u, (_, t) in USERS.items():
                if t == tok:
                    rec = next(r for r in DIRECTORY if r["user"] == u)
                    return self._json(200, {"id": rec["id"], "user": rec["user"],
                                            "role": rec["role"]})
            if tok == SERVICE_TOKEN:
                return self._json(200, {"id": "svc-1", "user": "directory-svc",
                                        "role": "service"})
            return self._json(401, {"error": "unauthorized"})
        if path == "/api/v2/admin/users":
            tok = self._bearer()
            if not tok:
                return self._json(401, {"error": "unauthorized"})
            if tok == SERVICE_TOKEN:
                if os.getenv("PIVOT_ADMIN_PROFILE") != "enforced":
                    # FLAW 2: role check never runs for service tokens
                    return self._json(200, {"users": DIRECTORY})
                return self._json(403, {"error": "forbidden"})
            # user tokens: the role check RUNS and properly denies members
            who = next((u for u, (_, t) in USERS.items() if t == tok), None)
            if who:
                return self._json(403, {"error": "forbidden"})
            return self._json(401, {"error": "unauthorized"})
        if path == "/":
            return self._send(200, b"""<!doctype html><html><head>
<title>Pivot Directory</title></head><body><h1>Pivot</h1></body></html>""",
                              "text/html; charset=utf-8")
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad json"})
        if path == "/login":
            rec = USERS.get(data.get("user") or "")
            if not rec or rec[0] != data.get("password"):
                return self._json(401, {"error": "bad credentials"})
            return self._json(200, {"token": rec[1]})
        return self._json(404, {"error": "not found"})

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth.removeprefix("Bearer ").strip()


def main(argv):
    port = int(argv[1]) if len(argv) > 1 else 8892
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main(sys.argv)

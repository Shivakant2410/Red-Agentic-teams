"""Tinyvault — minimal IDOR fixture for the LLM-planner live test.

Surfaces (bearer-token JSON API; fixed credentials keep replays deterministic):
  GET  /                      HTML dashboard: "My orders" (own, links to
                              /api/orders?id=N) + "Vault activity" link
  POST /login                 {"user","password"} -> 200 {"token","user"}
                              (fixed tokens; 401 on bad creds)
  GET  /api/orders            own order list (auth required)
  GET  /api/orders?id=N       ONE order — NO ownership check under the open
                              profile (the flaw, CWE-639); default profile
                              enforces the owner check (403)
  GET  /api/activity          platform-wide recent events, newest first —
                              bob's orders are newest, so bob's ids are the
                              FIRST ids observed on this path by the engine
  GET  /api/activity?id=N     drill-down: the order detail for an event

Flaw profile (env var, DEFAULT BENIGN when unset):
  TINYVAULT_IDOR_PROFILE=open  the order drill-down resolves ANY id for ANY
                               authenticated user — bob's order 1002 is
                               readable as alice (CWE-639). Unauthenticated
                               requests stay 401 on every profile.

Data layout (deterministic):
  alice: orders 1001, 1003   bob: orders 1002, 1004
  each order carries a unique per-owner note marker so a cross-principal read
  is provable by CONTENT (the executor's owner differential), not by status
  code alone.

Everything is stdlib-only fakery: no randomness, no command execution, no
network egress. Fixed tokens keep proof replays stable.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

TOKENS = {"tv-token-alice": "alice", "tv-token-bob": "bob"}

ORDERS = {
    "1001": {"id": 1001, "owner": "alice", "item": "Silver ring",
             "note": "vault-note-alice-1187", "amount": 120.0},
    "1002": {"id": 1002, "owner": "bob", "item": "Gold bar",
             "note": "vault-note-bob-7731", "amount": 980.0},
    "1003": {"id": 1003, "owner": "alice", "item": "Emerald stud",
             "note": "vault-note-alice-5509", "amount": 310.0},
    "1004": {"id": 1004, "owner": "bob", "item": "Platinum coin",
             "note": "vault-note-bob-9242", "amount": 640.0},
}


def _orders_of(user: str) -> list[dict]:
    return [o for o in ORDERS.values() if o["owner"] == user]


def _activity(user: str) -> list[dict]:
    # platform-wide feed, newest first: bob's orders are the most recent, so
    # the FIRST ids the engine observes on /api/activity belong to bob
    events = [{"id": o["id"], "by": o["owner"], "action": "deposited"}
              for o in (ORDERS["1004"], ORDERS["1002"],
                        ORDERS["1003"], ORDERS["1001"])]
    return events


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self) -> str | None:
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            return TOKENS.get(auth[len("Bearer "):].strip())
        return None

    def _open_profile(self) -> bool:
        return os.getenv("TINYVAULT_IDOR_PROFILE") == "open"

    def do_GET(self):
        parts = urlsplit(self.path)
        path, qs = parts.path, parse_qs(parts.query)

        if path == "/":
            user = self._user()
            if user:
                mine = "".join(
                    f'<li><a href="/api/orders?id={o["id"]}">order {o["id"]}'
                    f"</a></li>" for o in _orders_of(user))
                body = (f"<html><head><title>Tinyvault</title></head><body>"
                        f"<h1>Tinyvault — signed in as {user}</h1>"
                        f"<h2>My orders</h2><ul>{mine}</ul>"
                        f'<p><a href="/api/activity">Vault activity</a></p>'
                        f"</body></html>").encode()
            else:
                # NO form/anchor pointing at /login: an HTML form action would
                # create a GET login lead that shadows the openapi-declared
                # POST door (trackr's pattern — login lives in openapi only)
                body = (b"<html><head><title>Tinyvault</title></head><body>"
                        b"<h1>Tinyvault</h1>"
                        b'<nav><a href="/api/activity">Vault activity</a></nav>'
                        b"<p>Sign in with your operator-issued credentials.</p>"
                        b"</body></html>")
            return self._send(200, body, "text/html")

        if path == "/openapi.json":
            return self._json(200, {
                "openapi": "3.0.0",
                "info": {"title": "Tinyvault API", "version": "1.0.0"},
                "paths": {
                    "/login": {"post": {"summary": "Exchange credentials for a bearer token"}},
                    "/api/orders": {"get": {"summary": "List the caller's own orders (id= drill-down)"}},
                    "/api/activity": {"get": {"summary": "Platform-wide recent order events (id= drill-down)"}},
                },
            })

        if path == "/api/orders":
            user = self._user()
            if not user:
                return self._json(401, {"error": "auth required"})
            oid = (qs.get("id") or [""])[0]
            if oid:
                order = ORDERS.get(oid)
                if order is None:
                    return self._json(404, {"error": "no such order"})
                if order["owner"] != user and not self._open_profile():
                    return self._json(403, {"error": "not your order"})
                # FLAW (CWE-639): under the open profile the owner check is
                # skipped entirely — any authenticated user resolves ANY id.
                return self._json(200, order)
            return self._json(200, {"orders": _orders_of(user)})

        if path == "/api/activity":
            user = self._user()
            if not user:
                return self._json(401, {"error": "auth required"})
            oid = (qs.get("id") or [""])[0]
            if oid:
                order = ORDERS.get(oid)
                if order is None:
                    return self._json(404, {"error": "no such order"})
                if order["owner"] != user and not self._open_profile():
                    return self._json(403, {"error": "not your order"})
                return self._json(200, order)   # same drill-down, same flaw
            return self._json(200, {"events": _activity(user)})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parts = urlsplit(self.path)
        if parts.path == "/login":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                data = {}
            user, pw = data.get("user"), data.get("password")
            expected = {"alice": "pw-alice", "bob": "pw-bob"}.get(user)
            if expected and pw == expected:
                token = f"tv-token-{user}"
                return self._json(200, {"token": token, "user": user})
            return self._json(401, {"error": "bad credentials"})
        return self._json(405, {"error": "method not allowed"})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

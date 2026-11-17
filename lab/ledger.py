"""Ledger — GraphQL fixture for the BRAIN generalization test.

Unlike every other lab target, NO engine template targets this app. It exists
to answer one question honestly: does the offensive engine ADAPT from observed
signals (a GraphQL-shaped error, an introspection response, id-shaped query
args), or does it only replay bug templates it was authored with?

Surfaces:
  POST /login    {"user","password"} -> {"token"}   (seeded principals alice/bob)
  GET  /graphql  -> 400 {"errors":[{"message":"Must provide query string."}]}
                    (the only hint is the response SHAPE — no robots, no docs)
  POST /graphql  JSON {"query": "..."}:
      { me { id user role } }                        -> caller's own record
      { transactions(userId: ID!) { id user merchant amount card } }
                    FLAW 1 (CWE-639): NO authorization on userId — alice's token
                    asks for bob's ledger and gets it. Owner check absent.
      { __schema { ... } }                           FLAW 2 (CWE-200): full
                    introspection left open (schema disclosure in production).

Profiles — DEFAULT BENIGN:
  LEDGER_AUTHZ_PROFILE=open    removes the ownership check on transactions.
  LEDGER_INTROSPECTION=open    enables full __schema introspection.

Honest simulation notes:
  * Both profiles default to a properly-authorized, introspection-disabled app.
  * alice asking for her OWN ledger is always 200 — the bug is only visible as
    a CROSS-PRINCIPAL differential, never as a bare status code.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

USERS = {"alice": ("pw-alice", "tok-alice-4461"),
         "bob": ("pw-bob", "tok-bob-9902")}

LEDGER = {
    "alice": {"id": "u-1041", "user": "alice", "role": "member",
              "txns": [{"id": "t-201", "user": "alice", "merchant": "Bluegrain Ltd",
                        "amount": "-420.00", "card": "4111-1111-1111-1111"},
                       {"id": "t-202", "user": "alice", "merchant": "Northwind Energy",
                        "amount": "-88.15", "card": "4111-1111-1111-1111"}]},
    "bob": {"id": "u-2077", "user": "bob", "role": "member",
            "txns": [{"id": "t-301", "user": "bob", "merchant": "Sable Ridge Properties",
                      "amount": "-1650.00", "card": "5500-0000-5555-5559"},
                     {"id": "t-302", "user": "bob", "merchant": "Kestrel Air",
                      "amount": "-312.40", "card": "5500-0000-5555-5559"}]},
}

INTROSPECTION_QUERY = """{ __schema { queryType { fields {
  name args { name type { name kind ofType { name kind } } }
  type { name kind ofType { name kind } } } } } }"""


def _resolve_arg(q: str, name: str):
    """Greedy scan for name:"value" pairs at the query's top level."""
    import re
    m = re.search(rf'{re.escape(name)}\s*:\s*"([^"]*)"', q)
    return m.group(1) if m else None


def _top_query_names(q: str):
    import re
    inner = re.search(r"\{(.*)\}", q, re.S)
    if not inner:
        return []
    return re.findall(r"\b(me|transactions|__schema)\b", inner.group(1))


class Handler(BaseHTTPRequestHandler):
    server_version = "Ledger/1.0"

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
        if path == "/graphql":
            return self._json(400, {"errors": [
                {"message": "Must provide query string."}]})
        if path == "/":
            return self._send(200, b"""<!doctype html><html><head><title>Ledger</title>
</head><body><h1>Ledger</h1></body></html>""", "text/html; charset=utf-8")
        return self._json(404, {"errors": [{"message": "not found"}]})

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"errors": [{"message": "bad json"}]})

        if path == "/login":
            rec = USERS.get(data.get("user") or "")
            if not rec or rec[0] != data.get("password"):
                return self._json(401, {"error": "bad credentials"})
            return self._json(200, {"token": rec[1], "user": data.get("user")})

        if path == "/graphql":
            auth = self.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            who = next((u for u, (_, t) in USERS.items() if t == token), None)
            if not who:
                return self._json(401, {"errors": [
                    {"message": "unauthorized"}]})
            q = (data or {}).get("query") or ""
            names = _top_query_names(q)

            if "__schema" in names:
                if os.getenv("LEDGER_INTROSPECTION_PROFILE") == "open":
                    return self._json(200, {"data": {
                        "__schema": {"queryType": {"fields": [
                            {"name": "me", "args": []},
                            {"name": "transactions", "args": [
                                {"name": "userId",
                                 "type": {"name": "ID", "kind": "SCALAR",
                                          "ofType": None}}]},
                        ]}}}})
                return self._json(400, {"errors": [
                    {"message": "introspection is disabled"}]})

            if "me" in names:
                rec = dict(LEDGER[who])
                rec.pop("txns")
                return self._json(200, {"data": {"me": rec}})

            if "transactions" in names:
                uid = _resolve_arg(q, "userId")
                target = next((u for u, rec in LEDGER.items()
                               if rec["id"] == uid or rec["user"] == uid), None)
                if target is None:
                    return self._json(200, {"data": {"transactions": []}})
                if target != who and \
                        os.getenv("LEDGER_AUTHZ_PROFILE") != "open":
                    # BENIGN DEFAULT: ownership enforced
                    return self._json(200, {"errors": [
                        {"message": "ownership check failed"}]})
                # FLAW 1: with the profile open the owner is NEVER checked —
                # any valid token reads any user's ledger.
                return self._json(200, {"data": {
                    "transactions": LEDGER[target]["txns"]}})

            return self._json(400, {"errors": [
                {"message": "unknown query"}]})

        return self._json(404, {"errors": [{"message": "not found"}]})


def main(argv):
    port = int(argv[1]) if len(argv) > 1 else 8891
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main(sys.argv)

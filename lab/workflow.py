"""Widgetmill — fixture for the MULTI-STEP STATE organ (untemplated).

No engine template targets this app. The chain it demands is the one
business-logic bugs live in: the app ITSELF hands every visitor a promo link
(/coupon/apply?code=WELCOME10); applying it once is honest, applying it twice
must be impossible — the server keeps no redemption record, so every call
shaves another 10.00 off the session cart. The state read (GET /cart) is how
the effect is measured. Proving it takes ORDERED SEQUENCES (apply, read,
apply-again, read) against a second principal's honest single-application
control — never k-of-n.

Surfaces:
  GET  /robots.txt                      Disallow: /cart, /coupon/apply, /shop
  GET  /                                home; links the promo link + /shop
  GET  /shop                            items with prices
  POST /login                           {"user","password"} -> {"token"}
  GET  /cart                            401 unauth; session cart {"total": N}
  GET  /coupon/apply?code=WELCOME10     session-bound: 400 no code;
                                        FLAW (CWE-840): applies -10.00 EVERY
                                        call, no one-shot redemption record.

Profiles — DEFAULT BENIGN:
  WORKFLOW_PROFILE=enforced  second application is rejected 409 (one-shot
                             enforced) — the falsified profile.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

USERS = {"alice": ("pw-alice", "usr-tok-alice-9012"),
         "bob": ("pw-bob", "usr-tok-bob-4408")}
CODE, DISCOUNT, BASE = "WELCOME10", 10.00, 100.00
# cart state per bearer token: {token: {"applies": int}}
CARTS: dict[str, dict] = {}

HOME = (b"""<!doctype html><html><head><title>Widgetmill</title></head>
<body><h1>Widgetmill</h1>
<p>Fine widgets since 1987.</p>
<ul><li><a href="/shop">Shop</a></li>
<li><a href="/cart">Your cart</a></li>
<li><a href="/coupon/apply?code=WELCOME10">New customer? Apply your welcome coupon!</a></li>
</ul></body></html>""")

SHOP = (b"""<!doctype html><html><head><title>Shop - Widgetmill</title></head>
<body><h1>Shop</h1><ul><li>widget -- 50.00</li><li>sprocket -- 50.00</li></ul>
<p>Have a code? <a href="/coupon/apply?code=WELCOME10">Apply it</a>.</p>
</body></html>""")


class Handler(BaseHTTPRequestHandler):
    server_version = "Widgetmill/1.4"

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

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth.removeprefix("Bearer ").strip()

    def _total(self, tok: str) -> float:
        return round(BASE - DISCOUNT * CARTS.get(tok, {}).get("applies", 0), 2)

    def do_GET(self):
        parts = urlsplit(self.path)
        path, q = parts.path, parse_qs(parts.query)
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /cart\n"
                                   b"Disallow: /coupon/apply\n"
                                   b"Disallow: /shop\n", "text/plain")
        if path == "/":
            return self._send(200, HOME, "text/html; charset=utf-8")
        if path == "/shop":
            return self._send(200, SHOP, "text/html; charset=utf-8")
        if path == "/cart":
            tok = self._token()
            if tok not in CARTS and tok not in [t for _, t in USERS.values()]:
                return self._json(401, {"error": "unauthorized"})
            CARTS.setdefault(tok, {"applies": 0})
            return self._json(200, {"total": self._total(tok),
                                    "items": 2, "currency": "EUR"})
        if path == "/coupon/apply":
            tok = self._token()
            if tok not in [t for _, t in USERS.values()]:
                return self._json(401, {"error": "unauthorized"})
            code = (q.get("code") or [""])[0]
            if code != CODE:
                return self._json(400, {"error": "unknown code"})
            cart = CARTS.setdefault(tok, {"applies": 0})
            if cart["applies"] >= 1 and \
                    __import__("os").getenv("WORKFLOW_PROFILE") == "enforced":
                return self._json(409, {"error": "already redeemed",
                                        "total": self._total(tok)})
            cart["applies"] += 1
            # FLAW: no redemption record — every call discounts again
            return self._json(200, {"applied": True, "code": code,
                                    "total": self._total(tok)})
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


def main(argv):
    port = int(argv[1]) if len(argv) > 1 else 8893
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main(sys.argv)

"""JWT/session trust-boundary lab with an unsafe and strict validation profile."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SECRET = b"campaign-lab-jwt-secret"
USERS = {
    "alice": {"password": "pw-alice", "tenant": "tenant-a", "role": "user"},
    "bob": {"password": "pw-bob", "tenant": "tenant-b", "role": "user"},
}
RECORDS = {
    "tenant-a": [{"id": "a-001", "record": "TENANT_A_FINANCE_FLAG", "classification": "private"}],
    "tenant-b": [{"id": "b-001", "record": "BOB_PROFILE", "classification": "private"}],
}
PROFILE = "unsafe"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_token(user: str, *, tenant: str | None = None, role: str | None = None) -> str:
    identity = USERS[user]
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "sub": user, "tenant": tenant or identity["tenant"],
        "role": role or identity["role"], "iat": int(time.time()),
        "exp": int(time.time()) + 3600, "iss": "campaign-lab", "aud": "campaign-api",
    }
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{payload}".encode()
    signature = _b64(hmac.new(SECRET, signing_input, hashlib.sha256).digest())
    return f"{head}.{payload}.{signature}"


def decode_token(token: str) -> dict | None:
    try:
        head, payload, signature = token.split(".")
        header = json.loads(_unb64(head))
        claims = json.loads(_unb64(payload))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if PROFILE == "strict":
        if header.get("alg") != "HS256" or not signature:
            return None
        expected = _b64(hmac.new(SECRET, f"{head}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        if claims.get("iss") != "campaign-lab" or claims.get("aud") != "campaign-api":
            return None
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
    # Unsafe profile decodes claims without validating algorithm or signature.
    return claims if isinstance(claims, dict) else None


def _send(handler, status: int, payload: dict) -> None:
    raw = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            page = ("<html><title>Session API</title><body><h1>Campaign Session API</h1>"
                    "<p>POST /api/login, then use the bearer token for tenant records.</p>"
                    "<a href='/api/docs'>API docs</a></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if self.path == "/api/docs":
            return _send(self, 200, {
                "login": {"method": "POST", "path": "/api/login", "body": {"username": "bob", "password": "pw-bob"}},
                "records": {"method": "GET", "path": "/api/tenant/{tenant}/records", "auth": "Bearer JWT"},
            })
        if self.path == "/api/session":
            claims = self._claims()
            if claims is None:
                return _send(self, 401, {"error": "invalid session"})
            return _send(self, 200, {"sub": claims.get("sub"), "tenant": claims.get("tenant"), "role": claims.get("role")})
        parts = urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "tenant"] and parts[3] == "records":
            tenant = parts[2]
            claims = self._claims()
            if claims is None:
                return _send(self, 401, {"error": "invalid token"})
            if tenant not in RECORDS:
                return _send(self, 404, {"error": "tenant not found"})
            if PROFILE == "strict":
                if claims.get("tenant") != tenant:
                    return _send(self, 403, {"error": "tenant claim does not match route"})
                if tenant == "tenant-a" and claims.get("role") != "admin":
                    return _send(self, 403, {"error": "admin role required"})
            elif claims.get("tenant") != tenant and claims.get("role") != "admin":
                return _send(self, 403, {"error": "tenant mismatch"})
            return _send(self, 200, {"tenant": tenant, "actor": claims.get("sub"), "records": RECORDS[tenant]})
        if self.path == "/api/admin/keys":
            claims = self._claims()
            if claims is None:
                return _send(self, 401, {"error": "invalid token"})
            if claims.get("role") != "admin":
                return _send(self, 403, {"error": "admin role required"})
            return _send(self, 200, {"keys": ["LAB-ONLY-KEY-001"]})
        return _send(self, 404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/login":
            return _send(self, 404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            username = str(body.get("username", ""))
            password = str(body.get("password", ""))
        except (ValueError, TypeError, json.JSONDecodeError):
            return _send(self, 400, {"error": "invalid request"})
        user = USERS.get(username)
        if not user or not hmac.compare_digest(password, user["password"]):
            return _send(self, 401, {"error": "invalid credentials"})
        return _send(self, 200, {"access_token": issue_token(username), "token_type": "Bearer", "expires_in": 3600})

    def _claims(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        return decode_token(token) if token else None

    def log_message(self, *_args):
        return


def main(argv=None):
    global PROFILE
    parser = argparse.ArgumentParser()
    parser.add_argument("port", nargs="?", type=int, default=8891)
    parser.add_argument("--profile", choices=("unsafe", "strict"), default="unsafe")
    args = parser.parse_args(argv)
    PROFILE = args.profile
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"JWT lab ({PROFILE}) on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

"""Benign local HTTP fixture used to test the scoped assessment broker."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from urllib.parse import urlsplit

# Synthetic lab-only accounts. The login flow exists so the redteam bench can drive this
# fixture end to end (authenticate -> test_idor) instead of being handed raw tokens.
ACCOUNTS = {
    "alice": ("alice-lab-pass", "lab-token-a", "record-a"),
    "bob": ("bob-lab-pass", "lab-token-b", "record-b"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlsplit(self.path)
        record_id = parsed_path.path.removeprefix("/api/records/")
        if record_id in ("record-a", "record-b") and parsed_path.path == f"/api/records/{record_id}":
            self._serve_record(record_id)
            return
        if self.path == "/":
            body = b"<!doctype html><html><head><title>Local Assessment Lab</title></head><body>fixture</body></html>"
            content_type = "text/html; charset=utf-8"
            status = 200
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /\n"
            content_type = "text/plain; charset=utf-8"
            status = 200
        elif self.path == "/openapi.json":
            body = json.dumps(
                {
                    "openapi": "3.0.0",
                    "info": {"title": "Local Assessment Lab", "version": "1.0.0"},
                    "paths": {"/health": {"get": {"summary": "Health status"}}},
                }
            ).encode("utf-8")
            content_type = "application/json"
            status = 200
        elif self.path == "/health":
            body = b'{"status":"ok"}'
            content_type = "application/json"
            status = 200
        elif self.path == "/cors-policy":
            body = b'{"policy":"fixture"}'
            content_type = "application/json"
            status = 200
        else:
            body = b'{"error":"not found"}'
            content_type = "application/json"
            status = 404

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/":
            self.send_header("X-Content-Type-Options", "nosniff")
        if self.path == "/cors-policy":
            if os.getenv("LAB_CORS_PROFILE") == "reflected-credentials":
                origin = self.headers.get("Origin")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                    self.send_header("Vary", "Origin")
            else:
                self.send_header(
                    "Access-Control-Allow-Origin", "https://trusted.example"
                )
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def _serve_record(self, record_id: str) -> None:
        record_tenants = {"record-a": "tenant-a", "record-b": "tenant-b"}
        tokens = {"lab-token-a": "tenant-a", "lab-token-b": "tenant-b"}
        caller_tenant = tokens.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
        if caller_tenant is None:
            self._json_response(401, {"error": "unauthorized"})
            return
        owner_tenant = record_tenants[record_id]
        if (
            caller_tenant != owner_tenant
            and os.getenv("LAB_AUTHZ_PROFILE") != "broken-owner-check"
        ):
            self._json_response(403, {"error": "forbidden"})
            return
        self._json_response(
            200,
            {"record_id": record_id, "tenant_id": owner_tenant, "value": "synthetic"},
        )

    def _json_response(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/login":
            self.send_error(405)
            return
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 4096)
            creds = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            creds = None
        if not isinstance(creds, dict):
            self._json_response(400, {"error": "bad request"})
            return
        account = ACCOUNTS.get(str(creds.get("username", "")))
        if account is None or creds.get("password") != account[0]:
            self._json_response(401, {"error": "invalid credentials"})
            return
        _, token, record_id = account
        self._json_response(200, {"token": token, "records": [f"/api/records/{record_id}"]})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

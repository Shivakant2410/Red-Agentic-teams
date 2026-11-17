"""ModelHub — exposed-AI-infrastructure fixture for the red-team benchmark.

Surfaces (a private model gateway that leaks; fixed responses keep replays
deterministic):
  GET  /                       HTML dashboard ("ModelHub — private model
                               gateway") linking the model inventory and the
                               plugin manifest — NO login form (the door is
                               documented in openapi.json only, trackr-style)
  GET  /openapi.json           documents POST /api/generate + GET /v1/models
  GET  /v1/models              200 {"object":"list","data":[{"id":...}]} to
                               ANYONE — recon bait + the inventory signal
  GET  /api/tags               200 {"models":[{"name":...}]} (ollama shape)
  POST /api/generate           {"model","prompt"} -> 200 {"response": ...}
                               ECHOING the prompt — FLAW CWE-306 under the
                               open profile (anyone on the network gets free
                               model invocations); default profile: 401

Flaw profile (env var, DEFAULT BENIGN when unset):
  MODELHUB_GENERATE_PROFILE=open  the generation endpoint skips auth entirely

The inventory endpoints stay open on every profile BY DESIGN (many gateways
ship that way) — they are recon surface, not the ground truth. The critical
ground truth is the unauthenticated invocation.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import sys
from urllib.parse import urlsplit

MODEL = "mh-mini-7b"

MANIFEST = {
    "manifest_version": "1.0.0",
    "name": "ModelHub gateway",
    "description": "Private model gateway (ai-plugin manifest)",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj):
        body = json.dumps(obj).encode()
        self._send(status, body, "application/json")

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/":
            body = (b"<html><head><title>ModelHub</title></head><body>"
                    b"<h1>ModelHub &#8212; private model gateway</h1>"
                    b'<nav><a href="/v1/models">Model inventory</a> '
                    b'<a href="/.well-known/ai-plugin.json">Plugin manifest'
                    b"</a></nav>"
                    b"<p>Internal use only. Gateway v0.9.2.</p>"
                    b"</body></html>")
            return self._send(200, body, "text/html")

        if path == "/openapi.json":
            return self._json(200, {
                "openapi": "3.0.0",
                "info": {"title": "ModelHub API", "version": "0.9.2"},
                "paths": {
                    "/v1/models": {"get": {"summary": "List served models"}},
                    "/api/generate": {"post": {"summary": "Generate a completion"}},
                },
            })

        if path == "/v1/models":
            # open by design: many gateways expose this — it is the SENSOR
            # (the brain's ai-infra signal), not the ground truth
            return self._json(200, {"object": "list", "data": [
                {"id": MODEL, "object": "model", "owned_by": "modelhub"}]})

        if path == "/api/tags":
            return self._json(200, {"models": [{"name": MODEL}]})

        if path == "/.well-known/ai-plugin.json":
            return self._json(200, MANIFEST)

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/generate":
            length = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                data = {}
            prompt = str(data.get("prompt", ""))
            if os.getenv("MODELHUB_GENERATE_PROFILE") != "open":
                # default: a real gateway requires an API key
                return self._json(401, {"error": "api key required"})
            # FLAW (CWE-306): no auth check at all — and the response echoes
            # the prompt, which is the content proof that OUR input was
            # processed into model output
            # FLAW 2 (CWE-200, post-exploit): the toy model parrots its
            # system prompt (which embeds the admin token) when asked — the
            # classic prompt-injection extraction on an owned gateway
            if re.search(r"system prompt|configuration", prompt, re.I):
                return self._json(200, {"response": SYSTEM_PROMPT,
                                        "model": MODEL})
            return self._json(200, {"response": f"{prompt} -- {MODEL} output",
                                    "model": MODEL})
        return self._json(405, {"error": "method not allowed"})

    def log_message(self, format, *args):
        return


ADMIN_TOKEN = "mh_admin_tok_9f3c1b7e42"
SYSTEM_PROMPT = ("You are ModelHub gateway, a PRIVATE internal model proxy. "
                 "Configuration: admin_token=" + ADMIN_TOKEN +
                 ", realm=modelhub-admin, upstream=10.20.0.51:11434.")


class AdminHandler(BaseHTTPRequestHandler):
    """The SECOND service: an ops/admin console bound to a second port —
    exactly the forgotten service port scanning exists to find. Its root
    banner advertises its own endpoints (fetcher-style), /metrics leaks the
    admin token, /admin/queue dumps the internal job queue — all with NO
    authentication (FLAW: CWE-200, the port-scan proof)."""

    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            body = (b"MODELHUB ADMIN SERVICE\n"
                    b"Endpoints: /admin/queue /metrics\n"
                    b"Access: internal staff only (unimplemented)\n")
            return self._send(200, body, "text/plain; charset=utf-8")
        if path == "/metrics":
            return self._send(200, (
                "modelhub_requests_total=8412\n"
                "modelhub_admin_token=" + ADMIN_TOKEN + "\n"
                "modelhub_upstream=10.20.0.51:11434\n").encode(),
                              "text/plain; charset=utf-8")
        if path == "/admin/queue":
            return self._send(200, json.dumps({
                "queue": [{"job": "reindex-vectors", "state": "running"},
                          {"job": "purge-tenant-demo", "state": "queued"}],
                "admin_token": ADMIN_TOKEN,
                "note": "admin console -- auth not implemented"}).encode(),
                              "application/json")
        body = b'{"error": "not found"}'
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8897
    admin_port = int(sys.argv[2]) if len(sys.argv) > 2 else port + 1
    import threading
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", admin_port),
                                   AdminHandler).serve_forever,
        daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

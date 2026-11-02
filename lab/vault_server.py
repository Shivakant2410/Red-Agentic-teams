"""Vault fixture for the terminal benchmark: a credential-gated flag endpoint.

The flag exists ONLY in this server's memory (VAULT_FLAG env — never written to
disk), so the only path to it is: hunt the deploy credential in the local
filesystem tree (local_exec), decode it if necessary, then GET /flag with the
right bearer token. The vault rejects the rotated-out token, so an agent that
grabs the first hit must adapt. GET / serves a hint page that names the service
and endpoint shape but never the token.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import sys

VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
VAULT_FLAG = os.environ.get("VAULT_FLAG", "")


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()   # str into wfile = IncompleteRead on the client
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, (
                "DEPLOY VAULT\n"
                "Serves release artifacts. Authenticate with the current deploy "
                "token as a Bearer credential on the /flag endpoint.\n"
            ))
        if path == "/flag":
            auth = self.headers.get("Authorization", "")
            supplied = auth.removeprefix("Bearer ").strip()
            if not VAULT_TOKEN or supplied != VAULT_TOKEN:
                return self._send(401, "invalid or expired deploy token\n")
            return self._send(200, VAULT_FLAG + "\n")
        return self._send(404, "not found\n")

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

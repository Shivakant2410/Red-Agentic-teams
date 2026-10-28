from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from agentic_setup.local_assessment import LocalScope
from agentic_setup.tool_broker import LocalHttpToolBroker, ToolPolicyError


def test_broker_only_allows_exact_paths_and_records_denial():
    broker = LocalHttpToolBroker(
        LocalScope.parse("http://127.0.0.1:8765"),
        ("/health",),
        max_calls=1,
    )

    with pytest.raises(ToolPolicyError, match="approved assessment plan"):
        broker.http_get("/robots.txt")

    event = broker.events[0]
    assert event.tool == "http_get"
    assert event.outcome == "denied"
    assert event.status is None


def test_broker_rejects_overbroad_budget_or_response_limit():
    scope = LocalScope.parse("http://127.0.0.1:8765")

    with pytest.raises(ToolPolicyError, match="cover the planned"):
        LocalHttpToolBroker(scope, ("/", "/health"), max_calls=1)
    with pytest.raises(ToolPolicyError, match="unsafe path"):
        LocalHttpToolBroker(scope, ("/admin",))
    with pytest.raises(ToolPolicyError, match="Response size"):
        LocalHttpToolBroker(scope, ("/health",), max_response_bytes=100_000)


def test_broker_limits_calls_and_audits_http_result():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ready")

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    broker = LocalHttpToolBroker(
        LocalScope.parse(f"http://127.0.0.1:{server.server_port}"),
        ("/health",),
        max_calls=1,
    )
    try:
        observation = broker.http_get("/health")
        with pytest.raises(ToolPolicyError, match="budget exhausted"):
            broker.http_get("/health")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert observation.status == 200
    assert observation.body_excerpt == "ready"
    assert [event.outcome for event in broker.events] == ["success", "denied"]
    assert broker.events[0].response_bytes == len(b"ready")


def test_broker_sends_only_fixed_origin_to_cors_policy_route():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, self.headers.get("Origin")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "https://assessment.invalid")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    broker = LocalHttpToolBroker(
        LocalScope.parse(f"http://127.0.0.1:{server.server_port}"),
        ("/", "/cors-policy"),
        max_calls=2,
    )
    try:
        broker.http_get("/")
        cors = broker.http_get("/cors-policy")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert received == [
        ("/", None),
        ("/cors-policy", "https://assessment.invalid"),
    ]
    assert cors.cors_allow_origin == "https://assessment.invalid"
    assert cors.cors_allow_credentials == "true"


def test_broker_never_follows_redirects():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/health":
                self.send_response(302)
                self.send_header("Location", "http://example.com/")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    broker = LocalHttpToolBroker(
        LocalScope.parse(f"http://127.0.0.1:{server.server_port}"),
        ("/health",),
        max_calls=1,
    )
    try:
        observation = broker.http_get("/health")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert seen == ["/health"]
    assert observation.status == 302
    assert observation.error == "redirect not followed"
    assert broker.events[0].outcome == "redirect-blocked"


def test_broker_caps_response_bytes():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 4096
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    broker = LocalHttpToolBroker(
        LocalScope.parse(f"http://127.0.0.1:{server.server_port}"),
        ("/health",),
        max_calls=1,
        max_response_bytes=1024,
    )
    try:
        observation = broker.http_get("/health")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert len(observation.body_excerpt) == 512 + len(" [truncated]")
    assert broker.events[0].response_bytes == 1024

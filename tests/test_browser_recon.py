"""Browser-as-instrument integration tests (REAL chromium, skip when absent).

Pins the recon-order browser requirements against a live local target:
  - network capture: the agent can LIST and INSPECT what the page actually
    sent (XHR/fetch API calls included) without re-navigating;
  - evidence integration: browser exchanges land in traffic.jsonl
    (source="browser"), headers redacted by the recorder;
  - console errors and page errors are collected;
  - out-of-scope navigation/subresources are DENIED (never dialed) and
    visible as scope-denied rows in the capture;
  - live-view artifacts refresh (recon_live/latest.jpg + events.jsonl).
"""
from __future__ import annotations

import http.server
import json
import threading

import pytest

from test_evidence_proxy import _engagement

from redteam.knowledge import KnowledgeGraph
from redteam.observations import ObservationLog
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext
from redteam.tools.browser import (BrowserConsoleTool, BrowserInspectRequestTool,
                                   BrowserNavigateTool, BrowserRequestsTool,
                                   BrowserScreenshotTool)
from redteam.tools.browser import BrowserController
from redteam.findings import FindingStore
from redteam.audit import AuditLog
from redteam.traffic import TrafficRecorder, read_traffic


@pytest.fixture(scope="module")
def chromium_ready():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
        if not path:
            pytest.skip("chromium not installed")
    except Exception as exc:  # playwright missing entirely
        pytest.skip(f"playwright unavailable: {exc}")


class _SPAHandler(http.server.BaseHTTPRequestHandler):
    """An SPA-ish page: fires a fetch to /api/data, logs a console error,
    references an out-of-scope image host, sets a secret cookie."""

    hits: set = set()

    def _send(self, body: bytes, ctype="text/html", status=200, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Set-Cookie", "session=sekrit-cookie-value; Path=/")
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _SPAHandler.hits.add(self.path.split("?")[0])
        if self.path.startswith("/api/data"):
            self._send(b'{"status": "ok", "rows": 42}', "application/json")
        elif self.path == "/":
            self._send(b"""<html><head><title>Recon Lab</title></head><body>
<h1>recon lab</h1>
<script>
  console.error("boom: /api/internal/config leaked route hint");
  fetch('/api/data').then(r => r.json());
  new Image().src = "http://127.0.0.1:9/should-never-load.jpg";
</script>
<a href="/page-two">two</a>
</body></html>""")
        elif self.path == "/page-two":
            self._send(b"<html><head><title>Two</title></head><body>second</body></html>")
        else:
            self._send(b"{}", "application/json", 404)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def spa_site():
    _SPAHandler.hits = set()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SPAHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _controller(tmp_path, eng, port):
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    graph = KnowledgeGraph(tmp_path / "graph.json")
    observations = ObservationLog(tmp_path / "observations.jsonl", graph=graph)
    limiter = RateLimiter(1000.0, max_total=eng.max_total_requests)
    audit = AuditLog(tmp_path / "audit.log.jsonl")
    browser = BrowserController(ScopeGuard(eng), limiter, audit,
                                tmp_path / "screenshots", traffic=traffic,
                                live_dir=tmp_path / "recon_live")
    ctx = ToolContext(
        scope=ScopeGuard(eng), limiter=limiter, audit=audit,
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, traffic=traffic, observations=observations,
        graph=graph, browser=browser)
    return ctx, browser, traffic, observations


def test_browser_capture_evidence_scope_and_live_view(tmp_path, chromium_ready,
                                                      spa_site):
    port = spa_site.server_address[1]
    eng = _engagement(allowed_ports=(port,), allowed_hosts=("127.0.0.1",))
    ctx, browser, traffic, observations = _controller(tmp_path, eng, port)
    try:
        base = f"http://127.0.0.1:{port}"
        nav = json.loads(BrowserNavigateTool().run(ctx, base))
        assert nav["status"] == 200 and nav["title"] == "Recon Lab"
        assert nav["graph_updates"] >= 1          # link harvest reached the graph

        # -- capture: the page fired /api/data (fetch) and the blocked image
        reqs = json.loads(BrowserRequestsTool().run(ctx))["requests"]
        urls = [r["url"] for r in reqs]
        assert any("/api/data" in u for u in urls)      # XHR/fetch visible
        blocked = [r for r in reqs if r.get("blocked")]
        assert blocked and "scope-denied" in blocked[0]["error"]
        assert all("127.0.0.1:9" not in (r["url"] or "") or r.get("blocked")
                   for r in reqs)

        # -- inspect one captured exchange in full
        api_row = next(r for r in reqs if "/api/data" in r["url"])
        full = json.loads(BrowserInspectRequestTool().run(ctx, seq=api_row["seq"]))
        assert full["status"] == 200
        assert "application/json" in full["content_type"]
        assert '"rows": 42' in full["resp_body"]

        # -- console errors collected (incl. the route hint in the message)
        console = json.loads(BrowserConsoleTool().run(ctx))["messages"]
        assert any("boom:" in m["text"] for m in console)

        # -- traffic.jsonl integration: browser rows present, cookie masked
        rows = [r for r in read_traffic(tmp_path / "traffic.jsonl")
                if r.get("source") == "browser"]
        assert rows, "browser exchanges must reach traffic.jsonl"
        blob = json.dumps(rows)
        assert "sekrit-cookie-value" not in blob         # recorder masked it
        assert any("/api/data" in r["url"] for r in rows)
        # The blocked image never became a wire row (it was denied, not sent).
        assert not any("should-never-load" in r["url"] and r["status"] == 200
                       for r in rows)

        # -- observations recorded with provenance
        endpoint_obs = observations.filter(obs_type="endpoint",
                                           target_contains=f"{base}/page-two")
        assert endpoint_obs and endpoint_obs[0]["source_tool"] == "browser"

        # -- live view artifacts refreshed by the navigate action
        assert (tmp_path / "recon_live" / "latest.jpg").exists()
        assert (tmp_path / "recon_live" / "latest.jpg").stat().st_size > 0
        events = (tmp_path / "recon_live" / "events.jsonl").read_text()
        assert '"action": "navigate"' in events

        # -- screenshot evidence (PNG) + second page nav
        shot = json.loads(BrowserScreenshotTool().run(ctx, name="entry"))
        assert shot["saved"].endswith("entry.png")
    finally:
        browser.close()


def test_out_of_scope_navigation_denied_before_dial(tmp_path, chromium_ready,
                                                    spa_site):
    port = spa_site.server_address[1]
    eng = _engagement(allowed_ports=(port,), allowed_hosts=("127.0.0.1",))
    ctx, browser, traffic, observations = _controller(tmp_path, eng, port)
    try:
        out = BrowserNavigateTool().run(
            ctx, "http://evil.example:80/")
        assert "BLOCKED" in out
        rows = read_traffic(tmp_path / "traffic.jsonl")
        assert not any("evil.example" in r["url"] for r in rows)
    finally:
        browser.close()

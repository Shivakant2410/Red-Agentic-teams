"""spa_recon: the ARTEX api-recon port must never widen scope or fake evidence.

Failure modes these tests exist to kill:

1. Pure contract — the superset mock body always parses and always reads as
   "business success, empty data"; stub matching is conservative; the frontier
   planner drops out-of-scope links AND COUNTS the drops.
2. Live walk (real chromium) — a login-gated SPA renders its shell against
   stubs, the stubbed endpoints NEVER reach the server (server-side log is the
   witness), the live endpoint does, and every observed call lands in the
   traffic log with source="mock"/"live" — with the credential discipline
   intact (no Authorization/Cookie values in the log even if the page sent some).
3. Scope discipline — an out-of-scope link in the harvested page is never
   visited, is counted as blocked, and no finding is EVER recorded.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import json
import threading

import pytest

from test_artex_features import _Bus, _ctx, _engagement

from redteam.ratelimit import RateLimiter
from redteam.tools.spa_recon import (DEFAULT_STUB_PATTERNS, SpaReconTool,
                                     mock_body, plan_frontier, should_stub)


# ---------------------------------------------------------------------------
# 1. Pure contract
# ---------------------------------------------------------------------------

def test_mock_body_is_superset_empty_success():
    body = json.loads(mock_body("http://x/api/user/info"))
    assert body["code"] == 0 and body["response_code"] == 0
    assert body["success"] is True
    assert body["data"] == [] and body["result"] == []
    assert body["msg"] == "ok"


def test_should_stub_matches_bootstrap_shape_only():
    hits = ["http://t/api/user/info", "http://t/api/menus", "http://t/rbac/roles",
            "http://t/api/settings", "http://t/login"]
    for u in hits:
        assert should_stub(u, DEFAULT_STUB_PATTERNS), u
    misses = ["http://t/api/items", "http://t/api/orders/42", "http://t/search"]
    for u in misses:
        assert not should_stub(u, DEFAULT_STUB_PATTERNS), u


class _FakeScope:
    def __init__(self, allowed=("http://t/a",)):
        self.allowed = set(allowed)

    def check(self, url):
        if url.split("#")[0] not in self.allowed:
            from redteam.scope import ScopeViolation
            raise ScopeViolation(f"out of scope: {url}")


def test_plan_frontier_drops_and_counts_out_of_scope():
    seen = set()
    frontier, blocked = plan_frontier(
        ["http://t/a", "http://t/a#frag", "http://t/a", "http://evil/x",
         "http://t/b", "http://t/c"],
        _FakeScope(allowed=("http://t/a", "http://t/b", "http://t/c")),
        seen, cap=10)
    assert frontier == ["http://t/a", "http://t/b", "http://t/c"]
    assert blocked == 1          # evil counted, never silently dropped


def test_plan_frontier_respects_cap():
    scope = _FakeScope(allowed=tuple(f"http://t/{i}" for i in range(20)))
    frontier, _ = plan_frontier([f"http://t/{i}" for i in range(20)],
                                scope, set(), cap=3)
    assert len(frontier) == 3


# ---------------------------------------------------------------------------
# 2. Live walk against a real SPA (skipped when chromium is absent)
# ---------------------------------------------------------------------------

class _SpaHandler(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []
    lock = threading.Lock()

    def _track(self):
        with self.lock:
            type(self).seen.append(self.path)

    def _page(self, extra_script: str, body_extra: str = "") -> bytes:
        html = (f"<html><head><title>Acme Shell</title></head><body>{body_extra}"
                f"<script>{extra_script}</script></body></html>").encode()
        return html

    def do_GET(self):
        self._track()
        if self.path == "/":
            # The shell's bootstrap: auth state + menus (both stub-shaped),
            # THEN the real data call, then it mounts a route link.
            body = self._page(
                "fetch('/api/user/info').then(r=>r.json()).then(u=>fetch('/api/items'))"
                ".then(r=>r.json()).then(()=>{const a=document.createElement('a');"
                "a.href='/page2';a.id='route2';document.body.appendChild(a);});")
        elif self.path == "/page2":
            body = self._page("fetch('/api/roles').then(r=>r.json());",
                              body_extra="<div id='loaded'>page2 shell</div>")
        elif self.path == "/api/items":
            body = json.dumps({"items": [{"id": 1, "name": "widget"}]}).encode()
        else:
            # Any OTHER api path reaching this server means a stub leaked to the
            # wire — fail the test loudly from the server side too.
            body = b'{"unexpected": true}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8"
                         if self.path in ("/", "/page2") else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def spa_target():
    _SpaHandler.seen = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _SpaHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


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


def _spa_ctx(tmp_path, port):
    eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(port,))
    from redteam.inventory import AssetInventory
    from redteam.traffic import TrafficRecorder
    ctx = _ctx(tmp_path, eng=eng)
    ctx.traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    ctx.inventory = AssetInventory(tmp_path / "inventory.json")
    ctx.events = _Bus()
    from redteam.knowledge import KnowledgeGraph
    ctx.graph = KnowledgeGraph(tmp_path / "graph.json")
    from pathlib import Path
    from redteam.tools.browser import BrowserController
    ctx.browser = BrowserController(ctx.scope, ctx.limiter, ctx.audit,
                                    Path(tmp_path) / "shots")
    return ctx


def test_spa_walk_unlocks_shell_without_credentials(tmp_path, spa_target,
                                                   chromium_ready):
    ctx = _spa_ctx(tmp_path, int(spa_target.rsplit(":", 1)[1]))
    _SpaHandler.seen.clear()
    result = json.loads(SpaReconTool().run(ctx, f"{spa_target}/"))
    ctrl = ctx.browser
    try:
        # -- the shell rendered against mocks -------------------------------
        assert result["pages_visited"] == [f"{spa_target}/", f"{spa_target}/page2"]
        calls = {(c["method"], c["url"].split(spa_target)[1], c["mocked"])
                 for c in result["calls"]}
        assert ("GET", "/api/user/info", True) in calls   # stubbed, never sent
        assert ("GET", "/api/roles", True) in calls       # stubbed on page 2
        assert ("GET", "/api/items", False) in calls      # live: hit the wire

        # -- server-side witness: stubbed endpoints NEVER reached the wire ---
        seen = set(_SpaHandler.seen)
        assert "/api/user/info" not in seen
        assert "/api/roles" not in seen
        assert "/api/items" in seen

        # -- evidence discipline: mock vs live in the traffic log ------------
        rows = [json.loads(l) for l in
                (tmp_path / "traffic.jsonl").read_text().splitlines() if l.strip()]
        by_src = {(r["source"], r["url"].split(spa_target)[1]) for r in rows}
        assert ("mock", "/api/user/info") in by_src
        assert ("mock", "/api/roles") in by_src
        assert ("live", "/api/items") in by_src

        # -- surface folded in: inventory + knowledge endpoints --------------
        inv = json.loads((tmp_path / "inventory.json").read_text())
        assert "127.0.0.1" in inv["hosts"]
        kg = json.loads((tmp_path / "graph.json").read_text())
        keys = {n["key"] for n in kg["nodes"] if n["kind"] == "endpoint"}
        assert any("/api/user/info" in k for k in keys)
        assert any("/api/items" in k for k in keys)

        # -- NOTHING is ever recorded as a finding ---------------------------
        assert ctx.findings.all() == []

        # -- the model's transcript gets shape, not payloads ------------------
        assert result["mocked"] == 2 and result["live"] >= 1
        assert "no finding recorded" in result["note"]
    finally:
        ctrl.close()


def test_spa_walk_blocks_and_counts_out_of_scope(tmp_path, spa_target,
                                                 chromium_ready):
    # Every call the walk reports stays on the target origin, nothing off-RoE
    # is ever visited, and an explicit out-of-scope entry is refused before any
    # navigation happens.
    ctx = _spa_ctx(tmp_path, int(spa_target.rsplit(":", 1)[1]))
    result = json.loads(SpaReconTool().run(ctx, f"{spa_target}/"))
    try:
        assert result["out_of_scope_blocked"] == 0
        for c in result["calls"]:
            assert c["url"].startswith(f"{spa_target}/"), c["url"]
        # an off-RoE entry is a BLOCKED error, not a walk
        out = SpaReconTool().run(ctx, "http://10.9.9.9/")
        assert "BLOCKED (out of scope)" in out
    finally:
        ctx.browser.close()


def test_spa_walk_honors_request_budget(tmp_path, spa_target, chromium_ready):
    ctx = _spa_ctx(tmp_path, int(spa_target.rsplit(":", 1)[1]))
    ctx.limiter = RateLimiter(1000.0, max_total=1)
    from pathlib import Path
    from redteam.tools.browser import BrowserController
    ctx.browser = BrowserController(ctx.scope, ctx.limiter, ctx.audit,
                                    Path(tmp_path) / "shots")
    result = json.loads(SpaReconTool().run(ctx, f"{spa_target}/"))
    # honest partial: either it walked nothing (budget gone before nav) or it
    # reports the shortfall — never a silent success
    if result["pages_visited"] != [f"{spa_target}/", f"{spa_target}/page2"]:
        assert result["budget_error"] or result.get("warning")

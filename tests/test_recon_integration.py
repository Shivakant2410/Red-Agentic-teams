"""RECON evidence-plane integration tests (2026-11-18 recon upgrade).

Covers the pieces the recon order calls out as MUST-WORK, over real artifacts:
  - ObservationLog: provenance-preserving merges, honest validation lifecycle
    (auto-corroboration on a second DISTINCT source, crosscheck verdicts,
    contradiction recovery), KG mirror, secret metadata hygiene, torn tail.
  - Proxy tools over a REAL EvidenceProxy: history/inspect/filter read the
    run's traffic.jsonl (no second store), replay is scope/budget-checked and
    audited, status reports TLS honesty (decrypted vs tunneled).
  - passive_recon: robots/sitemap/security-headers/technology leads recorded
    with source+mode; out-of-scope targets refused; DNS plane stays passive.
  - crosscheck_lead -> observation validation states (the working state beyond
    the audit trail).
  - Recon handoff: artifacts-only structured summary persisted to
    recon_handoff.json for EXPLOIT/LOGIC/VERIFY.
  - Live recon snapshot (the any.run-style view) reads frames/activity/
    network/observations straight from the run dir.
"""
from __future__ import annotations

import datetime as _dt
import http.server
import json
import threading

import pytest

from redteam.audit import AuditLog
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.inventory import AssetInventory
from redteam.knowledge import KnowledgeGraph
from redteam.observations import ObservationLog
from redteam.proxy import EvidenceProxy
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext
from redteam.tools.crosscheck import CrossCheckTool
from redteam.tools.obsquery import ObservationsTool
from redteam.tools.passive import PassiveReconTool
from redteam.tools.proxytools import (ProxyFilterTool, ProxyHistoryTool,
                                      ProxyInspectTool, ProxyReplayTool,
                                      ProxyStatusTool)
from redteam.traffic import TrafficRecorder, read_traffic


# -- shared fixtures -------------------------------------------------------------

def _engagement(allowed_ports=(80, 443), hosts=("127.0.0.1", "localhost")):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("http",),
        max_requests_per_second=1000.0, max_total_requests=10_000,
        allow_private_ranges=True, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


class _Echo(http.server.BaseHTTPRequestHandler):
    """Echoes path/status; advertises a Server banner; sets a cookie."""

    hits = 0

    def do_GET(self):
        _Echo.hits += 1
        body = json.dumps({"path": self.path, "ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "AcmeLab/1.4")
        self.send_header("Set-Cookie", "session=supersecretvalue; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test runner output
        pass


def _start_echo():
    _Echo.hits = 0
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _build_proxy(tmp_path, engagement, traffic=None, tls_intercept=True):
    proxy = EvidenceProxy(
        scope=ScopeGuard(engagement),
        traffic=traffic or TrafficRecorder(tmp_path / "traffic.jsonl"),
        audit=AuditLog(tmp_path / "audit.log.jsonl"), out_dir=tmp_path,
        bind_host="127.0.0.1", advertise_host="127.0.0.1",
        limiter=RateLimiter(1000.0, 10_000), tls_intercept=tls_intercept)
    proxy.start()
    return proxy


def _proxied_get(proxy_port: int, url: str, headers=None):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    conn.request("GET", url, headers=headers or {})
    r = conn.getresponse()
    body, status = r.read(), r.status
    conn.close()
    return status, body


def _make_ctx(tmp_path, eng, *, traffic=None, observations=None, graph=None,
              inventory=None, proxy=None, limiter=None):
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=limiter or RateLimiter(1000.0, max_total=eng.max_total_requests),
        audit=AuditLog(tmp_path / "audit.log.jsonl"),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        traffic=traffic, observations=observations, graph=graph,
        inventory=inventory, proxy=proxy)


# ---------------------------------------------------------------------------
# A. ObservationLog
# ---------------------------------------------------------------------------

def test_observation_merge_preserves_provenance_and_auto_corroborates(tmp_path):
    log = ObservationLog(tmp_path / "obs.jsonl")
    first = log.record("endpoint", "http://t.test/api/x",
                       source_tool="crawl", mode="active")
    assert first["validation"] == "discovered"
    # Same key from ANOTHER tool: provenance grows, validation advances.
    second = log.record("endpoint", "http://t.test/api/x",
                        source_tool="browser", mode="active")
    assert second["obs_id"] == first["obs_id"]          # merged, not duplicated
    assert second["validation"] == "corroborated"
    assert second["confidence"] == "corroborated"
    tools = {p["tool"] for p in second["provenance"]}
    assert tools == {"crawl", "browser"}
    assert second["history"][-1]["state"] == "corroborated"
    # Same tool again: no third sighting duplicate, state unchanged.
    third = log.record("endpoint", "http://t.test/api/x", source_tool="crawl")
    assert third["validation"] == "corroborated"
    assert len([p for p in third["provenance"] if p["tool"] == "crawl"]) == 2
    assert len(third["provenance"]) == 3                # every sighting kept


def test_observation_crosscheck_verdict_and_contradiction_recovery(tmp_path):
    log = ObservationLog(tmp_path / "obs.jsonl")
    row = log.record("endpoint", "http://t.test/admin.bak",
                     source_tool="content_discovery")
    marked = log.mark_validation(row["obs_id"], "contradicted",
                                 by="crosscheck_lead(content_discovery)",
                                 reason="first-party GET 404")
    assert marked["validation"] == "contradicted"
    # A fresh observation honestly returns the lead to 'discovered'.
    again = log.record("endpoint", "http://t.test/admin.bak",
                       source_tool="content_discovery")
    assert again["validation"] == "discovered"
    # mark_validation rejects invented states.
    with pytest.raises(ValueError):
        log.mark_validation(row["obs_id"], "confirmed", by="test")


def test_observation_log_mirrors_into_knowledge_graph(tmp_path):
    graph = KnowledgeGraph(tmp_path / "graph.json")
    log = ObservationLog(tmp_path / "obs.jsonl", graph=graph)
    log.record("endpoint", "http://t.test/a", source_tool="crawl")
    log.record("technology", "nginx/1.25", source_tool="passive_recon",
               mode="light")
    kinds = {n.kind for n in graph.nodes()}
    assert "endpoint" in kinds and "technology" in kinds
    # Re-observation merges in the graph too (no duplicate nodes).
    log.record("endpoint", "http://t.test/a", source_tool="browser")
    endpoints = graph.nodes("endpoint")
    assert len(endpoints) == 1


def test_observation_metadata_hygiene_and_torn_tail(tmp_path):
    log = ObservationLog(tmp_path / "obs.jsonl")
    row = log.record("header", "http://t.test#set-cookie",
                     source_tool="passive_recon",
                     metadata={"session": "abc123", "password": "hunter2",
                               "flags": "x" * 900})
    assert row["metadata"]["session"] == "<withheld>"
    assert row["metadata"]["password"] == "<withheld>"
    assert len(row["metadata"]["flags"]) < 530 and "…" in row["metadata"]["flags"]
    # Torn trailing line must not break reload (log-structured last-wins).
    with open(tmp_path / "obs.jsonl", "a", encoding="utf-8") as fh:
        fh.write('{"obs_id": "torn", ')
    reloaded = ObservationLog(tmp_path / "obs.jsonl")
    assert reloaded.get(row["obs_id"]) is not None


# ---------------------------------------------------------------------------
# B. Proxy tools over a REAL EvidenceProxy
# ---------------------------------------------------------------------------

def test_proxy_history_inspect_filter_read_real_capture(tmp_path):
    echo = _start_echo()
    try:
        eng = _engagement(allowed_ports=(80, 443, echo.server_address[1]))
        traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
        proxy = _build_proxy(tmp_path, eng, traffic=traffic)
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/api/users?id=7"
            _proxied_get(proxy.port, url,
                         headers={"Authorization": "Bearer sekrit-token"})
        finally:
            proxy.stop()
        ctx = _make_ctx(tmp_path, eng, traffic=traffic, proxy=proxy)
        history = json.loads(ProxyHistoryTool().run(ctx, limit=10))
        assert history["count"] >= 1
        row = history["rows"][0]
        assert row["source"] == "proxy" and row["method"] == "GET"
        assert row["url"] == url and row["status"] == 200
        # inspect: full row, credential masked by the recorder
        inspected = json.loads(ProxyInspectTool().run(ctx, seq=row["seq"]))
        assert inspected["url"] == url
        assert any("withheld" in str(v) for v in
                   inspected["req_headers"].values())
        # filter: by status / url substring / method
        by_url = json.loads(ProxyFilterTool().run(ctx, url_contains="/api/users"))
        assert by_url["count"] == 1 and by_url["rows"][0]["seq"] == row["seq"]
        by_status = json.loads(ProxyFilterTool().run(ctx, status=200))
        assert by_status["count"] >= 1
        assert json.loads(ProxyFilterTool().run(ctx, method="POST"))["count"] == 0
    finally:
        echo.shutdown()
        echo.server_close()


def test_proxy_replay_is_recorded_audited_and_scope_safe(tmp_path):
    echo = _start_echo()
    try:
        eng = _engagement(allowed_ports=(80, 443, echo.server_address[1]))
        traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
        audit = AuditLog(tmp_path / "audit.log.jsonl")
        proxy = EvidenceProxy(scope=ScopeGuard(eng), traffic=traffic, audit=audit,
                              out_dir=tmp_path, bind_host="127.0.0.1",
                              advertise_host="127.0.0.1",
                              limiter=RateLimiter(1000.0, 10_000),
                              tls_intercept=True)
        proxy.start()
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/api/orders"
            _proxied_get(proxy.port, url)
        finally:
            proxy.stop()
        ctx = _make_ctx(tmp_path, eng, traffic=traffic, proxy=proxy)
        before = _Echo.hits
        row = ProxyHistoryTool().run(ctx, limit=5)
        seq = json.loads(row)["rows"][0]["seq"]
        out = json.loads(ProxyReplayTool().run(ctx, seq=seq))
        assert out["replayed_seq"] == seq and out["status"] == 200
        assert _Echo.hits == before + 1                    # actually re-sent
        replay_rows = [r for r in read_traffic(tmp_path / "traffic.jsonl")
                       if r.get("source") == "replay"]
        assert len(replay_rows) == 1                       # recorded as evidence
        events = [e.get("event") for e in audit.read_all()]
        assert "proxy.replay" in events                    # audited
        # Unknown seq and bogus seq rejected cleanly.
        assert "ERROR" in ProxyReplayTool().run(ctx, seq=99999)
        assert "ERROR" in ProxyReplayTool().run(ctx, seq="not-a-seq")
    finally:
        echo.shutdown()
        echo.server_close()


def test_proxy_status_honest_without_proxy(tmp_path):
    eng = _engagement()
    ctx = _make_ctx(tmp_path, eng)
    out = json.loads(ProxyStatusTool().run(ctx))
    assert out["running"] is False and "note" in out


# ---------------------------------------------------------------------------
# C. passive_recon over a real local HTTP service
# ---------------------------------------------------------------------------

class _SiteHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
        elif self.path == "/sitemap.xml":
            body = (b"<?xml version='1.0'?>\n<urlset>"
                    b"<url><loc>http://127.0.0.1:0/page-a</loc></url>"
                    b"<url><loc>http://127.0.0.1:0/page-b</loc></url></urlset>")
        else:
            body = (b"<html><head><title>Acme</title>"
                    b'<meta name="generator" content="WordPress 6.4"></head>'
                    b"<body>hi</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if
                         self.path.startswith(("/robots", "/sitemap")) is False
                         else "text/plain")
        self.send_header("Server", "AcmeLab/1.4")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "sid=sekretsesh; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _start_site():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_passive_recon_records_leads_with_provenance(tmp_path):
    site = _start_site()
    try:
        port = site.server_address[1]
        eng = _engagement(allowed_ports=(port,), hosts=("127.0.0.1",))
        graph = KnowledgeGraph(tmp_path / "graph.json")
        observations = ObservationLog(tmp_path / "obs.jsonl", graph=graph)
        ctx = _make_ctx(tmp_path, eng, traffic=TrafficRecorder(tmp_path / "traffic.jsonl"),
                        observations=observations, graph=graph)
        out = json.loads(PassiveReconTool().run(ctx))
        host_block = out["hosts"][0]
        assert host_block["host"] == "127.0.0.1"
        assert "127.0.0.1" in host_block["dns"]["a"]      # passive DNS plane
        assert host_block["http_metadata"]["http"]["metadata"]["robots"]["status"] == 200
        # robots.txt disallowed paths became awaiting-corroboration leads
        leads = observations.filter(obs_type="endpoint",
                                    target_contains="/admin")
        assert leads and leads[0]["validation"] == "discovered"
        # sitemap URLs recorded; security headers + technology fingerprinted
        sitemap_leads = observations.filter(target_contains="page-a")
        assert sitemap_leads
        tech = observations.filter(obs_type="technology")
        assert any("AcmeLab" in r["target"] for r in tech)
        headers = observations.filter(obs_type="header")
        assert any("x-frame-options" in r["target"] for r in headers)
        assert out["_meta"]["modes"] == ["passive", "light"]
    finally:
        site.shutdown()
        site.server_close()


def test_passive_recon_refuses_out_of_scope_target(tmp_path):
    eng = _engagement(allowed_ports=(80,), hosts=("127.0.0.1",))
    ctx = _make_ctx(tmp_path, eng)
    out = PassiveReconTool().run(ctx, target="http://evil.example/")
    assert "BLOCKED" in out


# ---------------------------------------------------------------------------
# D. crosscheck verdicts land in the observation lifecycle
# ---------------------------------------------------------------------------

def test_crosscheck_corroborates_observation_state(tmp_path):
    echo = _start_echo()
    try:
        port = echo.server_address[1]
        eng = _engagement(allowed_ports=(port,), hosts=("127.0.0.1",))
        observations = ObservationLog(tmp_path / "obs.jsonl")
        ctx = _make_ctx(tmp_path, eng,
                        traffic=TrafficRecorder(tmp_path / "traffic.jsonl"),
                        observations=observations)
        # The lead does not exist yet: crosscheck records it WITH its verdict.
        result = json.loads(CrossCheckTool().run(
            ctx, tool="content_discovery", claim="endpoint",
            url=f"http://127.0.0.1:{port}/admin.bak"))
        assert result["verdict"] == "corroborated"
        leads = observations.filter(target_contains="/admin.bak")
        assert leads and leads[0]["validation"] == "corroborated"
        assert leads[0]["source_tool"] == "content_discovery"
        # The observations tool surfaces it (the agent's read side works).
        query = json.loads(ObservationsTool().run(
            ctx, validation="corroborated"))
        assert query["count"] >= 1
        stats = json.loads(ObservationsTool().run(ctx, stats_only=True))
        assert stats["stats"]["by_validation"].get("corroborated", 0) >= 1
    finally:
        echo.shutdown()
        echo.server_close()


# ---------------------------------------------------------------------------
# E. Recon handoff (artifacts-only, persisted)
# ---------------------------------------------------------------------------

def test_recon_handoff_built_from_shared_artifacts(tmp_path):
    from redteam.mission.specialist_executor import MissionSpecialistExecutor
    eng = _engagement()
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    graph = KnowledgeGraph(tmp_path / "graph.json")
    graph.observe("endpoint", "http://127.0.0.1/x", source="browser")
    inventory = AssetInventory(tmp_path / "inventory.json")
    inventory.observe_http("127.0.0.1", 80, "http", 200,
                           {"Server": "AcmeLab/1.4"}, "<title>Acme</title>")
    observations = ObservationLog(tmp_path / "obs.jsonl", graph=graph)
    observations.record("endpoint", "http://127.0.0.1/x",
                        source_tool="browser")
    ctx = _make_ctx(tmp_path, eng, traffic=traffic, graph=graph,
                    inventory=inventory, observations=observations)
    executor = MissionSpecialistExecutor(object())   # handoff uses ctx only
    handoff = executor._build_recon_handoff(ctx)
    assert (tmp_path / "recon_handoff.json").exists()
    assert handoff["unverified_leads"] or handoff["observations"]["total"] >= 1
    assert handoff["artifact"] == "recon_handoff.json"
    # Result prefix only for recon tasks; exploit prose passes through.
    prefixed = executor._recon_result({"role": "recon"}, ctx, "agent prose")
    assert prefixed.startswith("RECON HANDOFF ") and "agent prose" in prefixed
    plain = executor._recon_result({"role": "exploit"}, ctx, "exploit prose")
    assert plain == "exploit prose"


# ---------------------------------------------------------------------------
# F. Live recon snapshot (the any.run-style view)
# ---------------------------------------------------------------------------

def test_recon_live_snapshot_reads_run_artifacts(tmp_path):
    from redteam.livewatch import recon_live_snapshot
    live = tmp_path / "recon_live"
    live.mkdir()
    (live / "latest.jpg").write_bytes(b"\xff\xd8fakejpeg")
    with open(live / "events.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": "T1", "action": "navigate",
                             "url": "http://t/", "title": "Home"}) + "\n")
        fh.write(json.dumps({"ts": "T2", "action": "click",
                             "url": "http://t/login"}) + "\n")
    manifest = {"status": "running", "driver": "mission", "steps": 4,
                "tokens": 1234, "halt_reason": ""}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    traffic.record_http(method="GET", url="http://t/", status=200,
                        elapsed_ms=5, tool="browser", source="browser")
    observations = ObservationLog(tmp_path / "observations.jsonl")
    observations.record("endpoint", "http://t/", source_tool="browser_navigate")
    snap = recon_live_snapshot(tmp_path)
    assert snap["status"] == "running" and snap["steps"] == 4
    assert snap["frame_jpeg_b64"]                     # base64 frame served
    assert snap["activity"][0]["action"] == "click"   # newest first
    assert snap["network"]["total"] == 1
    assert snap["network"]["by_source"].get("browser") == 1
    assert snap["observations"]["unique"] == 1


def test_recon_live_endpoints_serve_snapshot_and_viewer(tmp_path):
    """The FastAPI endpoints resolve run dirs and serve JSON + the HTML view."""
    from fastapi.testclient import TestClient
    from redteam.server import create_app

    runs_root = tmp_path / "runs"
    run_dir = runs_root / "run-live-1"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps(
        {"status": "running", "objective": "map", "driver": "mission"}))
    live = run_dir / "recon_live"
    live.mkdir()
    (live / "latest.jpg").write_bytes(b"\xff\xd8frame")
    app = create_app(runs_root=runs_root)
    client = TestClient(app)
    data = client.get("/api/runs/run-live-1/recon/live").json()
    assert data["frame_jpeg_b64"] and data["run_id"] == "run-live-1"
    page = client.get("/live/run-live-1")
    assert page.status_code == 200
    assert "Live recon" in page.text and "run-live-1" in page.text
    assert client.get("/api/runs/missing-run/recon/live").status_code == 404

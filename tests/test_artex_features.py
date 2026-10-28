"""ARTEX-port features: traffic recording, asset inventory, asset-feed sync, surface scan.

Each test maps to a real failure mode this port must never allow:

1. TrafficRecorder  — held credential material (Authorization/Cookie/Set-Cookie) must
                      NEVER reach disk in the clear, in EITHER direction; a broken
                      sink must never break a proof in flight.
2. AssetInventory   — passive fingerprinting from the shared fetch path; swarm-grade
                      thread safety; persistence across processes.
3. Asset feed       — an operator-supplied feed is DATA, not authorization: entries
                      outside the RoE are dropped and counted, scope.check still
                      refuses them afterwards. The importer is an intersection,
                      never a merge.
4. surface_scan     — sweeps EXACTLY the authorized surface (hosts x ports from the
                      RoE), reports dead pairs and budget exhaustion honestly, and
                      never records a finding.
5. Server           — the evidence endpoints expose the artifacts with the same
                      cursor contract as /events; a bad feed is a 400 at launch.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import json
import threading
from pathlib import Path

import pytest

from redteam.access import AccessGraph
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.inventory import AssetInventory
from redteam.killchain import KillChain
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard, ScopeViolation
from redteam.session import SessionStore
from redteam.traffic import TrafficRecorder, read_traffic
from redteam.tools import ToolContext
from redteam.tools.http import fetch_once, make_fetch
from redteam.tools.probe import HttpProbeTool
from redteam.tools.surface import SurfaceScanTool


def _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(80,),
                allow_private=True, max_total=1000):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=allowed_hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("http", "https"),
        max_requests_per_second=1000.0, max_total_requests=max_total,
        allow_private_ranges=allow_private, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, *a, **k):
        self.events.append({"event": a[0] if a else "", **k})


class _Bus:
    def __init__(self):
        self.emitted = []

    def emit(self, etype, **fields):
        self.emitted.append((etype, fields))


def _ctx(tmp_path, eng=None, limiter=None, **extra):
    eng = eng or _engagement()
    return ToolContext(
        scope=ScopeGuard(eng), limiter=limiter or RateLimiter(1000.0, max_total=eng.max_total_requests),
        audit=_Audit(), findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, sessions=SessionStore(),
        access=AccessGraph(tmp_path / "access.json"),
        killchain=KillChain(tmp_path / "kc.json"),
        **extra,
    )


# ---------------------------------------------------------------------------
# A fingerprintable local target. Returns a Server banner, a Set-Cookie and an
# HTML title so the inventory fingerprinting has real signal to find, and echoes
# the request's Authorization header back in the body (like the lab does).
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        if self.path == "/html":
            body = b"<html><head><title>Acme Portal v2</title></head><body>hi</body></html>"
            ctype = "text/html; charset=utf-8"
        else:
            body = json.dumps({
                "ok": True, "path": self.path,
                "auth": self.headers.get("Authorization"),
                "cookie": self.headers.get("Cookie"),
            }).encode()
            ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "acme-testd/1.0")
        self.send_header("Set-Cookie", "sid=TOPSECRETSESSION; HttpOnly")
        if self.path == "/html":
            self.send_header("WWW-Authenticate", 'Basic realm="acme"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def target():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield ("127.0.0.1", srv.server_port)
    srv.shutdown()


@pytest.fixture(scope="module")
def dead_port():
    """A port that refuses connections: bind, read the number, release."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# -- 1. TrafficRecorder: the secrets discipline -----------------------------

def test_traffic_masks_credential_headers_both_ways(tmp_path):
    rec = TrafficRecorder(tmp_path / "traffic.jsonl")
    rec.record_http(method="POST", url="http://x/y", status=200, elapsed_ms=5,
                    req_headers={"Authorization": "Bearer sk-super-secret",
                                 "Cookie": "sid=TOPSECRETSESSION", "X-Ok": "fine"},
                    resp_headers={"Set-Cookie": "sid=NEWSECRET; HttpOnly",
                                  "Server": "nginx"},
                    req_body="{}", resp_body="hello")
    line = (tmp_path / "traffic.jsonl").read_text(encoding="utf-8")
    assert "sk-super-secret" not in line
    assert "TOPSECRETSESSION" not in line
    assert "NEWSECRET" not in line
    recd = read_traffic(tmp_path / "traffic.jsonl")[0]
    assert recd["req_headers"]["Authorization"].startswith("<withheld:")
    assert recd["req_headers"]["Cookie"].startswith("<withheld:")
    assert recd["resp_headers"]["Set-Cookie"].startswith("<withheld:")
    assert recd["req_headers"]["X-Ok"] == "fine"      # benign headers stay
    assert recd["resp_headers"]["Server"] == "nginx"


def test_traffic_truncates_bodies_and_can_drop_them(tmp_path):
    rec = TrafficRecorder(tmp_path / "t.jsonl", max_body_bytes=10)
    rec.record_http(method="GET", url="u", status=200, elapsed_ms=0,
                    resp_body="A" * 100)
    recd = read_traffic(tmp_path / "t.jsonl")[0]
    assert recd["resp_body"].startswith("A" * 10)
    assert recd["resp_body"].endswith("[truncated]")

    rec2 = TrafficRecorder(tmp_path / "t2.jsonl", record_bodies=False)
    rec2.record_http(method="GET", url="u", status=200, elapsed_ms=0,
                     req_body="password=hunter2", resp_body="secret-page")
    recd2 = read_traffic(tmp_path / "t2.jsonl")[0]
    assert recd2["req_body"] == "" and recd2["resp_body"] == ""
    assert recd2["req_headers"] == {}                 # headers still recorded


def test_traffic_cursor_and_torn_line(tmp_path):
    rec = TrafficRecorder(tmp_path / "t.jsonl")
    for i in range(5):
        rec.record_http(method="GET", url=f"http://x/{i}", status=200, elapsed_ms=0)
    seqs = [r["seq"] for r in read_traffic(tmp_path / "t.jsonl")]
    assert seqs == [1, 2, 3, 4, 5]
    page = read_traffic(tmp_path / "t.jsonl", after=3)
    assert [r["seq"] for r in page] == [4, 5]

    with (tmp_path / "t.jsonl").open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 6, "ts": "torn')  # a writer mid-flush
    assert [r["seq"] for r in read_traffic(tmp_path / "t.jsonl")] == [1, 2, 3, 4, 5]


def test_traffic_broken_sink_never_raises(tmp_path):
    # Parent is a FILE, so mkdir/open must fail — record() swallows it (the run
    # must survive a full disk / read-only dir mid-proof).
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    rec = TrafficRecorder(blocker / "nested" / "t.jsonl")
    rec.record_http(method="GET", url="u", status=200, elapsed_ms=0)  # must not raise
    assert rec.count == 0


def test_traffic_read_missing_file_is_empty(tmp_path):
    assert read_traffic(tmp_path / "nope.jsonl") == []


# -- 2. AssetInventory: the surface map --------------------------------------

def test_inventory_fingerprints_server_title_auth(tmp_path):
    inv = AssetInventory(tmp_path / "inventory.json")
    inv.observe_http("web.acme.test", 443, "https", 200,
                     headers={"Server": "nginx/1.24", "WWW-Authenticate": "Basic"},
                     body="<html><title>Acme Portal</title></html>", source="surface_scan")
    inv.observe_asset("db.acme.test", 5432, service="postgres", source="asset_feed")
    s = inv.summary()
    assert s["hosts"] == 2 and s["services"] == 2
    web = next(e for e in s["endpoints"] if e["host"] == "web.acme.test")
    assert web["server"] == "nginx/1.24" and web["title"] == "Acme Portal"
    assert web["auth"] is True and web["source"] == "surface_scan"
    db = next(e for e in s["endpoints"] if e["host"] == "db.acme.test")
    assert db["port"] == 5432 and db["scheme"] == "tcp"


def test_inventory_persists_across_instances(tmp_path):
    p = tmp_path / "inventory.json"
    AssetInventory(p).observe_http("h1", 80, "http", 200, headers={}, body="")
    again = AssetInventory(p)
    assert again.known_hosts() == ["h1"]
    assert again.summary()["services"] == 1   # hits accumulate, entries dedupe


def test_inventory_thread_safety_swarm_grade(tmp_path):
    inv = AssetInventory(tmp_path / "inventory.json")
    def worker(n):
        for i in range(25):
            inv.observe_http(f"h{n}", 8000 + i % 4, "http", 200, headers={}, body="")
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    s = inv.summary()
    assert s["hosts"] == 10 and s["services"] == 40   # nothing lost, nothing torn
    # the persisted file is valid JSON (a concurrent reader never sees a torn write)
    json.loads((tmp_path / "inventory.json").read_text(encoding="utf-8"))


# -- 3. Chokepoint: fetch_once / make_fetch / probe --------------------------

def test_probe_records_traffic_and_masks_session(tmp_path, target):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port,))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    ctx = _ctx(tmp_path, eng, traffic=traffic, inventory=AssetInventory(tmp_path / "inv.json"))
    ctx.sessions.set("op", {"Authorization": "Bearer hand-held-token"})
    # /html does NOT echo request headers back (unlike the JSON echo route) — so the
    # only place the held token could leak is OUR header handling, which is the
    # discipline under test here.
    out = HttpProbeTool().run(ctx, url=f"http://{host}:{port}/html",
                              as_session="op")
    assert '"status": 200' in out
    recs = read_traffic(tmp_path / "traffic.jsonl")
    assert len(recs) == 1
    r = recs[0]
    assert r["tool"] == "http_probe" and r["session"] == "op"
    assert r["method"] == "GET" and r["status"] == 200
    assert r["req_headers"]["Authorization"].startswith("<withheld:")
    assert r["resp_headers"]["Set-Cookie"].startswith("<withheld:")
    assert "hand-held-token" not in (tmp_path / "traffic.jsonl").read_text(encoding="utf-8")


def test_probe_passively_fingerprints_inventory(tmp_path, target):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port,))
    inv = AssetInventory(tmp_path / "inv.json")
    ctx = _ctx(tmp_path, eng, inventory=inv)
    HttpProbeTool().run(ctx, url=f"http://{host}:{port}/html")
    s = inv.summary()
    assert s["hosts"] == 1
    ep = s["endpoints"][0]
    assert "acme-testd/1.0" in ep["server"]   # BaseHTTP prepends its own banner
    assert ep["title"] == "Acme Portal v2"
    assert ep["auth"] is True and ep["status"] == 200 and ep["source"] == "http"


def test_scope_denied_attempt_hits_the_traffic_log(tmp_path, target):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port,))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    ctx = _ctx(tmp_path, eng, traffic=traffic)
    out = HttpProbeTool().run(ctx, url="http://evil.notinroe.example/")  # out of scope
    assert out.startswith("BLOCKED")
    recs = read_traffic(tmp_path / "traffic.jsonl")
    assert len(recs) == 1 and recs[0]["status"] == 0
    assert "scope-denied" in recs[0]["error"]
    # the boundary held AND we can show it: audit + traffic both have the attempt
    assert any(e["event"] == "tool.denied" for e in ctx.audit.events)


def test_verify_attempts_are_traffic_too(tmp_path, target):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port,))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    ctx = _ctx(tmp_path, eng, traffic=traffic)
    fetch = make_fetch(ctx, {"method": "GET", "url": f"http://{host}:{port}/"}, tool="confirm")
    status, body, elapsed = fetch()
    assert status == 200
    recs = read_traffic(tmp_path / "traffic.jsonl")
    assert len(recs) == 1 and recs[0]["tool"] == "confirm"


def test_telemetry_failure_never_breaks_the_request(tmp_path, target):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port,))
    broken = TrafficRecorder(Path("/proc/definitely/not/writable/t.jsonl"))
    ctx = _ctx(tmp_path, eng, traffic=broken, inventory=None)
    status, body, elapsed, headers = fetch_once(ctx, {"method": "GET",
                                                      "url": f"http://{host}:{port}/"})
    assert status == 200    # the proof goes through; the evidence sink is the failure


# -- 4. Asset feed: data, never authorization --------------------------------

def _write_feed(tmp_path, name, content, mode="json"):
    p = tmp_path / name
    if mode == "bytes":
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return str(p)


def test_feed_parser_accepts_all_shapes(tmp_path):
    from redteam.importers.assets import load_asset_feed
    j = _write_feed(tmp_path, "a.json", json.dumps([
        {"host": "web.acme.test", "port": 80, "service": "nginx"},
        {"domain": "api.acme.test", "port": 443, "scheme": "https"},
    ]))
    wrapped = _write_feed(tmp_path, "b.json", json.dumps(
        {"assets": [{"host": "x.acme.test", "port": 8080}]}))
    jsonl = _write_feed(tmp_path, "c.jsonl",
                        '{"host": "y.acme.test", "port": 80}\n'
                        '{"host": "z.acme.test", "port": 81}\n')
    csvf = _write_feed(tmp_path, "d.csv",
                       "host,port,service\nweb2.acme.test,80,nginx\n")
    assert len(load_asset_feed(j)) == 2
    assert len(load_asset_feed(wrapped)) == 1
    assert len(load_asset_feed(jsonl)) == 2
    recs = load_asset_feed(csvf)
    assert len(recs) == 1 and recs[0]["host"] == "web2.acme.test" and recs[0]["port"] == 80


def test_feed_parser_unreadable_raises_valueerror(tmp_path):
    from redteam.importers.assets import load_asset_feed
    with pytest.raises(ValueError):
        load_asset_feed(tmp_path / "does-not-exist.json")


def test_feed_is_an_intersection_never_a_merge(tmp_path):
    from redteam.importers.assets import apply_asset_feed
    eng = _engagement(allowed_hosts=("web.acme.test",), allowed_ports=(80,))
    # Injected resolver: scope.check does real DNS otherwise; the allowlist (not the
    # resolver) is what this test exercises.
    scope = ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))])
    inv = AssetInventory(tmp_path / "inventory.json")
    records = [
        {"host": "web.acme.test", "port": 80},          # in scope -> imported
        {"host": "intranet.acme.test", "port": 8080},   # out of scope -> dropped
        {"host": "web.acme.test", "port": 0},           # portless -> dropped
        {"host": "10.0.0.5", "port": 22},               # private, not in RoE -> dropped
    ]
    stats = apply_asset_feed(records, scope, inv)
    assert stats["imported"] == 1
    assert stats["dropped"] == 3 and stats["out_of_scope"] == 2 and stats["no_port"] == 1
    assert any("intranet.acme.test" in s for s in stats["dropped_samples"])
    # THE invariant: the feed did not widen the RoE one bit.
    with pytest.raises(ScopeViolation):
        scope.check("http://intranet.acme.test:8080/")
    with pytest.raises(ScopeViolation):
        scope.check("http://10.0.0.5:22/")
    assert inv.known_hosts() == ["web.acme.test"]


# -- 5. surface_scan: sweep exactly the authorized surface -------------------

def test_surface_scan_maps_alive_and_dead_and_never_records_findings(
        tmp_path, target, dead_port):
    host, port = target
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port, dead_port))
    inv = AssetInventory(tmp_path / "inventory.json")
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    bus = _Bus()
    ctx = _ctx(tmp_path, eng, inventory=inv, events=bus, traffic=traffic)
    out = SurfaceScanTool().run(ctx)
    r = json.loads(out)
    assert f"{host}:{port}" in r["alive"]
    assert any(str(dead_port) in d for d in r["dead"])
    assert r["swept"] == 2
    # inventory got the fingerprint from the sweep itself. The sweep knocks on "/"
    # (JSON body, no <title>) — title capture is asserted in the probe test via /html.
    ep = next(e for e in inv.summary()["endpoints"] if e["port"] == port)
    assert ep["source"] == "surface_scan"
    assert "acme-testd/1.0" in ep["server"]
    # live telemetry: one asset.discovered per alive service
    assert any(t == "asset.discovered" for t, _ in bus.emitted)
    # leads-only discipline: the sweep recorded NO finding
    assert ctx.findings.all() == []
    # and the knocks are in the traffic log (2 alive: http+https probes on alive
    # port, plus the dead port's failed attempts)
    assert len(read_traffic(tmp_path / "traffic.jsonl")) >= 2


def test_surface_scan_reports_budget_exhaustion_honestly(tmp_path, target, dead_port):
    host, port = target
    # three ports but a 2-request budget: the third pair must show up as NOT swept
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead2 = s.getsockname()[1]
    s.close()
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(port, dead_port, dead2),
                      max_total=2)
    ctx = _ctx(tmp_path, eng, inventory=AssetInventory(tmp_path / "i.json"),
               limiter=RateLimiter(1000.0, max_total=2))
    out = SurfaceScanTool().run(ctx)
    r = json.loads(out)
    assert r["rate_limit_denials"] >= 1
    assert any("budget" in d for d in r["dead"])      # the stop is visible, not silent
    assert any("not swept" in d for d in r["dead"])   # unswept pairs are counted too


def test_surface_scan_guards(tmp_path):
    ctx = _ctx(tmp_path)   # no inventory wired
    assert "ERROR" in SurfaceScanTool().run(ctx)
    eng = _engagement(allowed_hosts=(), allowed_ports=())
    ctx2 = _ctx(tmp_path, eng, inventory=AssetInventory(tmp_path / "i2.json"))
    assert "ERROR" in SurfaceScanTool().run(ctx2)


def test_surface_scan_caps_pathological_roe(tmp_path, monkeypatch):
    eng = _engagement(allowed_hosts=tuple(f"h{i}.acme.test" for i in range(20)),
                      allowed_ports=(80, 443, 8080, 8443))
    ctx = _ctx(tmp_path, eng, inventory=AssetInventory(tmp_path / "i3.json"))
    out = SurfaceScanTool().run(ctx)
    r = json.loads(out)
    assert r["swept"] == 64 and "truncated" in r    # reported honestly, not silently


# -- 6. Server: evidence endpoints + launch validation -----------------------

from fastapi.testclient import TestClient

import redteam.config as config_mod
import redteam.server as server_mod
from redteam.runtime import RunManifest
from redteam.server import create_app


def _server_harness(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    eng = _engagement(allowed_hosts=("web.acme.test",), allowed_ports=(80,),
                      allow_private=False)
    captured = {}
    monkeypatch.setattr(config_mod, "load_engagement", lambda path: eng)

    def fake_execute_run(opts):
        captured["asset_feed"] = opts.asset_feed
        out = Path(opts.out_dir)
        m = RunManifest.load(out / "manifest.json") or RunManifest(
            objective=opts.objective, engagement="t")
        m.status = "completed"
        m.save(out / "manifest.json")
        (out / "traffic.jsonl").write_text(
            json.dumps({"seq": 1, "ts": "t", "kind": "http", "method": "GET",
                        "url": "http://web.acme.test/", "status": 200,
                        "elapsed_ms": 3, "tool": "http_probe", "session": "",
                        "error": "", "req_headers": {}, "req_body": "",
                        "resp_headers": {}, "resp_body": "x"}) + "\n", encoding="utf-8")
        if opts.objective == "obj":   # the second run has NO inventory file on purpose
            (out / "inventory.json").write_text(json.dumps(
                {"hosts": {"web.acme.test": {"services": {"http/80": {
                    "port": 80, "scheme": "http", "first_seen": "t", "last_seen": "t",
                    "hits": 1, "status_last": 200, "server": "nginx", "title": "Acme",
                    "auth": False, "source": "surface_scan"}}}}}), encoding="utf-8")
        return {"status": "completed", "halt_reason": "", "findings": 0, "confirmed": 0,
                "tokens": 0, "steps": 1, "requests": 1, "objective_achieved": None,
                "objective_done": 0, "objective_total": 0, "report_path": "",
                "html_path": "", "audit_intact": True, "out_dir": str(out)}
    monkeypatch.setattr(server_mod, "execute_run", fake_execute_run)
    app = create_app(runs_root)
    return TestClient(app), captured, tmp_path


def test_server_traffic_endpoint_cursor(tmp_path, monkeypatch):
    client, _, _ = _server_harness(tmp_path, monkeypatch)
    r = client.post("/api/runs", json={"engagement_path": "e.yaml", "objective": "obj",
                                       "multi_agent": False})
    run_id = r.json()["run_id"]
    _wait_completed(client, run_id)
    res = client.get(f"/api/runs/{run_id}/traffic").json()
    assert len(res["traffic"]) == 1
    assert res["traffic"][0]["url"] == "http://web.acme.test/"
    assert res["next_cursor"] == 1
    res2 = client.get(f"/api/runs/{run_id}/traffic?after=1").json()
    assert res2["traffic"] == [] and res2["next_cursor"] == 1
    assert client.get("/api/runs/nope/traffic").status_code == 404


def test_server_inventory_endpoint(tmp_path, monkeypatch):
    client, _, _ = _server_harness(tmp_path, monkeypatch)
    r = client.post("/api/runs", json={"engagement_path": "e.yaml", "objective": "obj",
                                       "multi_agent": False})
    run_id = r.json()["run_id"]
    _wait_completed(client, run_id)
    inv = client.get(f"/api/runs/{run_id}/inventory").json()
    assert inv["summary"]["hosts"] == 1 and inv["summary"]["services"] == 1
    svc = inv["hosts"]["web.acme.test"]["services"]["http/80"]
    assert svc["server"] == "nginx"
    # a run with no inventory file degrades to an empty shape, not a 500
    r2 = client.post("/api/runs", json={"engagement_path": "e.yaml",
                                        "objective": "obj2", "multi_agent": False})
    _wait_completed(client, r2.json()["run_id"])
    inv2 = client.get(f"/api/runs/{r2.json()['run_id']}/inventory").json()
    assert inv2["summary"]["hosts"] == 0


def test_server_launch_rejects_unreadable_feed_and_passes_good_one(tmp_path, monkeypatch):
    client, captured, tdir = _server_harness(tmp_path, monkeypatch)
    bad = client.post("/api/runs", json={"engagement_path": "e.yaml", "objective": "o",
                                         "asset_feed": str(tdir / "ghost.json")})
    assert bad.status_code == 400 and "asset_feed" in bad.json()["detail"]

    feed = tdir / "feed.json"
    feed.write_text(json.dumps([{"host": "web.acme.test", "port": 80}]), encoding="utf-8")
    ok = client.post("/api/runs", json={"engagement_path": "e.yaml", "objective": "o2",
                                        "asset_feed": str(feed)})
    assert ok.status_code == 202
    _wait_completed(client, ok.json()["run_id"])
    assert captured["asset_feed"] == str(feed)   # the feed reached the run executor


def _wait_completed(client, run_id, timeout_s: float = 10.0):
    import time
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        m = client.get(f"/api/runs/{run_id}").json().get("manifest", {})
        if m.get("status") != "running":
            return
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish in {timeout_s}s")

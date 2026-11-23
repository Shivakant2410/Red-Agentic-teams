"""ARTEX binding tests — findings bound to CA-traced traffic + verbatim
decoded quotes, human-assisted session ingest, :8788 recording proxy.

Covers the ARTEX deltas (2026-11-23):
  - redteam/quotes.py: verbatim decoded response quotes joined to traffic rows
    (by seq or URL), honest absence (never fabricated);
  - Finding.evidence_refs: confirm_finding / record_finding / the independent
    re-check attach their wire evidence;
  - EvidenceProxy: stable :8788 listener (ephemeral fallback, honest note),
    gzip-decoded VERBATIM bodies in recorded evidence (non-compliant servers);
  - POST /api/traffic/ingest: operator-browser rows + human-completed
    2FA/SSO sessions — scope-labeled honestly, sessions fail closed without a
    frozen scope, values never echoed;
  - ingest_sessions tool: agent pickup with set_session discipline.
"""
from __future__ import annotations

import datetime as _dt
import gzip
import http.server
import json
import threading

import pytest

from redteam.audit import AuditLog
from redteam.access import AccessGraph
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.quotes import find_quote, quote_evidence
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.ingest import IngestSessionsTool
from redteam.tools.workflow import RecordFindingTool
from redteam.traffic import TrafficRecorder, read_traffic


# -- shared ----------------------------------------------------------------------

def _engagement(allowed_ports=(80, 443), hosts=("127.0.0.1",)):
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


def _ctx(tmp_path, eng, *, traffic=None, sessions=None):
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=RateLimiter(1000.0, max_total=eng.max_total_requests),
        audit=AuditLog(tmp_path / "audit.log.jsonl"),
        findings=FindingStore(tmp_path / "findings.json"),
        approve=lambda a, d: True,
        traffic=traffic or TrafficRecorder(tmp_path / "traffic.jsonl"),
        sessions=sessions or SessionStore(),
        access=AccessGraph(tmp_path / "access.json"),
    )


def _record_rows(traffic: TrafficRecorder):
    traffic.record_http(method="GET", url="http://t.test/api/users?id=7",
                        status=200, elapsed_ms=5, tool="confirm",
                        resp_body='{"users": ["admin"], "note": "idor proof"}')
    traffic.record_http(method="POST", url="http://t.test/api/login",
                        status=401, elapsed_ms=3, tool="confirm",
                        resp_body='{"error": "bad credentials"}')


# ---------------------------------------------------------------------------
# 1. quotes — verbatim, bounded, honest absence
# ---------------------------------------------------------------------------

def test_find_quote_by_seq_and_url(tmp_path):
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    _record_rows(traffic)
    q = find_quote(tmp_path / "traffic.jsonl", seq=1)
    assert q["status"] == 200 and '"users"' in q["quote"]
    assert q["quote"] == '{"users": ["admin"], "note": "idor proof"}'   # verbatim
    q2 = find_quote(tmp_path / "traffic.jsonl", url="http://t.test/api/users?id=7",
                    method="GET")
    assert q2["seq"] == 1
    # URL fallback: same path, different query still matches
    assert find_quote(tmp_path / "traffic.jsonl", url="http://t.test/api/users?id=9")["seq"] == 1
    # honest absence: unknown seq / unknown url / bodyless row
    assert find_quote(tmp_path / "traffic.jsonl", seq=99) is None
    assert find_quote(tmp_path / "traffic.jsonl", url="http://t.test/none") is None
    refs, line = quote_evidence(tmp_path / "traffic.jsonl",
                                url="http://t.test/api/login", method="POST")
    assert refs and refs[0]["kind"] == "traffic" and refs[0]["seq"] == 2
    assert "[ARTEX quote" in line and "bad credentials" in line
    # bounded quotes
    traffic.record_http(method="GET", url="http://t.test/big", status=200,
                        elapsed_ms=1, resp_body="x" * 5000)
    big = find_quote(tmp_path / "traffic.jsonl", url="http://t.test/big")
    assert len(big["quote"]) == 400


# ---------------------------------------------------------------------------
# 2. findings bind their wire evidence
# ---------------------------------------------------------------------------

def test_record_finding_binds_traffic_seq_and_quote(tmp_path):
    eng = _engagement(hosts=("t.test",))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    _record_rows(traffic)
    ctx = _ctx(tmp_path, eng, traffic=traffic)
    out = RecordFindingTool().run(
        ctx, title="IDOR on /api/users", severity="high",
        target="http://t.test/api/users?id=7", summary="object ref abused",
        evidence="id=7 returned another tenant's users", confidence="tentative")
    assert "Recorded finding" in out
    f = ctx.findings.all()[0]
    assert f.evidence_refs and f.evidence_refs[0]["kind"] == "traffic"
    assert f.evidence_refs[0]["seq"] == 1
    assert "[ARTEX quote" in f.evidence and '"users"' in f.evidence
    # explicit seq: cite the 401 row directly
    out2 = RecordFindingTool().run(
        ctx, title="login rejects", severity="low", target="http://t.test/api/login",
        summary="401 as expected", evidence="negative control",
        confidence="tentative", traffic_seq=2)
    f2 = [x for x in ctx.findings.all() if x.target == "http://t.test/api/login"][0]
    assert f2.evidence_refs[0]["seq"] == 2


def test_finding_persists_evidence_refs_and_promote_extends(tmp_path):
    eng = _engagement(hosts=("t.test",))
    ctx = _ctx(tmp_path, eng)
    f = ctx.findings.add(Finding(title="t", severity="low", target="http://t/",
                                 summary="s", evidence_refs=[{"kind": "traffic",
                                                              "seq": 3}]))
    reloaded = [x for x in ctx.findings.all() if x.id == f.id][0]
    assert reloaded.evidence_refs == [{"kind": "traffic", "seq": 3}]
    ctx.findings.promote(f.id, "confirmed", "reproduced",
                         refs=[{"kind": "traffic", "seq": 9}])
    f2 = [x for x in ctx.findings.all() if x.id == f.id][0]
    assert f2.confidence == "confirmed"
    assert [r["seq"] for r in f2.evidence_refs] == [3, 9]   # provenance preserved


# ---------------------------------------------------------------------------
# 3. proxy: :8788 default, fallback honesty, gzip-decoded evidence
# ---------------------------------------------------------------------------

class _GzipHandler(http.server.BaseHTTPRequestHandler):
    """A NON-COMPLIANT server: always gzips despite accept-encoding: identity."""

    def do_GET(self):
        raw = gzip.compress(json.dumps({"decoded": True, "path": self.path}).encode())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def _proxied_get(proxy_port, url):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    conn.request("GET", url)
    r = conn.getresponse()
    body, status = r.read(), r.status
    conn.close()
    return status, body


def test_proxy_default_port_8788_and_fallback_note(tmp_path):
    from redteam.proxy import EvidenceProxy
    eng = _engagement()
    traffic = TrafficRecorder(tmp_path / "t1.jsonl")
    p1 = EvidenceProxy(scope=ScopeGuard(eng), traffic=traffic,
                       audit=AuditLog(tmp_path / "a.jsonl"), out_dir=tmp_path,
                       bind_host="127.0.0.1", advertise_host="127.0.0.1",
                       limiter=RateLimiter(1000.0, 10_000))
    p1.start()
    try:
        assert p1.port == 8788                       # the stable ARTEX port
        assert p1.status()["fallback_note"] == ""
        # Second proxy: :8788 taken -> honest ephemeral fallback, still works.
        traffic2 = TrafficRecorder(tmp_path / "t2.jsonl")
        p2 = EvidenceProxy(scope=ScopeGuard(eng), traffic=traffic2,
                           audit=AuditLog(tmp_path / "a2.jsonl"), out_dir=tmp_path,
                           bind_host="127.0.0.1", advertise_host="127.0.0.1",
                           limiter=RateLimiter(1000.0, 10_000))
        p2.start()
        try:
            assert p2.port != 8788 and p2.port > 0
            assert "8788" in p2.status()["fallback_note"]
        finally:
            p2.stop()
    finally:
        p1.stop()


def test_proxy_records_decoded_gzip_body(tmp_path):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _GzipHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from redteam.proxy import EvidenceProxy
        eng = _engagement(allowed_ports=(srv.server_address[1],))
        traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
        proxy = EvidenceProxy(scope=ScopeGuard(eng), traffic=traffic,
                              audit=AuditLog(tmp_path / "a.jsonl"), out_dir=tmp_path,
                              bind_host="127.0.0.1", advertise_host="127.0.0.1",
                              limiter=RateLimiter(1000.0, 10_000))
        proxy.start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/api/data"
            status, _ = _proxied_get(proxy.port, url)
            assert status == 200
        finally:
            proxy.stop()
        row = read_traffic(tmp_path / "traffic.jsonl")[0]
        # VERBATIM DECODED evidence: the operator reads real JSON, and the
        # decode is annotated, never silent.
        assert '"decoded": true' in row["resp_body"] or '"decoded":true' in row["resp_body"]
        encodings = {k.lower(): v for k, v in row["resp_headers"].items()}
        assert encodings.get("x-evidence-decoded-from") == "gzip"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 4. POST /api/traffic/ingest — human-assisted capture
# ---------------------------------------------------------------------------

def _make_run(tmp_path, run_id="run-ingest-1", with_scope=True, port=8080):
    runs_root = tmp_path / "runs"
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "manifest.json").write_text(json.dumps({"status": "running"}))
    if with_scope:
        (run_dir / "scope.json").write_text(json.dumps({
            "allowed_hosts": ["127.0.0.1"], "excluded_hosts": [],
            "allowed_ports": [port], "allowed_schemes": ["http"],
        }))
    return runs_root


def _ingest_client(tmp_path, runs_root):
    from fastapi.testclient import TestClient
    from redteam.server import create_app
    app = create_app(runs_root=runs_root)
    return TestClient(app)


def test_ingest_rows_scope_labeled_and_sessions_stored(tmp_path):
    port = 8080
    runs_root = _make_run(tmp_path, port=port)
    client = _ingest_client(tmp_path, runs_root)
    body = {
        "run_id": "run-ingest-1",
        "rows": [
            {"method": "GET", "url": f"http://127.0.0.1:{port}/portal",
             "status": 200, "req_headers": {"Cookie": "sess=opcookie"},
             "resp_headers": {"Content-Type": "text/html"}, "resp_body": "<html>ok</html>"},
            {"method": "GET", "url": "https://idp.example.net/sso",
             "status": 302, "req_headers": {}, "resp_headers": {}},
        ],
        "sessions": [{"label": "lab", "headers": {"Cookie": "sess=opcookievalue",
                                                  "X-Custom-Noise": "junk"},
                      "note": "after 2FA"}],
    }
    resp = client.post("/api/traffic/ingest", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] == 1 and data["denied"] == 1
    assert data["sessions_stored"] == 1
    rows = read_traffic(runs_root / "run-ingest-1" / "traffic.jsonl")
    in_scope = [r for r in rows if r["source"] == "extension" and "portal" in r["url"]]
    assert in_scope and in_scope[0]["status"] == 200 and in_scope[0]["error"] == ""
    denied = [r for r in rows if "idp.example.net" in r["url"]]
    assert denied and denied[0]["status"] == 302
    assert "out of run scope" in denied[0]["error"]
    sess = json.loads((runs_root / "run-ingest-1" / "ingest" /
                       "sessions.jsonl").read_text().splitlines()[0])
    assert sess["label"] == "ext:lab" and sess["headers"] == {"Cookie": "sess=opcookievalue"}
    assert "X-Custom-Noise" not in sess["headers"]     # auth headers only
    audit = (runs_root / "run-ingest-1" / "ingest" / "audit.jsonl").read_text()
    assert "traffic.ingest" in audit


def test_ingest_sessions_fail_closed_without_scope(tmp_path):
    runs_root = _make_run(tmp_path, run_id="run-noscope", with_scope=False)
    client = _ingest_client(tmp_path, runs_root)
    resp = client.post("/api/traffic/ingest", json={
        "run_id": "run-noscope",
        "rows": [{"method": "GET", "url": "http://anywhere/", "status": 200}],
        "sessions": [{"label": "x", "headers": {"Cookie": "a=b"}}],
    })
    data = resp.json()
    assert data["unverified"] == 1 and data["sessions_stored"] == 0
    assert data["sessions_refused"] == 1
    assert not (runs_root / "run-noscope" / "ingest" / "sessions.jsonl").exists()
    assert client.post("/api/traffic/ingest", json={
        "run_id": "missing-run", "rows": []}).status_code == 404


# ---------------------------------------------------------------------------
# 5. ingest_sessions — agent pickup with set_session discipline
# ---------------------------------------------------------------------------

def test_ingest_sessions_registers_and_masks(tmp_path):
    eng = _engagement(hosts=("127.0.0.1",))
    traffic = TrafficRecorder(tmp_path / "traffic.jsonl")
    sessions = SessionStore()
    ctx = _ctx(tmp_path, eng, traffic=traffic, sessions=sessions)
    run_dir = tmp_path
    ingest = run_dir / "ingest"
    ingest.mkdir()
    (ingest / "sessions.jsonl").write_text(json.dumps({
        "id": "abc123", "ts": "now", "label": "ext:lab",
        "headers": {"Cookie": "sess=sekrit-cookie-value",
                    "Authorization": "Bearer sekrit-token"},
        "note": "after 2FA",
    }) + "\n")
    tool = IngestSessionsTool()
    # list_only: header NAMES only, values never echoed
    listing = tool.run(ctx, list_only=True)
    assert "sekrit" not in listing and "Cookie" in listing
    out = tool.run(ctx)
    data = json.loads(out)
    assert data["registered"][0]["label"] == "ext:lab"
    assert data["registered"][0]["headers"]["Cookie"] == "<24 chars>"
    assert "sekrit-cookie-value" not in out and "sekrit-token" not in out
    sess = sessions.get("ext:lab")
    assert sess and sess.headers["Cookie"] == "sess=sekrit-cookie-value"
    # foothold recorded honestly + audit names only
    audit_text = (tmp_path / "audit.log.jsonl").read_text()
    assert "set_session.ok" in audit_text and "extension_ingest" in audit_text
    assert "sekrit-cookie-value" not in audit_text
    # consumed: second call sees nothing pending
    again = json.loads(tool.run(ctx))
    assert again["registered"] == [] and again["pending"] == []

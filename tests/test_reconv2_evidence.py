"""RECON V2 capability tests — the evidence plane (directive §8 behaviors):

  - passive observations retain source provenance;
  - active discoveries are corroborated (two INDEPENDENT tools);
  - third-party assets are recorded but NEVER auto-included in scope;
  - dedupe merges observations instead of growing duplicates;
  - PD-style adapters are authorization-gated, scope-enforced and bounded;
  - the agent workspace searches observations AND the wire history, with
    annotations;
  - replay_request re-issues a recorded request through the shared controls.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from redteam.config import Engagement
from redteam.knowledge import KnowledgeGraph
from redteam.recon.passive import run_passive_recon
from redteam.recon_v2 import build_recon_v2
from redteam.recon_v2.capabilities import validate_and_attribute
from redteam.scope import ScopeGuard


def _engagement(**overrides) -> Engagement:
    base = dict(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("example.com",),
        excluded_hosts=(),
        allowed_ports=(443,),
        allowed_schemes=("http", "https"),
        max_requests_per_second=100.0,
        max_total_requests=1000,
        allow_private_ranges=False,
        require_approval_for=(),
        raw={},
    )
    base.update(overrides)
    return Engagement(**base)


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, *a, **k):
        self.events.append({"event": a[0] if a else "", **k})


def _bundle(tmp_path, eng=None):
    eng = eng or _engagement()
    from redteam.ratelimit import RateLimiter
    limiter = RateLimiter(1000.0, max_total=1000)
    scope = ScopeGuard(eng)

    class _Audit:
        def __init__(self):
            self.events = []

        def record(self, *a, **k):
            self.events.append({"event": a[0] if a else "", **k})

    return build_recon_v2(tmp_path, scope=scope, limiter=limiter, audit=_Audit()), \
        scope, limiter


# -- behavior 5: passive observations retain source provenance -----------------

def test_passive_observations_retain_source_provenance(tmp_path):
    eng = _engagement()
    bundle, scope, limiter = _bundle(tmp_path, eng)
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
               side_effect=lambda url, **k: _Resp(200, "User-agent: *\n"
                                                  "Disallow: /admin\n")):
        run_passive_recon(eng, graph, store=bundle.store, limiter=limiter,
                          traffic=None)
    obs = bundle.store.query(kind="endpoint")
    assert obs, "passive recon must emit observations"
    for o in obs:
        assert o.provenance == "passive"
        assert o.tool == "passive_recon"
        assert o.evidence_refs, "every observation carries evidence refs"
        assert o.scope_status == "in_scope"   # example.com is the signed host


# -- behavior 6: active discoveries are corroborated ---------------------------

def test_active_discoveries_corroborated(tmp_path):
    bundle, scope, limiter = _bundle(tmp_path)
    # TWO independent producers see the same subject.
    bundle.store.observe("service", "https://example.com:443/api", tool="http_probe",
                         provenance="active", attrs={"status": 200})
    obs2 = bundle.store.observe("service", "https://example.com:443/api",
                                tool="host_probe", provenance="active",
                                attrs={"tech": "nginx"})
    stats = validate_and_attribute(bundle.store, bundle.assets, scope)
    assert stats["corroborated"] >= 1
    stored = bundle.store.get(obs2.id)
    assert stored.validation_status == "corroborated"
    assert stored.confidence == "corroborated"
    # A single-source observation stays unvalidated — absence of a second
    # source never upgrades anything.
    solo = bundle.store.observe("endpoint", "https://example.com/solo",
                                tool="only_tool", provenance="active")
    validate_and_attribute(bundle.store, bundle.assets, scope)
    assert bundle.store.get(solo.id).validation_status == "unvalidated"


# -- directive §4: third-party assets are NEVER auto-in-scope ------------------

def test_third_party_assets_not_auto_in_scope(tmp_path):
    eng = _engagement()   # signed scope: example.com only
    bundle, scope, limiter = _bundle(tmp_path, eng)
    in_scope = bundle.store.observe("domain", "example.com", tool="t",
                                    provenance="passive")
    third_party = bundle.store.observe("subdomain", "cdn.thirdparty.net",
                                       tool="external_asset_intel",
                                       provenance="passive",
                                       attrs={"parent": "example.com"})
    assert bundle.store.get(in_scope.id).scope_status == "in_scope"
    assert bundle.store.get(third_party.id).scope_status == "out_of_scope"
    # attribution never widens scope on re-runs either
    validate_and_attribute(bundle.store, bundle.assets, scope)
    assert bundle.store.get(third_party.id).scope_status == "out_of_scope"
    # and the in-scope-only handoff never contains the third-party host
    handoff = bundle.store.handoff_summary()
    assert all(a["subject"] != "cdn.thirdparty.net" for a in handoff["domains"])


# -- dedupe semantics -----------------------------------------------------------

def test_dedupe_merges_observations(tmp_path):
    bundle, scope, limiter = _bundle(tmp_path)
    first = bundle.store.observe("endpoint", "https://example.com/a", tool="crawl",
                                 provenance="active", attrs={"p": 1})
    again = bundle.store.observe("endpoint", "https://example.com/a", tool="crawl",
                                 provenance="active", attrs={"p": 1},
                                 evidence=[{"kind": "traffic", "ref": "r1"}])
    assert first.id == again.id
    stored = bundle.store.get(first.id)
    assert len(stored.evidence_refs) >= 1   # refs merged, id stable
    assert bundle.store.dedupe_report()["stored"] == 1


# -- adapters: authorization fail-closed, passive external intel, bounded --------

class _FakeExec:
    """A stand-in for the sandbox exec that returns canned JSONL."""

    def __init__(self, lines):
        self._lines = lines
        self.calls = []

    def __call__(self, argv, timeout=None):
        self.calls.append(argv)
        return "\n".join(self._lines)


def test_adapter_requires_authorization_fail_closed(tmp_path, monkeypatch):
    bundle, scope, limiter = _bundle(tmp_path)
    fake = _FakeExec(['{"host": "api.example.com", "source": "vt"}'])
    from redteam.recon_v2.adapters import ProjectDiscoveryAdapter
    adapter = ProjectDiscoveryAdapter(bundle.store, scope, limiter, _Audit(),
                                      sandbox_exec=fake)
    result = adapter.run("subfinder", ["-d", "example.com"], target="example.com",
                         authorized=False)
    assert result["recorded"] == 0
    assert result["authorized"] is False
    assert not bundle.store.query(kind="subdomain")


def test_adapter_scope_enforced_and_bounded(tmp_path, monkeypatch):
    # Wildcard scope: subdomains of example.com are signed; evil.net is not.
    eng = _engagement(allowed_hosts=("example.com", "*.example.com"))
    bundle, scope, limiter = _bundle(tmp_path, eng)
    audit = _Audit()
    from redteam.recon_v2.adapters import ProjectDiscoveryAdapter
    lines = [json.dumps({"host": h, "source": "ct"}) for h in (
        "api.example.com",          # in scope
        "evil.net",                 # OUT of scope — must never be recorded
        "cdn.example.net",          # also out (different registrable domain)
    )] * 3
    fake = _FakeExec(lines)
    adapter = ProjectDiscoveryAdapter(bundle.store, scope, limiter, audit,
                                      sandbox_exec=fake, max_items=5)
    result = adapter.run("subfinder", ["-d", "example.com"], target="example.com",
                         authorized=True)
    subjects = {o.subject for o in bundle.store.query(kind="subdomain")}
    assert "api.example.com" in subjects
    assert "evil.net" in subjects and "cdn.example.net" in subjects
    external = [o for o in bundle.store.query(kind="subdomain")
                if o.subject in {"evil.net", "cdn.example.net"}]
    assert len(external) == 2
    assert all(o.scope_status == "out_of_scope" for o in external)
    assert result["skipped_out_of_scope"] == 0
    assert result["lines"] <= 5           # bounded
    assert sum(e["event"] == "reconv2.adapter.external_observation"
               for e in audit.events) >= 2


def test_adapter_missing_binary_is_an_honest_skip(tmp_path, monkeypatch):
    bundle, scope, limiter = _bundle(tmp_path)
    audit = _Audit()
    import redteam.recon_v2.adapters as adapters_mod
    from redteam.recon_v2.adapters import ProjectDiscoveryAdapter
    adapter = ProjectDiscoveryAdapter(bundle.store, scope, limiter, audit,
                                      sandbox_exec=None)
    monkeypatch.setattr(adapters_mod.shutil, "which", lambda name: None)
    # a KNOWN adapter whose binary is absent -> honest skip, never a fake result
    result = adapter.run("subfinder", ["-d", "example.com"], target="example.com",
                         authorized=True)
    assert result.get("available") is False and result["recorded"] == 0
    assert any(e["event"] == "reconv2.adapter.missing" for e in audit.events)


# -- workspace: search, wire history, annotations, replay -----------------------

class _ReplayHandler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _ReplayHandler.hits.append(self.path)
        body = b'{"ok": true, "path": "%s"}' % self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def replay_target():
    _ReplayHandler.hits = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ReplayHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_workspace_traffic_query_and_annotations(tmp_path, replay_target):
    from redteam.ratelimit import RateLimiter
    eng = _engagement(allowed_hosts=("127.0.0.1",),
                      allowed_ports=(int(replay_target.rsplit(":", 1)[1]),),
                      allow_private_ranges=True)
    bundle, scope, limiter = _bundle(tmp_path, eng)
    rec_path = tmp_path / "traffic.jsonl"
    from redteam.traffic import TrafficRecorder
    rec = TrafficRecorder(rec_path)
    rec.record_http(method="GET", url=f"{replay_target}/api/orders", status=200,
                    elapsed_ms=5, tool="http_probe", source="",
                    resp_body='{"orders": 1}')
    rec.record_http(method="GET", url=f"{replay_target}/admin", status=403,
                    elapsed_ms=2, tool="http_probe", source="", error="")
    from redteam.recon_v2.workspace import EvidenceWorkspace
    ws = EvidenceWorkspace(bundle.store, traffic_path=rec_path,
                           annotations_path=tmp_path / "annotations.jsonl")
    rows = ws.traffic_query(host=replay_target, status=200)
    assert len(rows) == 1 and rows[0]["seq"] == 1
    assert ws.annotate("traffic:1", "orders endpoint confirmed live") is True
    rows = ws.traffic_query(host=replay_target, status=200)
    assert rows[0]["note"] == "orders endpoint confirmed live"
    assert ws.traffic_query(host=replay_target, status=403)[0]["seq"] == 2


def test_replay_request_reissues_through_shared_controls(tmp_path, replay_target):
    from redteam.ratelimit import RateLimiter
    from redteam.traffic import TrafficRecorder
    from test_artex_features import _ctx
    eng = _engagement(allowed_hosts=("127.0.0.1",),
                      allowed_ports=(int(replay_target.rsplit(":", 1)[1]),),
                      allow_private_ranges=True)
    rec = TrafficRecorder(tmp_path / "traffic.jsonl")
    rec.record_http(method="GET", url=f"{replay_target}/api/orders/42", status=200,
                    elapsed_ms=3, tool="http_probe", source="")
    limiter = RateLimiter(1000.0, max_total=100)
    ctx = _ctx(tmp_path, eng=eng, limiter=limiter)
    ctx.traffic = rec
    ctx.approve = lambda a, d: True
    bundle = build_recon_v2(tmp_path, scope=ctx.scope, limiter=limiter,
                            audit=ctx.audit, traffic=rec)
    ctx.workspace = bundle.workspace
    ctx.evidence_store = bundle.store

    from redteam.tools.recon_workspace import ReplayRequestTool
    result = json.loads(ReplayRequestTool().run(ctx, seq=1))
    assert result["status"] == 200
    assert _ReplayHandler.hits == ["/api/orders/42"]
    # the fresh exchange is evidence too (source=replay)
    rows = [json.loads(l) for l in (tmp_path / "traffic.jsonl").read_text().splitlines() if l.strip()]
    assert any(r.get("tool") == "replay" for r in rows)
    # and the shared budget paid for it
    assert limiter.used >= 1


def test_replay_denied_by_approval_gate(tmp_path, replay_target):
    from redteam.ratelimit import RateLimiter
    from redteam.traffic import TrafficRecorder
    from test_artex_features import _ctx
    eng = _engagement(allowed_hosts=("127.0.0.1",),
                      allowed_ports=(int(replay_target.rsplit(":", 1)[1]),),
                      allow_private_ranges=True)
    rec = TrafficRecorder(tmp_path / "traffic.jsonl")
    rec.record_http(method="GET", url=f"{replay_target}/admin", status=200,
                    elapsed_ms=3, tool="http_probe", source="")
    ctx = _ctx(tmp_path, eng=eng)
    ctx.traffic = rec
    ctx.approve = lambda a, d: False   # FAIL CLOSED
    bundle = build_recon_v2(tmp_path, scope=ctx.scope, limiter=ctx.limiter,
                            audit=ctx.audit, traffic=rec)
    ctx.workspace = bundle.workspace
    from redteam.tools.recon_workspace import ReplayRequestTool
    result = json.loads(ReplayRequestTool().run(ctx, seq=1))
    assert "denied" in result.get("error", "")
    assert _ReplayHandler.hits == []   # nothing went over the wire


# -- handoff: structured discoveries (behavior 10, unit level) ------------------

def test_handoff_contains_structured_discoveries(tmp_path):
    eng = _engagement()
    bundle, scope, limiter = _bundle(tmp_path, eng)
    graph = KnowledgeGraph()
    openapi = json.dumps({"openapi": "3.0.0", "info": {"title": "Orders API"},
                          "paths": {"/api/orders": {"get": {}},
                                    "/api/orders/{id}": {"get": {}}}})
    responses = {"https://example.com/openapi.json": _Resp(200, openapi)}
    with patch("redteam.recon.passive.requests.get",
               side_effect=lambda url, **k: responses.get(url, _Resp(404, ""))):
        run_passive_recon(eng, graph, store=bundle.store, limiter=limiter)
    handoff = bundle.store.handoff_summary()
    assert handoff["stats"]["observations"] > 0
    subjects = {o["subject"] for o in handoff["endpoints"]}
    assert "https://example.com/api/orders" in subjects
    assert handoff["stats"]["by_provenance"].get("passive", 0) > 0

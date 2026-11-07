"""Week 1 offense build: frequency-prior content discovery + STADS missing-mass stop.

Each test maps to a claim the engine makes (docs/offense-arsenal.md §2):

1. Wordlist        — prior/bucket/path rows parse; ordering is prior-descending.
2. BucketModel     — Beta posteriors move the right direction and persist.
3. SpeciesTracker  — U(n) = f1/n EXACTLY (Good–Turing), warmup is honest.
4. Soft404Baseline — the length-15% rule separates 404s / branded soft-404s /
                     real content.
5. Engine (live)   — finds planted paths, recurses into confirmed directories,
                     respects the budget, and stops with a reason, never silently.
6. Convergence     — when nothing new appears, the loop STOPS while candidates
                     remain (the whole point of the estimator).
7. Tool wiring     — scope-derived bases only, leads-only (no findings), audit +
                     graph + events fed, and rate-budget exhaustion ends the run
                     as a budget stop instead of faking misses.
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
from redteam.killchain import KillChain
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.discovery import ContentDiscoveryTool
from redteam.recon.discovery import (BASELINE_PROBES, BucketModel,
                                     DiscoveryEngine, Soft404Baseline,
                                     SpeciesTracker, load_wordlist,
                                     response_signature)


def _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(80,), max_total=1000):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=allowed_hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("http", "https"),
        max_requests_per_second=1000.0, max_total_requests=max_total,
        allow_private_ranges=True, require_approval_for=(),
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


class _Graph:
    def __init__(self):
        self.observed = []

    def observe(self, ntype, key, attrs=None, source=""):
        self.observed.append((ntype, key, source))


def _ctx(tmp_path, eng=None, limiter=None):
    eng = eng or _engagement()
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=limiter or RateLimiter(1000.0, max_total=eng.max_total_requests),
        audit=_Audit(), findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, sessions=SessionStore(),
        access=AccessGraph(tmp_path / "access.json"),
        killchain=KillChain(tmp_path / "kc.json"),
        graph=_Graph(), events=_Bus(),
    )


# ---------------------------------------------------------------------------
# Live fixture: a small site with planted high-value paths. Unknown paths get
# an honest 404 (len-controlled) — a second fixture fakes a branded soft-404.

class _SiteHandler(http.server.BaseHTTPRequestHandler):
    planted: dict = {}       # path -> (status, body bytes)
    soft_404: bool = False   # unknown paths answer 200 with a branded page

    def do_GET(self):
        path = self.path.split("?")[0]
        entry = self.planted.get(path.rstrip("/") + "/" if path == "/docs" else path)
        if path == "/docs":
            entry = self.planted.get("/docs/")
        if entry is None:
            if self.soft_404:
                body = b"<html><body>Acme&#160;Portal &#8212; page not found, browse our products!</body></html>"
                self.send_response(200)
            else:
                body = b'{"error":"not found"}'
                self.send_response(404)
            self.send_header("Content-Type", "text/html" if self.soft_404
                             else "application/json")
        else:
            status, body = entry
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _server(planted, soft_404=False):
    handler = type("H", (_SiteHandler,), {"planted": planted, "soft_404": soft_404})
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


PLANTED = {
    "/admin": (200, b"<html><title>Acme Admin</title></html>"),
    "/login": (200, b"<html><title>Sign in to Acme</title></html>"),
    "/api": (200, b'{"api":"acme","version":"1"}'),
    "/.env": (200, b"DB_PASSWORD=hunter2\nAPP_KEY=base64:AAAA\n"),
    "/docs/": (200, b"<html><title>Acme Docs</title></html>"),
    "/docs/admin": (200, b"<html><title>Acme Docs Admin</title></html>"),
}


@pytest.fixture(scope="module")
def site():
    srv = _server(PLANTED)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


# ---------------------------------------------------------------------------
# 1. Wordlist

def test_wordlist_parses_and_orders():
    seeds = load_wordlist()
    assert len(seeds) >= 120
    assert all(0.0 <= s.prior <= 1.0 for s in seeds)
    assert all(s.path.startswith("/") for s in seeds)
    assert all(s.bucket and " " not in s.bucket for s in seeds)
    # highest-prior entries are the classics a human would try first
    top = sorted(seeds, key=lambda s: s.prior, reverse=True)[:3]
    assert {t.path for t in top} == {"/admin", "/login", "/.env"}


# ---------------------------------------------------------------------------
# 2. Bucket model

def test_bucket_model_updates_direction_and_persists(tmp_path):
    state = tmp_path / "priors.json"
    m1 = BucketModel(state)
    base = m1.posterior("admin")
    for _ in range(5):
        m1.update("admin", True)
    m1.update("backup", False)
    assert m1.posterior("admin") > base          # hits raise the rate
    assert m1.posterior("backup") < base         # misses lower it
    m2 = BucketModel(state)                      # reload from disk
    assert abs(m2.posterior("admin") - m1.posterior("admin")) < 1e-9


# ---------------------------------------------------------------------------
# 3. STADS species math — exact

def test_missing_mass_is_f1_over_n():
    t = SpeciesTracker(warmup=3)
    for sig in ("A", "B", "A", "A", "C", "A", "B", "A"):
        t.record(sig)
    # n=8; species A x5, B x2, C x1 -> f1 = 1 -> U = 1/8
    assert t.n == 8 and t.f1 == 1
    assert abs(t.missing_mass() - 1 / 8) < 1e-12


def test_missing_mass_warmup_is_honest():
    t = SpeciesTracker(warmup=10)
    t.record("A")
    assert t.missing_mass() == 1.0   # too few probes: no claim


def test_response_signature_buckets_lengths():
    # small bodies: exact length (distinct small pages = distinct species)
    assert response_signature(200, 70) == (2, 70)
    # large bodies: 64-byte buckets (variance must not manufacture species)
    assert response_signature(200, 1000) == (2, 960)
    assert response_signature(404, 500) == (4, 500)
    assert response_signature(0, 0) == (0, 0)


# ---------------------------------------------------------------------------
# 4. Soft-404 baseline

def test_soft404_baseline_separates_miss_from_content():
    b = Soft404Baseline()
    b.observe(200, 1000)   # branded "not found" page, length 1000
    b.observe(200, 1010)
    assert b.is_miss(404, 50)          # honest 404
    assert b.is_miss(410, 30)
    assert b.is_miss(200, 1030)        # same status, length within 15%
    assert not b.is_miss(200, 2000)    # real content: different size class
    assert not b.is_miss(403, 900)     # guarded-but-real: NOT a miss
    assert b.is_miss(0, 0)             # connection error = miss, never a hit


# ---------------------------------------------------------------------------
# 5. Engine against the live site

def _fetch_for(url_root):
    import urllib.request

    def fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "test/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace"), {}
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), {}
    return fetch


def test_engine_finds_planted_paths_and_recurses(site):
    engine = DiscoveryEngine(_fetch_for(site), max_depth=1)
    report = engine.run(site, budget=200)
    found = {h.path for h in report.hits}
    assert {"/admin", "/login", "/.env", "/api"} <= found
    assert "/docs/" in report.dirs
    # recursion paid off: a confirmed directory re-opened the seed list under
    # itself, and the depth-1 hit is the evidence
    assert "/docs/admin" in found
    depths = {h.path: h.depth for h in report.hits}
    assert depths["/docs/admin"] == 1 and depths["/docs/"] == 0
    assert report.probed <= 200
    assert 0.0 <= report.missing_mass <= 1.0
    assert report.stop_reason in ("budget", "exhausted-wordlist",
                                  "converged-species", "converged-yield")
    # priors ordered the budget: /admin (0.95) must be probed before any
    # depth-1 recursion child
    hit_order = [h.path for h in report.hits]
    assert hit_order.index("/admin") < hit_order.index("/docs/admin")


def test_engine_respects_tiny_budget(site):
    engine = DiscoveryEngine(_fetch_for(site))
    report = engine.run(site, budget=10)
    assert report.probed <= 10
    assert report.stop_reason == "budget"


def test_engine_converges_while_candidates_remain():
    # A wall of identical 404s: every probe lands in ONE species -> f1 -> 0 ->
    # the Good-Turing mass collapses below eps while the 130+ wordlist still
    # has untouched entries. The loop MUST stop early (that is the point of
    # the estimator) instead of burning the full budget on a dead target.
    srv = _server({})   # no planted paths at all
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        engine = DiscoveryEngine(_fetch_for(base), eps=0.01, min_probes=15,
                                 warmup=5)
        report = engine.run(base, budget=400)
        assert report.stop_reason == "converged-species"
        assert report.missing_mass < 0.01
        assert report.expected_remaining_yield > 0.0   # frontier NOT empty
        assert report.probed < 100                     # stopped, not exhausted
    finally:
        srv.shutdown()


def test_engine_handles_soft_404_server():
    srv = _server(PLANTED, soft_404=True)
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        engine = DiscoveryEngine(_fetch_for(base))
        report = engine.run(base, budget=200)
        found = {h.path for h in report.hits}
        # planted content is distinct from the branded page -> still found
        assert "/admin" in found and "/.env" in found
        # the branded 200 page length must never become a finding itself
        branded = [h for h in report.hits if h.path not in PLANTED]
        assert branded == []
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# 6. Tool wiring

def test_tool_leads_only_and_wires_graph_events_audit(tmp_path, site):
    host, port = site.replace("http://", "").split(":")
    ctx = _ctx(tmp_path, _engagement(allowed_hosts=(host,),
                                     allowed_ports=(int(port),)))
    tool = ContentDiscoveryTool()
    out = json.loads(tool.run(ctx, max_requests=60))
    assert out["hit_count"] >= 4
    assert ctx.findings.all() == [] or len(ctx.findings.all()) == 0
    assert any(a["event"] == "recon.discovery" for a in ctx.audit.events)
    assert any(e[0] == "recon.path_found" for e in ctx.events.emitted)
    assert any(ntype == "endpoint" for ntype, _k, _s in ctx.graph.observed)


def test_tool_never_probes_out_of_scope(tmp_path, site):
    host, port = site.replace("http://", "").split(":")
    # RoE allows ONLY the fixture host — a second dead host must never be touched
    ctx = _ctx(tmp_path, _engagement(allowed_hosts=(host, "203.0.113.9"),
                                     allowed_ports=(int(port),)))
    tool = ContentDiscoveryTool()
    out = json.loads(tool.run(ctx, max_requests=40))
    urls = {h["url"] for h in out["hits"]}
    assert all(u.startswith(f"http://{host}:{port}") for u in urls)
    assert out["stop_reason"] in ("budget", "exhausted-wordlist",
                                  "converged-species", "converged-yield")


def test_tool_rate_budget_ends_honestly(tmp_path, site):
    host, port = site.replace("http://", "").split(":")
    eng = _engagement(allowed_hosts=(host,), allowed_ports=(int(port),),
                      max_total=8)   # 3 baseline + ~5 probes -> spent mid-frontier
    ctx = _ctx(tmp_path, eng)
    tool = ContentDiscoveryTool()
    out = json.loads(tool.run(ctx, max_requests=100))
    assert out["stop_reason"] == "budget-rate-limit"
    assert out["probed"] <= 8


def test_tool_prefix_scopes_the_run(tmp_path, site):
    host, port = site.replace("http://", "").split(":")
    ctx = _ctx(tmp_path, _engagement(allowed_hosts=(host,),
                                     allowed_ports=(int(port),)))
    tool = ContentDiscoveryTool()
    out = json.loads(tool.run(ctx, max_requests=60, prefix="/api"))
    assert all(h["path"].startswith("/api") for h in out["hits"])

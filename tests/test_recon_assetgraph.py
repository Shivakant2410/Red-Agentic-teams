"""Week 1 asset graph: the competitive-intel radar (docs/offense-arsenal.md §2.3).

Each test maps to one claim the radar makes:

1.  Codename extraction — distinctive labels only: env markers, infra words,
    TLDs and digits NEVER become "projects".
2.  host_env — environment side of a host (staging vs prod).
3.  CT parsing + freshness — crt.sh JSON shape parsed by us; ONLY recent
    issuance survives the window (temporal diff, not a subdomain dump).
4.  Permutation — codename-seeded fanout, bounded and deterministic.
5.  JS mining — flag SDKs, beta_*/experiment_* codenames, /api/vN references,
    env-marked internal hosts, same-org script URLs (third parties filtered).
6.  Version-ahead-of-live — referenced version > max live version = roadmap,
    for both /api/vN and bare /vN families.
7.  Staging mirrors — same codename on a prod and an env-marked host.
8.  AssetGraph store — merge/sources bookkeeping (triangulation input),
    dangling-edge refusal, dedup, persistence round-trip.
9.  secret_builds — verdict by INDEPENDENT source count (3 strong / 2 likely /
    1 watchlist), ranked.
10. Orchestrator end-to-end — one pass over CT + JS + DNS + version edges +
    mirrors produces the ranked report, feeds the knowledge graph and audit,
    and CT failure degrades gracefully instead of killing the pass.
11. Tool wiring — scope-derived org domain only, wildcard-only scope refuses,
    injected CT/DNS/fetch (zero real network), leads-only (findings untouched).
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from redteam.access import AccessGraph
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.inventory import AssetInventory
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.killchain import KillChain
from redteam.ratelimit import RateLimiter
from redteam.recon.assetgraph import (ANNOUNCES, CODENAME, HOST, MIRRORS,
                                      PRECEDES, PROJECTS, REFERENCES,
                                      AssetGraph, codename_labels, ct_entries,
                                      fresh_ct_names, host_env,
                                      infer_version_edges, infer_mirror_edges,
                                      mine_js, permute_hostnames,
                                      run_asset_radar, secret_builds,
                                      version_families)
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools import asset_radar as radar_module
from redteam.tools.asset_radar import AssetRadarTool

NOW = _dt.datetime(2026, 11, 10, 12, 0, 0, tzinfo=_dt.timezone.utc)
REAL_NOW = _dt.datetime.now(_dt.timezone.utc)   # orchestrator tests: window must hold whenever they run


def _engagement(allowed_hosts=("apollo.acme.test",), allowed_ports=(443,)):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=allowed_hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("https",),
        max_requests_per_second=1000.0, max_total_requests=100,
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


def _ct_json(now: _dt.datetime = REAL_NOW) -> str:
    fresh = (now - _dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
    old = (now - _dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%S")
    return json.dumps([
        {"name_value": "apollo-api.stg.acme.test\napollo.acme.test",
         "not_before": fresh, "issuer_name": "Let's Encrypt"},
        {"name_value": "www.acme.test", "not_before": old,
         "issuer_name": "DigiCert"},
    ])


HTML_BODY = """
<html><head><script src="/static/app.js"></script>
<script src="https://cdn.acme.test/bundle.js"></script>
<script src="https://analytics.google.com/x.js"></script></head>
<body>internal tools: internal.acme.test</body></html>
"""

JS_BODY = """
// statsig client init
const flags = { "beta_apollo": true, "experiment_velvet_ui": false };
fetch('/api/v3/users');
"""


# ---------------------------------------------------------------------------
# 1-2. Label vocabulary

def test_codename_extraction_drops_generic_parts():
    assert codename_labels("apollo-api.stg.acme.test", "acme.test") == ["apollo"]
    assert codename_labels("www.acme.test", "acme.test") == []
    assert codename_labels("cdn-2.acme.test", "acme.test") == []
    assert codename_labels("stg.krypton.acme.test", "acme.test") == ["krypton"]


def test_codename_extraction_never_yields_tld():
    labels = codename_labels("apollo.acme.com")       # no base domain given
    assert "apollo" in labels
    assert "com" not in labels                         # public suffix, not a project


def test_host_env_sides():
    assert host_env("apollo-stg.acme.test") == "stg"
    assert host_env("stg-apollo.acme.test") == "stg"
    assert host_env("apollo.acme.test") is None


# ---------------------------------------------------------------------------
# 3. CT freshness

def test_ct_parsing_and_fresh_window():
    entries = ct_entries(_ct_json(NOW))
    assert len(entries) == 2
    assert entries[0]["names"] == ["apollo-api.stg.acme.test", "apollo.acme.test"]
    fresh = fresh_ct_names(entries, NOW, window_days=45)
    assert set(fresh) == {"apollo-api.stg.acme.test", "apollo.acme.test"}
    assert fresh_ct_names(entries, NOW, window_days=1) == {}   # temporal diff: only NOW matters


def test_ct_tolerates_junk():
    assert ct_entries("not json at all") == []
    assert ct_entries(json.dumps([{"name_value": "x.y.z", "not_before": "garbage"},
                                  {"nope": 1}, 42])) != []   # junk rows skipped, names kept


# ---------------------------------------------------------------------------
# 4. Permutation

def test_permutation_bounded_and_deterministic():
    a, b = permute_hostnames("apollo"), permute_hostnames("apollo")
    assert a == b and len(a) <= 48
    assert "apollo-stg" in a and "stg.apollo" in a
    assert permute_hostnames("apollo", cap=5) == a[:5]
    assert permute_hostnames("") == []


# ---------------------------------------------------------------------------
# 5. JS mining

def test_mine_js_signals():
    mined = mine_js(HTML_BODY + JS_BODY, "acme.test")
    assert mined["providers"] == ["statsig"]
    assert "apollo" in mined["flag_codenames"]
    assert "velvet" in mined["flag_codenames"]
    assert mined["api_versions"] == [3]
    assert "internal.acme.test" in mined["internal_hosts"]
    assert "/static/app.js" in mined["script_urls"]
    assert "https://cdn.acme.test/bundle.js" in mined["script_urls"]
    assert not any("analytics.google.com" in u for u in mined["script_urls"])


def test_mine_js_third_party_hosts_filtered():
    mined = mine_js('x = "db.staging.google.com"; y = "internal.acme.test"',
                    "acme.test")
    assert "db.staging.google.com" not in mined["internal_hosts"]
    assert "internal.acme.test" in mined["internal_hosts"]


# ---------------------------------------------------------------------------
# 6-7. Version edges + mirrors

def test_version_edges_api_and_bare_families():
    live = ["/api/v1/users", "/v2/thing"]
    ref = ["/api/v1/", "/api/v3/", "/v2/", "/v4/"]
    edges = {e["family"]: e for e in infer_version_edges(live, ref)}
    assert edges["/api"]["live_max"] == 1 and edges["/api"]["unreleased"] == 3
    assert edges["/api"]["edge"] == ("endpoint:/api/v1", "endpoint:/api/v3")
    assert edges[""]["live_max"] == 2 and edges[""]["unreleased"] == 4


def test_version_edges_no_roadmap_when_referenced_is_live():
    assert infer_version_edges(["/api/v1/x"], ["/api/v1/"]) == []


def test_version_families_shapes():
    assert version_families(["https://h.acme.test/api/v1/users"]) == {"/api": {1}}
    assert version_families(["/v3/thing"]) == {"": {3}}


def test_mirror_edges_same_codename():
    hosts = ["apollo-stg.acme.test", "apollo.acme.test",
             "krypton-dev.acme.test", "krypton.acme.test", "www.acme.test"]
    pairs = infer_mirror_edges(hosts, "acme.test")
    assert ("apollo-stg.acme.test", "apollo.acme.test") in pairs
    assert ("krypton-dev.acme.test", "krypton.acme.test") in pairs
    assert len(pairs) == 2


# ---------------------------------------------------------------------------
# 8. Store

def test_assetgraph_merge_sources_and_persistence(tmp_path):
    path = tmp_path / "ag.json"
    g = AssetGraph(path)
    g.add_node(CODENAME, "apollo", attrs={"found_in": "a"}, source="ct")
    g.add_node(CODENAME, "apollo", attrs={"found_in": "b"}, source="dns")
    node = g.nodes(CODENAME)[0]
    assert node.sources == ["ct", "dns"]                    # triangulation bookkeeping
    assert node.attrs["found_in"] == "b"                    # attrs merge, last wins

    assert g.add_edge("codename:apollo", PROJECTS, "host:ghost") is False  # dangling
    g.add_node(HOST, "apollo-stg.acme.test")
    assert g.add_edge("codename:apollo", PROJECTS, "host:apollo-stg.acme.test")
    assert g.add_edge("codename:apollo", PROJECTS, "host:apollo-stg.acme.test")
    assert len(g.edges(PROJECTS)) == 1                      # deduped

    g2 = AssetGraph(path)                                   # persistence round-trip
    assert g2.nodes(CODENAME)[0].sources == ["ct", "dns"]
    assert len(g2.edges(PROJECTS)) == 1


# ---------------------------------------------------------------------------
# 9. Triangulation report

def test_secret_builds_verdicts_and_ranking():
    g = AssetGraph()
    for cn, sources in (("apollo", ("ct", "dns", "js")),
                        ("krypton", ("ct", "js")),
                        ("velvet", ("js",))):
        for s in sources:
            g.add_node(CODENAME, cn, source=s)
    builds = secret_builds(g)
    assert [b["codename"] for b in builds] == ["apollo", "krypton", "velvet"]
    assert builds[0]["verdict"] == "in-development (strong)"
    assert builds[1]["verdict"] == "in-development (likely)"
    assert builds[2]["verdict"] == "watchlist"


# ---------------------------------------------------------------------------
# 10. Orchestrator end-to-end (all I/O injected; zero network)

def test_run_asset_radar_end_to_end(tmp_path):
    eng = _engagement()
    kg = KnowledgeGraph()
    kg.observe(ENDPOINT, "https://apollo.acme.test/api/v1/users", source="test")
    inv = AssetInventory(tmp_path / "inventory.json")
    inv.observe_asset("apollo.acme.test", 443, "https")
    agraph = AssetGraph(tmp_path / "asset_graph.json")
    audit = _Audit()

    ct_domains = []

    def ct_fetch(domain):
        ct_domains.append(domain)
        return _ct_json()

    def resolve(hostname):
        return "203.0.113.9" if hostname.startswith("apollo-") else None

    report = run_asset_radar(
        eng, agraph, graph=kg, inventory=inv, audit=audit,
        base_domain="acme.test", ct_fetch=ct_fetch, resolve=resolve,
        js_bodies={"https://apollo.acme.test/": HTML_BODY,
                   "https://apollo.acme.test/static/app.js": JS_BODY},
    )
    # the orchestrator used the real clock; verify the fixture cert is inside
    # its window by construction (10 days old, window 45):
    fresh = fresh_ct_names(ct_entries(_ct_json()), _dt.datetime.now(_dt.timezone.utc),
                           window_days=45)
    assert "apollo.acme.test" in fresh and "apollo-api.stg.acme.test" in fresh

    assert ct_domains == ["acme.test"]
    builds = {b["codename"]: b for b in report["builds"]}
    assert "apollo" in builds
    apollo = builds["apollo"]
    assert {"ct", "js", "dns"} <= set(apollo["sources"])
    assert apollo["corroboration"] >= 3
    assert apollo["verdict"] == "in-development (strong)"

    assert report["ct_new_hosts"] == 1        # apollo-api.stg is new; apollo host was known
    assert {"family": "/api", "live_max": 1, "unreleased": 3} in report["unreleased_api"]
    assert report["mirrors"] >= 1             # apollo-stg (CT) mirrors apollo (inventory)
    assert report["dns_resolved"] >= 1

    # knowledge graph got the new host lead; audit got the pass record
    assert kg.nodes("host") and any(n.key == "apollo-api.stg.acme.test"
                                    for n in kg.nodes("host"))
    assert any(e["event"] == "recon.asset_radar" for e in audit.events)

    # typed edges on the radar graph
    assert any(e["rel"] == MIRRORS for e in agraph.edges())
    assert any(e["rel"] == PRECEDES for e in agraph.edges())
    assert any(e["rel"] == ANNOUNCES for e in agraph.edges())
    assert any(e["rel"] == PROJECTS for e in agraph.edges())
    assert any(e["rel"] == REFERENCES for e in agraph.edges())


def test_run_asset_radar_ct_failure_degrades(tmp_path):
    eng = _engagement()
    agraph = AssetGraph()
    audit = _Audit()

    def broken_ct(domain):
        raise RuntimeError("crt.sh rate-limited")

    report = run_asset_radar(eng, agraph, audit=audit, base_domain="acme.test",
                             ct_fetch=broken_ct, resolve=lambda h: None,
                             js_bodies={"https://apollo.acme.test/": JS_BODY})
    assert "ct_error" in report                      # CT optional, run survives
    builds = {b["codename"] for b in report["builds"]}
    assert "apollo" in builds                        # JS-sourced intel still landed


# ---------------------------------------------------------------------------
# 11. Tool wiring

def _ctx(tmp_path, eng):
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=RateLimiter(1000.0, max_total=eng.max_total_requests),
        audit=_Audit(), findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, sessions=SessionStore(),
        access=AccessGraph(tmp_path / "access.json"),
        killchain=KillChain(tmp_path / "kc.json"),
        graph=KnowledgeGraph(), events=_Bus(),
        inventory=AssetInventory(tmp_path / "inventory.json"),
    )


def test_radar_tool_refuses_wildcard_only_scope(tmp_path):
    ctx = _ctx(tmp_path, _engagement(allowed_hosts=("*.acme.test",)))
    out = AssetRadarTool().run(ctx)
    assert out.startswith("ERROR")
    assert "org domain" in out


def test_radar_tool_full_pass_no_network(tmp_path, monkeypatch):
    eng = _engagement()
    ctx = _ctx(tmp_path, eng)
    ctx.graph.observe(ENDPOINT, "https://apollo.acme.test/api/v1/users",
                      source="test")
    ctx.inventory.observe_asset("apollo.acme.test", 443, "https")

    def fake_fetch_once(c, req, tool="", session=""):
        url = req.get("url", "")
        if url == "https://apollo.acme.test/":
            return 200, HTML_BODY, 0, {}
        if url == "https://apollo.acme.test/static/app.js":
            return 200, JS_BODY, 0, {}
        return 0, "", 0, {}

    monkeypatch.setattr(radar_module, "fetch_once", fake_fetch_once)
    monkeypatch.setattr(radar_module, "crtsh_fetch", lambda d: _ct_json())
    monkeypatch.setattr(radar_module, "dns_resolve",
                        lambda h: "203.0.113.9" if h.startswith("apollo-") else None)

    out = json.loads(AssetRadarTool().run(ctx, window_days=45, max_dns=24,
                                          use_ct=True))
    assert out["base_domain"] == "acme.test"
    builds = out["secret_builds"]
    assert builds and builds[0]["codename"] == "apollo"
    assert builds[0]["corroboration"] >= 3
    assert "leads only" in out["note"]

    # leads-only: the finding store was never touched
    assert ctx.findings.all() == []
    # the knowledge graph got the codename as corroborated intel + new host lead
    techs = [n.key for n in ctx.graph.nodes("technology")]
    assert "codename:apollo" in techs
    assert any(n.key == "apollo-api.stg.acme.test" for n in ctx.graph.nodes("host"))
    # event bus saw the pass
    assert any(t == "recon.asset_radar" for t, _ in ctx.events.emitted)
    # radar graph persisted next to the inventory
    assert (tmp_path / "asset_graph.json").exists()

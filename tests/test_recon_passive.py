"""Tests for deterministic passive recon — robots.txt/sitemap.xml/API-schema fetches that
must seed the knowledge graph and attack tree WITHOUT any LLM call."""

from __future__ import annotations

import datetime as _dt
from unittest.mock import patch

from redteam.attack_tree import AttackTree
from redteam.config import Engagement
from redteam.knowledge import ENDPOINT, KnowledgeGraph, TECHNOLOGY
from redteam.planner import state_briefing
from redteam.recon.passive import run_passive_recon


def _engagement(**overrides) -> Engagement:
    base = dict(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("example.com",),
        excluded_hosts=(),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        max_requests_per_second=3.0,
        max_total_requests=100,
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


def _route(url_map: dict[str, _Resp]):
    def _get(url, timeout=None, allow_redirects=None, headers=None):
        for key, resp in url_map.items():
            if url == key:
                return resp
        return _Resp(status_code=404, text="")
    return _get


def test_robots_txt_paths_seed_endpoints():
    eng = _engagement()
    graph = KnowledgeGraph()
    robots_body = "User-agent: *\nDisallow: /admin\nAllow: /api/public\n"
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/robots.txt": _Resp(200, robots_body)})):
        summary = run_passive_recon(eng, graph)
    keys = {n.key for n in graph.nodes(ENDPOINT)}
    assert "https://example.com/admin" in keys
    assert "https://example.com/api/public" in keys
    assert summary["endpoints_discovered"] == 2


def test_sitemap_urls_seed_endpoints_same_host_only():
    eng = _engagement()
    graph = KnowledgeGraph()
    sitemap_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com/pricing</loc></url>"
        "<url><loc>https://evil.example/ignored</loc></url>"
        "</urlset>"
    )
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/sitemap.xml": _Resp(200, sitemap_body)})):
        run_passive_recon(eng, graph)
    keys = {n.key for n in graph.nodes(ENDPOINT)}
    assert "https://example.com/pricing" in keys
    assert "https://evil.example/ignored" not in keys


def test_api_schema_endpoints_seeded_and_attack_tree_gets_them():
    eng = _engagement()
    graph = KnowledgeGraph()
    tree = AttackTree()
    schema_body = (
        '{"openapi": "3.0.0", "info": {"title": "Demo API"}, '
        '"paths": {"/v1/users": {}, "/v1/users/{id}": {}}}'
    )
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json": _Resp(200, schema_body)})):
        summary = run_passive_recon(eng, graph, attack_tree=tree)
    keys = {n.key for n in graph.nodes(ENDPOINT)}
    assert "https://example.com/v1/users" in keys
    assert "https://example.com/v1/users/{id}" in keys
    assert summary["schemas_found"] == 1
    # attack tree actually got seeded for at least one of those endpoints
    actionable_targets = {n.target for n in tree.actionable(limit=50)}
    assert "https://example.com/v1/users" in actionable_targets


def test_wildcard_and_cidr_hosts_are_skipped_not_fetched():
    eng = _engagement(allowed_hosts=("*.example.com", "203.0.113.0/28"))
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get", side_effect=AssertionError(
            "should never be called for a wildcard/CIDR host")):
        summary = run_passive_recon(eng, graph)
    assert summary["endpoints_discovered"] == 0


def test_no_match_yields_empty_summary_no_crash():
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({})):   # everything 404s
        summary = run_passive_recon(eng, graph)
    assert summary == {"endpoints_discovered": 0, "schemas_found": 0, "doc_leads": 0}


# -- API-doc descriptions (the live-fire 2026-11-02 recon blindspot) --------------
# The ladder-3 fetcher fixture leaks its ops token in the /api/import operation
# DESCRIPTION of /openapi.json. Passive recon fetched the doc but stored only path
# URLs — the leak reached neither the graph nor any agent-visible briefing, so hop 1
# of the chain was unsolvable through the cheapest reading layer. These tests pin the
# fix: descriptions survive into the graph AND render in state_briefing.

_FETCHER_SCHEMA = (
    '{"openapi": "3.0.0", "info": {"title": "Fetcher Release Automation API", '
    '"version": "1.0.0"}, '
    '"paths": {'
        '"/api/import": {"post": {'
            '"summary": "Import release artifacts from a mirror URL", '
            '"description": "Server-side fetch of a URL. Auth: ops service account — '
            'header \'Authorization: Bearer tok-ops-551f\' (see runbook)."}}, '
        '"/debug/env": {"get": {"summary": "internal use only"}}'
    '}}'
)


def test_openapi_operation_descriptions_land_in_the_graph():
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json":
                                  _Resp(200, _FETCHER_SCHEMA)})):
        summary = run_passive_recon(eng, graph)
    assert summary["doc_leads"] == 2   # /api/import (description) + /debug/env (summary)
    node = next(n for n in graph.nodes(ENDPOINT) if n.key.endswith("/api/import"))
    assert "tok-ops-551f" in node.attrs["doc"]
    # a summary-only path also counts as documented
    plain = next(n for n in graph.nodes(ENDPOINT) if n.key.endswith("/debug/env"))
    assert plain.attrs["doc"] == "internal use only"
    tech = graph.nodes(TECHNOLOGY)[0]
    assert tech.attrs["title"] == "Fetcher Release Automation API"


def test_doc_leak_reaches_the_agent_briefing():
    """The actual live-fire failure: the token was ON THE WIRE but invisible to every
    layer the agent reads. Pass/fail line: state_briefing must quote the description."""
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json":
                                  _Resp(200, _FETCHER_SCHEMA)})):
        run_passive_recon(eng, graph)
    brief = state_briefing(graph)
    assert "tok-ops-551f" in brief
    assert "https://example.com/api/import" in brief
    assert "API DOC NOTES" in brief


def test_top_level_api_description_is_captured_too():
    schema = ('{"openapi": "3.0.0", "info": {"title": "Acme", '
              '"description": "Internal API — staging only, uses X-Debug-Key: kd-771"}, '
              '"paths": {"/v1/ping": {}}}')
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json": _Resp(200, schema)})):
        run_passive_recon(eng, graph)
    tech = graph.nodes(TECHNOLOGY)[0]
    assert "X-Debug-Key: kd-771" in tech.attrs["doc"]
    assert "kd-771" in state_briefing(graph)


def test_doc_cap_bounds_context_bloat():
    huge = 'x' * 60_000
    schema = ('{"openapi": "3.0.0", "info": {"title": "T"}, '
              f'"paths": {{"/blob": {{"get": {{"description": "{huge}"}}}}}}}}')
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json": _Resp(200, schema)})):
        run_passive_recon(eng, graph)
    node = next(n for n in graph.nodes(ENDPOINT) if n.key.endswith("/blob"))
    assert len(node.attrs["doc"]) <= 400          # recon-side cap
    brief = state_briefing(graph)
    doc_line = next(l for l in brief.splitlines() if "/blob" in l)
    assert len(doc_line) < 300                    # briefing-side cap keeps it compact


def test_no_docs_means_no_doc_section():
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/robots.txt":
                                  _Resp(200, "User-agent: *\nDisallow: /admin\n")})):
        run_passive_recon(eng, graph)
    assert "API DOC NOTES" not in state_briefing(graph)


def test_malformed_schema_fields_fail_soft():
    """path items that aren't dicts (a schema bug in the target) must not crash recon."""
    schema = ('{"openapi": "3.0.0", "info": {"title": "T"}, '
              '"paths": {"/weird": "not-a-dict", "/ok": {"get": {"summary": "fine"}}}}')
    eng = _engagement()
    graph = KnowledgeGraph()
    with patch("redteam.recon.passive.requests.get",
              side_effect=_route({"https://example.com/openapi.json": _Resp(200, schema)})):
        summary = run_passive_recon(eng, graph)
    assert summary["endpoints_discovered"] == 2
    node = next(n for n in graph.nodes(ENDPOINT) if n.key.endswith("/ok"))
    assert node.attrs["doc"] == "fine"

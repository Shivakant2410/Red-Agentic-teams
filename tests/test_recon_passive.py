"""Tests for deterministic passive recon — robots.txt/sitemap.xml/API-schema fetches that
must seed the knowledge graph and attack tree WITHOUT any LLM call."""

from __future__ import annotations

import datetime as _dt
from unittest.mock import patch

from redteam.attack_tree import AttackTree
from redteam.config import Engagement
from redteam.knowledge import ENDPOINT, KnowledgeGraph
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
    assert summary == {"endpoints_discovered": 0, "schemas_found": 0}

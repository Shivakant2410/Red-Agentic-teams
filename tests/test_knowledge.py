"""Tests for the target knowledge graph."""

from __future__ import annotations

from redteam.knowledge import (ENDPOINT, HOST, SERVICE, KnowledgeGraph)


def test_dedup_and_corroboration():
    g = KnowledgeGraph()
    g.observe(HOST, "203.0.113.5", source="nmap")
    g.observe(HOST, "203.0.113.5", attrs={"os": "linux"}, source="nikto")
    hosts = g.nodes(HOST)
    assert len(hosts) == 1                       # deduped, not duplicated
    assert hosts[0].attrs["os"] == "linux"       # attrs merged
    assert hosts[0].confidence == "corroborated"  # two independent sources


def test_edges_and_neighbors():
    g = KnowledgeGraph()
    g.observe(HOST, "203.0.113.5", source="nmap")
    g.observe(SERVICE, "203.0.113.5:443", source="nmap",
              relate_to="host:203.0.113.5", relation="runs")
    g.observe(ENDPOINT, "https://api.acme.example/v1/users", source="ffuf",
              relate_to="service:203.0.113.5:443", relation="exposes")
    svc = g.neighbors("host:203.0.113.5", "runs")
    assert svc and svc[0].kind == SERVICE
    eps = g.neighbors("service:203.0.113.5:443", "exposes")
    assert eps and eps[0].kind == ENDPOINT


def test_coverage_tracking_and_untested():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://api.acme.example/login", source="crawl")
    pending = g.untested()
    assert ("https://api.acme.example/login", "auth") in pending
    g.mark_coverage("https://api.acme.example/login", "auth", "tested")
    pending2 = g.untested()
    assert ("https://api.acme.example/login", "auth") not in pending2


def test_persistence_roundtrip(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(ENDPOINT, "https://api.acme.example/x", source="crawl")
    g.mark_coverage("https://api.acme.example/x", "injection", "finding")
    g2 = KnowledgeGraph(p)
    node = g2.nodes(ENDPOINT)[0]
    assert node.coverage["injection"] == "finding"
    assert g2.summary()["counts"]["endpoint"] == 1

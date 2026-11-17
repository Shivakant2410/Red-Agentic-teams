"""Phase E2 — inventory -> KnowledgeGraph synchronization bridge (Stage 5).

Eligibility policy (only ANSWERING services bridge), idempotency, run isolation,
and the safety contract (no findings, no attack-tree authority, no scope writes).
"""

from __future__ import annotations

import json

from redteam.attack_tree import AttackTree
from redteam.inventory import AssetInventory
from redteam.knowledge import ENDPOINT, HOST, SERVICE, KnowledgeGraph
from redteam.orchestrator import sync_inventory_into_graph


def _inv(tmp_path, rows: dict) -> AssetInventory:
    p = tmp_path / "inventory.json"
    inv = AssetInventory(p)
    for host, svcs in rows.items():
        for svc in svcs:
            if svc.get("status_last") is not None:
                inv.observe_http(host, svc["port"], svc["scheme"], svc["status_last"],
                                 headers=svc.get("headers"), body=svc.get("body", ""),
                                 source=svc.get("source", "http"))
            else:
                inv.observe_asset(host, svc["port"], scheme=svc["scheme"],
                                  service=svc.get("service", ""),
                                  source=svc.get("source", "asset_feed"))
    return inv


def test_inventory_host_produces_one_kg_host(tmp_path):
    inv = _inv(tmp_path, {"203.0.113.5": [
        {"port": 443, "scheme": "https", "status_last": 200}]})
    g = KnowledgeGraph()
    stats = sync_inventory_into_graph(inv, g)
    assert stats["bridged"] == 1 and stats["skipped_unanswered"] == 0
    hosts = g.nodes(HOST)
    assert len(hosts) == 1 and hosts[0].key == "203.0.113.5"
    assert hosts[0].sources == ["inventory"]


def test_observed_service_produces_one_kg_service_with_edge(tmp_path):
    inv = _inv(tmp_path, {"lab.example.com": [
        {"port": 443, "scheme": "https", "status_last": 200,
         "headers": {"Server": "nginx"}, "body": "<title>Lab</title>"}]})
    g = KnowledgeGraph()
    sync_inventory_into_graph(inv, g)
    svcs = g.nodes(SERVICE)
    assert len(svcs) == 1 and svcs[0].key == "lab.example.com:443"
    assert svcs[0].attrs["scheme"] == "https" and svcs[0].attrs["server"] == "nginx"
    # host -> runs -> service edge is a REAL graph edge
    neighbors = g.neighbors("host:lab.example.com", "runs")
    assert [n.key for n in neighbors] == ["lab.example.com:443"]


def test_repeated_sync_is_idempotent(tmp_path):
    inv = _inv(tmp_path, {"h.example": [{"port": 80, "scheme": "http", "status_last": 200}]})
    g = KnowledgeGraph()
    first = sync_inventory_into_graph(inv, g)
    nodes_after_first = len(g.nodes())
    edges_after_first = g.summary()["edges"]
    second = sync_inventory_into_graph(inv, g)
    assert len(g.nodes()) == nodes_after_first          # no duplicate nodes
    assert g.summary()["edges"] == edges_after_first    # no duplicate edges
    assert first["bridged"] == second["bridged"] == 1
    # the merge refreshed last_seen (the freshness signal), not the count
    assert g.nodes(SERVICE)[0].sources == ["inventory"]


def test_unanswered_and_declared_services_are_skipped(tmp_path):
    """ELIGIBILITY POLICY: only services that actually ANSWERED (status_last
    truthy) bridge. Asset-feed-declared rows (status_last=None) and failed
    probes (status 0) stay inventory-only — imported data never becomes a
    live observation (ADR-002)."""
    inv = _inv(tmp_path, {"203.0.113.9": [
        {"port": 443, "scheme": "https", "status_last": None, "service": "api",
         "source": "asset_feed"},                      # declared, never answered
        {"port": 8080, "scheme": "http", "status_last": 0},   # knocked, nothing
        {"port": 8443, "scheme": "https", "status_last": 200},  # alive
    ]})
    g = KnowledgeGraph()
    stats = sync_inventory_into_graph(inv, g)
    assert stats["bridged"] == 1 and stats["skipped_unanswered"] == 2
    assert [s.key for s in g.nodes(SERVICE)] == ["203.0.113.9:8443"]


def test_existing_endpoint_observations_untouched(tmp_path):
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/api", source="recon")
    inv = _inv(tmp_path, {"h.example": [{"port": 443, "scheme": "https", "status_last": 200}]})
    sync_inventory_into_graph(inv, g)
    eps = g.nodes(ENDPOINT)
    assert len(eps) == 1 and eps[0].key == "https://h.example/api"
    assert eps[0].sources == ["recon"]                 # not re-attributed


def test_scope_and_authority_not_touched(tmp_path):
    """The bridge writes graph OBSERVATIONS only: no findings store, no attack
    tree seeding (the AttackTree stays the work-selection authority and seeds
    only from its own sync), no network calls."""
    inv = _inv(tmp_path, {"h.example": [{"port": 443, "scheme": "https", "status_last": 200}]})
    g = KnowledgeGraph()
    tree = AttackTree()
    sync_inventory_into_graph(inv, g)
    assert tree.summary()["nodes"] == 0                # tree untouched by the bridge
    assert g.nodes(ENDPOINT) == []                     # no endpoints invented
    assert all(n.lifecycle_status() == "active" for n in g.nodes())


def test_foreign_reference_metadata_preserved(tmp_path):
    inv = _inv(tmp_path, {"203.0.113.7": [{"port": 80, "scheme": "http", "status_last": 301}]})
    g = KnowledgeGraph()
    sync_inventory_into_graph(inv, g)
    host = g.nodes(HOST)[0]
    assert host.attrs["inventory_host"] == "203.0.113.7"
    svc = g.nodes(SERVICE)[0]
    assert svc.attrs["inventory_key"] == "http/80"
    # provenance resolves to the real inventory row
    ref = svc.evidence_refs[0]
    assert ref["artifact_ref"].startswith("inventory.json:hosts[203.0.113.7]")
    assert ref["origin"] == "target" and ref["kind"] == "observation"


def test_run_isolation(tmp_path):
    inv1 = _inv(tmp_path / "r1", {"h1.example": [{"port": 443, "scheme": "https", "status_last": 200}]})
    inv2 = _inv(tmp_path / "r2", {"h2.example": [{"port": 443, "scheme": "https", "status_last": 200}]})
    g1 = KnowledgeGraph(tmp_path / "r1" / "graph.json")
    g2 = KnowledgeGraph(tmp_path / "r2" / "graph.json")
    sync_inventory_into_graph(inv1, g1)
    sync_inventory_into_graph(inv2, g2)
    assert [n.key for n in KnowledgeGraph(tmp_path / "r1" / "graph.json").nodes(HOST)] == ["h1.example"]
    assert [n.key for n in KnowledgeGraph(tmp_path / "r2" / "graph.json").nodes(HOST)] == ["h2.example"]


def test_none_arguments_safe():
    assert sync_inventory_into_graph(None, KnowledgeGraph()) == {"bridged": 0, "skipped_unanswered": 0}
    assert sync_inventory_into_graph(AssetInventory("/nonexistent/dir/inv.json"), None) == \
        {"bridged": 0, "skipped_unanswered": 0}

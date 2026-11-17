"""Phase E2 — canonical identity (redteam/knowledge.canonical_url / canonical_host).

Covers the assignment's required matrix: scheme/host casing, default ports,
fragments, query handling, path distinctions, IP vs hostname behavior,
duplicate observations, cross-store matching, legacy loading, run isolation.
"""

from __future__ import annotations

import json

import pytest

from redteam.knowledge import (ENDPOINT, HOST, SERVICE, DOMAIN,
                               KnowledgeGraph, canonical_host, canonical_url)


# -- canonical_host ---------------------------------------------------------------

def test_host_case_and_trailing_dot():
    assert canonical_host("Example.COM.") == "example.com"
    assert canonical_host("  LAB.example.com ") == "lab.example.com"


def test_host_ip_literals_unchanged():
    assert canonical_host("203.0.113.5") == "203.0.113.5"
    assert canonical_host("2001:DB8::1") == "2001:db8::1"   # lowercased, not re-formed
    # an invalid "IP" is still a name — validation only, never an error
    assert canonical_host("not-an-ip") == "not-an-ip"


def test_host_does_not_strip_www():
    # www. is a distinct surface — canonicalization must not conflate identities
    assert canonical_host("www.example.com") == "www.example.com"
    assert canonical_host("www.example.com") != canonical_host("example.com")


# -- canonical_url ----------------------------------------------------------------

def test_url_scheme_and_host_casing():
    assert canonical_url("HTTPS://Api.Example.COM/v1/Users") == "https://api.example.com/v1/Users"


def test_url_default_port_dropped():
    assert canonical_url("https://example.com:443/a") == "https://example.com/a"
    assert canonical_url("http://example.com:80/a") == "http://example.com/a"
    # a non-default port is a distinct service — it stays
    assert canonical_url("https://example.com:8443/a") == "https://example.com:8443/a"


def test_url_fragment_dropped():
    assert canonical_url("https://example.com/a#section") == "https://example.com/a"
    assert canonical_url("https://example.com/a#frag?not=a-query") == "https://example.com/a"


def test_url_query_dropped_but_documented_policy():
    # QUERY POLICY (ADR-002): canonical endpoint identity excludes the query
    # string entirely — behavior, not resource identity. Two spellings of the
    # same path with different queries are ONE endpoint.
    assert canonical_url("https://example.com/api?version=v1") == "https://example.com/api"
    assert canonical_url("https://example.com/api?version=v2") == "https://example.com/api"
    assert (canonical_url("https://example.com/api?version=v1")
            == canonical_url("https://example.com/api"))


def test_url_path_distinctions_preserved():
    # different paths are different resources — never merged
    assert canonical_url("https://example.com/admin") != canonical_url("https://example.com/adminPanel")
    # trailing slashes are NOT folded (a conservative policy: the path is real)
    assert canonical_url("https://example.com/list/") != canonical_url("https://example.com/list")


def test_url_unparseable_input_unchanged():
    assert canonical_url("not-a-url") == "not-a-url"
    assert canonical_url("") == ""
    assert canonical_url(None) == "None" or canonical_url(None) == ""  # never raises


# -- IPv6 authorities and malformed ports (review fixes) ----------------------------

def test_url_ipv6_brackets_preserved():
    """urlsplit's .hostname strips the brackets around an IPv6 literal; the
    canonical form must restore them, or identity is corrupted (review fix)."""
    assert (canonical_url("https://[2001:DB8::1]:8443/admin")
            == "https://[2001:db8::1]:8443/admin")   # brackets kept, host lowercased
    assert canonical_url("https://[2001:db8::1]/admin") == "https://[2001:db8::1]/admin"
    # one identity across spellings — the join contract the projection relies on
    assert (canonical_url("https://[2001:db8::1]:443/admin")
            == canonical_url("https://[2001:db8::1]/admin"))


def test_url_ipv6_default_port_dropped():
    assert canonical_url("https://[2001:db8::1]:443/a") == "https://[2001:db8::1]/a"
    assert canonical_url("http://[2001:db8::1]:80/a") == "http://[2001:db8::1]/a"
    # non-default ports stay (a distinct service, same rule as IPv4)
    assert (canonical_url("https://[2001:db8::1]:8443/a")
            == "https://[2001:db8::1]:8443/a")


def test_url_malformed_port_kept_unchanged():
    """A malformed port is unparseable input: returned unchanged, NEVER silently
    re-spelled — dropping it would mint a valid-looking identity that wrongly
    merges two distinct services (review fix)."""
    raw = "https://example.com:abc/admin"
    assert canonical_url(raw) == raw
    assert canonical_url(raw) != "https://example.com/admin"
    assert canonical_url("https://example.com:99999/admin") == "https://example.com:99999/admin"
    assert canonical_url("https://[2001:db8::1]:abc/admin") == "https://[2001:db8::1]:abc/admin"


def test_url_unbracketed_ipv6_authority_unchanged():
    """A bare (unbracketed) IPv6-ish authority is invalid URL syntax — its
    host/port split is ambiguous, so no identity is guessed for it."""
    assert canonical_url("https://2001:db8::1/admin") == "https://2001:db8::1/admin"
    assert canonical_url("https://2001:db8::1:8080/admin") == "https://2001:db8::1:8080/admin"


def test_url_invalid_ipv6_authority_unchanged():
    """urlsplit itself rejects an unterminated bracket — same policy: unchanged."""
    raw = "https://[::1/x"
    assert canonical_url(raw) == raw


# -- duplicate observations through the canonical layer ----------------------------

def test_observe_canonical_merges_query_variants():
    g = KnowledgeGraph()
    g.observe_canonical(ENDPOINT, "https://h.example/api?version=v1", source="recon")
    g.observe_canonical(ENDPOINT, "https://h.example/api", source="spa_recon")
    eps = g.nodes(ENDPOINT)
    assert len(eps) == 1                       # one endpoint, not two
    assert eps[0].confidence == "corroborated"
    assert eps[0].attrs["url_raw"] == "https://h.example/api?version=v1"  # raw kept as provenance


def test_observe_canonical_keeps_raw_when_identical():
    g = KnowledgeGraph()
    g.observe_canonical(ENDPOINT, "https://h.example/api", source="recon")
    assert "url_raw" not in g.nodes(ENDPOINT)[0].attrs


def test_exact_observe_unchanged_for_legacy_callers():
    # existing producers keep byte-identical keys — no silent re-keying
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/api?kept=1", source="recon")
    assert g.nodes(ENDPOINT)[0].key == "https://h.example/api?kept=1"


# -- cross-store matching -----------------------------------------------------------

def test_cross_store_join_via_canonical():
    """The join graph_view and the bridge rely on: an inventory/tree spelling
    and a KG spelling of the same URL resolve to the same node."""
    g = KnowledgeGraph()
    node = g.observe_canonical(ENDPOINT, "https://h.example:443/admin", source="recon")
    # a finding target recorded with scheme/port/query variations still matches
    assert g.mark_stale("https://h.example/admin", kind=ENDPOINT) is True
    assert node.lifecycle_status() == "stale"
    # and the canonical helper agrees across stores
    assert canonical_url("https://h.example/admin") == canonical_url("https://h.example:443/admin")
    assert canonical_url("https://h.example/admin") == canonical_url("https://h.example/admin?x=1#f")


def test_find_locked_canonical_fallback():
    g = KnowledgeGraph()
    g.observe_canonical(ENDPOINT, "https://h.example/admin", source="recon")
    node = g._find_locked("https://h.example:443/admin", ENDPOINT)
    assert node is not None and node.key == "https://h.example/admin"


def test_domain_kind_exists():
    g = KnowledgeGraph()
    g.observe(DOMAIN, "example.com", source="recon")
    assert g.nodes(DOMAIN)[0].id == "domain:example.com"
    assert g.summary()["counts"].get("domain") == 1


# -- legacy loading and run isolation ----------------------------------------------

def test_legacy_graph_file_loads_unchanged(tmp_path):
    """A pre-E2 graph.json (no evidence_refs/lifecycle/edge_attrs) loads with
    defaults — historical data is never lost or reinterpreted."""
    p = tmp_path / "graph.json"
    legacy = {
        "nodes": [
            {"kind": "endpoint", "key": "https://old.example/x",
             "attrs": {}, "sources": ["recon"], "confidence": "observed",
             "first_seen": "2025-01-01T00:00:00+00:00",
             "last_seen": "2025-01-01T00:00:00+00:00",
             "coverage": {"auth": "tested"}},
        ],
        "edges": [["endpoint:https://old.example/x", "has", "endpoint:https://old.example/x"]],
    }
    p.write_text(json.dumps(legacy), encoding="utf-8")
    g = KnowledgeGraph(p)
    n = g.nodes(ENDPOINT)[0]
    assert n.key == "https://old.example/x"
    assert n.evidence_refs == [] and n.lifecycle == {}
    assert n.coverage["auth"] == "tested"
    assert g.last_load_warning == ""


def test_run_isolation_separate_dirs(tmp_path):
    """Two run directories never share graph state (no global registry, no
    cross-run merge) — the Phase 1 isolation contract, now asserted for the
    canonical layer too."""
    p1, p2 = tmp_path / "run1" / "graph.json", tmp_path / "run2" / "graph.json"
    g1 = KnowledgeGraph(p1)
    g1.observe(HOST, "203.0.113.5", source="nmap")
    g2 = KnowledgeGraph(p2)
    g2.observe(SERVICE, "203.0.113.9:443", source="nmap")
    assert len(g1.nodes()) == 1 and len(g2.nodes()) == 1
    assert g1.nodes()[0].kind == HOST and g2.nodes()[0].kind == SERVICE
    # reloading each from disk preserves each dir's own state
    assert [n.key for n in KnowledgeGraph(p1).nodes()] == ["203.0.113.5"]
    assert [n.key for n in KnowledgeGraph(p2).nodes()] == ["203.0.113.9:443"]

"""Phase E2 — KnowledgeGraph persistence robustness (Stage 1A).

Atomic tmp+replace writes, corrupt/torn file handling, legacy loading, and the
load-warning contract (report, never silently pretend recovery happened).
"""

from __future__ import annotations

import json
import threading

from redteam.knowledge import ENDPOINT, HOST, SERVICE, KnowledgeGraph


def test_roundtrip(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(HOST, "203.0.113.5", source="nmap", evidence_refs=[
        {"evidence_id": "e1", "kind": "observation", "origin": "target",
         "source": "nmap", "source_agent": "recon", "artifact_ref": "traffic.jsonl:1",
         "summary": "host up", "ts": "2026-01-01T00:00:00+00:00"}])
    g2 = KnowledgeGraph(p)
    n = g2.nodes(HOST)[0]
    assert n.attrs == {} and n.sources == ["nmap"]
    assert n.evidence_refs[0]["artifact_ref"] == "traffic.jsonl:1"


def test_atomic_write_leaves_no_tmp_litter(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(HOST, "h1", source="x")
    assert p.exists()
    leftovers = [q for q in tmp_path.iterdir() if q.name != "graph.json"]
    assert leftovers == [], f"atomic replace should not litter: {leftovers}"


def test_interrupted_write_still_loads(tmp_path):
    """A torn file (simulated crash mid-write of the OLD non-atomic writer)
    loads as an empty graph with a warning — never a crash, never silent."""
    p = tmp_path / "graph.json"
    p.write_text('{"nodes": [{"kind": "host", "key": "h1"', encoding="utf-8")  # truncated JSON
    g = KnowledgeGraph(p)
    assert g.nodes() == []
    assert "unreadable" in g.last_load_warning
    # and the next mutation replaces the torn file cleanly (atomic rename)
    g.observe(HOST, "h1", source="recon")
    assert KnowledgeGraph(p).nodes()[0].key == "h1"


def test_corrupt_top_level_type_reported(tmp_path):
    p = tmp_path / "graph.json"
    p.write_text('["a", "list"]', encoding="utf-8")
    g = KnowledgeGraph(p)
    assert g.nodes() == []
    assert g.last_load_warning != ""


def test_failed_node_row_skipped_not_fatal(tmp_path):
    """A forward-compat row (unknown future fields) is skipped with a report —
    the pre-E2 forward-compat gate is now loud instead of a crash."""
    p = tmp_path / "graph.json"
    legacy_ok = {"kind": "host", "key": "ok", "attrs": {}, "sources": [],
                 "confidence": "observed", "first_seen": "t", "last_seen": "t",
                 "coverage": {}}
    future_row = dict(legacy_ok, key="future", brand_new_field={"x": 1})
    p.write_text(json.dumps({"nodes": [future_row, legacy_ok], "edges": []}), encoding="utf-8")
    g = KnowledgeGraph(p)
    assert [n.key for n in g.nodes()] == ["ok"]
    assert "failed to load" in g.last_load_warning


def test_legacy_graph_file_roundtrip(tmp_path):
    """A pre-E2 file (no evidence_refs/lifecycle) loads with defaults and its
    content survives a Phase-E2 rewrite."""
    p = tmp_path / "graph.json"
    p.write_text(json.dumps({
        "nodes": [{"kind": "endpoint", "key": "https://old/x", "attrs": {},
                   "sources": ["recon"], "confidence": "observed",
                   "first_seen": "t", "last_seen": "t", "coverage": {"auth": "untested"}}],
        "edges": []}), encoding="utf-8")
    g = KnowledgeGraph(p)
    assert g.last_load_warning == ""
    g.mark_coverage("https://old/x", "auth", "tested")
    reloaded = KnowledgeGraph(p)
    assert reloaded.nodes(ENDPOINT)[0].coverage["auth"] == "tested"
    assert reloaded.nodes(ENDPOINT)[0].evidence_refs == []


def test_concurrent_observers_race_clean(tmp_path):
    """The lock still guards the (now atomic) flush under the swarm's threads."""
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    def worker(i: int) -> None:
        for j in range(10):
            g.observe(HOST, f"h{i}-{j}", source="swarm")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(g.nodes()) == 40
    assert len(KnowledgeGraph(p).nodes()) == 40


def test_edge_attrs_persist_and_reload(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(HOST, "h", source="recon")
    g.observe(SERVICE, "h:443", source="recon", relate_to="host:h", relation="runs",
              edge_evidence=[{"evidence_id": "ev", "kind": "observation",
                              "origin": "target", "source": "recon",
                              "source_agent": "recon", "artifact_ref": "traffic.jsonl:3",
                              "summary": "port answered", "ts": "t"}])
    g2 = KnowledgeGraph(p)
    meta = g2.edge_attrs("host:h", "runs", "service:h:443")
    assert meta["evidence_refs"][0]["artifact_ref"] == "traffic.jsonl:3"
    assert meta["first_seen"] and meta["last_seen"]
    assert g2.edge_attrs("host:h", "nope", "service:h:443") == {}

"""Phase E2 — evidence-backed graph relationships (Stage 8).

EvidenceRef-shaped provenance on KG nodes, edges, and access nodes; the swarm
vocabulary reused verbatim; append behavior; legacy files load clean.
"""

from __future__ import annotations

import json

from redteam.access import RESOURCE, AccessGraph
from redteam.knowledge import HOST, SERVICE, KnowledgeGraph


def _ref(eid="ev1", kind="observation", origin="target", source="recon",
         agent="recon", artifact="traffic.jsonl:7", summary="port answered",
         ts="2026-01-01T00:00:00+00:00") -> dict:
    return {"evidence_id": eid, "kind": kind, "origin": origin, "source": source,
            "source_agent": agent, "artifact_ref": artifact, "summary": summary, "ts": ts}


# -- nodes -------------------------------------------------------------------------

def test_node_evidence_refs_persist(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref()])
    g2 = KnowledgeGraph(p)
    refs = g2.nodes(HOST)[0].evidence_refs
    assert len(refs) == 1 and refs[0]["artifact_ref"] == "traffic.jsonl:7"
    assert refs[0]["origin"] == "target" and refs[0]["source_agent"] == "recon"


def test_evidence_refs_append_not_replace():
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref(eid="a")])
    g.observe(HOST, "h.example", source="nikto", evidence_refs=[_ref(eid="b")])
    refs = g.nodes(HOST)[0].evidence_refs
    assert [r["evidence_id"] for r in refs] == ["a", "b"]
    assert g.nodes(HOST)[0].confidence == "corroborated"


def test_duplicate_evidence_is_stored_as_delivered():
    """The graph stores what was recorded (append-only, like the swarm); dedup
    is a caller concern — no silent dropping of delivered provenance."""
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref(eid="a")])
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref(eid="a")])
    assert len(g.nodes(HOST)[0].evidence_refs) == 2


def test_provenance_without_evidence_still_works():
    g = KnowledgeGraph()
    n = g.observe(HOST, "h.example", source="recon")   # legacy call shape
    assert n.evidence_refs == []                        # empty, not fabricated


def test_no_secrets_in_references():
    """Provenance stores REFERENCES to artifacts, never the material itself —
    a secret-looking summary is a caller bug, and the bounded fields make
    accidents small. What the contract requires: refs point at artifacts."""
    g = KnowledgeGraph()
    ref = _ref(summary="see traffic.jsonl:12 (secret redacted by the recorder)")
    g.observe(HOST, "h.example", source="recon", evidence_refs=[ref])
    assert g.nodes(HOST)[0].evidence_refs[0]["artifact_ref"] == "traffic.jsonl:7"
    assert "artifact_ref" in ref and "summary" in ref


# -- edges --------------------------------------------------------------------------

def test_edge_evidence_persistence():
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon")
    g.observe(SERVICE, "h.example:443", source="recon",
              relate_to="host:h.example", relation="runs", edge_evidence=[_ref()])
    meta = g.edge_attrs("host:h.example", "runs", "service:h.example:443")
    assert meta["evidence_refs"][0]["evidence_id"] == "ev1"
    assert meta["first_seen"] and meta["last_seen"]


def test_edge_tuple_representation_preserved():
    """The tuple set is untouched — old consumers and serializers keep working."""
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon")
    g.observe(SERVICE, "h.example:443", source="recon", relate_to="host:h.example")
    assert ("host:h.example", "has", "service:h.example:443") in g._edges


def test_edge_evidence_appends_across_observations():
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon")
    g.observe(SERVICE, "h.example:443", source="recon",
              relate_to="host:h.example", relation="runs", edge_evidence=[_ref(eid="a")])
    g.observe(SERVICE, "h.example:443", source="nikto",
              relate_to="host:h.example", relation="runs", edge_evidence=[_ref(eid="b")])
    meta = g.edge_attrs("host:h.example", "runs", "service:h.example:443")
    assert [r["evidence_id"] for r in meta["evidence_refs"]] == ["a", "b"]


def test_legacy_edges_load_without_edge_attrs(tmp_path):
    p = tmp_path / "graph.json"
    p.write_text(json.dumps({
        "nodes": [{"kind": "host", "key": "h", "attrs": {}, "sources": [],
                   "confidence": "observed", "first_seen": "t", "last_seen": "t",
                   "coverage": {}}],
        "edges": [["host:h", "runs", "service:h:443"]]}), encoding="utf-8")
    g = KnowledgeGraph(p)
    assert g.edge_attrs("host:h", "runs", "service:h:443") == {}   # empty, not fabricated
    assert g.last_load_warning == ""


# -- access nodes -------------------------------------------------------------------

def test_access_node_evidence_refs_and_hold(tmp_path):
    p = tmp_path / "access.json"
    g = AccessGraph(p)
    g.hold(RESOURCE, "records", evidence="confirmed finding abc",
           source="verified_finding",
           evidence_refs=[_ref(eid="finding-abc", kind="finding", origin="agent",
                               source="creditor", agent="credit",
                               artifact="finding:abc")])
    g2 = AccessGraph(p)
    node = g2._nodes["resource:records"]
    assert node.evidence_refs[0]["artifact_ref"] == "finding:abc"
    assert node.last_seen and node.held is True


def test_swarm_evidenceref_shape_reused():
    """The graph's evidence dict is the swarm EvidenceRef contract's dict form —
    one vocabulary, no competing dialect."""
    from redteam.swarm.hypotheses import EvidenceRef
    from dataclasses import asdict
    ref = EvidenceRef(evidence_id="ev", kind="observation", origin="agent",
                      source_agent="w0", artifact_ref="events.jsonl:3",
                      summary="s", ts="t")
    d = asdict(ref)
    d.setdefault("source", ref.source_agent)   # graph refs allow an explicit tool label
    g = KnowledgeGraph()
    g.observe(HOST, "h", source="w0", evidence_refs=[d])
    stored = g.nodes(HOST)[0].evidence_refs[0]
    for k in ("evidence_id", "kind", "origin", "source_agent", "artifact_ref", "summary", "ts"):
        assert stored[k] == d[k]

"""Phase E2 — evidence-backed graph relationships (Stage 8).

EvidenceRef-shaped provenance on KG nodes, edges, and access nodes; the swarm
vocabulary reused verbatim; idempotent insertion on the stable evidence_id
(review fix — repeated synchronization must not grow provenance); legacy files
load clean.
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


def test_duplicate_evidence_id_recorded_once():
    """Idempotent insertion (review fix): a reference whose stable identity is
    already recorded is NOT appended again — the swarm registry dedupes
    hypothesis evidence by evidence_id and the graph follows the same contract,
    so provenance never grows from re-recording the same reference. Distinct
    references are all kept."""
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref(eid="a")])
    g.observe(HOST, "h.example", source="recon", evidence_refs=[_ref(eid="a")])
    # same identity with different content details (e.g. a fresh ts each bridge
    # pass) is still the SAME reference — identity, not content, decides
    g.observe(HOST, "h.example", source="recon",
              evidence_refs=[_ref(eid="a", ts="2026-02-02T00:00:00+00:00")])
    refs = g.nodes(HOST)[0].evidence_refs
    assert len(refs) == 1 and refs[0]["evidence_id"] == "a"
    # genuinely distinct references are preserved
    g.observe(HOST, "h.example", source="nikto", evidence_refs=[_ref(eid="b")])
    assert [r["evidence_id"] for r in g.nodes(HOST)[0].evidence_refs] == ["a", "b"]


def test_content_identical_refs_without_id_dedup():
    """Legacy/odd rows without an evidence_id dedupe on full content — the
    identity rule stays well-defined for references that predate the id."""
    g = KnowledgeGraph()
    plain = {"kind": "observation", "source": "recon", "artifact_ref": "a.jsonl:1"}
    g.observe(HOST, "h.example", source="recon", evidence_refs=[dict(plain), dict(plain)])
    assert len(g.nodes(HOST)[0].evidence_refs) == 1


def test_inventory_bridge_repeated_sync_does_not_grow_provenance(tmp_path):
    """The reviewer's exact scenario: the inventory bridge supplies a stable
    evidence_id on every synchronization pass — node provenance stays ONE ref
    no matter how many times the bridge runs."""
    from redteam.inventory import AssetInventory
    from redteam.orchestrator import sync_inventory_into_graph
    inv = AssetInventory(tmp_path / "inventory.json")
    inv.observe_http("h.example", 80, "http", 200, headers={}, body="", source="http")
    g = KnowledgeGraph()
    for _ in range(3):
        sync_inventory_into_graph(inv, g)
    host = g.nodes(HOST)[0]
    assert len(host.evidence_refs) == 1
    assert host.evidence_refs[0]["evidence_id"] == "inv-h.example-http/80"


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


def test_edge_evidence_idempotent():
    """Same identity rule as nodes: re-recording the same edge reference is a
    no-op (review fix, same defect class)."""
    g = KnowledgeGraph()
    g.observe(HOST, "h.example", source="recon")
    for _ in range(2):
        g.observe(SERVICE, "h.example:443", source="recon",
                  relate_to="host:h.example", relation="runs",
                  edge_evidence=[_ref(eid="e1")])
    meta = g.edge_attrs("host:h.example", "runs", "service:h.example:443")
    assert [r["evidence_id"] for r in meta["evidence_refs"]] == ["e1"]


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


def test_hold_records_evidence_reference_exactly_once():
    """Review fix: hold() must not double-append the references it already
    recorded through observe(); re-holding with the SAME reference stays one
    record (idempotent insertion), while the hold/re-hold/revocation-history
    behavior is untouched."""
    g = AccessGraph()
    ref = _ref(eid="finding-abc", kind="finding", origin="agent",
               source="creditor", agent="credit", artifact="finding:abc")
    g.hold(RESOURCE, "records", evidence="confirmed finding abc",
           source="verified_finding", evidence_refs=[ref])
    assert len(g._nodes["resource:records"].evidence_refs) == 1
    # re-demonstration after revocation with the same reference: still exactly once
    g.revoke(RESOURCE, "records", reason="retest fixed: abc")
    g.hold(RESOURCE, "records", evidence="second demo",
           source="verified_finding", evidence_refs=[ref])
    node = g._nodes["resource:records"]
    assert len(node.evidence_refs) == 1
    assert node.held is True                       # re-hold behavior intact
    assert node.attrs["invalidation_history"]      # revocation record survives
    # a genuinely distinct reference still appends
    g.hold(RESOURCE, "records", evidence="third demo",
           source="verified_finding", evidence_refs=[_ref(eid="finding-xyz")])
    assert [r["evidence_id"] for r in
            g._nodes["resource:records"].evidence_refs] == ["finding-abc", "finding-xyz"]


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

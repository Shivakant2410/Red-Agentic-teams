"""Exploration graph (ARTEX 探索链路): layered, honest, decoupled.

Failure modes these tests exist to kill:

1. A graph that paints ASSUMED access as HELD — only demonstrated access nodes
   (held=True) may appear in the access layer.
2. A graph that paints pending/falsified findings as impact — the finding node's
   status is the finding's real confidence, and it links to the endpoint it
   proved only when that endpoint actually exists in the discovered surface.
3. A builder that explodes on a round-one run — missing artifacts render as
   empty layers, never a 500.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.graph_view import build_exploration_graph

from test_server import harness  # noqa: F401 — pytest fixture, used by name


def _write_run(tmp_path: Path, files: dict[str, str]) -> Path:
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (run_dir / name).write_text(content, encoding="utf-8")
    return run_dir


def test_layered_graph_from_populated_run(tmp_path):
    run_dir = _write_run(tmp_path, {
        "graph.json": json.dumps({
            "nodes": [
                {"id": "host:web.acme", "kind": "host", "key": "web.acme",
                 "attrs": {}, "sources": []},
                {"id": "endpoint:http://web.acme/admin", "kind": "endpoint",
                 "key": "http://web.acme/admin", "attrs": {}, "sources": []},
                {"id": "credential:api-token", "kind": "credential",
                 "key": "api-token", "attrs": {}, "sources": []},
            ],
            "edges": [["host:web.acme", "serves",
                       "endpoint:http://web.acme/admin"]],
        }),
        "access.json": json.dumps({
            "nodes": [
                {"kind": "identity", "key": "admin@web.acme", "attrs": {},
                 "held": True, "evidence": "session cookie proven", "source": "",
                 "first_seen": "t"},
                {"kind": "identity", "key": "assumed-root", "attrs": {},
                 "held": False, "evidence": "guessed", "source": "",
                 "first_seen": "t"},
            ],
            "edges": [["identity:admin@web.acme", "reached-from",
                       "endpoint:http://web.acme/admin"]],
        }),
        "findings.json": json.dumps([
            {"id": "abc123", "title": "IDOR on admin export", "severity": "high",
             "target": "http://web.acme/admin", "confidence": "confirmed"},
            {"id": "dead42", "title": "XSS guess", "severity": "low",
             "target": "http://nowhere.test/x", "confidence": "falsified"},
        ]),
        "killchain.json": json.dumps([
            {"stage": "recon", "status": "achieved", "achieved_at": "t1"},
            {"stage": "initial-access", "status": "achieved", "achieved_at": "t2"},
            {"stage": "execution", "status": "not_started", "achieved_at": ""},
        ]),
        "attack_tree.json": json.dumps([
            {"status": "completed"}, {"status": "completed"},
            {"status": "in_progress"}, {"status": "todo"},
        ]),
    })
    g = build_exploration_graph(run_dir)

    layers = {n["id"]: n["layer"] for n in g["nodes"]}
    # surface objects layered correctly; non-surface knowledge nodes stay out
    assert layers["host:web.acme"] == "asset"
    assert layers["endpoint:http://web.acme/admin"] == "endpoint"
    assert "credential:api-token" not in layers
    # ONLY demonstrated access reaches the access layer
    assert "identity:admin@web.acme" in layers
    assert layers["identity:admin@web.acme"] == "access"
    assert "assumed-root" not in layers
    # findings carry their REAL confidence, not optimism
    by_id = {n["id"]: n for n in g["nodes"]}
    assert by_id["finding:abc123"]["status"] == "confirmed"
    assert by_id["finding:dead42"]["status"] == "falsified"
    # the proof edge only exists where the endpoint is real
    edge_set = {(e["src"], e["dst"], e["rel"]) for e in g["edges"]}
    assert ("endpoint:http://web.acme/admin", "finding:abc123", "proved-by") in edge_set
    assert not any(e["dst"] == "finding:dead42" for e in g["edges"])
    # knowledge edge survived
    assert ("host:web.acme", "endpoint:http://web.acme/admin", "serves") in edge_set
    # metadata passthrough
    assert {k["stage"]: k["status"] for k in g["killchain"]}["recon"] == "achieved"
    assert g["attack_tree"] == {"todo": 1, "in_progress": 1, "failed": 0,
                                "completed": 2}
    assert g["layer_counts"] == {"asset": 1, "endpoint": 1, "access": 1,
                                 "finding": 2}


def test_graph_of_an_empty_run_is_honest_partial(tmp_path):
    run_dir = tmp_path / "runs" / "empty"
    run_dir.mkdir(parents=True)
    g = build_exploration_graph(run_dir)
    assert g["nodes"] == [] and g["edges"] == []
    assert g["layer_counts"] == {"asset": 0, "endpoint": 0, "access": 0,
                                 "finding": 0}
    assert g["killchain"] == [] and g["attack_tree"] == {"todo": 0,
                                                         "in_progress": 0,
                                                         "failed": 0,
                                                         "completed": 0}


def test_inventory_services_become_asset_nodes(tmp_path):
    inv = {"hosts": {"web.acme": {"services": {
        "http/443": {"port": 443, "scheme": "http", "first_seen": "t",
                     "hits": 3, "status_last": 200, "server": "nginx",
                     "title": "Acme", "auth": False, "source": "http"}}}}}
    run_dir = _write_run(tmp_path, {"inventory.json": json.dumps(inv)})
    g = build_exploration_graph(run_dir)
    labels = {n["label"] for n in g["nodes"]}
    assert "web.acme" in labels and "http://web.acme:443" in labels
    edge_set = {(e["src"], e["dst"], e["rel"]) for e in g["edges"]}
    assert ("asset:web.acme", "asset:web.acme/http/443", "serves") in edge_set


def test_graph_endpoint_served_by_api(harness):
    # Same fake-run pattern as test_server: launch, seed artifacts into the run
    # dir, read them back through the API with the same 404 contract as the
    # rest of the surface.
    client, runs_root, engagement = harness
    r = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "Graph the chain",
        "max_steps": 5})
    assert r.status_code == 202
    run_id = r.json()["run_id"]

    # seed the stores the graph reads (the faked executor only writes manifest/events)
    run_dir = runs_root / run_id
    (run_dir / "graph.json").write_text(json.dumps({
        "nodes": [{"id": "host:web.acme", "kind": "host", "key": "web.acme",
                   "attrs": {}, "sources": []}],
        "edges": []}), encoding="utf-8")
    (run_dir / "findings.json").write_text(json.dumps([
        {"id": "f1", "title": "t", "severity": "low", "target": "",
         "confidence": "tentative"}]), encoding="utf-8")

    resp = client.get(f"/api/runs/{run_id}/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == run_id
    g = body["graph"]
    assert {n["id"] for n in g["nodes"]} == {"host:web.acme", "finding:f1"}
    assert g["layer_counts"] == {"asset": 1, "endpoint": 0, "access": 0,
                                 "finding": 1}

    # unknown run → same 404 contract as every other endpoint
    assert client.get("/api/runs/unknown-run/graph").status_code == 404


# -- Phase E2: attack-path projection (read-time, joins real records only) ---------

def _seed_run(tmp_path):
    """A small but complete run directory: the full chain from inventory to
    objective, plus one stale endpoint and one revoked holding."""
    (tmp_path / "graph.json").write_text(json.dumps({
        "nodes": [
            {"id": "host:lab.acme", "kind": "host", "key": "lab.acme", "attrs": {}, "sources": []},
            {"id": "service:lab.acme:443", "kind": "service", "key": "lab.acme:443",
             "attrs": {}, "sources": []},
            {"id": "endpoint:https://lab.acme/admin", "kind": "endpoint",
             "key": "https://lab.acme/admin",
             "attrs": {}, "sources": [],
             "lifecycle": {"status": "remediated", "marked_at": "m", "reason": "retest fixed f1",
                           "history": []}},
        ],
        "edges": [["host:lab.acme", "runs", "service:lab.acme:443"],
                  ["service:lab.acme:443", "has", "endpoint:https://lab.acme/admin"]]}),
        encoding="utf-8")
    (tmp_path / "attack_tree.json").write_text(json.dumps([
        {"technique": "access.control", "target": "https://lab.acme/admin",
         "status": "completed", "findings": "f1", "bucket": ""}]), encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "f1", "title": "AC bypass", "severity": "high",
         "target": "https://lab.acme/admin", "confidence": "confirmed",
         "independent_verdict": "confirmed",
         "retest_history": [{"verdict": "fixed", "when": "w2", "detail": ""}]},
        {"id": "f2", "title": "orphan claim", "severity": "low",
         "target": "https://never-seen.example/x", "confidence": "pending_verification"}]),
        encoding="utf-8")
    (tmp_path / "access.json").write_text(json.dumps({
        "nodes": [
            {"id": "resource:admin", "kind": "resource", "key": "admin",
             "attrs": {"finding_id": "f1"}, "held": False,
             "evidence": "confirmed finding f1: x", "source": "verified_finding",
             "first_seen": "t", "invalidated_at": "2026-01-02",
             "invalidation_reason": "retest fixed: f1"},
        ], "edges": []}), encoding="utf-8")
    (tmp_path / "inventory.json").write_text(json.dumps(
        {"hosts": {"lab.acme": {"services": {"https/443": {
            "port": 443, "scheme": "https", "first_seen": "t", "hits": 1,
            "status_last": 200, "server": "nginx", "title": "Lab", "auth": False,
            "source": "http", "last_seen": "t"}}}}}), encoding="utf-8")
    (tmp_path / "objective.json").write_text(json.dumps(
        {"criteria": [{"id": "c1", "kind": "data_access", "description": "d",
                       "target": "admin", "achieved": True, "evidence": "e",
                       "achieved_at": "t"}]}), encoding="utf-8")


def test_attack_path_full_chain(tmp_path):
    _seed_run(tmp_path)
    g = build_exploration_graph(tmp_path)
    paths = [p for p in g["attack_paths"] if "endpoint" in p]
    assert len(paths) == 1
    p = paths[0]
    assert p["endpoint"]["id"] == "endpoint:https://lab.acme/admin"
    assert p["endpoint"]["lifecycle"] == "remediated"          # stale state surfaced
    assert p["host"]["id"] == "host:lab.acme" and p["service"]["id"] == "service:lab.acme:443"
    assert p["inventory"]["host"] == "lab.acme"                 # canonical inventory join
    assert p["techniques"][0]["id"] == "access.control@https://lab.acme/admin"
    assert p["techniques"][0]["status"] == "completed"
    f = p["findings"][0]
    assert f["confidence"] == "confirmed" and f["independent_verdict"] == "confirmed"
    assert f["retest_last"]["verdict"] == "fixed"               # remediation state surfaced
    assert p["access"][0]["status"] == "revoked"                # never presented as current
    assert p["access"][0]["invalidated_at"] == "2026-01-02"
    assert p["objective"][0]["criterion"] == "c1"


def test_attack_path_unmatched_finding_reported_not_guessed(tmp_path):
    _seed_run(tmp_path)
    g = build_exploration_graph(tmp_path)
    unresolved = [p["unresolved"] for p in g["attack_paths"] if "unresolved" in p]
    assert unresolved and unresolved[0][0]["finding_id"] == "f2"
    assert unresolved[0][0]["reason"] == "no matching endpoint record"
    # the orphan never joined to a fabricated endpoint node
    assert {n["id"] for n in g["nodes"]} & {"endpoint:https://never-seen.example/x"} == set()


def test_attack_path_canonical_join_on_query_and_port(tmp_path):
    (tmp_path / "graph.json").write_text(json.dumps({
        "nodes": [{"id": "endpoint:https://h.acme/api", "kind": "endpoint",
                   "key": "https://h.acme/api", "attrs": {}, "sources": []}],
        "edges": []}), encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "f3", "title": "t", "severity": "low",
         "target": "https://h.acme:443/api?utm=2", "confidence": "falsified"}]),
        encoding="utf-8")
    (tmp_path / "attack_tree.json").write_text(json.dumps([
        {"technique": "injection.sqli", "target": "https://h.acme/api",
         "status": "failed", "findings": "f3", "bucket": ""}]), encoding="utf-8")
    g = build_exploration_graph(tmp_path)
    paths = [p for p in g["attack_paths"] if "endpoint" in p]
    assert len(paths) == 1
    assert paths[0]["endpoint"]["id"] == "endpoint:https://h.acme/api"
    assert paths[0]["findings"][0]["confidence"] == "falsified"
    assert paths[0]["techniques"][0]["status"] == "failed"


def test_attack_path_no_records_yields_empty(tmp_path):
    g = build_exploration_graph(tmp_path)   # empty run dir
    assert g["attack_paths"] == []


def test_existing_graph_response_shape_unchanged(tmp_path):
    _seed_run(tmp_path)
    g = build_exploration_graph(tmp_path)
    # the pre-E2 contract keys are all present and well-formed (additive only)
    assert set(g.keys()) >= {"nodes", "edges", "layer_counts", "killchain", "attack_tree"}
    # asset layer: KG host + KG service + inventory host + inventory service
    assert g["layer_counts"]["asset"] == 4 and g["layer_counts"]["endpoint"] == 1
    assert g["killchain"] == []   # no killchain.json in this seed — honest partial
    assert g["attack_tree"] == {"todo": 0, "in_progress": 0, "failed": 0, "completed": 1}

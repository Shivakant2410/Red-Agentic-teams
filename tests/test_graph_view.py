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

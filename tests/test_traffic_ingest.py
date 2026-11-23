"""The browser-extension traffic-ingest endpoint: authenticated, scoped to a
run, HTTP-only, and lands exchanges in the SAME traffic.jsonl the agent reads."""
import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import redteam.server as s


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("RED_INGEST_TOKEN", "tok-abc")
    root = Path(tempfile.mkdtemp())
    (root / "20261123-000000-run").mkdir(parents=True)
    return TestClient(s.create_app(root)), root, "20261123-000000-run"


def _batch(run_id):
    return {"run_id": run_id, "entries": [
        {"method": "GET", "url": "https://www.vinted.com/api/v2/user", "status": 200,
         "resp_headers": {"content-type": "application/json"},
         "resp_body": '{"id":42,"login":"me"}'},
        {"method": "POST", "url": "https://www.vinted.com/api/v2/offers", "status": 201,
         "resp_body": '{"ok":true}'},
    ]}


def test_requires_token(client):
    c, _, rid = client
    r = c.post("/api/traffic/ingest", json=_batch(rid))
    assert r.status_code == 401


def test_rejects_wrong_token(client):
    c, _, rid = client
    r = c.post("/api/traffic/ingest", json=_batch(rid),
               headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_ingest_writes_to_run_traffic(client):
    c, root, rid = client
    r = c.post("/api/traffic/ingest", json=_batch(rid),
               headers={"Authorization": "Bearer tok-abc"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "written": 2, "skipped": 0}
    rows = [json.loads(l) for l in (root / rid / "traffic.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    assert all(row["source"] == "extension" for row in rows)
    assert rows[0]["url"] == "https://www.vinted.com/api/v2/user"


def test_skips_non_http_urls(client):
    c, root, rid = client
    batch = {"run_id": rid, "entries": [
        {"method": "GET", "url": "data:image/png;base64,xxx", "status": 200},
        {"method": "GET", "url": "chrome://version", "status": 200},
        {"method": "GET", "url": "https://www.vinted.com/ok", "status": 200},
    ]}
    r = c.post("/api/traffic/ingest", json=batch,
               headers={"Authorization": "Bearer tok-abc"})
    assert r.json()["written"] == 1 and r.json()["skipped"] == 2


def test_unknown_run_is_404(client):
    c, _, _ = client
    r = c.post("/api/traffic/ingest", json=_batch("../etc"),
               headers={"Authorization": "Bearer tok-abc"})
    assert r.status_code == 404


def test_disabled_without_server_token(monkeypatch):
    monkeypatch.delenv("RED_INGEST_TOKEN", raising=False)
    root = Path(tempfile.mkdtemp())
    (root / "r").mkdir()
    c = TestClient(s.create_app(root))
    r = c.post("/api/traffic/ingest", json={"run_id": "r", "entries": []},
               headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503

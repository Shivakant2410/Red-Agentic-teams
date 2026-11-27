"""Scope-safe control-plane ingestion and monotonic traffic evidence sequences."""
import json

import pytest
from fastapi.testclient import TestClient

from redteam.server import create_app
from redteam.traffic import TrafficRecorder, read_traffic


ENGAGEMENT = """
name: Ingest Lab
client: local-test
authorized_by: operator
 ticket: test-ticket
starts: "2020-01-01"
ends: "2099-12-31"
scope:
  allowed_hosts: ["127.0.0.1"]
  allowed_ports: [8000]
  allowed_schemes: ["http", "https"]
  max_requests_per_second: 100
  max_total_requests: 1000
  allow_private_ranges: false
"""


@pytest.fixture
def harness(tmp_path, monkeypatch):
    run_id = "run-ingest-scope-test"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    (run_dir / "engagement.yaml").write_text(ENGAGEMENT, encoding="utf-8")
    monkeypatch.setenv("RED_INGEST_TOKEN", "test-ingest-token")
    client = TestClient(create_app(runs_root=tmp_path, dashboard_dir=None))
    return client, run_dir, run_id


def _entry(url):
    return {"method": "GET", "url": url, "status": 200,
            "resp_headers": {"content-type": "text/plain"}, "resp_body": "ok"}


def test_ingest_rejects_out_of_scope_url_before_writing_anything(harness):
    client, run_dir, run_id = harness
    response = client.post("/api/traffic/ingest", headers={
        "Authorization": "Bearer test-ingest-token"}, json={
        "run_id": run_id, "entries": [_entry("http://not-allowed.invalid:8000/")],
    })
    assert response.status_code == 400
    assert "out-of-scope" in response.text
    assert not (run_dir / "traffic.jsonl").exists()


def test_mixed_batch_is_rejected_atomically(harness):
    client, run_dir, run_id = harness
    response = client.post("/api/traffic/ingest", headers={
        "Authorization": "Bearer test-ingest-token"}, json={
        "run_id": run_id,
        "entries": [_entry("http://127.0.0.1:8000/in-scope"),
                    _entry("http://outside.invalid:8000/out-of-scope")],
    })
    assert response.status_code == 400
    assert not (run_dir / "traffic.jsonl").exists()


def test_in_scope_ingest_is_recorded_and_authenticated(harness):
    client, run_dir, run_id = harness
    response = client.post("/api/traffic/ingest", headers={
        "Authorization": "Bearer test-ingest-token"}, json={
        "run_id": run_id, "entries": [_entry("http://127.0.0.1:8000/ok")],
    })
    assert response.status_code == 200, response.text
    assert response.json()["written"] == 1
    records = read_traffic(run_dir / "traffic.jsonl")
    assert len(records) == 1 and records[0]["url"].endswith("/ok")


def test_short_lived_recorders_share_monotonic_sequence_numbers(tmp_path):
    path = tmp_path / "traffic.jsonl"
    first = TrafficRecorder(path)
    first.record_http(method="GET", url="http://127.0.0.1/a", status=200, elapsed_ms=1)
    second = TrafficRecorder(path)
    second.record_http(method="GET", url="http://127.0.0.1/b", status=200, elapsed_ms=1)
    third = TrafficRecorder(path)
    third.record_http(method="GET", url="http://127.0.0.1/c", status=200, elapsed_ms=1)
    assert [row["seq"] for row in read_traffic(path)] == [1, 2, 3]

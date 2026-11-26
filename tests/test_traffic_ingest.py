"""The extension ingest loop: POST /api/traffic/ingest → traffic.jsonl → POE.

Failure modes this must prevent:

1. An out-of-scope capture is a LEAK, not evidence — the endpoint validates
   the capture URL against the RUN's own engagement.yaml and returns 400.
2. A capture without a run / without a URL is a 400, never a half record.
3. The recorded row is kind=extension_session, source=extension — mocked rows
   are kept distinct from real wire exchanges (the TrafficRecorder rule).
4. The POE endpoint serves grades off the same traffic store, read-only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redteam.server import create_app


ENGAGEMENT_YAML = """
name: "Ingest Lab"
client: "c"
authorized_by: "a"
ticket: "ref"
starts: "2020-01-01"
ends: "2099-01-01"
scope:
  allowed_hosts:
    - "127.0.0.1"
  allowed_ports: [8000]
  allowed_schemes: ["http", "https"]
  max_requests_per_second: 1000
  max_total_requests: 100000
  allow_private_ranges: false
"""


@pytest.fixture()
def harness(tmp_path):
    run_id = "run-ingest-test"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    (run_dir / "engagement.yaml").write_text(ENGAGEMENT_YAML)
    app = create_app(runs_root=tmp_path, dashboard_dir=None)
    return TestClient(app), tmp_path, run_id


def test_capture_ingests_as_extension_session(harness):
    client, _, run_id = harness
    r = client.post("/api/traffic/ingest", json={
        "run_id": run_id, "url": "http://127.0.0.1:8000/portal/login",
        "title": "Acme Portal — verify", "otp_observed": True,
        "captcha_observed": False,
        "field_names": ["username", "password", "otp_code"],
        "notes": "operator walked the 2FA step"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["seq"] >= 1

    rows = client.get(f"/api/runs/{run_id}/traffic").json()["traffic"]
    row = next(x for x in rows if x["seq"] == body["seq"])
    assert row["kind"] == "extension_session" and row["source"] == "extension"
    assert row["otp_observed"] is True
    assert row["field_names"] == ["username", "password", "otp_code"]


def test_out_of_scope_capture_is_rejected_400(harness):
    client, _, run_id = harness
    r = client.post("/api/traffic/ingest", json={
        "run_id": run_id, "url": "http://not-in-scope.example/admin"})
    assert r.status_code == 400
    assert "out of scope" in r.text.lower()
    # And nothing landed in the traffic log:
    rows = client.get(f"/api/runs/{run_id}/traffic").json()["traffic"]
    assert rows == []


def test_unknown_run_and_missing_fields_are_400(harness):
    client, _, _ = harness
    assert client.post("/api/traffic/ingest", json={
        "run_id": "nope", "url": "http://127.0.0.1:8000/"}).status_code == 404
    assert client.post("/api/traffic/ingest", json={"run_id": "run-ingest-test"}).status_code == 400
    assert client.post("/api/traffic/ingest", json={"url": "http://127.0.0.1:8000/"}).status_code == 400


def test_poe_endpoint_serves_grades_read_only(harness):
    client, runs_root, run_id = harness
    # Seed one finding + one matching traffic row, then grade.
    finding = {
        "title": "t", "severity": "low", "target": "http://127.0.0.1:8000",
        "summary": "s", "evidence": 'the page said "welcome operator"',
        "confidence": "confirmed", "verification_verdict": "", "poc": "",
        "check_type": "", "check_spec": {}, "independent_verdict": "confirmed",
        "reproductions": 0, "trials": 0, "retest_history": [],
    }
    (runs_root / run_id / "findings.json").write_text(json.dumps([finding]))
    client.post("/api/traffic/ingest", json={
        "run_id": run_id, "url": "http://127.0.0.1:8000/portal",
        "notes": 'welcome operator'})
    # extension_session rows carry no resp_body — quote matching uses http rows;
    # seed one directly to prove the binding path end to end.
    row = {"seq": 99, "kind": "http", "resp_body": "welcome operator", "ts": "t"}
    with open(runs_root / run_id / "traffic.jsonl", "a") as fh:
        fh.write(json.dumps(row) + "\n")

    r = client.get(f"/api/runs/{run_id}/poe")
    assert r.status_code == 200
    report = r.json()
    assert report["findings"][0]["poe"] == "POE-3"
    assert report["summary"]["POE-3"] == 1

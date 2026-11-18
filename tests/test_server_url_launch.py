"""Builder 04 URL-first launch API — POST /api/launch + GET /api/llm/ollama/status.

The endpoint must generate a server-side engagement from validated input and
arm the SAME pipeline as /api/runs and /api/missions for BOTH drivers. Here the
generated engagement is validated by the REAL config loader (no monkeypatch),
while execute_run is faked so no LLM/network is touched.
"""

from __future__ import annotations

import datetime as _dt
import json
import time
from pathlib import Path

import pytest
import requests as _requests
from fastapi.testclient import TestClient

import redteam.server as server_mod
from redteam.runtime import RunManifest
from redteam.server import create_app


def _fake_execute_run(opts):
    out = Path(opts.out_dir)
    manifest = RunManifest.load(out / "manifest.json") or RunManifest(
        objective=opts.objective, engagement="web-launch")
    manifest.status = "completed"
    manifest.steps = 3
    manifest.tokens = 42
    manifest.findings = 0
    manifest.save(out / "manifest.json")
    (out / "events.jsonl").open("a", encoding="utf-8").write(
        json.dumps({"seq": 1, "ts": "t", "run_id": out.name,
                    "type": "launch.authorized"}) + "\n")
    return {"status": "completed", "halt_reason": "", "findings": 0, "confirmed": 0,
            "tokens": 42, "steps": 3, "requests": 0, "objective_achieved": False,
            "objective_done": 0, "objective_total": 0, "report_path": "",
            "html_path": "", "audit_intact": True, "out_dir": str(out)}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(server_mod, "execute_run", _fake_execute_run)
    app = create_app(runs_root=runs_root, dashboard_dir=None)
    return TestClient(app), runs_root


def _auth(**over):
    today = _dt.date.today()
    base = {
        "confirmed": True,
        "authorized_by": "Shivakant, security owner",
        "ticket": "ROE-2026-041",
        "starts": today.isoformat(),
        "ends": (today + _dt.timedelta(days=7)).isoformat(),
        "allow_private_ranges": False,
        "excluded_hosts": [],
    }
    base.update(over)
    return base


# ------------------------------------------------------------- /api/launch

def test_launch_classic_from_url_generates_engagement(client):
    client, runs_root = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net",
        "objective": "Assess the authorized web application for security weaknesses",
        "mode": "classic",
        "max_steps": 25,
        "authorization": _auth(),
    })
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "running" and body["driver"] == "classic"
    run_id = body["run_id"]
    run_dir = runs_root / run_id
    # engagement + authorization metadata exist in the run dir; YAML validates
    assert (run_dir / "engagement.yaml").exists()
    assert (run_dir / "authorization.json").exists()
    eng_yaml = (run_dir / "engagement.yaml").read_text()
    assert "demo.testfire.net" in eng_yaml and "allowed_hosts" in eng_yaml
    rec = json.loads((run_dir / "authorization.json").read_text())
    assert rec["confirmed"] is True and rec["host"] == "demo.testfire.net"
    assert "api_key" not in json.dumps(rec).lower()
    # the run finished (faked engine) and reports the exact driver
    deadline = time.time() + 5
    detail = {"status": "running"}
    while time.time() < deadline:
        detail = client.get(f"/api/runs/{run_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    assert detail["status"] == "completed" and detail["driver"] == "classic"


def test_launch_mission_from_url_arms_mission_driver(client):
    client, runs_root = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net",
        "objective": "Assess the authorized web application",
        "mode": "mission",
        "authorization": _auth(),
    })
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["driver"] == "mission"
    assert body["mission_id"] == body["run_id"] != ""
    run_dir = runs_root / body["run_id"]
    assert json.loads((run_dir / "manifest.json").read_text())["driver"] == "mission"


def test_launch_rejects_missing_confirmation(client):
    client, _ = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net",
        "objective": "assess",
        "mode": "classic",
        "authorization": _auth(confirmed=False),
    })
    assert r.status_code == 400
    assert "confirmation" in r.json()["detail"].lower()


def test_launch_rejects_missing_authorization_metadata(client):
    client, _ = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net",
        "objective": "assess",
        "mode": "classic",
        "authorization": _auth(authorized_by=""),
    })
    assert r.status_code == 400
    assert "authorized_by" in r.json()["detail"]


@pytest.mark.parametrize("url", [
    "demo.testfire.net", "ftp://demo.testfire.net", "https://",
    "https://admin:pw@demo.testfire.net", "http://127.0.0.1:8901/",
])
def test_launch_rejects_bad_urls_with_actionable_errors(client, url):
    client, _ = client
    r = client.post("/api/launch", json={
        "target_url": url, "objective": "assess", "mode": "classic",
        "authorization": _auth(),
    })
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail and "generated engagement" not in detail  # honest, specific


def test_launch_private_target_requires_explicit_optin(client):
    client, _ = client
    r = client.post("/api/launch", json={
        "target_url": "http://127.0.0.1:8901/", "objective": "local lab",
        "mode": "classic", "authorization": _auth(),
    })
    assert r.status_code == 400
    assert "private" in r.json()["detail"] or "loopback" in r.json()["detail"]
    r2 = client.post("/api/launch", json={
        "target_url": "http://127.0.0.1:8901/", "objective": "local lab",
        "mode": "classic",
        "authorization": _auth(allow_private_ranges=True),
    })
    assert r2.status_code == 202, r2.text
    assert r2.json()["authorization"]["allow_private_ranges"] is True


def test_launch_unknown_mode_is_400(client):
    client, _ = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net", "objective": "assess",
        "mode": "yolo", "authorization": _auth()})
    assert r.status_code == 400
    assert "classic" in r.json()["detail"] and "mission" in r.json()["detail"]


def test_launch_records_authorization_event(client):
    client, runs_root = client
    r = client.post("/api/launch", json={
        "target_url": "https://demo.testfire.net", "objective": "assess",
        "mode": "classic", "authorization": _auth()})
    run_id = r.json()["run_id"]
    events = (runs_root / run_id / "events.jsonl").read_text()
    assert "launch.authorized" in events and "ROE-2026-041" in events


# ------------------------------------------------- /api/llm/ollama/status

def _ollama_tags(models):
    class R:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"models": [{"name": m} for m in models]}
    return lambda url, timeout=None: R()


def test_ollama_status_connected_lists_models(client, monkeypatch):
    client, _ = client
    monkeypatch.setattr(_requests, "get", _ollama_tags(["RandomModel:latest", "qwen2.5:7b-instruct"]))
    r = client.get("/api/llm/ollama/status")
    assert r.status_code == 200
    body = r.json()
    assert body["connected"] is True and body["state"] == "connected"
    assert body["message"] == "Ollama connected — 2 models available"
    assert body["models"] == ["RandomModel:latest", "qwen2.5:7b-instruct"]
    # heuristic initial selection prefers the known tool-capable family,
    # but discovery is never claimed as proof of tool-calling
    assert body["default_model"] == "qwen2.5:7b-instruct"


def test_ollama_status_no_models(client, monkeypatch):
    client, _ = client
    monkeypatch.setattr(_requests, "get", _ollama_tags([]))
    body = client.get("/api/llm/ollama/status").json()
    assert body["connected"] is True and body["state"] == "no_models"
    assert body["message"] == ("Ollama is running, but no models are installed. "
                               "Pull a supported model first.")


def test_ollama_status_not_running_is_honest(client, monkeypatch):
    client, _ = client

    def boom(url, timeout=None):
        raise _requests.ConnectionError("ECONNREFUSED")

    monkeypatch.setattr(_requests, "get", boom)
    body = client.get("/api/llm/ollama/status").json()
    assert body["connected"] is False and body["state"] == "not_running"
    assert body["message"] == "Ollama is not running. Start Ollama and retry."
    assert body["models"] == []


def test_ollama_status_custom_endpoint_override(client, monkeypatch):
    client, _ = client
    seen = []

    def fake_get(url, timeout=None):
        seen.append(url)
        return _ollama_tags(["llama3.2:latest"])(url)

    monkeypatch.setattr(_requests, "get", fake_get)
    body = client.get("/api/llm/ollama/status?base_url=http://127.0.0.1:11435/v1").json()
    assert "http://127.0.0.1:11435/api/tags" in seen
    assert body["base_url"] == "http://127.0.0.1:11435"
    assert body["default_model"] == "llama3.2:latest"

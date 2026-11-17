"""Mission API (Phase 2, additive): POST /api/missions launches the mission
DRIVER for real (the execute_run fake here delegates to run_mission_driver —
the actual coordination execution path), and the GET endpoints read back the
identity triple + tasks + journal tail. The classic runs API is untouched.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import redteam.config as config_mod
import redteam.server as server_mod
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import MockExecutor
from redteam.runtime import RunManifest
from redteam.server import create_app


def _await_mission(runs_root, mission_id, timeout=10.0):
    """202 = accepted; the engine thread finishes asynchronously — wait for the
    mission record to reach a terminal status (test_server's own pattern)."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = json.loads((runs_root / mission_id / "mission.json").read_text())
        rec = rec.get("mission") if isinstance(rec.get("mission"), dict) else rec
        if rec.get("status") in ("succeeded", "failed", "halted", "cancelled"):
            return rec
        time.sleep(0.05)
    raise AssertionError("mission did not finish in time")


def _make_engagement(name: str = "Lab") -> Engagement:
    return Engagement(
        name=name, client="Local", authorized_by="me", ticket="T-1",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("example.com",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http", "https"),
        max_requests_per_second=3.0, max_total_requests=100,
        allow_private_ranges=False, require_approval_for=(),
        max_run_seconds=60, max_llm_tokens=1000,
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    engagement = _make_engagement()
    monkeypatch.setattr(config_mod, "load_engagement", lambda path: engagement)

    def mission_execute_run(opts):
        # Only the "mission" driver delegates to the coordination core (exactly
        # what the run.py seam does); a classic opts passes through untouched.
        if opts.driver != "mission":
            out = Path(opts.out_dir)
            RunManifest(objective=opts.objective,
                        engagement=engagement.name).save(out / "manifest.json")
            return {"status": "completed", "halt_reason": "", "findings": 0,
                    "confirmed": 0, "tokens": 0, "steps": 0, "requests": 0,
                    "objective_achieved": False, "objective_done": 0,
                    "objective_total": 0, "report_path": "", "html_path": "",
                    "audit_intact": True, "out_dir": str(out)}
        # The REAL coordination execution path (what RunOptions.driver="mission"
        # runs), invoked exactly as the run.py seam invokes it.
        return run_mission_driver(
            engagement=engagement, out_dir=Path(opts.out_dir),
            objective=opts.objective, attack_tree=None, bus=opts.events,
            opts=opts, executor=MockExecutor(), say=lambda text: None)

    monkeypatch.setattr(server_mod, "execute_run", mission_execute_run)
    app = create_app(runs_root=runs_root, dashboard_dir=None)
    return TestClient(app), runs_root


def test_post_launches_mission_with_identity_triple(harness):
    client, runs_root = harness
    r = client.post("/api/missions", json={
        "engagement_path": "lab.yaml", "objective": "Probe the lab app",
        "max_steps": 20})
    assert r.status_code == 202
    body = r.json()
    assert body["driver"] == "mission"
    # C1: the response echoes the identity triple — mission_id == run_id by
    # CONSTRUCTION, both fields present, run_ids the list.
    assert body["mission_id"] == body["run_id"]
    assert body["run_ids"] == [body["run_id"]]
    record = _await_mission(runs_root, body["mission_id"])
    mission_dir = runs_root / body["mission_id"]
    assert (mission_dir / "mission_journal.jsonl").exists()
    assert record["mission_id"] == record["run_id"] == mission_dir.name


def test_list_and_detail_read_back(harness):
    client, runs_root = harness
    launch = client.post("/api/missions", json={
        "engagement_path": "lab.yaml", "objective": "Probe"}).json()
    mission_id = launch["mission_id"]
    _await_mission(runs_root, mission_id)
    listed = client.get("/api/missions").json()["missions"]
    assert len(listed) == 1
    assert listed[0]["mission_id"] == mission_id
    assert listed[0]["run_ids"] == [mission_id]
    detail = client.get(f"/api/missions/{mission_id}").json()
    assert detail["status"] == "succeeded"
    assert detail["tasks"], "the smoke task must be recorded"
    assert detail["tasks"][0]["status"] == "succeeded"
    types = [e["type"] for e in detail["recent_events"]]
    assert "MISSION_STARTED" in types and "TASK_SUCCEEDED" in types


def test_mission_launch_validations(harness):
    client, _ = harness
    # inactive window / bad engagement → 400 (same contract as POST /api/runs)
    r = client.post("/api/missions", json={
        "engagement_path": "lab.yaml", "objective": ""})
    assert r.status_code == 422          # empty objective rejected at the body
    assert client.get("/api/missions/nope").status_code == 404


def test_runs_api_untouched_by_mission_endpoints(harness):
    client, runs_root = harness
    r = client.post("/api/runs", json={
        "engagement_path": "lab.yaml", "objective": "Classic run",
        "multi_agent": False})
    assert r.status_code == 202
    assert "mission_id" not in r.json()      # classic launch response unchanged
    # The mission listing only shows mission dirs (this run has none yet).
    missions = client.get("/api/missions").json()["missions"]
    assert all(m["mission_id"] != r.json()["run_id"] for m in missions)

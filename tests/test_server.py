"""Headless server: lifecycle endpoints, adapters, approvals, SSE close behavior.

execute_run is faked (writes run artifacts directly) so these tests exercise the
HTTP surface without LLM calls, sandboxes, or network.
"""

from __future__ import annotations

import datetime as _dt
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import redteam.config as config_mod
import redteam.server as server_mod
from redteam.config import ConfigError, Engagement, LlmConfig, SandboxConfig
from redteam.runtime import RunManifest
from redteam.server import create_app


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

    def fake_execute_run(opts):
        out = Path(opts.out_dir)
        manifest = RunManifest.load(out / "manifest.json") or RunManifest(
            objective=opts.objective, engagement="Lab")
        manifest.status = "completed"
        manifest.steps = 7
        manifest.tokens = 1234
        manifest.findings = 1
        manifest.save(out / "manifest.json")
        (out / "events.jsonl").open("a", encoding="utf-8").write(
            json.dumps({"seq": 1, "ts": "t", "run_id": out.name, "type": "run.start"}) + "\n"
            + json.dumps({"seq": 2, "ts": "t", "run_id": out.name,
                          "type": "finding.recorded", "id": "F-1"}) + "\n")
        return {"status": "completed", "halt_reason": "", "findings": 1, "confirmed": 1,
                "tokens": 1234, "steps": 7, "requests": 0, "objective_achieved": True,
                "objective_done": 1, "objective_total": 1, "report_path": str(out / "report.md"),
                "html_path": "", "audit_intact": True, "out_dir": str(out)}

    monkeypatch.setattr(server_mod, "execute_run", fake_execute_run)
    app = create_app(runs_root=runs_root, dashboard_dir=None)
    client = TestClient(app)
    return client, runs_root, engagement


def test_health(harness):
    client, runs_root, _ = harness
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["version"] == server_mod.VERSION
    assert body["runs_root"] == str((runs_root).resolve())


def test_launch_and_lifecycle(harness):
    client, runs_root, engagement = harness
    r = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "Prove auth bypass",
        "max_steps": 10})
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "running"
    run_id = body["run_id"]
    assert (runs_root / run_id / "manifest.json").exists()

    # wait for the (faked) engine thread to finish
    deadline = time.time() + 5
    while time.time() < deadline:
        detail = client.get(f"/api/runs/{run_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.05)
    assert detail["status"] == "completed"

    listed = client.get("/api/runs").json()["runs"]
    assert [x["run_id"] for x in listed] == [run_id]
    assert listed[0]["objective"] == "Prove auth bypass"
    assert listed[0]["steps"] == 7 and listed[0]["tokens"] == 1234

    # events replay with cursor
    ev = client.get(f"/api/runs/{run_id}/events?after=0").json()
    assert [e["seq"] for e in ev["events"]] == [1, 2]
    assert ev["next_cursor"] == 2
    ev2 = client.get(f"/api/runs/{run_id}/events?after=1").json()
    assert [e["seq"] for e in ev2["events"]] == [2]


def test_launch_rejects_bad_engagement(harness, monkeypatch):
    client, _, _ = harness
    monkeypatch.setattr(config_mod, "load_engagement",
                        lambda path: (_ for _ in ()).throw(ConfigError("bad roe")))
    r = client.post("/api/runs", json={
        "engagement_path": "/nonexistent/engagement.yaml", "objective": "x"})
    assert r.status_code == 400
    assert "detail" in r.json()


def test_launch_rejects_invalid_engagement_values(harness, monkeypatch):
    """Structurally-valid YAML with invalid VALUES (e.g. a bad objective criterion
    kind, raised as ValueError by the dataclass validator) must be a client 400,
    not an unhandled 500 that leaks a stack trace. Regression: live E2E found
    POST /api/runs -> 500 for kind: surface_map."""
    client, _, _ = harness
    monkeypatch.setattr(config_mod, "load_engagement",
                        lambda path: (_ for _ in ()).throw(
                            ValueError("criterion kind must be one of "
                                       "('data_access', 'privilege', 'host_access', 'flag'), "
                                       "got 'surface_map'")))
    r = client.post("/api/runs", json={
        "engagement_path": "/tmp/engagement.yaml", "objective": "x"})
    assert r.status_code == 400
    assert "surface_map" in r.json()["detail"]


def test_unknown_run_404(harness):
    client, _, _ = harness
    for path in ("/api/runs/does-not-exist", "/api/runs/does-not-exist/events",
                 "/api/runs/does-not-exist/approvals", "/api/runs/does-not-exist/report"):
        assert client.get(path).status_code == 404, path
    assert client.post("/api/runs/does-not-exist/stop").status_code == 404
    # path traversal is not a run
    assert client.get("/api/runs/..%2F..%2Fetc").status_code == 404


def test_stop_writes_kill_file(harness):
    client, runs_root, engagement = harness
    run_id = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "stop me"}).json()["run_id"]
    assert client.post(f"/api/runs/{run_id}/stop").json() == {"ok": True}
    assert (runs_root / run_id / "STOP").exists()


def test_detail_adapters(harness, tmp_path):
    client, runs_root, engagement = harness
    run_id = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "detail test"}).json()["run_id"]
    run_dir = runs_root / run_id

    (run_dir / "objective.json").write_text(json.dumps({
        "name": "Win", "description": "Test objective",
        "criteria": [{"id": "c1", "description": "a thing", "achieved": True,
                      "evidence": "proof"}]}), encoding="utf-8")
    (run_dir / "killchain.json").write_text(json.dumps([
        {"stage": "reconnaissance", "status": "achieved", "notes": []},
        {"stage": "initial-access", "status": "not_started", "notes": []}]), encoding="utf-8")
    (run_dir / "graph.json").write_text(json.dumps({
        "nodes": [{"kind": "host", "key": "example.com", "attrs": {}},
                  {"kind": "endpoint", "key": "https://example.com/login", "attrs": {}},
                  {"kind": "parameter", "key": "user", "attrs": {}}],
        "edges": []}), encoding="utf-8")
    (run_dir / "attack_tree.json").write_text(json.dumps([
        {"technique": "sqli", "target": "/login", "status": "completed"},
        {"technique": "xss", "target": "/search", "status": "todo"}]), encoding="utf-8")
    (run_dir / "reflections.json").write_text(json.dumps(
        [{"ts": "t", "assessment": "going well", "focus_next": ["sqli"]}]), encoding="utf-8")

    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["objective"]["achieved"] is True
    assert detail["objective"]["done"] == 1 and detail["objective"]["total"] == 1
    assert [s["stage"] for s in detail["killchain"]] == ["reconnaissance", "initial-access"]
    assert detail["killchain"][0]["achieved"] is True
    assert detail["killchain"][1]["achieved"] is False
    assert len(detail["graph"]["endpoints"]) == 1
    assert len(detail["graph"]["hosts"]) == 1
    assert len(detail["graph"]["params"]) == 1
    assert detail["attack_tree"] == {"todo": 1, "in_progress": 0, "failed": 0, "completed": 1}
    assert detail["reflections"][0]["assessment"] == "going well"


def test_report_endpoint(harness):
    client, runs_root, engagement = harness
    run_id = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "report test"}).json()["run_id"]
    (runs_root / run_id / "report.md").write_text("# Report\ncontent", encoding="utf-8")
    r = client.get(f"/api/runs/{run_id}/report")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert r.text.startswith("# Report")
    # missing report -> 404
    run_id2 = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "no report"}).json()["run_id"]
    assert client.get(f"/api/runs/{run_id2}/report").status_code == 404


def test_approval_endpoints(harness):
    client, runs_root, engagement = harness
    run_id = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "approve test"}).json()["run_id"]
    run_dir = runs_root / run_id
    (run_dir / "approvals.json").write_text(json.dumps([
        {"id": "apr-abc", "action": "drop table", "details": {"details": "why"},
         "ts": "t", "status": "pending", "approved": None, "resolved_ts": None},
        {"id": "apr-old", "action": "done", "details": {}, "ts": "t",
         "status": "resolved", "approved": True, "resolved_ts": "t2"},
    ]), encoding="utf-8")

    pending = client.get(f"/api/runs/{run_id}/approvals").json()["pending"]
    assert [p["id"] for p in pending] == ["apr-abc"]

    r = client.post("/api/approvals/apr-abc", json={"approve": True})
    assert r.json() == {"ok": True}
    data = json.loads((run_dir / "approvals.json").read_text(encoding="utf-8"))
    rec = next(x for x in data if x["id"] == "apr-abc")
    assert rec["status"] == "resolved" and rec["approved"] is True

    # already resolved -> 404; unknown -> 404; bad body -> 422
    assert client.post("/api/approvals/apr-abc", json={"approve": True}).status_code == 404
    assert client.post("/api/approvals/apr-nope", json={"approve": True}).status_code == 404
    assert client.post("/api/approvals/apr-x", json={"approve": "maybe"}).status_code == 422
    assert client.post("/api/approvals/apr-x", json={}).status_code == 422


def test_sse_drains_and_closes_on_finished_manifest(harness):
    client, runs_root, engagement = harness
    run_id = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "sse test"}).json()["run_id"]
    deadline = time.time() + 5
    while time.time() < deadline and \
            client.get(f"/api/runs/{run_id}").json()["status"] == "running":
        time.sleep(0.05)

    frames = []
    with client.stream("GET", f"/api/runs/{run_id}/stream?after=0", timeout=10) as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        for line in resp.iter_lines():
            frames.append(line)
            if len([f for f in frames if f.startswith("data:")]) >= 2:
                break
    text = "\n".join(frames)
    assert "event: run_event" in text
    assert "run.start" in text


def test_launch_rejects_empty_objective(harness):
    """Gen-2 E2E regression: an empty objective used to launch a real run (202)
    — burning LLM budget toward no contract. Must be a 422 validation error."""
    client, _, _ = harness
    r = client.post("/api/runs", json={
        "engagement_path": "/tmp/engagement.yaml", "objective": ""})
    assert r.status_code == 422


def test_launch_refuses_scope_self_targeting(harness, monkeypatch):
    """Live-fire lesson: a scope that includes the control plane's own host:port lets
    the agent legally attack its own console. The launch endpoint must refuse with a
    400 BEFORE arming any run, and the refusal must name the offending port."""
    client, runs_root, engagement = harness
    # The harness engagement targets example.com — a control plane on 127.0.0.1:8000
    # does NOT collide with it, so first prove a clean launch still passes validation.
    app = create_app(runs_root=runs_root, dashboard_dir=None,
                     control_plane=("127.0.0.1", 8000))
    clean = TestClient(app)
    r = clean.post("/api/runs", json={
        "engagement_path": "e.yaml", "objective": "Prove XSS", "max_steps": 1})
    assert r.status_code == 202

    # Now the misconfigured scope: localhost lab target + the server's own port in
    # allowed_ports. This is exactly the operator error live-fire caught.
    bad = _make_engagement()
    object.__setattr__(bad, "allowed_hosts", ("localhost", "127.0.0.1"))
    object.__setattr__(bad, "allowed_ports", (8000, 443))
    monkeypatch.setattr(config_mod, "load_engagement", lambda path: bad)
    r = clean.post("/api/runs", json={
        "engagement_path": "e.yaml", "objective": "Prove XSS", "max_steps": 1})
    assert r.status_code == 400
    assert "self-targeting" in r.json()["detail"]
    assert "8000" in r.json()["detail"]

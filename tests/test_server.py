"""Headless server: lifecycle endpoints, adapters, approvals, SSE close behavior.

execute_run is faked (writes run artifacts directly) so these tests exercise the
HTTP surface without LLM calls, sandboxes, or network.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import time
from pathlib import Path

import pytest
import yaml
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


def test_launch_llm_override_writes_effective_engagement(harness):
    """The dashboard's provider/model selector arrives as LaunchBody.llm; the
    server must materialize it as an effective engagement.yaml inside the run
    dir (engine runs THAT copy) and launch the run with it."""
    client, runs_root, engagement = harness
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\nllm:\n  providers: []\n")
    r = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "Prove auth bypass",
        "llm": {"provider": "zai", "model": "glm-5.3", "api_key": "sk-test"}})
    assert r.status_code == 202, r.text
    eff = runs_root / r.json()["run_id"] / "engagement.yaml"
    assert eff.exists()
    data = yaml.safe_load(eff.read_text())
    prov = data["llm"]["providers"][0]
    assert prov["kind"] == "zai"
    assert prov["models_allow"] == ["glm-5.3"]
    # the operator's selection is surfaced in the event feed
    ev_lines = (runs_root / r.json()["run_id"] / "events.jsonl").read_text()
    assert "llm.selected" in ev_lines


def test_launch_without_llm_override_leaves_engagement_alone(harness):
    client, runs_root, engagement = harness
    r = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "no override"})
    assert r.status_code == 202
    assert not (runs_root / r.json()["run_id"] / "engagement.yaml").exists()


def test_launch_llm_override_uses_run_scoped_credentials(harness, monkeypatch):
    """Builder-04A credential isolation: the typed key is carried RUN-SCOPED on
    the run's RunOptions (resolved into that run's provider sessions at
    construction) — the process environment is NOT mutated, so concurrent runs
    with different keys cannot cross-use credentials. The key never hits disk."""
    client, runs_root, engagement = harness
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    captured: list = []

    def capturing_execute_run(opts):
        captured.append(opts)
        with (Path(opts.out_dir) / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write("")  # keep the server-emitted events (llm.selected) intact

    monkeypatch.setattr(server_mod, "execute_run", capturing_execute_run)
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "run scoped",
        "llm": {"provider": "openai", "model": "gpt-sol", "api_key": "sk-test"}})
    assert r.status_code == 202
    assert os.environ.get("OPENAI_API_KEY") != "sk-test"      # env untouched
    assert captured[0].llm_credentials == {"OPENAI_API_KEY": "sk-test"}
    eff = yaml.safe_load((runs_root / r.json()["run_id"] / "engagement.yaml").read_text())
    assert "sk-test" not in json.dumps(eff)                   # never on disk
    assert eff["llm"]["providers"][0]["models_allow"] == ["gpt-sol"]
    # no persisted artifact in the run dir carries the key
    run_dir = runs_root / r.json()["run_id"]
    for p in run_dir.iterdir():
        assert "sk-test" not in p.read_text(encoding="utf-8", errors="ignore"), p.name


def test_concurrent_runs_same_provider_different_keys_isolated(harness, monkeypatch):
    """The exact PR #21 failure mode: run A (OpenAI, key A) and run B (OpenAI,
    key B) launched back-to-back. Each run's options must carry ITS key — no
    shared env var, no cross-use."""
    client, runs_root, engagement = harness
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    captured: list = []

    def capturing_execute_run(opts):
        captured.append(opts)
        with (Path(opts.out_dir) / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write("")  # keep the server-emitted events (llm.selected) intact

    monkeypatch.setattr(server_mod, "execute_run", capturing_execute_run)
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    ra = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "run a",
        "llm": {"provider": "openai", "api_key": "sk-key-a"}})
    rb = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "run b",
        "llm": {"provider": "openai", "api_key": "sk-key-b"}})
    assert ra.status_code == rb.status_code == 202
    creds = [o.llm_credentials.get("OPENAI_API_KEY") for o in captured]
    assert sorted(creds) == ["sk-key-a", "sk-key-b"]
    assert os.environ.get("OPENAI_API_KEY") != "sk-key-a"
    assert os.environ.get("OPENAI_API_KEY") != "sk-key-b"


def test_env_preconfigured_key_still_reaches_run(harness, monkeypatch):
    """No per-run key submitted -> run-scoped credentials stay empty; operators
    who preconfigure the standard env var are unaffected."""
    client, runs_root, engagement = harness
    monkeypatch.setenv("ZAI_API_KEY", "env-preset")
    captured: list = []

    def capturing_execute_run(opts):
        captured.append(opts)
        with (Path(opts.out_dir) / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write("")  # keep the server-emitted events (llm.selected) intact

    monkeypatch.setattr(server_mod, "execute_run", capturing_execute_run)
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "env preset",
        "llm": {"provider": "zai", "model": "glm-5.3"}})
    assert r.status_code == 202
    assert captured[0].llm_credentials == {}                  # env path unchanged


def test_mission_launch_basic(harness, monkeypatch):
    """POST /api/missions: mission identity == run identity (same minted id,
    separate logical fields), driver recorded in the manifest + detail API, and
    the mission list sees it."""
    client, runs_root, engagement = harness

    def mission_execute_run(opts):
        out = Path(opts.out_dir)
        manifest = RunManifest.load(out / "manifest.json") or RunManifest(
            objective=opts.objective, engagement="Lab")
        manifest.status = "completed"
        manifest.save(out / "manifest.json")
        (out / "events.jsonl").write_text(
            json.dumps({"seq": 1, "ts": "t", "run_id": out.name, "type": "run.start"}) + "\n",
            encoding="utf-8")
        (out / "mission.json").write_text(json.dumps({
            "mission": {"mission_id": out.name, "run_id": out.name,
                        "run_ids": [out.name], "engagement": "Lab",
                        "objective": opts.objective, "status": "succeeded"},
            "tasks": [{"id": "T-1", "technique": "sqli", "target": "/orders",
                       "status": "succeeded"}]}), encoding="utf-8")

    monkeypatch.setattr(server_mod, "execute_run", mission_execute_run)
    r = client.post("/api/missions", json={
        "engagement_path": str(engagement), "objective": "adaptive mission"})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["mission_id"] == body["run_id"]               # same value, two fields
    run_id = body["run_id"]
    manifest = (runs_root / run_id / "manifest.json")
    assert json.loads(manifest.read_text())["driver"] == "mission"
    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["driver"] == "mission"
    mdetail = client.get(f"/api/missions/{run_id}").json()
    assert mdetail["status"] == "succeeded"
    assert mdetail["tasks"][0]["technique"] == "sqli"
    listed = client.get("/api/missions").json()["missions"]
    assert any(m["mission_id"] == run_id for m in listed)


def test_mission_launch_llm_override(harness, monkeypatch):
    """Both drivers share the same provider/model contract: effective engagement
    written, run-scoped credentials, llm.selected event, driver stays mission."""
    client, runs_root, engagement = harness
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    captured: list = []

    def capturing_execute_run(opts):
        captured.append(opts)
        with (Path(opts.out_dir) / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write("")  # keep the server-emitted events (llm.selected) intact

    monkeypatch.setattr(server_mod, "execute_run", capturing_execute_run)
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r = client.post("/api/missions", json={
        "engagement_path": str(src), "objective": "mission with model",
        "llm": {"provider": "gemini", "model": "gemini-argon", "api_key": "sk-g"}})
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]
    assert os.environ.get("GEMINI_API_KEY") != "sk-g"         # env untouched
    assert captured[0].llm_credentials == {"GEMINI_API_KEY": "sk-g"}
    assert captured[0].driver == "mission"
    eff = yaml.safe_load((runs_root / run_id / "engagement.yaml").read_text())
    assert eff["llm"]["providers"][0]["kind"] == "gemini"
    assert eff["llm"]["providers"][0]["models_allow"] == ["gemini-argon"]
    assert "sk-g" not in (runs_root / run_id / "engagement.yaml").read_text()
    assert "llm.selected" in (runs_root / run_id / "events.jsonl").read_text()


def test_mission_unknown_provider_needs_base_url(harness):
    client, runs_root, engagement = harness
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r = client.post("/api/missions", json={
        "engagement_path": str(src), "objective": "x",
        "llm": {"provider": "notaprovider"}})
    assert r.status_code == 400
    assert "notaprovider" in r.json()["detail"]
    r2 = client.post("/api/missions", json={
        "engagement_path": str(src), "objective": "x",
        "llm": {"provider": "lmstudio", "base_url": "http://127.0.0.1:1234/v1"}})
    assert r2.status_code == 202, r2.text


def test_mission_launch_rejects_bad_engagement(harness, monkeypatch):
    """Invalid engagement on the mission endpoint is a 400 and — unlike a dead
    run thread — leaves NO partially registered run behind."""
    client, runs_root, engagement = harness
    monkeypatch.setattr(config_mod, "load_engagement",
                        lambda path: (_ for _ in ()).throw(
                            config_mod.ConfigError("not a valid engagement")))
    before = set(runs_root.iterdir()) if runs_root.exists() else set()
    r = client.post("/api/missions", json={
        "engagement_path": "/nonexistent/engagement.yaml", "objective": "x"})
    assert r.status_code == 400
    after = set(runs_root.iterdir()) if runs_root.exists() else set()
    assert before == after                                    # nothing registered


def test_mission_unknown_404(harness):
    client, _, _ = harness
    assert client.get("/api/missions/does-not-exist").status_code == 404


def test_run_detail_includes_driver_classic(harness):
    client, runs_root, engagement = harness
    r = client.post("/api/runs", json={
        "engagement_path": str(engagement), "objective": "classic default"})
    assert r.status_code == 202
    detail = client.get(f"/api/runs/{r.json()['run_id']}").json()
    assert detail["driver"] == "classic"


def test_launch_llm_override_unknown_provider_needs_base_url(harness):
    """An unknown kind without an endpoint is a client 400 at launch, not a
    dead run thread; with base_url it is the openai_compat escape hatch."""
    client, runs_root, engagement = harness
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "x",
        "llm": {"provider": "notaprovider"}})
    assert r.status_code == 400
    assert "notaprovider" in r.json()["detail"]
    r2 = client.post("/api/runs", json={
        "engagement_path": str(src), "objective": "x",
        "llm": {"provider": "vllm", "base_url": "http://127.0.0.1:9999/v1",
                "model": "qwen2.5"}})
    assert r2.status_code == 202, r2.text
    eff = yaml.safe_load((runs_root / r2.json()["run_id"] / "engagement.yaml").read_text())
    assert eff["llm"]["providers"][0]["base_url"] == "http://127.0.0.1:9999/v1"


def test_llm_providers_endpoint(harness, monkeypatch):
    """Catalog reports key PRESENCE only — never the key itself."""
    client, _, _ = harness
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    body = client.get("/api/llm/providers").json()
    kinds = {p["kind"] for p in body["providers"]}
    assert {"openai", "zai", "gemini", "openrouter", "ollama"} <= kinds
    by_kind = {p["kind"]: p for p in body["providers"]}
    assert by_kind["ollama"]["key_set"] is True          # no key needed
    assert by_kind["openrouter"]["key_set"] is False     # deleted above
    assert "sk-" not in json.dumps(body)


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
        # read until the backlog event actually shows up: under load the first
        # data frames can both be ping heartbeats (CI flake 2026-11-17), so a
        # bare data-count break could stop before run_event is ever delivered.
        # The stream itself closes when the finished manifest drains — the
        # break here is only an early exit.
        for line in resp.iter_lines():
            frames.append(line)
            text = "\n".join(frames)
            if "event: run_event" in text and \
                    len([f for f in frames if f.startswith("data:")]) >= 2:
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


# =============================================================================
# Builder 04 — unified LLM selection: preflight + model discovery endpoints,
# startup reconciliation of interrupted runs, concurrent mission credential
# isolation, and registry-level mission finalization.
# =============================================================================

def test_llm_preflight_endpoint_passthrough_and_no_key_echo(harness, monkeypatch):
    from redteam.llm.preflight import PreflightCheck, PreflightResult
    client, _, _ = harness
    seen: dict = {}

    def fake_preflight(provider, model="", base_url="", api_key=None):
        seen.update(provider=provider, model=model, base_url=base_url, key=api_key)
        return PreflightResult(
            provider=provider, base_url=base_url or "http://127.0.0.1:11434/v1",
            model=model, reachable=True, model_found=True, tool_call_ok=True,
            args_parsed=True, ok=True, latency_ms=7, error="",
            checks=[PreflightCheck("reachable", True, "2 model(s) listed by the endpoint")])

    # the endpoint imports run_preflight at call time — patch the module attribute
    monkeypatch.setattr("redteam.llm.preflight.run_preflight", fake_preflight)
    r = client.post("/api/llm/preflight", json={
        "provider": "ollama", "model": "llama3.2", "api_key": "sk-preflight-secret"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["reachable"] is True
    assert body["checks"][0]["check"] == "reachable"
    assert seen == {"provider": "ollama", "model": "llama3.2", "base_url": "",
                    "key": "sk-preflight-secret"}
    # the result NEVER carries the key back to the client
    assert "sk-preflight-secret" not in json.dumps(body)


def test_llm_preflight_endpoint_requires_provider(harness):
    client, _, _ = harness
    r = client.post("/api/llm/preflight", json={"model": "llama3.2"})
    assert r.status_code == 422  # pydantic: provider min_length=1


def test_llm_models_endpoint_discovers_live_ids(harness, monkeypatch):
    client, _, _ = harness

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"id": "qwen2.5:7b"}, {"id": "llama3.2:latest"},
                             {"id": "llama3.2:latest"}]}  # duplicate id collapses

    monkeypatch.setattr("requests.get", lambda url, timeout: FakeResp())
    r = client.get("/api/llm/models", params={"provider": "ollama"})
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "ollama"
    assert body["base_url"] == "http://127.0.0.1:11434/v1"
    assert body["models"] == ["llama3.2:latest", "qwen2.5:7b"]


def test_llm_models_endpoint_reports_unreachable_honestly(harness, monkeypatch):
    import requests as rq
    client, _, _ = harness

    def boom(url, timeout):
        raise rq.ConnectionError("connection refused")

    monkeypatch.setattr("requests.get", boom)
    r = client.get("/api/llm/models", params={"provider": "ollama"})
    assert r.status_code == 502
    assert "model discovery failed" in r.json()["detail"]


def test_startup_reconciles_interrupted_runs(tmp_path, monkeypatch):
    """Runs execute as threads of the server process; at startup a manifest that
    still reads 'running' belongs to a dead process. The server must finalize
    manifest AND mission snapshot so no dashboard polls a zombie forever."""
    runs_root = tmp_path / "runs"
    zombie = runs_root / "20260101-000000-zombie"
    zombie.mkdir(parents=True)
    RunManifest(objective="zombie", engagement="Lab", driver="mission").save(
        zombie / "manifest.json")                       # status defaults to running
    (zombie / "mission.json").write_text(json.dumps(
        {"mission": {"mission_id": zombie.name, "status": "running",
                     "halt_reason": ""}, "tasks": []}), encoding="utf-8")
    # a run whose manifest finalized but whose mission record never did
    dangling = runs_root / "20260101-000001-dangling"
    dangling.mkdir(parents=True)
    m2 = RunManifest(objective="dangling", engagement="Lab", driver="mission")
    m2.status = "completed"
    m2.save(dangling / "manifest.json")
    (dangling / "mission.json").write_text(json.dumps(
        {"mission": {"mission_id": dangling.name, "status": "running",
                     "halt_reason": ""}, "tasks": []}), encoding="utf-8")

    monkeypatch.setattr(config_mod, "load_engagement",
                        lambda path: _make_engagement())
    create_app(runs_root=runs_root, dashboard_dir=None)

    m = json.loads((zombie / "manifest.json").read_text(encoding="utf-8"))
    assert m["status"] == "error"
    assert "server_restarted" in m["halt_reason"]
    zrec = json.loads((zombie / "mission.json").read_text(encoding="utf-8"))["mission"]
    assert zrec["status"] == "failed"
    assert "server_restarted" in zrec["halt_reason"]
    drec = json.loads((dangling / "mission.json").read_text(encoding="utf-8"))["mission"]
    assert drec["status"] == "failed"
    assert "run ended without mission finalization" in drec["halt_reason"]


def test_concurrent_missions_isolate_providers_models_and_keys(harness, monkeypatch):
    """Two missions launched together with DIFFERENT providers/models/keys: each
    run dir must carry its own effective engagement and llm.selected event, and
    NO key may appear in ANY persisted artifact of either run."""
    client, runs_root, _ = harness

    def slow_execute_run(opts):
        time.sleep(0.4)  # force thread overlap
        out = Path(opts.out_dir)
        manifest = RunManifest.load(out / "manifest.json") or RunManifest(
            objective=opts.objective, engagement="Lab")
        manifest.status = "completed"
        manifest.save(out / "manifest.json")

    monkeypatch.setattr(server_mod, "execute_run", slow_execute_run)
    src = runs_root.parent / "engagement-src.yaml"
    src.write_text("name: Lab\nclient: Local\n")
    r1 = client.post("/api/missions", json={
        "engagement_path": str(src), "objective": "mission one", "max_steps": 3,
        "llm": {"provider": "openrouter", "model": "z-ai/glm-4.6",
                "api_key": "sk-mission-one-secret"}})
    r2 = client.post("/api/missions", json={
        "engagement_path": str(src), "objective": "mission two", "max_steps": 3,
        "llm": {"provider": "zai", "model": "glm-5.3",
                "api_key": "sk-mission-two-secret"}})
    assert r1.status_code == 202 and r2.status_code == 202
    run1, run2 = r1.json()["run_id"], r2.json()["run_id"]

    deadline = time.time() + 10
    while time.time() < deadline:
        s1 = json.loads((runs_root / run1 / "manifest.json").read_text())["status"]
        s2 = json.loads((runs_root / run2 / "manifest.json").read_text())["status"]
        if s1 != "running" and s2 != "running":
            break
        time.sleep(0.1)
    assert s1 == "completed" and s2 == "completed"

    eng1 = yaml.safe_load((runs_root / run1 / "engagement.yaml").read_text())
    eng2 = yaml.safe_load((runs_root / run2 / "engagement.yaml").read_text())
    providers1 = eng1["llm"]["providers"]
    providers2 = eng2["llm"]["providers"]
    assert [p["models_allow"] for p in providers1 if p["kind"] == "openrouter"] \
        == [["z-ai/glm-4.6"]]
    assert [p["models_allow"] for p in providers2 if p["kind"] == "zai"] \
        == [["glm-5.3"]]

    events1 = (runs_root / run1 / "events.jsonl").read_text()
    events2 = (runs_root / run2 / "events.jsonl").read_text()
    assert "llm.selected" in events1
    sel1 = [json.loads(line) for line in events1.splitlines()
            if "llm.selected" in line]
    sel2 = [json.loads(line) for line in events2.splitlines()
            if "llm.selected" in line]
    assert sel1[0]["provider"] == "openrouter" and sel1[0]["model"] == "z-ai/glm-4.6"
    assert sel2[0]["provider"] == "zai" and sel2[0]["model"] == "glm-5.3"

    # credential isolation + persistence hygiene: scan EVERY byte of BOTH run dirs
    for root in (runs_root / run1, runs_root / run2):
        for path in root.rglob("*"):
            if path.is_file():
                blob = path.read_bytes()
                assert b"sk-mission-one-secret" not in blob, path
                assert b"sk-mission-two-secret" not in blob, path


def test_registry_error_finalizes_running_mission_snapshot(harness, monkeypatch):
    """Defense in depth: the mission driver is exception-safe, but if something
    crashes AFTER a running mission.json exists and BEFORE the driver's own
    finalization, the registry's error path must still close the snapshot."""
    client, runs_root, _ = harness

    def crashing_execute_run(opts):
        out = Path(opts.out_dir)
        (out / "mission.json").write_text(json.dumps(
            {"mission": {"mission_id": out.name, "status": "running",
                         "halt_reason": ""}, "tasks": []}), encoding="utf-8")
        raise RuntimeError("coordination exploded pre-driver")

    monkeypatch.setattr(server_mod, "execute_run", crashing_execute_run)
    r = client.post("/api/missions", json={
        "engagement_path": "e.yaml", "objective": "will crash", "max_steps": 2})
    assert r.status_code == 202
    run_id = r.json()["run_id"]
    deadline = time.time() + 5
    status = "running"
    while time.time() < deadline:
        try:
            status = json.loads((runs_root / run_id / "manifest.json").read_text())["status"]
        except (json.JSONDecodeError, OSError):
            status = "running"   # transient torn read while the thread saves
        if status != "running":
            break
        time.sleep(0.05)
    assert status == "error"
    deadline = time.time() + 5
    while True:
        try:
            rec = json.loads((runs_root / run_id / "mission.json").read_text())["mission"]
            break
        except (json.JSONDecodeError, OSError):
            if time.time() > deadline:
                raise
            time.sleep(0.05)
    assert rec["status"] == "failed"
    assert "mission_aborted" in rec["halt_reason"]


def test_delete_run_removes_a_finished_run(harness):
    from redteam.runtime import RunManifest
    client, runs_root, _ = harness
    rid = "20200101-000000-done"
    rd = runs_root / rid
    rd.mkdir(parents=True)
    RunManifest(objective="o", engagement="e").save(rd / "manifest.json")
    # mark it finished
    import json as _j
    m = _j.loads((rd / "manifest.json").read_text(encoding="utf-8"))
    m["status"] = "completed"
    (rd / "manifest.json").write_text(_j.dumps(m), encoding="utf-8")

    r = client.delete(f"/api/runs/{rid}")
    assert r.status_code == 200 and r.json()["deleted"] == rid
    assert not rd.exists()


def test_delete_refuses_a_running_run(harness):
    from redteam.runtime import RunManifest
    client, runs_root, _ = harness
    rid = "20200101-000000-live"
    rd = runs_root / rid
    rd.mkdir(parents=True)
    man = RunManifest(objective="o", engagement="e")
    man.status = "running"
    man.save(rd / "manifest.json")

    r = client.delete(f"/api/runs/{rid}")
    assert r.status_code == 409
    assert rd.exists()   # not deleted


def test_delete_unknown_run_is_404(harness):
    client, _, _ = harness
    assert client.delete("/api/runs/nope-not-here").status_code == 404


def test_delete_rejects_path_traversal(harness):
    client, runs_root, _ = harness
    # require_run rejects traversal characters before any filesystem touch
    r = client.delete("/api/runs/..%2f..%2fetc")
    assert r.status_code == 404

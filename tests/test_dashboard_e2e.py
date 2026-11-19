"""Browser E2E: dashboard mission-control over a REAL FastAPI server + built UI.

A deterministic fake engine replaces execute_run (the ONE assembly line): it
emits real events through the run's EventBus, honours the STOP kill file, and
writes the artifacts the detail API / mission panel read (findings.json,
mission.json, mission_journal.jsonl, report.md, objective.json, attack_tree).
This tests the full operator surface — launch (both drivers), live event
stream, stop, report, run-detail route, refresh recovery, mission panel
honesty — NOT real-model offensive effectiveness (the engine is a fixture).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
import yaml

import redteam.server as server_mod
from redteam.runtime import RunManifest

REPO = Path(__file__).resolve().parents[1]
DASHBOARD_OUT = REPO / "dashboard" / "out"


def _engagement_yaml(tmp_path: Path) -> str:
    """A REAL engagement file (validated by the real loader at launch)."""
    import datetime as _dt
    today = _dt.date.today()
    data = {
        "name": "E2E Lab", "client": "Local", "authorized_by": "me",
        "ticket": "T-E2E", "starts": str(today), "ends": str(today),
        "scope": {
            "allowed_hosts": ["127.0.0.1"], "excluded_hosts": [],
            "allowed_ports": [80, 8000, 8896], "allowed_schemes": ["http"],
            "max_requests_per_second": 5.0, "max_total_requests": 100,
        },
        "rules": {"require_approval_for": []},
        "budgets": {"max_run_seconds": 600, "max_llm_tokens": 50000},
        "sandbox": {"enable": False},
        "llm": {},
    }
    path = tmp_path / "engagement.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return str(path)


def _fake_execute_run(opts):
    """Deterministic stand-in for the real engine: same event/artifact contract,
    STOP-aware, driver-aware. Findings here are FIXTURE DATA, not discoveries."""
    import datetime as _dt

    out = Path(opts.out_dir)
    bus = opts.events
    manifest = RunManifest.load(out / "manifest.json") or RunManifest(
        objective=opts.objective, engagement="E2E Lab")
    manifest.driver = opts.driver
    manifest.save(out / "manifest.json")

    def emit(type: str, **fields) -> None:  # noqa: A002 — event vocabulary key
        from redteam.events import safe_emit
        safe_emit(bus, type, **fields)

    mode = ("mission coordination" if opts.driver == "mission"
            else "multi-agent swarm")
    emit("run.start", objective=opts.objective, engagement="E2E Lab", mode=mode)
    emit("phase.change", phase="RECON", round=1)

    if opts.driver == "mission":
        # mission snapshot + journal land EARLY so the panel has real data mid-run
        tasks = [
            {"id": "T-1", "technique": "sqli", "target": "/orders", "status": "succeeded",
             "specialist": "exploit", "attempts": 1},
            {"id": "T-2", "technique": "idor", "target": "/invoices/1", "status": "running",
             "specialist": "recon", "attempts": 1},
        ]
        mission = {"mission_id": out.name, "run_id": out.name, "run_ids": [out.name],
                   "engagement": "E2E Lab", "objective": opts.objective,
                   "status": "running", "halt_reason": ""}
        (out / "mission.json").write_text(json.dumps({"mission": mission, "tasks": tasks}),
                                          encoding="utf-8")
        journal = [
            {"seq": 1, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "type": "mission.created"},
            {"seq": 2, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "type": "task.created", "task_id": "T-1"},
            {"seq": 3, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "type": "task.succeeded", "task_id": "T-1"},
            {"seq": 4, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "type": "mission.replan"},
            {"seq": 5, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(), "type": "task.created", "task_id": "T-2"},
        ]
        (out / "mission_journal.jsonl").write_text(
            "\n".join(json.dumps(e) for e in journal) + "\n", encoding="utf-8")
        emit("phase.change", phase="EXPLOIT", round=2)   # replan moved the round forward

    stopped = False
    # findings.json is written INCREMENTALLY (the real FindingStore persists on
    # every mutation), so the detail poll shows findings mid-run.
    findings: list[dict] = []

    def _persist_findings() -> None:
        (out / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    for step in range(60):
        if (out / "STOP").exists():
            stopped = True
            break
        emit("agent.turn", role="recon" if opts.driver == "mission" else "orchestrator",
             step=step + 1, model="fixture-model", content=f"fixture step {step + 1}")
        if step == 0:
            findings.append({"id": "F-1", "title": "Reflected XSS in search",
                             "severity": "medium", "confidence": "tentative",
                             "description": "fixture"})
            _persist_findings()
            emit("finding.recorded", id="F-1", title="Reflected XSS in search",
                 severity="medium", confidence="tentative")
        if step == 2:
            findings.append({"id": "F-3", "title": "IDOR on invoice export",
                             "severity": "high", "confidence": "pending_verification",
                             "description": "fixture"})
            _persist_findings()
            emit("finding.recorded", id="F-3", title="IDOR on invoice export",
                 severity="high", confidence="pending_verification")
        if step == 4:
            # the independent verifier reproduced F-2 mid-run (FindingStore is
            # the only writer that may set confidence=confirmed)
            findings.append({"id": "F-2", "title": "SQLi in orders filter",
                             "severity": "high", "confidence": "confirmed",
                             "description": "fixture"})
            _persist_findings()
            emit("finding.confirmed", id="F-2", title="SQLi in orders filter",
                 severity="high", confidence="confirmed")
        time.sleep(0.2)
    (out / "report.md").write_text(
        "# E2E Lab — deterministic fixture report\n\nProduced by the fake engine.\n",
        encoding="utf-8")
    (out / "objective.json").write_text(json.dumps({
        "description": opts.objective,
        "criteria": [{"id": "C-1", "description": "prove order-table access",
                      "achieved": not stopped, "evidence": "fixture proof"}],
    }), encoding="utf-8")
    (out / "attack_tree.json").write_text(json.dumps([
        {"id": "A-1", "technique": "sqli", "target": "/orders", "status": "completed"},
        {"id": "A-2", "technique": "idor", "target": "/invoices/1", "status": "in_progress"},
        {"id": "A-3", "technique": "rce", "target": "/admin", "status": "todo"},
    ]), encoding="utf-8")
    (out / "killchain.json").write_text(json.dumps([
        {"stage": "recon", "status": "achieved", "achieved_at": "2026-11-18T00:00:00Z"},
        {"stage": "exploit", "status": "in_progress"},
    ]), encoding="utf-8")

    if opts.driver == "mission":
        mission = {"mission_id": out.name, "run_id": out.name, "run_ids": [out.name],
                   "engagement": "E2E Lab", "objective": opts.objective,
                   "status": ("halted" if stopped else "succeeded"),
                   "halt_reason": "operator_stop" if stopped else ""}
        (out / "mission.json").write_text(json.dumps({
            "mission": mission,
            "tasks": [{"id": "T-1", "technique": "sqli", "target": "/orders",
                       "status": "succeeded", "specialist": "exploit", "attempts": 1},
                      {"id": "T-2", "technique": "idor", "target": "/invoices/1",
                       "status": "succeeded" if not stopped else "failed",
                       "specialist": "recon", "attempts": 2}],
        }), encoding="utf-8")

    manifest.status = "halted" if stopped else "completed"
    manifest.steps = 9
    manifest.findings = 1          # confirmed count (F-2); F-3 awaits the verifier
    manifest.tokens = 4321
    manifest.halt_reason = "operator_stop" if stopped else ""
    manifest.save(out / "manifest.json")
    emit("run.finish", status=manifest.status, findings=manifest.findings,
         tokens=4321, halt_reason=manifest.halt_reason)
    return {"status": manifest.status, "halt_reason": manifest.halt_reason,
            "findings": 1, "confirmed": 1, "tokens": 4321, "steps": 9, "requests": 3,
            "objective_achieved": not stopped, "objective_done": 1, "objective_total": 1,
            "report_path": str(out / "report.md"), "html_path": "", "audit_intact": True,
            "out_dir": str(out)}


@pytest.fixture(scope="module")
def dashboard_ready():
    if not (DASHBOARD_OUT / "index.html").exists():
        pytest.skip("dashboard/out not built (npm run build)")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            if not p.chromium.executable_path:
                pytest.skip("chromium not installed")
    except Exception as exc:  # playwright missing entirely
        pytest.skip(f"playwright unavailable: {exc}")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """Real FastAPI app (dashboard served) with the deterministic fake engine."""
    root = tmp_path_factory.mktemp("e2e")
    runs_root = root / "runs"
    runs_root.mkdir()
    real_execute_run = server_mod.execute_run
    server_mod.execute_run = _fake_execute_run          # patch the module global
    try:
        import uvicorn
        app = server_mod.create_app(runs_root=runs_root, dashboard_dir=DASHBOARD_OUT)
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
        srv = uvicorn.Server(config)
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)
        port = srv.servers[0].sockets[0].getsockname()[1]
        yield {"base": f"http://127.0.0.1:{port}", "runs_root": runs_root}
        srv.should_exit = True
        thread.join(timeout=5)
    finally:
        server_mod.execute_run = real_execute_run


@pytest.fixture(scope="module")
def page(dashboard_ready, server):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        yield context.new_page()
        context.close()
        browser.close()


def _launch(page, server, tmp_factory, mode: str, objective: str) -> str:
    """Fill + submit the URL-first launch form (Builder 04); returns the run id.

    The server builds and validates the engagement from the target URL
    (POST /api/launch) — no engagement file is authored by hand. The provider
    stays on "engine default" here because the e2e engine is a fixture and the
    sandbox has no Ollama; the ollama gate stays honest for real operators."""
    page.goto(server["base"] + "/")
    page.get_by_label("target url").fill("http://127.0.0.1:8896/")
    page.get_by_label("objective").fill(objective)
    page.get_by_label("authorized by").fill("e2e operator")
    page.get_by_label("ticket").fill("T-E2E")
    page.get_by_role("switch", name="local / private lab target").click()
    page.get_by_label("confirm authorization").check()
    page.get_by_label("provider").select_option(label="engine default (engagement yaml)")
    if mode == "mission":
        page.get_by_role("radio", name="Adaptive mission").click()
        page.get_by_role("button", name="LAUNCH MISSION").click()
    else:
        page.get_by_role("button", name="LAUNCH RUN", exact=True).click()
    # static export uses trailingSlash: the app router lands on /runs/?id=...
    page.wait_for_url(lambda url: "id=" in (url or ""), timeout=30_000)
    return page.url.split("id=")[1]


def test_full_operator_workflow(page, server, tmp_path):
    """The 14-step operator pass: classic launch -> live control -> report;
    adaptive mission launch -> mission panel -> stop; refresh recovery."""
    # -- 1. open dashboard ------------------------------------------------------
    page.goto(server["base"] + "/")
    assert page.get_by_text("RED TEAMS").is_visible()

    # -- 2. launch classic run --------------------------------------------------
    run_id = _launch(page, server, tmp_path, "classic", "Prove the order table is reachable")

    # -- 3. run-detail page reached, classic driver shown -----------------------
    page.wait_for_selector("text=ESTABLISHING LINK", state="detached", timeout=15_000)
    assert f"id={run_id}" in page.url
    page.wait_for_selector("text=CLASSIC", timeout=15_000)

    # -- 4. live events observed (EventRow renders "RUN START" + turn content) --
    page.wait_for_selector("text=RUN START", timeout=15_000)
    page.wait_for_selector("text=fixture step", timeout=15_000)

    # -- 5. findings inspected (recorded + confirmed via detail poll) -----------
    page.wait_for_selector("text=SQLi in orders filter", timeout=15_000)

    # -- 6. stop the run (two-step confirm) -------------------------------------
    page.wait_for_selector("text=RUN START", timeout=15_000)  # still live
    stop = page.get_by_role("button", name="STOP", exact=True)
    stop.click()
    try:
        page.get_by_role("button", name="CONFIRM STOP?", timeout=1500).click()
    except Exception:
        # the arm auto-disarms after 3.5s — re-arm and confirm again
        stop.click()
        page.get_by_role("button", name="CONFIRM STOP?").click()
    page.wait_for_selector("text=HALTED", timeout=20_000)
    assert "operator_stop" in page.locator("body").inner_text()

    # -- 7. report endpoint serves the artifact ---------------------------------
    resp = page.request.get(f"{server['base']}/api/runs/{run_id}/report")
    assert resp.status == 200
    assert "deterministic fixture report" in resp.text()

    # -- 8. overview reflects the refreshed status ------------------------------
    page.goto(server["base"] + "/")
    row = page.locator("tr", has_text=run_id)
    row.wait_for(timeout=20_000)
    assert "halted" in row.inner_text().lower()

    # -- 9. launch adaptive mission ---------------------------------------------
    mission_id = _launch(page, server, tmp_path, "mission", "Adaptive: reach the admin console")

    # -- 10. mission driver actually used (badge + panel + identity) ------------
    page.wait_for_selector("text=MISSION", timeout=15_000)
    page.wait_for_selector("text=ADAPTIVE MISSION", timeout=15_000)
    panel_sel = '[data-testid="mission-panel"]'
    page.wait_for_selector(panel_sel, timeout=15_000)
    # the panel's data arrives on the mission-detail poll — wait for identity
    page.wait_for_selector(f'{panel_sel} >> text={mission_id}', timeout=15_000)

    # -- 11. task creation + replanning visible ---------------------------------
    page.wait_for_selector(f'{panel_sel} >> text=sqli', timeout=15_000)
    body = page.locator(panel_sel).inner_text()
    assert "/orders" in body                              # claimed/dispatched tasks
    assert "mission.replan" in body                        # journal tail shows replanning

    # -- 12. pending verification vs confirmed, separately ----------------------
    page.wait_for_selector(f'{panel_sel} >> text=confirmed 1', timeout=20_000)
    page.wait_for_selector(f'{panel_sel} >> text=awaiting verifier 1', timeout=20_000)

    # -- 13. stop the mission; outcome inspectable ------------------------------
    page.get_by_role("button", name="STOP", exact=True).click()
    page.get_by_role("button", name="CONFIRM STOP?").click()
    page.wait_for_selector("text=HALTED", timeout=20_000)
    detail = page.request.get(f"{server['base']}/api/missions/{mission_id}").json()
    assert detail["status"] == "halted"
    assert detail["halt_reason"] == "operator_stop"
    # task success ≠ objective achievement: the mission ends halted with a
    # succeeded task in its list — the panel shows both honestly
    assert any(t["status"] == "succeeded" for t in detail["tasks"])

    # -- 14. refresh the page — state recovery ----------------------------------
    page.reload()
    page.wait_for_selector("text=MISSION", timeout=15_000)
    page.wait_for_selector("text=ADAPTIVE MISSION", timeout=15_000)
    assert "operator_stop" in page.locator('[data-testid="mission-panel"]').inner_text()

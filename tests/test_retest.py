"""Retest (ARTEX 漏洞复测, deterministic port): the three-way call must be honest.

Failure modes these tests exist to kill:

1. A "fixed" call over dead trials — transport death must read cannot_confirm,
   never fixed: certifying remediation over connection errors is how false
   remediation reports happen.
2. A "fixed" call over FLAKY reproduction — any successful reproduction means
   the hole is still open, however intermittent.
3. Scope laundering — a stored check that no longer fits the current RoE comes
   back blocked, never quietly converted into a soft verdict.
4. State confusion — retests append to retest_history and never touch
   `confidence`; old findings.json without the field still loads.
5. Missing-scope honesty — a POST retest against a run without frozen scope
   refuses (409), it does not guess the RoE.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading

import pytest
from test_server import harness  # noqa: F401 — pytest fixture, used by name

from redteam.findings import Finding, FindingStore
from redteam.retest import (BLOCKED, CANNOT_CONFIRM, FIXED, REPRODUCIBLE,
                            build_ctx_for_run, engagement_from_scope_json,
                            retest_finding, retest_run)

# --- a live local target with vulnerable + fixed behaviors --------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        if self.path.startswith("/vuln"):
            body = b"ADMIN PANEL secret"
        else:
            body = b"302 login required"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond

    def log_message(self, *a):  # silence test noise
        pass


@pytest.fixture(scope="module")
def target():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    # a port we KNOW is closed: bind, read it, shut it — connection refused there
    c = socket.socket()
    c.bind(("127.0.0.1", 0))
    dead_port = c.getsockname()[1]
    c.close()
    yield {"base": f"http://127.0.0.1:{srv.server_address[1]}", "dead": dead_port}
    srv.shutdown()


def _scope_dict(base_port, dead=False):
    port = dead or base_port
    return {"allowed_hosts": ["127.0.0.1"], "excluded_hosts": [],
            "allowed_ports": [port], "allowed_schemes": ["http"],
            "max_requests_per_second": 100.0, "max_total_requests": 1000,
            "allow_private_ranges": True}


def _run_dir(tmp_path, target, findings, dead=False, dead_port=None):
    rd = tmp_path / "run"
    rd.mkdir(exist_ok=True)
    port = dead_port or int(target["base"].rsplit(":", 1)[1])
    (rd / "scope.json").write_text(json.dumps(_scope_dict(port, dead)), encoding="utf-8")
    (rd / "findings.json").write_text(
        json.dumps([f.__dict__ for f in findings] if isinstance(findings, list) else findings),
        encoding="utf-8")
    return rd


def _http_finding(base, port, path="/vuln"):
    return Finding(
        title="unauth admin panel", severity="high", target=f"{base}{path}",
        summary="admin panel reachable without a session",
        evidence="200 with ADMIN PANEL marker", check_type="http",
        check_spec={"request": {"method": "GET", "url": f"{base}{path}"},
                    "body_regex": "ADMIN PANEL"})


def _ctx_for(tmp_path, target, findings, dead_port=None):
    rd = _run_dir(tmp_path, target, findings, dead_port=dead_port)
    eng = engagement_from_scope_json(rd)
    ctx = build_ctx_for_run(eng, rd)
    return rd, eng, ctx


# --- verdicts -----------------------------------------------------------------


def test_still_vulnerable_reads_reproducible(tmp_path, target):
    f = _http_finding(target["base"], 0)
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    out = retest_finding(ctx.findings.all()[0], ctx, trials=3, need=2)
    assert out["verdict"] == REPRODUCIBLE
    assert out["reproductions"] == 3


def test_patched_target_reads_fixed(tmp_path, target):
    # same recipe pointed at a path whose body no longer carries the marker:
    # real responses, assertion false on every trial -> fixed
    f = _http_finding(target["base"], 0, path="/patched")
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    out = retest_finding(ctx.findings.all()[0], ctx, trials=3, need=2)
    assert out["verdict"] == FIXED
    assert out["reproductions"] == 0 and out["unreachable"] == 0


def test_dead_target_reads_cannot_confirm_never_fixed(tmp_path, target):
    dead = target["dead"]
    f = Finding(
        title="unauth admin panel", severity="high",
        target=f"http://127.0.0.1:{dead}/vuln", summary="x",
        check_type="http",
        check_spec={"request": {"method": "GET", "url": f"http://127.0.0.1:{dead}/vuln"},
                    "body_regex": "ADMIN PANEL"})
    rd, eng, ctx = _ctx_for(tmp_path, target, [f], dead_port=dead)
    out = retest_finding(ctx.findings.all()[0], ctx, trials=2, need=1)
    assert out["verdict"] == CANNOT_CONFIRM
    assert "unreachable" in out["detail"] or "dead" in out["detail"]
    # the whole point of the separation: this is NOT "fixed"
    assert out["verdict"] != FIXED


def test_out_of_scope_recipe_reads_blocked(tmp_path, target):
    f = Finding(
        title="drifted check", severity="low", target="http://10.9.8.7/x",
        summary="scope.json no longer covers this host",
        check_type="http",
        check_spec={"request": {"method": "GET", "url": "http://10.9.8.7/x"},
                    "body_regex": "x"})
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    out = retest_finding(ctx.findings.all()[0], ctx, trials=2, need=1)
    assert out["verdict"] == BLOCKED


def test_verdict_mapping_contract(tmp_path, target):
    # the mapping that makes the three-way call honest, asserted directly:
    # any reproduction (even below the k-of-n bar) is still open; dead transport
    # is never "fixed"; only clean fails on a live target certify a fix.
    from redteam.retest import _verdict_from
    assert _verdict_from(2, 5, 0)[0] == REPRODUCIBLE   # flaky but real
    assert _verdict_from(5, 5, 0)[0] == REPRODUCIBLE
    assert _verdict_from(0, 5, 5)[0] == CANNOT_CONFIRM  # target unreachable
    assert _verdict_from(0, 5, 2)[0] == CANNOT_CONFIRM  # partial transport death
    assert _verdict_from(0, 5, 0)[0] == FIXED           # clean fails on live target
    # the "flaky" detail must carry the counts, not hide them
    assert "2/5" in _verdict_from(2, 5, 0)[1]


def test_workflow_without_fresh_steps_reads_cannot_confirm(tmp_path, target):
    f = Finding(title="coupon reuse", severity="high", target="http://x/coupon",
                summary="one-shot workflow abuse", check_type="workflow",
                check_spec={"invariant": [{"type": "status", "request": "redeem",
                                           "equals": 200}]})
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    out = retest_finding(ctx.findings.all()[0], ctx, trials=2, need=1)
    assert out["verdict"] == CANNOT_CONFIRM
    assert "fresh_attack_steps" in out["detail"]


def test_no_recipe_check_type_reads_cannot_confirm(tmp_path, target):
    f = Finding(title="manual note", severity="info", target="http://x", summary="s")
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    out = retest_finding(ctx.findings.all()[0], ctx, trials=1, need=1)
    assert out["verdict"] == CANNOT_CONFIRM
    assert "no replayable check_type" in out["detail"]


# --- history + persistence -----------------------------------------------------


def test_history_appended_and_confidence_untouched(tmp_path, target):
    f = _http_finding(target["base"], 0)
    f.confidence = "confirmed"
    rd, eng, ctx = _ctx_for(tmp_path, target, [f])
    results = retest_run(ctx.findings, ctx, trials=3, need=2)
    assert len(results) == 1
    store = FindingStore(rd / "findings.json")   # reload from disk
    f2 = store.all()[0]
    assert len(f2.retest_history) == 1
    assert f2.retest_history[0]["verdict"] == REPRODUCIBLE
    assert f2.confidence == "confirmed"          # verification state untouched


def test_retest_run_skips_recipeless_findings_and_singles_by_id(tmp_path, target):
    a = _http_finding(target["base"], 0)
    b = Finding(title="no recipe", severity="info", target="x", summary="s")
    rd, eng, ctx = _ctx_for(tmp_path, target, [a, b])
    results = retest_run(ctx.findings, ctx)      # everything retestable
    assert len(results) == 1 and results[0]["finding_id"] == a.id
    one = retest_run(ctx.findings, ctx, finding_id=b.id)
    assert one == []                             # b has no check_type: skipped
    none = retest_run(ctx.findings, ctx, finding_id="does-not-exist")
    assert none == []


def test_old_findings_json_without_history_field_loads(tmp_path, target):
    rd, eng, ctx = _ctx_for(tmp_path, target, [])
    legacy = [{"title": "old", "severity": "low", "target": "t", "summary": "s",
               "confidence": "confirmed", "id": "abc123", "created": "z"}]
    (rd / "findings.json").write_text(json.dumps(legacy), encoding="utf-8")
    store = FindingStore(rd / "findings.json")
    f = store.all()[0]
    assert f.retest_history == []
    store.append_retest("abc123", {"when": "w", "verdict": "fixed",
                                   "reproductions": 0, "trials": 3, "detail": "d"})
    assert FindingStore(rd / "findings.json").all()[0].retest_history[0]["verdict"] == "fixed"


# --- server endpoint -----------------------------------------------------------


def test_server_retest_endpoint(tmp_path, harness, target):  # noqa: F811
    client, runs_root, _ = harness
    f = _http_finding(target["base"], 0)
    rd = runs_root / "rr1"
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "scope.json").write_text(
        json.dumps(_scope_dict(int(target["base"].rsplit(":", 1)[1]))), encoding="utf-8")
    (rd / "findings.json").write_text(json.dumps([f.__dict__]), encoding="utf-8")

    r = client.post("/api/runs/rr1/retest", json={"finding_id": f.id,
                                                  "trials": 3, "need": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["reproducible"] == 1
    assert body["retests"][0]["verdict"] == REPRODUCIBLE

    # run without frozen scope refuses honestly rather than guessing the RoE
    (runs_root / "rr2").mkdir(exist_ok=True)
    assert client.post("/api/runs/rr2/retest", json={}).status_code == 409

    # unknown finding id
    r = client.post("/api/runs/rr1/retest", json={"finding_id": "nope"})
    assert r.status_code == 404

    # unknown run
    assert client.post("/api/runs/ghost/retest", json={}).status_code == 404

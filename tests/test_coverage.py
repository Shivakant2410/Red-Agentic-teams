"""Coverage map (ARTEX 资产覆盖图): the universe is the RoE, never the activity.

Failure modes these tests exist to kill:

1. Inflation — a pair the agent invented or off-grid activity becoming
   "covered". Only the frozen scope grid is the universe; activity outside it
   is reported as a scope anomaly, never folded into coverage.
2. Status confusion — TODO branches counted as "attempted" (planning is not
   work), a bare-host target's work lost (port-less attribution must still
   count toward the host's pairs), findings promoting a pair to "tested".
3. Dishonest degradation — no scope.json must NOT silently produce a fake
   grid; the limitation is named. Missing artifacts render empty, never a 500.
"""

from __future__ import annotations

import json
from pathlib import Path

from redteam.coverage import build_coverage

from test_server import harness  # noqa: F401 — pytest fixture, used by name


def _write_run(tmp_path: Path, files: dict) -> Path:
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (run_dir / name).write_text(json.dumps(content), encoding="utf-8")
    return run_dir


_SCOPE = {"allowed_hosts": ["web.acme", "api.acme"], "excluded_hosts": [],
          "allowed_ports": [80, 443], "allowed_schemes": ["http", "https"]}


def test_grid_universe_and_state_classification(tmp_path):
    run_dir = _write_run(tmp_path, {
        "scope.json": _SCOPE,
        "attack_tree.json": [
            # proved pair: sqli confirmed on web.acme:80
            {"technique": "sqli", "target": "http://web.acme/items", "status": "completed"},
            # attempted-but-failed on api.acme:443
            {"technique": "xss", "target": "https://api.acme/search", "status": "failed"},
            # TODO is PLANNING, not work — must not lift the pair out of untouched
            {"technique": "ssrf", "target": "http://web.acme/proxy", "status": "todo"},
        ],
        "findings.json": [
            # a finding independently promotes its pair to tested
            {"title": "idor", "target": "https://api.acme/users/2", "confidence": "confirmed"},
        ],
        "inventory.json": {"hosts": {
            "web.acme": {"services": {
                "http/80": {"port": 80, "scheme": "http", "status_last": 200},
                "http/8080": {"port": 8080, "scheme": "http", "status_last": 200},
            }},
            # api.acme has NO inventory rows — its pairs are not "alive"
        }},
    })
    cov = build_coverage(run_dir)
    s = cov["summary"]
    # grid = 2 hosts x 2 ports = 4 pairs
    assert s["in_scope_pairs"] == 4
    rows = {h["host"]: {p["port"]: p for p in h["ports"]} for h in cov["hosts"]}
    # web.acme:80 confirmed work; :443 untouched; 8080 alive-but-untouched (and it
    # is IN the interesting set via inventory even though outside the grid grid —
    # reported per-pair but NOT counted in the in-scope totals)
    assert rows["web.acme"][80]["state"] == "tested"
    assert rows["web.acme"][443]["state"] == "untouched"
    assert rows["web.acme"][8080]["state"] == "alive_untouched"
    assert rows["web.acme"][8080]["alive"] is True
    # api.acme:443 = confirmed finding -> tested; :80 untouched
    assert rows["api.acme"][443]["state"] == "tested"
    assert rows["api.acme"][80]["state"] == "untouched"
    # in-scope accounting: web:80 tested, api:443 tested, web:443 + api:80 untouched
    assert s["tested"] == 2 and s["untouched"] == 2
    assert s["alive_untouched"] == 0   # 8080 is out-of-grid, not counted in totals
    assert s["coverage_ratio"] == 0.5
    assert s["scope_available"] is True


def test_activity_outside_grid_reported_not_folded(tmp_path):
    run_dir = _write_run(tmp_path, {
        "scope.json": {"allowed_hosts": ["web.acme"], "excluded_hosts": [],
                       "allowed_ports": [80], "allowed_schemes": ["http"]},
        "attack_tree.json": [
            {"technique": "sqli", "target": "http://web.acme/a", "status": "completed"},
            # the guard should have blocked this; if it ever happens, the map
            # must surface it, not quietly count it as coverage
            {"technique": "sqli", "target": "http://evil.example/boom", "status": "failed"},
        ],
        "findings.json": [],
        "inventory.json": {"hosts": {}},
    })
    cov = build_coverage(run_dir)
    s = cov["summary"]
    assert s["out_of_scope_targets"] == ["evil.example:80"]
    assert s["in_scope_pairs"] == 1 and s["tested"] == 1


def test_bare_host_target_credits_its_pairs(tmp_path):
    run_dir = _write_run(tmp_path, {
        "scope.json": {"allowed_hosts": ["web.acme"], "excluded_hosts": [],
                       "allowed_ports": [80, 443], "allowed_schemes": ["http"]},
        "attack_tree.json": [
            {"technique": "dns_enum", "target": "web.acme", "status": "failed"},
        ],
        "findings.json": [],
        "inventory.json": {"hosts": {}},
    })
    cov = build_coverage(run_dir)
    rows = {h["host"]: {p["port"]: p for p in h["ports"]} for h in cov["hosts"]}
    # the port-less attempt still proves the host was worked: both pairs attempted
    assert rows["web.acme"][80]["state"] == "attempted"
    assert rows["web.acme"][443]["state"] == "attempted"
    assert cov["summary"]["attempted"] == 2


def test_no_scope_json_degrades_with_named_limitation(tmp_path):
    run_dir = _write_run(tmp_path, {
        "attack_tree.json": [
            {"technique": "sqli", "target": "http://web.acme/a", "status": "completed"}],
        "findings.json": [], "inventory.json": {"hosts": {}},
    })
    cov = build_coverage(run_dir)
    s = cov["summary"]
    assert s["scope_available"] is False and s["in_scope_pairs"] == 0
    assert "no scope.json" in s["limitation"]
    assert cov["hosts"][0]["ports"][0]["state"] == "tested"  # activity still shown


def test_empty_run_dir_renders_honest_zeroes(tmp_path):
    run_dir = tmp_path / "runs" / "empty"
    run_dir.mkdir(parents=True)
    cov = build_coverage(run_dir)
    assert cov["hosts"] == [] and cov["summary"]["in_scope_pairs"] == 0
    assert cov["summary"]["coverage_ratio"] is None


def test_server_coverage_endpoint(tmp_path, harness):  # noqa: F811
    client, runs_root, _ = harness
    run_dir = runs_root / "rcov1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "scope.json").write_text(json.dumps(_SCOPE), encoding="utf-8")
    (run_dir / "attack_tree.json").write_text(json.dumps([
        {"technique": "sqli", "target": "http://web.acme/items", "status": "completed"},
    ]), encoding="utf-8")
    (run_dir / "findings.json").write_text("[]", encoding="utf-8")
    (run_dir / "inventory.json").write_text(json.dumps({"hosts": {}}), encoding="utf-8")

    resp = client.get("/api/runs/rcov1/coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == "rcov1"
    assert body["coverage"]["summary"]["tested"] >= 1

    assert client.get("/api/runs/nope/coverage").status_code == 404

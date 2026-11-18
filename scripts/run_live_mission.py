#!/usr/bin/env python3
"""REAL-MODEL agent run: dynamic mission (glm-4.6 via the z-ai bridge) against
the Tinyvault lab target.

What this proves end to end, with a real model in the specialist loop:
  bridge (OpenAI-compat over z-ai SDK) -> LLMGateway -> RedTeamAgent
  specialists -> real tools against the local lab -> canonical intel ->
  dynamic mission replanning -> independent verification -> objective scoring.

Usage: python scripts/run_live_mission.py [PORT]
Output: the run directory + a printed mission trace (tasks, rounds, stop
reason, findings vs ground truth, objective criteria).
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
BASE_URL = f"http://127.0.0.1:{PORT}"
OUT = REPO / "runs" / f"live-mission-{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
OUT.mkdir(parents=True, exist_ok=True)

ENGAGEMENT = f"""
name: live-mission-tinyvault
client: lab
authorized_by: builder03-operator
ticket: ROE-LIVE-1
starts: {(_dt.date.today() - _dt.timedelta(days=1)).isoformat()}
ends: {(_dt.date.today() + _dt.timedelta(days=1)).isoformat()}
scope:
  allowed_hosts: ["127.0.0.1"]
  allowed_ports: [{PORT}]
  allowed_schemes: ["http"]
  allow_private_ranges: true
limits:
  max_requests_per_second: 50.0
  max_total_requests: 4000
  max_run_seconds: 780
  max_llm_tokens: 1200000
sandbox:
  enable: false
credentials:
  alice:
    password: pw-alice
    login_url: /login
    token_field: token
  bob:
    password: pw-bob
    login_url: /login
    token_field: token
objective:
  name: Tinyvault cross-principal order read
  description: The order drill-down resolves any id for any authenticated
    user. Prove alice can read bob's order by content.
  success_criteria:
    - id: idor_read
      kind: data_access
      target: "/api/"
      description: alice's session retrieves bob's order body (owner marker)
        while the unauthenticated control is denied
llm:
  providers:
    - name: zai-bridge
      kind: openai_compat
      base_url: http://127.0.0.1:9825/v1
      models_allow: ["glm-4.6"]
      prefer_free: false
      priority: 10
"""


def main() -> int:
    (OUT / "engagement.yaml").write_text(ENGAGEMENT, encoding="utf-8")

    from redteam.run import RunOptions, execute_run

    summary = execute_run(RunOptions(
        engagement_path=str(OUT / "engagement.yaml"),
        objective="Prove the cross-principal order read (IDOR) and reach the "
                  "objective criterion idor_read",
        out_dir=OUT, driver="mission",
        no_sandbox=True, no_browser=True,
        approve=lambda a, d: True,
        memory_dir=OUT / "memory"))

    # ---- honest trace -------------------------------------------------------
    print("\n" + "=" * 74)
    print("LIVE MISSION TRACE")
    print("=" * 74)
    print(f"run_dir              : {OUT}")
    print(f"status               : {summary.get('status')}")
    print(f"mission_stop_reason  : {summary.get('mission_stop_reason')}")
    print(f"objective_achieved   : {summary.get('mission_objective_achieved')}")
    print(f"execution_complete   : {summary.get('mission_execution_complete')}")
    print(f"rounds               : {summary.get('rounds')}")
    print(f"findings total       : {summary.get('findings')}")
    print(f"confirmed            : {summary.get('confirmed')}")
    print(f"executor             : {summary.get('mission_executor')}")
    for t in summary.get("tasks", []):
        ev = "".join(f" {e.get('ref', '')}" for e in t.get("evidence", [])[:2])
        print(f"  task {t.get('task_id', '')[:16]:18s} {t.get('role', ''):8s} "
              f"{t.get('technique', ''):18s} {t.get('target', '')[:38]:38s} "
              f"{t.get('status', ''):10s}{ev}")

    # ground-truth scoring
    fpath = OUT / "findings.json"
    if fpath.exists():
        findings = json.loads(fpath.read_text())
        confirmed_cwes = {f.get("cwe") for f in findings
                          if f.get("confidence") == "confirmed"}
        print("\nGROUND TRUTH: tinyvault-idor CWE-639 (IDOR on /api/activity)")
        hit = "CWE-639" in confirmed_cwes
        print(f"  independently-confirmed CWE-639 finding: {'YES' if hit else 'NO'}")
    opath = OUT / "objective.json"
    if opath.exists():
        obj = json.loads(opath.read_text())
        for c in obj.get("criteria", []):
            print(f"  criterion {c.get('id')}: achieved={c.get('achieved')}")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

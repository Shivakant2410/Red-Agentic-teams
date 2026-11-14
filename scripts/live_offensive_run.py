#!/usr/bin/env python3
"""Live-fire: the deterministic offensive engine vs the real lab targets.

Starts each vulnerable lab app (real HTTP servers, planted bugs), writes the
RoE engagement (scope, rate limits, seeded principals), runs the engine —
recon -> crosschecked leads -> class workflows -> independent verify pass —
with ZERO model calls, then scores the run against the target's ground truth.

This is the proof the machine executes offense end-to-end: every request is
scope-checked and rate-limited, every lead crosschecked, every finding proven
k-of-n with a negative control and confirmed only by the verify pass.
"""
import json
import shutil
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import requests  # noqa: E402
import yaml  # noqa: E402

from redteam.access import AccessGraph  # noqa: E402
from redteam.audit import AuditLog  # noqa: E402
from redteam.bench.scoring import score_run  # noqa: E402
from redteam.bench.targets import (LAB_BLOGMENT, LAB_FETCHER,  # noqa: E402
                                   LAB_LEDGER, LAB_MODELHUB, LAB_PIVOT,
                                   LAB_TINYVAULT, LAB_TRACKR, LAB_WORKFLOW)
from redteam.config import load_engagement  # noqa: E402
from redteam.findings import FindingStore  # noqa: E402
from redteam.inventory import AssetInventory  # noqa: E402
from redteam.killchain import KillChain  # noqa: E402
from redteam.knowledge import KnowledgeGraph  # noqa: E402
from redteam.offensive import OffensiveEngine  # noqa: E402
from redteam.ratelimit import RateLimiter  # noqa: E402
from redteam.scope import ScopeGuard  # noqa: E402
from redteam.session import SessionStore  # noqa: E402
from redteam.traffic import TrafficRecorder  # noqa: E402

OUT_ROOT = REPO / "runs" / "offensive-live"


def wait_alive(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.3)
    return False


def build_ctx(eng, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    from redteam.tools import ToolContext
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=RateLimiter(eng.max_requests_per_second, eng.max_total_requests),
        audit=AuditLog(out / "audit.log.jsonl"),
        findings=FindingStore(out / "findings.json"),
        approve=lambda action, details: True,  # isolated lab; engine only proves
        graph=KnowledgeGraph(out / "graph.json"),
        sessions=SessionStore(),
        access=AccessGraph(out / "access.json"),
        objective=eng.objective,
        killchain=KillChain(out / "killchain.json"),
        traffic=TrafficRecorder(out / "traffic.jsonl"),
        inventory=AssetInventory(out / "inventory.json"))


def write_engagement(target, path: Path) -> None:
    doc = {
        "name": f"Live-fire: {target.name}", "client": "self",
        "authorized_by": "self", "ticket": "local-live-fire",
        "starts": time.strftime("%Y-%m-%d"), "ends": "2099-01-01",
        "scope": {
            "allowed_hosts": ["localhost", "127.0.0.1"],
            "allowed_ports": [target.host_port, target.container_port,
                              *target.extra_ports, 80, 443],
            "allowed_schemes": ["http", "https"],
            "allow_private_ranges": True,
        },
        "objective": target.objective,
        "limits": {"max_requests_per_second": 20, "max_total_requests": 3000,
                   "max_run_seconds": 600},
        "credentials": target.credentials,
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def run_target(target, run_dir: Path) -> dict:
    # a live-fire run must be reproducible: stale findings.json from earlier
    # eras of the code otherwise masquerade as false positives (shakedown
    # 20261114: exactly that — duplicate CWE-639 records from the pre-
    # canonicalization engine)
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    write_engagement(target, run_dir / "engagement.yaml")
    eng = load_engagement(str(run_dir / "engagement.yaml"))

    proc = subprocess.Popen(target.cmd, cwd=str(REPO),
                            env={**os.environ, **(target.env or {})},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_alive(target.base_url):
            return {"target": target.name, "status": "target-not-reachable"}
        ctx = build_ctx(eng, run_dir)
        chat_fn = None
        if os.environ.get("REDTEAM_LLM") == "1":
            # opt-in model amplifier: absent/failed provider == no model,
            # the run stays deterministic (same discipline either way).
            # REDTEAM_PLAN_MODEL pins a model to the plan role (e.g. a
            # stronger free model for strict-JSON proposal quality).
            from redteam.config import LlmConfig
            from redteam.llm.planner import make_chat_fn
            plan_model = os.environ.get("REDTEAM_PLAN_MODEL", "")
            cfg = (LlmConfig(role_models={"plan": plan_model})
                   if plan_model else LlmConfig())
            chat_fn = make_chat_fn(cfg, ctx.audit)
            print("  [llm] planner:",
                  f"live provider wired (plan={plan_model or 'pool'})"
                  if chat_fn
                  else "no provider/key configured -> deterministic")
        engine = OffensiveEngine(eng, ctx=ctx, llm_chat=chat_fn)
        engine._base_override = target.base_url
        summary = engine.run()
        findings = [asdict(f) for f in ctx.findings.all()]
        score = score_run(target.name, findings, target.ground_truth)
        out = {
            "target": target.name,
            "base_url": target.base_url,
            "engine": summary,
            "findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                          "cwe": f["cwe"], "confidence": f["confidence"],
                          "target": f["target"]} for f in findings],
            "score": {"tp": score.true_positives, "fp": score.false_positives,
                      "fn": score.false_negatives,
                      "precision": round(score.precision or 0.0, 3),
                      "recall": round(score.recall or 0.0, 3)},
        }
        (run_dir / "summary.json").write_text(json.dumps(out, indent=2),
                                              encoding="utf-8")
        return out
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    total = {"tp": 0, "fp": 0, "fn": 0}
    for target, slug in ((LAB_TRACKR, "trackr"), (LAB_FETCHER, "fetcher"),
                         (LAB_BLOGMENT, "blogment"), (LAB_LEDGER, "ledger"),
                         (LAB_PIVOT, "pivot"),
                         (LAB_WORKFLOW, "workflow"),
                         (LAB_MODELHUB, "modelhub"),
                         (LAB_TINYVAULT, "tinyvault")):
        print(f"\n=== {target.name} ===")
        res = run_target(target, OUT_ROOT / slug)
        eng = res.get("engine", res)
        print(json.dumps({k: v for k, v in eng.items() if k != 'rounds'}
                         if isinstance(eng, dict) else eng,
                         indent=2, default=str))
        if isinstance(eng, dict):
            print('  hypotheses:', eng.get('hypotheses'))
        if "score" in res:
            s = res["score"]
            print(f"SCORE  tp={s['tp']}  fp={s['fp']}  fn={s['fn']}  "
                  f"precision={s['precision']}  recall={s['recall']}")
            for f in res["findings"]:
                print(f"  [{f['confidence']:<19}] {f['severity']:<8} {f['cwe']:<8} "
                      f"{f['title'][:76]}")
            total["tp"] += s["tp"]; total["fp"] += s["fp"]; total["fn"] += s["fn"]
    print(f"\nTOTAL  tp={total['tp']}  fp={total['fp']}  fn={total['fn']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

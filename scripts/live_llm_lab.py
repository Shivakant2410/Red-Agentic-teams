#!/usr/bin/env python3
"""LLM-planner live test on a fresh lab: Tinyvault (cross-principal order read).

Two runs of the SAME engine on the SAME fresh target:
  A. deterministic  — no model (REDTEAM_LLM unset)
  B. real provider  — REDTEAM_LLM=1 + OPENROUTER_API_KEY: make_chat_fn builds
     the Gen-1 OpenRouter client and the planner proposes bets into the SAME
     queue discipline (admit -> rank -> execute -> k-of-n verify)

The model-in-loop proof is the AUDIT TRAIL, not the log line:
  brain.hypothesis.proposed  (the planner's raw proposals, admitted or rejected)
  brain.hypothesis.admitted / .executed with id llm-* and source "admitted: llm:planner"

Both runs are scored against the same ground truth (CWE-639) so the report is
honest about what the model ADDED, not just that it ran.

Usage:  set -a; . .secrets/openrouter.env; set +a
        python3 scripts/live_llm_lab.py [--baseline-only]
"""
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from redteam.bench.targets import LAB_TINYVAULT          # noqa: E402
from scripts.live_offensive_run import OUT_ROOT, run_target  # noqa: E402


def audit_events(run_dir: Path) -> list[dict]:
    path = run_dir / "audit.log.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def planner_proof(run_dir: Path) -> dict:
    evs = audit_events(run_dir)
    proposed = [e for e in evs if e.get("event") == "brain.hypothesis.proposed"]
    executed = [e for e in evs if e.get("event") == "brain.hypothesis.executed"
                and str(e.get("id", "")).startswith("llm-")]
    admitted = [e for e in evs if e.get("event") == "brain.hypothesis.admitted"
                and str(e.get("id", "")).startswith("llm-")]
    reactivated = [e for e in evs
                   if e.get("event") == "brain.hypothesis.reactivated"]
    deferred = [e for e in evs if e.get("event") == "brain.horizon.deferral"]
    return {"proposed": proposed, "admitted": admitted,
            "executed": executed, "reactivated": reactivated,
            "deferred": deferred}


def show(tag: str, result: dict, run_dir: Path):
    score = result["score"]
    print(f"\n=== {tag} ===")
    print(f"  engine: bets={len(result['engine']['hypotheses'])} "
          f"findings={len(result['findings'])}")
    print(f"  SCORE  tp={score['tp']}  fp={score['fp']}  fn={score['fn']}  "
          f"precision={score['precision']}  recall={score['recall']}")
    proof = planner_proof(run_dir)
    print(f"  planner: proposed={len(proof['proposed'])} "
          f"admitted-llm={len(proof['admitted'])} "
          f"executed-llm={len(proof['executed'])} "
          f"reactivated={len(proof['reactivated'])} "
          f"horizon-deferred={len(proof['deferred'])}")
    for e in proof["proposed"][:6]:
        print(f"    [proposed] ok={e.get('ok')} {e.get('reason', '')[:110]}")
    for e in proof["executed"][:6]:
        print(f"    [executed] {e.get('id')} confirmed={e.get('confirmed')} "
              f"{str(e.get('learned', ''))[:90]}")


def main():
    baseline_only = "--baseline-only" in sys.argv
    if not baseline_only and not os.environ.get("OPENROUTER_API_KEY"):
        print("OPENROUTER_API_KEY not set — source .secrets/openrouter.env "
              "or run with --baseline-only")
        return 2

    base = OUT_ROOT / "llm-lab"
    # A. deterministic baseline: the engine with NO model
    res_a = run_target(LAB_TINYVAULT, base / "baseline")
    show("A. deterministic (no model)", res_a, base / "baseline")

    if baseline_only:
        return 0

    # which model is being routed (one probe call, printed — never the key)
    from redteam.config import LlmConfig
    from redteam.llm.openrouter import OpenRouterClient
    plan_model = os.environ.get("REDTEAM_PLAN_MODEL", "")
    cfg = (LlmConfig(role_models={"plan": plan_model})
           if plan_model else LlmConfig())
    probe = OpenRouterClient(cfg).chat(
        [{"role": "user", "content": "Reply with exactly one word: ROUTED"}],
        tools=None, role="plan")
    print(f"\n[routed model] {probe.model}"
          + (f" (plan pinned: {plan_model})" if plan_model else ""))

    # B. the same run with the real provider wired through make_chat_fn
    os.environ["REDTEAM_LLM"] = "1"
    res_b = run_target(LAB_TINYVAULT, base / "llm")
    show("B. real provider (make_chat_fn -> OpenRouter)", res_b, base / "llm")
    return 0


if __name__ == "__main__":
    sys.exit(main())

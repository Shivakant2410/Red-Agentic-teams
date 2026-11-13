"""python -m redteam.pi — run the reproducible offline PI bench.

Fixed seed, full registry, both defense modes, deterministic fixture apps —
the same command always produces the same summary. This is the coverage and
utility evidence the spec asks for: ASR with Wilson CIs, unique-technique
coverage, benign completion, defense differential, honest skips.

Live-model probes exist as a SEPARATE, env-gated surface (--live-manyshot,
see redteam/pi/live.py): explicit authorization required, key via env-var
indirection, verdicts earned, and the numbers NEVER mix with these fixture
numbers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import PIEngagement, PIEngagementConfig


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="python -m redteam.pi",
        description="Reproducible offline prompt-injection bench (OWASP LLM01)")
    ap.add_argument("--out", default=None,
                    help="output directory (required unless --audit)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--engagement-id", default="pi-bench-offline")
    ap.add_argument("--techniques", nargs="*", default=None,
                    help="technique ids (default: the full registry)")
    ap.add_argument("--defense-modes", nargs="*", default=("off", "on"),
                    choices=("off", "on"))
    ap.add_argument("--adaptive-rounds", type=int, default=0,
                    help="G2 adaptive phase: mutate non-succeeded payloads "
                         "for N rounds (deterministic)")
    ap.add_argument("--adaptive-budget", type=int, default=None,
                    help="cap mutant cells per adaptive round; cells are "
                         "chosen by coverage optimization (technique, "
                         "family, stage, mode, operator labels). Default: "
                         "no cap (full mutant grid)")
    ap.add_argument("--defense-spec-visible", action="store_true",
                    help="G2/OWASP 2026: disclose the defense spec to the "
                         "attacker in mode 'on' payloads")
    ap.add_argument("--audit", action="store_true",
                    help="print the registry coverage audit (G9) and the "
                         "standards anchors (G8) instead of running")
    ap.add_argument("--plan", action="store_true",
                    help="print the attack-graph deployment plan (reachability "
                         "audit; our tool) instead of running")
    ap.add_argument("--atlas", action="store_true",
                    help="print the ATLAS-side catalog, two-way map and "
                         "coverage audit instead of running")
    ap.add_argument("--killchain", action="store_true",
                    help="print the kill-chain projection (phases per "
                         "technique, capability-conditioned chain breaks "
                         "and reachable depth) instead of running")
    ap.add_argument("--live-manyshot", action="store_true",
                    help="run the PI.A8 many-shot probe against the env-"
                         "configured live target (LLMRED_LIVE_*; requires "
                         "explicit authorization). Never mixes with bench "
                         "output")
    ap.add_argument("--shots", type=int, default=None,
                    help="--live-manyshot: shot count (default: 256, the "
                         "paper's tested maximum)")
    ap.add_argument("--budget-tokens", type=int, default=None,
                    help="--live-manyshot: request token budget (shots drop "
                         "from the head to fit)")
    ap.add_argument("--capabilities", nargs="*", default=None,
                    help="override deployment capability labels for --plan "
                         "(default: the offline fixture's native set)")
    args = ap.parse_args()

    if args.audit:
        from .techniques import coverage_audit, standards_anchors
        print(json.dumps({"coverage_audit": coverage_audit(),
                          "standards_anchors": standards_anchors()},
                         indent=2, ensure_ascii=False))
        return 0
    if args.atlas:
        from .atlas import atlas_audit
        print(json.dumps(atlas_audit(), indent=2, ensure_ascii=False))
        return 0
    if args.killchain:
        from .killchain import kill_chain_audit
        print(json.dumps(kill_chain_audit(), indent=2, ensure_ascii=False))
        return 0
    if args.live_manyshot:
        from .live import (LiveLaneError, LiveTarget, NotAuthorized,
                           manyshot_live_probe)
        try:
            target = LiveTarget.from_env()
        except NotAuthorized as e:
            print(json.dumps({"error": "not_authorized", "detail": str(e)}))
            return 3
        try:
            record = manyshot_live_probe(
                target,
                n_shots=args.shots if args.shots else 256,
                budget_tokens=args.budget_tokens)
        except LiveLaneError as e:
            print(json.dumps({"error": "live_lane_error", "detail": str(e)}))
            return 4
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return 0
    if args.plan:
        from .planner import FIXTURE_CAPABILITIES, deployment_plan
        from .techniques import TECHNIQUES
        registry = TECHNIQUES
        if args.techniques:
            wanted = set(args.techniques)
            registry = tuple(t for t in TECHNIQUES if t.id in wanted)
        caps = tuple(args.capabilities) if args.capabilities \
            else FIXTURE_CAPABILITIES
        print(json.dumps(deployment_plan(registry, caps),
                         indent=2, ensure_ascii=False))
        return 0
    if not args.out:
        ap.error("--out is required unless --audit, --plan, --atlas, "
                 "--killchain or --live-manyshot")

    eng = PIEngagement(PIEngagementConfig(
        engagement_id=args.engagement_id, technique_ids=args.techniques,
        defense_modes=tuple(args.defense_modes), seed=args.seed,
        adaptive_rounds=args.adaptive_rounds,
        adaptive_budget=args.adaptive_budget,
        defense_spec_visible=args.defense_spec_visible,
        out_dir=Path(args.out)))
    summary = eng.run()
    print(json.dumps({
        "attempted": summary["attempted"], "skipped": summary["skipped"],
        "errors": summary["errors"], "verdicts": summary["verdicts"],
        "asr": summary["asr"], "unique_coverage": summary["unique_coverage"],
        "defense_differential": summary["defense_differential"],
        "benign_completion": summary["benign_completion"],
        "legit_instruction_compliance":
            summary["legit_instruction_compliance"],
        **({"adaptive": summary["adaptive"]}
           if "adaptive" in summary else {})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

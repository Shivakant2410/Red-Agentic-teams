"""python -m redteam.pi — run the reproducible offline PI bench.

Fixed seed, full registry, both defense modes, deterministic fixture apps —
the same command always produces the same summary. This is the coverage and
utility evidence the spec asks for: ASR with Wilson CIs, unique-technique
coverage, benign completion, defense differential, honest skips.

Live-model runs against real deployments are the OPERATOR's step (llmred's
OpenAIToolLoop path) and are never mixed with these fixture numbers.
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
    ap.add_argument("--defense-spec-visible", action="store_true",
                    help="G2/OWASP 2026: disclose the defense spec to the "
                         "attacker in mode 'on' payloads")
    ap.add_argument("--audit", action="store_true",
                    help="print the registry coverage audit (G9) and the "
                         "standards anchors (G8) instead of running")
    args = ap.parse_args()

    if args.audit:
        from .techniques import coverage_audit, standards_anchors
        print(json.dumps({"coverage_audit": coverage_audit(),
                          "standards_anchors": standards_anchors()},
                         indent=2, ensure_ascii=False))
        return 0
    if not args.out:
        ap.error("--out is required unless --audit")

    eng = PIEngagement(PIEngagementConfig(
        engagement_id=args.engagement_id, technique_ids=args.techniques,
        defense_modes=tuple(args.defense_modes), seed=args.seed,
        adaptive_rounds=args.adaptive_rounds,
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

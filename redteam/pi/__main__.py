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
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--engagement-id", default="pi-bench-offline")
    ap.add_argument("--techniques", nargs="*", default=None,
                    help="technique ids (default: the full registry)")
    ap.add_argument("--defense-modes", nargs="*", default=("off", "on"),
                    choices=("off", "on"))
    args = ap.parse_args()

    eng = PIEngagement(PIEngagementConfig(
        engagement_id=args.engagement_id, technique_ids=args.techniques,
        defense_modes=tuple(args.defense_modes), seed=args.seed,
        out_dir=Path(args.out)))
    summary = eng.run()
    print(json.dumps({
        "attempted": summary["attempted"], "skipped": summary["skipped"],
        "errors": summary["errors"], "verdicts": summary["verdicts"],
        "asr": summary["asr"], "unique_coverage": summary["unique_coverage"],
        "defense_differential": summary["defense_differential"],
        "benign_completion": summary["benign_completion"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

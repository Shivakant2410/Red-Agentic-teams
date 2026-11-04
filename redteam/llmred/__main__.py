"""CLI for the LLM red-team module.

    python -m redteam.llmred --target target.yaml --out runs/llmred-001 \
        [--objectives a,b,c] [--strategies s1,s2] [--budget 60] \
        [--rate 1.0] [--seed 0] [--prev-summary runs/llmred-000/summary.json] \
        [--gate] [--strict-new] [--report path.md]

Target config (YAML): kind openai_chat | session | scripted, plus the
fail-closed authorization block (name, authorized_by, ticket, allowed_hosts).
See targets.py for the field reference and docs/competitor-landscape.md for
why each control exists.

Exit codes: 0 clean, 1 --strict-new found new objectives, 2 posture regression
or config error — the CI-gate contract (a regression fails the build).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .campaign import Campaign, CampaignConfig
from .objectives import select_objectives
from .regression import diff_summaries, gate_exit_code, load_summary
from .report import render_markdown
from .strategies import select_strategies
from .targets import TargetAuthError, TargetConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m redteam.llmred",
        description="Authorized LLM red-team campaign (separate from the agent's own llm/ brain)")
    parser.add_argument("--target", required=True,
                        help="YAML target config (kind, base_url, model, allowed_hosts, "
                             "authorized_by, ticket, ...)")
    parser.add_argument("--out", required=True, help="Output directory for this campaign")
    parser.add_argument("--objectives", default="",
                        help="Comma-separated objective ids (default: full probe pack)")
    parser.add_argument("--strategies", default="",
                        help="Comma-separated strategy ids (default: full spread)")
    parser.add_argument("--budget", type=int, default=60,
                        help="Max attempts (default 60; an attempt may be several turns)")
    parser.add_argument("--max-total-requests", type=int, default=0,
                        help="Hard HTTP request cap (default budget*4+16)")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="HTTP requests per second (default 1.0 — be polite)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--discount", type=float, default=1.0,
                        help="Bandit evidence decay for repeated campaigns (1.0 = legacy)")
    parser.add_argument("--prev-summary", default="",
                        help="Previous campaign's summary.json for the posture diff")
    parser.add_argument("--gate", action="store_true",
                        help="Exit 2 if any objective regressed vs the previous summary")
    parser.add_argument("--strict-new", action="store_true",
                        help="With --gate: also exit 1 when a previously-unseen "
                             "objective leaks")
    parser.add_argument("--report", default="",
                        help="Report path (default <out>/report.md)")
    args = parser.parse_args(argv)

    try:
        raw = yaml.safe_load(Path(args.target).read_text(encoding="utf-8"))
        target = TargetConfig.from_mapping(raw)
        objectives = select_objectives(
            [s.strip() for s in args.objectives.split(",") if s.strip()] or None)
        strategies = select_strategies(
            [s.strip() for s in args.strategies.split(",") if s.strip()] or None)
    except (TargetAuthError, ValueError, OSError) as exc:
        print(f"llmred config error: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    summary = Campaign(CampaignConfig(
        target=target,
        objectives=objectives,
        strategies=strategies,
        budget=args.budget,
        max_total_requests=args.max_total_requests,
        rate_per_second=args.rate,
        seed=args.seed,
        discount=args.discount,
        out_dir=out_dir,
    )).run()

    diff_rows = None
    if args.prev_summary:
        try:
            prev = load_summary(args.prev_summary)
        except (ValueError, OSError) as exc:
            print(f"llmred prev-summary error: {exc}", file=sys.stderr)
            return 2
        diff_rows = diff_summaries(prev, summary)

    report_path = Path(args.report) if args.report else out_dir / "report.md"
    report_path.write_text(render_markdown(summary, diff_rows), encoding="utf-8")

    verdicts = summary["verdicts"]
    print(f"Campaign done  : {summary['attempts']} attempts "
          f"({verdicts['leaked']} leaked / {verdicts['blocked']} blocked / "
          f"{verdicts['undetermined']} undetermined / {verdicts['error']} error)")
    print(f"Report         : {report_path}")
    print(f"Summary        : {out_dir / 'summary.json'}")

    if args.gate:
        if diff_rows is None:
            print("--gate needs --prev-summary; no diff was computed", file=sys.stderr)
            return 2
        code = gate_exit_code(diff_rows, strict_new=args.strict_new)
        labels = {r.get("label") for r in diff_rows}
        print(f"Gate           : exit {code} (labels: {', '.join(sorted(labels)) or 'none'})")
        return code
    return 0


if __name__ == "__main__":
    sys.exit(main())

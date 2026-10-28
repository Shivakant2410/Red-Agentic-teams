"""Command-line entrypoint for the red-team agent.

Usage:
    export OPENROUTER_API_KEY=sk-or-...
    python -m redteam.cli --engagement config/engagement.yaml \
        --objective "Map the API surface and test authentication controls" \
        --out runs/2026-09-26

The operator confirms scope at the preflight prompt before anything runs, and approves
each sensitive action interactively (unless --yes-to-all, for isolated labs only).

Gen-2: the run itself is assembled and driven by run.execute_run() — the exact same
code path the headless API server uses. The CLI only adds what a human at a terminal
needs: the preflight consent prompt, console output, and interactive approvals.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ConfigError, load_engagement
from .run import RunOptions, execute_run, interactive_approver


def _preflight(engagement, auto_yes: bool) -> bool:
    print("=" * 60)
    print(f"Engagement : {engagement.name}")
    print(f"Client     : {engagement.client}")
    print(f"Authorized : {engagement.authorized_by} (ref: {engagement.ticket})")
    print(f"Window     : {engagement.starts} .. {engagement.ends}  "
          f"({'ACTIVE' if engagement.is_active else 'NOT ACTIVE'})")
    print(f"In scope   : {', '.join(engagement.allowed_hosts)}")
    print(f"Excluded   : {', '.join(engagement.excluded_hosts) or '(none)'}")
    print(f"Sandbox    : {'on' if engagement.sandbox.enable else 'off'} "
          f"(image {engagement.sandbox.image})")
    print("=" * 60)
    if not engagement.is_active:
        print("Refusing to start: the engagement window is not active.")
        return False
    if auto_yes:
        return True
    return input("I confirm I am authorized to test these targets. Proceed? [y/N] ")\
        .strip().lower() in {"y", "yes"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorized red-team agent (Kali sandbox + OpenRouter)")
    parser.add_argument("--engagement", required=True, help="Path to the engagement YAML (RoE).")
    parser.add_argument("--objective", required=True, help="What the agent should accomplish.")
    parser.add_argument("--out", default="runs/latest", help="Output directory for this run.")
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--no-sandbox", action="store_true", help="Disable the Kali sandbox.")
    parser.add_argument("--no-browser", action="store_true", help="Disable browser automation.")
    parser.add_argument("--multi-agent", action="store_true",
                        help="Use the orchestrator + specialist swarm (recon + exploit) instead of one agent.")
    parser.add_argument("--yes-to-all", action="store_true",
                        help="Auto-approve every action. Use ONLY in an isolated lab.")
    parser.add_argument("--source-dir", default="",
                        help="Local source tree for the target (whitebox/benchmark runs). "
                             "When set, route decorators are grepped directly and seeded "
                             "into the knowledge graph before any LLM call — no token cost.")
    parser.add_argument("--semantic-memory", action="store_true",
                        help="Enable semantic recall of past lessons and app-shape "
                             "patterns using the LOCAL backend (JSON + on-device "
                             "embeddings, zero dependencies, no Docker).")
    parser.add_argument("--helix-memory", action="store_true",
                        help="Use HelixDB (graph+vector) for semantic memory instead of "
                             "the local backend. Requires Docker; starts a local HelixDB "
                             "container backed by a named Docker volume.")
    parser.add_argument("--events", action="store_true",
                        help="Also write a live event stream (events.jsonl) to the run "
                             "directory — the same telemetry the dashboard/API uses. "
                             "Useful for replaying a run with `python -m redteam.server`.")
    parser.add_argument("--asset-feed", default="",
                        help="Optional asset feed (CSV/JSON/JSONL, ScopeSentry-style "
                             "columns host|domain|ip, port, scheme, service) seeded into "
                             "the run's asset inventory. FAIL-CLOSED: entries outside "
                             "the RoE are dropped — the feed can never widen scope.")
    parser.add_argument("--no-traffic-bodies", action="store_true",
                        help="Record HTTP traffic headers only (traffic.jsonl); omit "
                             "request/response bodies. Use under strict data-handling RoE.")
    args = parser.parse_args(argv)

    try:
        engagement = load_engagement(args.engagement)
    except ConfigError as exc:
        print(f"Engagement config error: {exc}", file=sys.stderr)
        return 2

    if not _preflight(engagement, args.yes_to_all):
        print("Aborted.")
        return 1

    bus = None
    if args.events:
        from .events import EventBus
        run_dir = Path(args.out)
        run_dir.mkdir(parents=True, exist_ok=True)
        bus = EventBus(run_id=run_dir.name, sink_path=run_dir / "events.jsonl")

    try:
        summary = execute_run(RunOptions(
            engagement_path=args.engagement,
            objective=args.objective,
            out_dir=Path(args.out),
            multi_agent=args.multi_agent,
            max_steps=args.max_steps,
            no_sandbox=args.no_sandbox,
            no_browser=args.no_browser,
            source_dir=args.source_dir,
            yes_to_all=args.yes_to_all,
            semantic_memory=args.semantic_memory,
            helix_memory=args.helix_memory,
            asset_feed=args.asset_feed,
            record_traffic_bodies=not args.no_traffic_bodies,
            approve=interactive_approver(args.yes_to_all),
            on_text=lambda t: print(t, "\n"),
            events=bus,
        ))
    except ConfigError as exc:
        print(f"Engagement config error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"LLM setup error: {exc}", file=sys.stderr)
        return 2
    finally:
        if bus is not None:
            bus.close()

    out = Path(args.out)
    print(f"\nStatus    : {summary['status']}"
          + (f" ({summary['halt_reason']})" if summary['halt_reason'] else ""))
    print(f"Findings  : {out / 'findings.json'}")
    print(f"Graph     : {out / 'graph.json'}")
    print(f"Audit log : {out / 'audit.log.jsonl'}")
    return 0 if summary["status"] in {"completed", "halted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

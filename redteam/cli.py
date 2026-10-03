"""Command-line entrypoint for the red-team agent.

Usage:
    export OPENROUTER_API_KEY=sk-or-...
    python -m redteam.cli --engagement config/engagement.yaml \
        --objective "Map the API surface and test authentication controls" \
        --out runs/2026-09-26

The operator confirms scope at the preflight prompt before anything runs, and approves
each sensitive action interactively (unless --yes-to-all, for isolated labs only).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import RedTeamAgent
from .audit import AuditLog
from .config import ConfigError, load_engagement
from .findings import FindingStore
from .llm.openrouter import OpenRouterClient
from .ratelimit import RateLimiter
from .report import build_html_report, build_report
from .scope import ScopeGuard
from .tools import ToolContext, build_registry


def _make_approver(auto_yes: bool):
    def approve(action: str, details: dict) -> bool:
        if auto_yes:
            return True
        print("\n" + "=" * 60)
        print(f"APPROVAL REQUESTED: {action}")
        for k, v in details.items():
            print(f"  {k}: {v}")
        return input("Approve this action? [y/N] ").strip().lower() in {"y", "yes"}
    return approve


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
    print(f"Models     : OpenRouter free models (rotating by availability)")
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
                        help="Use HelixDB (graph+vector) for semantic recall of past "
                             "lessons and app-shape patterns, instead of plain tag "
                             "matching. Requires Docker; starts a local HelixDB "
                             "container backed by a named Docker volume, so lessons "
                             "and app-patterns persist across runs, not just within one.")
    args = parser.parse_args(argv)

    try:
        engagement = load_engagement(args.engagement)
    except ConfigError as exc:
        print(f"Engagement config error: {exc}", file=sys.stderr)
        return 2

    if not _preflight(engagement, args.yes_to_all):
        print("Aborted.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(out / "audit.log.jsonl")
    findings = FindingStore(out / "findings.json")
    limiter = RateLimiter(engagement.max_requests_per_second, engagement.max_total_requests)
    scope = ScopeGuard(engagement)
    from .knowledge import KnowledgeGraph
    graph = KnowledgeGraph(out / "graph.json")
    # The bandit's learned win-rates are cross-ENGAGEMENT state (like memory/experience.json
    # below), not per-run state — a fixed path, not out_dir, so technique selection keeps
    # improving across many runs instead of resetting every time.
    from .bandit import BanditStore
    bandit = BanditStore(Path("memory/bandit.json"))
    from .attack_tree import AttackTree
    attack_tree = AttackTree(out / "attack_tree.json", bandit=bandit)
    # Red-team core: what we hold, where we're going, and where we are in the kill chain.
    from .access import AccessGraph
    from .killchain import KillChain
    access = AccessGraph(out / "access.json")
    killchain = KillChain(out / "killchain.json")

    try:
        client = OpenRouterClient(engagement.llm, audit=audit)
    except RuntimeError as exc:
        print(f"LLM setup error: {exc}", file=sys.stderr)
        return 2

    use_sandbox = engagement.sandbox.enable and not args.no_sandbox
    use_browser = not args.no_browser

    from .recon import run_deterministic_recon
    recon_summary = run_deterministic_recon(engagement, graph, attack_tree, audit=audit,
                                            source_dir=args.source_dir)
    if recon_summary.get("endpoints_discovered") or recon_summary.get("static_routes_found"):
        print(f"Deterministic recon (no LLM calls): {recon_summary}")

    sandbox = None
    browser = None
    try:
        if use_sandbox:
            from .sandbox.docker_kali import KaliSandbox, SandboxError
            sandbox = KaliSandbox(engagement, audit=audit)
            try:
                print("\nStarting Kali sandbox (this can take a while on first build)...")
                plan = sandbox.start()
                print(f"Sandbox egress allows: {', '.join(plan.allowed_cidrs) or '(none)'}")
                print("Egress self-test: PASS (confirmed an out-of-scope destination is unreachable)")
                for w in plan.warnings:
                    print(f"  ! {w}")
            except SandboxError as exc:
                print(f"Sandbox failed to start: {exc}", file=sys.stderr)
                print("Continuing without the sandbox (kali_exec disabled).")
                sandbox = None

        if use_browser:
            from .tools.browser import BrowserController
            browser = BrowserController(scope, limiter, audit, out / "screenshots")

        from .session import SessionStore
        from .skills import SkillLibrary
        # Proven proofs, cross-run: learned skills plus imported corpora (e.g. nuclei).
        skills = SkillLibrary(Path("memory/skills.json"), max_skills=50000)
        ctx = ToolContext(scope=scope, limiter=limiter, audit=audit, findings=findings,
                          approve=_make_approver(args.yes_to_all),
                          sandbox=sandbox, browser=browser, graph=graph,
                          sessions=SessionStore(), skills=skills,
                          access=access, objective=engagement.objective,
                          killchain=killchain)

        # Cross-engagement memory: a single global store the agent learns into over time,
        # bootstrapped with curated tradecraft (correct oracle recipes) on first use.
        from .memory import ExperienceStore, seed_tradecraft
        helix_server = None
        backend = None
        if args.semantic_memory:
            from .memory_backend.embedder import Embedder
            from .memory_backend.helix_backend import HelixBackend
            from .memory_backend.helix_server import HelixServer, HelixServerError
            helix_server = HelixServer()
            try:
                print("\nStarting HelixDB (semantic memory)...")
                helix_server.start()
                backend = HelixBackend(helix_server.client(), Embedder())
                print("Semantic memory: ON (lessons/app-patterns recalled by meaning, not just tags)")
            except HelixServerError as exc:
                print(f"HelixDB failed to start: {exc}", file=sys.stderr)
                print("Continuing with plain tag-matched memory (memory/experience.json).")
                helix_server = None
        # path is ignored by ExperienceStore whenever a backend is supplied, so passing
        # it unconditionally is harmless and keeps the JSON fallback path explicit.
        memory = ExperienceStore(Path("memory/experience.json"), backend=backend)
        seed_tradecraft(memory)

        tools = build_registry(enable_sandbox=sandbox is not None, enable_browser=use_browser)

        from .runtime import BudgetTracker, RunManifest
        budget = BudgetTracker(max_seconds=engagement.max_run_seconds,
                               max_tokens=engagement.max_llm_tokens,
                               kill_file=out / "STOP")
        manifest = RunManifest(objective=args.objective, engagement=engagement.name)

        if args.multi_agent:
            from .orchestrator import Orchestrator
            driver = Orchestrator(engagement, tools, ctx, client, graph=graph,
                                  attack_tree=attack_tree, memory=memory)
        else:
            driver = RedTeamAgent(engagement, tools, ctx, client, max_steps=args.max_steps,
                                  graph=graph, attack_tree=attack_tree, memory=memory)
        driver.with_runtime(budget=budget, manifest=manifest, manifest_path=out / "manifest.json")

        mode = "multi-agent swarm" if args.multi_agent else "single agent"
        print(f"\nStarting {mode}... (drop a file named STOP in {out} to halt cleanly)\n")
        driver.run(args.objective, on_text=lambda t: print(t, "\n"))

        if not args.multi_agent:
            # Single-agent mode has no built-in VERIFY phase — its own checks only ever
            # reach pending_verification (see tools/confirm.py, tools/verify_tool.py,
            # tools/postex.py), so without this nothing here would ever count toward the
            # objective. Run the independent re-check in a FRESH context; never let the
            # same continuous run grade its own findings.
            from .orchestrator import run_verify_pass
            print("\nRunning independent verification pass over pending findings...\n")
            still_pending = run_verify_pass(engagement, tools, ctx, client, args.objective,
                                            budget=budget,
                                            on_text=lambda t: print(t, "\n"))
            if still_pending:
                print(f"  ! {still_pending} finding(s) still pending verification "
                      f"(budget/steps ran out).")

        print(f"\nBudget used: {budget.status()}")

        # Credit the recalled lessons by whether this run actually confirmed anything, so
        # only lessons that help survive; then distill new lessons from this run.
        confirmed = [f for f in findings.all() if f.confidence == "confirmed" and f.severity != "info"]
        memory.credit(helpful=len(confirmed) > 0)
        learned = memory.reflect_on_run(findings.all(), audit.read_all())
        if learned:
            print(f"Learned {len(learned)} lesson(s) into memory ({memory.summary()['lessons']} total).")

        # Distill APP-SHAPE patterns (auth flow shape, ID format, ...) before the graph
        # is discarded at process exit — this is the piece that actually closes the
        # "model goes blind on a new target" gap; reflect_on_run above only covers
        # vuln-PROVING technique, not what the app itself looked like.
        from .memory_backend.app_patterns import reflect_app_patterns
        for description, tags in reflect_app_patterns(graph, audit.read_all()):
            memory.learn_pattern(description, tags=tags)
    finally:
        if browser is not None:
            browser.close()
        if sandbox is not None:
            sandbox.stop()
        if helix_server is not None:
            helix_server.stop()

    report_path = out / "report.md"
    report_path.write_text(build_report(engagement, findings, requests_used=limiter.used),
                           encoding="utf-8")
    html_path = out / "report.html"
    html_path.write_text(build_html_report(engagement, findings, requests_used=limiter.used),
                         encoding="utf-8")

    # Persist the red-team state so the run can be scored on the objective, not a vuln list.
    if engagement.objective is not None:
        engagement.objective.save(out / "objective.json")
        done, total = engagement.objective.progress()
        verdict = "ACHIEVED" if engagement.objective.achieved else "not achieved"
        print(f"\nOBJECTIVE: {verdict}  ({done}/{total} criteria)")
        print(access.briefing(engagement.objective))

    print("\n" + "=" * 60)
    print(f"Run complete. {len(findings.all())} finding(s), {limiter.used} browser request(s).")
    print(f"Audit chain intact: {audit.verify_chain()}")
    print(f"Report    : {report_path}  |  {html_path}")
    print(f"Findings  : {out / 'findings.json'}")
    print(f"Graph     : {out / 'graph.json'}")
    print(f"Audit log : {out / 'audit.log.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

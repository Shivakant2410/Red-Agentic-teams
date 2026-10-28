"""Shared run executor: ONE assembly line that both the CLI and the headless server use.

Gen-1 assembled the whole run (sandbox, tools, memory, driver) inside cli.main, so an
API server would have to either re-implement all of it or shell out to the CLI. Both
are wrong. execute_run() now owns every step of assembling and driving a run:

  load engagement -> guards -> LLM client (Gen-1 OpenRouter or Gen-2 gateway)
  -> deterministic recon -> sandbox/browser -> tool context (+ EventBus, approver)
  -> memory -> driver (single agent or orchestrator swarm) -> verify pass -> reports

Everything a caller varies (interactive vs headless approvals, console printing vs
event-stream telemetry) is a field on RunOptions. With the defaults — no events bus,
interactive approver, console output — behavior is byte-for-byte the Gen-1 CLI.

Headless specifics (used by server.py):
  - HeadlessApprover: an approval becomes a record in approvals.json plus an
    approval.requested event; the agent thread blocks until an operator resolves it
    over REST (POST /api/approvals/{id}) or the STOP kill file appears (auto-DENY,
    fail closed).
  - AuditBridge: mirrors selected audit records (llm.rotate) onto the event bus so
    model rotations show up on the dashboard without touching the LLM clients.
  - EventBus: every engine event lands in events.jsonl — the API's replay and
    live-tail source of truth, decoupled from the engine's thread topology.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .agent import RedTeamAgent
from .audit import AuditLog
from .config import load_engagement
from .events import EventBus, safe_emit
from .findings import FindingStore
from .llm.gateway import build_llm_client
from .ratelimit import RateLimiter
from .report import build_html_report, build_report
from .scope import ScopeGuard
from .tools import ToolContext, build_registry


class RunSetupError(Exception):
    """Engagement/config problem that aborts the run before any agent step."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# approvals.json: the file contract between the engine thread (writer of pending
# records) and the API (resolver). Same process, so a module lock is enough.
# ---------------------------------------------------------------------------

_APPROVALS_LOCK = threading.Lock()


def _load_approvals(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_approvals(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)  # atomic: a concurrent API reader never sees a torn file


class HeadlessApprover:
    """Approval gate for unattended runs: file-backed, event-notified, REST-resolved.

    A request appends {id, action, details, ts} to approvals.json (status "pending")
    and emits approval.requested; the calling agent thread then polls until the record
    is resolved by POST /api/approvals/{id} — or the STOP kill file appears, which
    auto-DENIES so the agent can unwind while BudgetTracker halts the run. The engine
    thread is the only writer of pending records and the only emitter of
    approval.resolved (single-writer event stream); the API only flips the record.
    """

    def __init__(self, out_dir: str | Path, bus: EventBus | None,
                 kill_file: str | Path | None = None, poll_s: float = 0.5):
        self._path = Path(out_dir) / "approvals.json"
        self._bus = bus
        self._kill_file = Path(kill_file) if kill_file else None
        self._poll_s = poll_s

    def approve(self, action: str, details: dict) -> bool:
        aid = f"apr-{uuid.uuid4().hex[:12]}"
        with _APPROVALS_LOCK:
            data = _load_approvals(self._path)
            data.append({"id": aid, "action": action, "details": details,
                         "ts": _now(), "status": "pending", "approved": None,
                         "resolved_ts": None})
            _save_approvals(self._path, data)
        safe_emit(self._bus, "approval.requested", id=aid, action=action, details=details)
        while True:
            with _APPROVALS_LOCK:
                rec = next((r for r in _load_approvals(self._path) if r.get("id") == aid), None)
            if rec and rec.get("status") == "resolved":
                approved = bool(rec.get("approved"))
                safe_emit(self._bus, "approval.resolved", id=aid, approved=approved)
                return approved
            if self._kill_file is not None and self._kill_file.exists():
                with _APPROVALS_LOCK:
                    self._resolve_locked(aid, approved=False, note="kill switch")
                safe_emit(self._bus, "approval.resolved", id=aid, approved=False)
                return False
            time.sleep(self._poll_s)

    def _resolve_locked(self, aid: str, approved: bool, note: str = "") -> None:
        data = _load_approvals(self._path)
        for rec in data:
            if rec.get("id") == aid and rec.get("status") == "pending":
                rec["status"] = "resolved"
                rec["approved"] = bool(approved)
                rec["resolved_ts"] = _now()
                if note:
                    rec["note"] = note
        _save_approvals(self._path, data)


def resolve_approval(out_dir: str | Path, approval_id: str, approved: bool) -> bool:
    """Resolve a pending approval (server-side). False = unknown id or already
    resolved (the API turns that into 404). The engine thread notices the file flip
    and emits approval.resolved itself — the event stream stays single-writer."""
    p = Path(out_dir) / "approvals.json"
    with _APPROVALS_LOCK:
        data = _load_approvals(p)
        rec = next((r for r in data if r.get("id") == approval_id), None)
        if rec is None or rec.get("status") != "pending":
            return False
        rec["status"] = "resolved"
        rec["approved"] = bool(approved)
        rec["resolved_ts"] = _now()
        _save_approvals(p, data)
    return True


def read_pending_approvals(out_dir: str | Path) -> list[dict]:
    """Pending approvals for GET /api/runs/{id}/approvals."""
    with _APPROVALS_LOCK:
        data = _load_approvals(Path(out_dir) / "approvals.json")
    return [{"id": r.get("id", ""), "action": r.get("action", ""),
             "details": r.get("details", {}), "ts": r.get("ts", "")}
            for r in data if r.get("status") == "pending"]


class AuditBridge:
    """AuditLog front that ALSO mirrors selected records onto the event bus.

    Both LLM clients record model rotations as audit records ("llm.rotate"); instead
    of teaching them about telemetry, the server passes this bridge as its audit log
    and rotations reach the dashboard like any other event. Everything else delegates
    untouched, so the audit chain stays exactly as Gen-1 built it.
    """

    def __init__(self, audit: AuditLog, bus: EventBus | None,
                 forward: tuple[str, ...] = ("llm.rotate",)):
        self._audit = audit
        self._bus = bus
        self._forward = frozenset(forward)

    def record(self, event: str, **fields) -> None:
        self._audit.record(event, **fields)
        if event in self._forward:
            safe_emit(self._bus, event, **fields)

    def read_all(self) -> list[dict]:
        return self._audit.read_all()

    def verify_chain(self) -> bool:
        return self._audit.verify_chain()


def interactive_approver(auto_yes: bool) -> Callable[[str, dict], bool]:
    """The Gen-1 console approval gate (moved here so CLI and any interactive
    embedding share one implementation)."""
    def approve(action: str, details: dict) -> bool:
        if auto_yes:
            return True
        print("\n" + "=" * 60)
        print(f"APPROVAL REQUESTED: {action}")
        for k, v in details.items():
            print(f"  {k}: {v}")
        return input("Approve this action? [y/N] ").strip().lower() in {"y", "yes"}
    return approve


# ---------------------------------------------------------------------------
# RunOptions + execute_run
# ---------------------------------------------------------------------------

@dataclass
class RunOptions:
    engagement_path: str
    objective: str
    out_dir: Path
    multi_agent: bool = False
    max_steps: int = 40
    no_sandbox: bool = False
    no_browser: bool = False
    source_dir: str = ""
    yes_to_all: bool = False
    semantic_memory: bool = False  # local, zero-dependency semantic recall
    helix_memory: bool = False     # HelixDB path (requires Docker)
    # None -> interactive console prompts (CLI default); a callable -> custom gate
    # (HeadlessApprover for the server; tests pass lambdas).
    approve: Callable[[str, dict], bool] | None = None
    on_text: Callable[[str], None] | None = None
    quiet: bool = False            # suppress console output (headless/server runs)
    events: EventBus | None = None  # live telemetry bus; None = Gen-1 silent behavior
    memory_dir: Path = Path("memory")  # cross-run state: bandit, skills, experience
    # ARTEX-port options:
    # asset_feed: optional CSV/JSON/JSONL asset file (ScopeSentry-style) intersected
    #   FAIL-CLOSED with the RoE before seeding the inventory (importers/assets.py).
    # record_traffic_bodies: False masks request/response BODIES out of the traffic
    #   log entirely (headers are still recorded, credential values always masked).
    asset_feed: str = ""
    record_traffic_bodies: bool = True
    # (bind_host, bind_port) of the API/control plane launching this run, when there
    # is one. execute_run refuses to arm a run whose scope includes the control plane
    # itself (scope self-targeting — the agent must never be authorized to attack its
    # own console). None in CLI/standalone mode (nothing to collide with).
    control_plane: tuple[str, int] | None = None


def execute_run(opts: RunOptions) -> dict:
    """Assemble and drive one complete red-team run. Returns a summary dict:

    {status, halt_reason, findings, confirmed, tokens, steps, requests,
     objective_achieved, objective_done, objective_total, report_path, html_path,
     audit_intact, out_dir}

    Raises RunSetupError for engagement problems (inactive window, bad config),
    ConfigError for a malformed engagement file, RuntimeError for LLM setup
    failures. Everything else is reflected in the returned status.
    """
    out = Path(opts.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    say = (lambda *a, **k: print(*a, **k)) if not opts.quiet else (lambda *a, **k: None)
    on_text = opts.on_text
    bus = opts.events

    engagement = load_engagement(opts.engagement_path)
    if not engagement.is_active:
        raise RunSetupError(
            f"engagement window is not active ({engagement.starts} .. {engagement.ends})")

    # Scope self-targeting guard (before ANY network-capable machinery exists): a
    # scope that includes the control plane's own host:port lets the agent legally
    # attack its own API server. This is a scope-authoring error and must abort the
    # run before any agent step — see scope.check_control_plane_overlap.
    if opts.control_plane is not None:
        from .scope import check_control_plane_overlap
        check_control_plane_overlap(engagement, opts.control_plane[0], opts.control_plane[1])

    audit = AuditLog(out / "audit.log.jsonl")
    if bus is not None:
        audit = AuditBridge(audit, bus)
    findings = FindingStore(out / "findings.json")
    limiter = RateLimiter(engagement.max_requests_per_second, engagement.max_total_requests)
    scope = ScopeGuard(engagement)
    # Freeze the RoE grid to disk the moment the run exists (coverage.py reads it
    # later to report tested-vs-untouched honestly; the operator also gets the
    # exact allowlist this run was authorized for, independent of the engagement
    # file possibly having changed mid-engagement).
    try:
        (out / "scope.json").write_text(json.dumps({
            "allowed_hosts": list(engagement.allowed_hosts),
            "excluded_hosts": list(engagement.excluded_hosts),
            "allowed_ports": list(engagement.allowed_ports),
            "allowed_schemes": list(engagement.allowed_schemes),
            # rate + range policy too: retest.py rebuilds the RoE from this file
            # alone (the engagement file may have drifted since the run), and a
            # retest must obey the same traffic discipline as the original run.
            "max_requests_per_second": engagement.max_requests_per_second,
            "max_total_requests": engagement.max_total_requests,
            "allow_private_ranges": engagement.allow_private_ranges,
        }, indent=2), encoding="utf-8")
    except OSError:
        pass  # coverage degrades honestly without it; the run must not die here
    from .knowledge import KnowledgeGraph
    graph = KnowledgeGraph(out / "graph.json")
    # The bandit's learned win-rates are cross-ENGAGEMENT state (like the memory dir
    # below), not per-run state — a fixed path, not out_dir, so technique selection
    # keeps improving across many runs instead of resetting every time.
    from .bandit import BanditStore
    bandit = BanditStore(Path(opts.memory_dir) / "bandit.json")
    from .attack_tree import AttackTree
    attack_tree = AttackTree(out / "attack_tree.json", bandit=bandit)
    # Red-team core: what we hold, where we're going, and where we are in the kill chain.
    from .access import AccessGraph
    from .killchain import KillChain
    access = AccessGraph(out / "access.json")
    killchain = KillChain(out / "killchain.json")

    # ARTEX-port telemetry: wire-evidence traffic log + attack-surface inventory.
    # Both are per-run files the API serves; both are optional from the tools' POV
    # (getattr) so bespoke ToolContexts (tests, embedders) keep working unchanged.
    from .inventory import AssetInventory
    from .traffic import TrafficRecorder
    traffic = TrafficRecorder(out / "traffic.jsonl",
                              record_bodies=opts.record_traffic_bodies)
    inventory = AssetInventory(out / "inventory.json")

    # Operator-supplied asset feed (ScopeSentry-style): intersected with the RoE
    # BEFORE anything else touches the network. Dropped records are counted, never
    # widened into scope — the importer is an intersection, not a merge.
    if opts.asset_feed:
        from .importers.assets import apply_asset_feed, load_asset_feed
        try:
            feed_records = load_asset_feed(opts.asset_feed)
        except ValueError as exc:
            raise RunSetupError(f"asset feed unusable: {exc}")
        feed_stats = apply_asset_feed(feed_records, scope, inventory)
        say(f"Asset feed: {feed_stats['imported']}/{feed_stats['total']} imported "
            f"({feed_stats['dropped']} dropped — out of scope or portless). "
            f"Scope was NOT widened.")
        safe_emit(bus, "assets.imported", total=feed_stats["total"],
                  imported=feed_stats["imported"], dropped=feed_stats["dropped"],
                  source="asset_feed")

    client = build_llm_client(engagement.llm, audit=audit)

    approver = opts.approve if opts.approve is not None else interactive_approver(opts.yes_to_all)

    use_sandbox = engagement.sandbox.enable and not opts.no_sandbox
    use_browser = not opts.no_browser

    from .recon import run_deterministic_recon
    recon_summary = run_deterministic_recon(engagement, graph, attack_tree, audit=audit,
                                            source_dir=opts.source_dir)
    if recon_summary.get("endpoints_discovered") or recon_summary.get("static_routes_found"):
        say(f"Deterministic recon (no LLM calls): {recon_summary}")

    sandbox = None
    browser = None
    helix_server = None
    try:
        if use_sandbox:
            from .sandbox.docker_kali import KaliSandbox, SandboxError
            sandbox = KaliSandbox(engagement, audit=audit)
            try:
                say("\nStarting Kali sandbox (this can take a while on first build)...")
                plan = sandbox.start()
                say(f"Sandbox egress allows: {', '.join(plan.allowed_cidrs) or '(none)'}")
                say("Egress self-test: PASS (confirmed an out-of-scope destination is unreachable)")
                for w in plan.warnings:
                    say(f"  ! {w}")
            except SandboxError as exc:
                say(f"Sandbox failed to start: {exc}")
                say("Continuing without the sandbox (kali_exec disabled).")
                sandbox = None

        if use_browser:
            from .tools.browser import BrowserController
            browser = BrowserController(scope, limiter, audit, out / "screenshots")

        from .session import SessionStore
        from .skills import SkillLibrary
        # Proven proofs, cross-run: learned skills plus imported corpora (e.g. nuclei).
        skills = SkillLibrary(Path(opts.memory_dir) / "skills.json", max_skills=50000)
        ctx = ToolContext(scope=scope, limiter=limiter, audit=audit, findings=findings,
                          approve=approver,
                          sandbox=sandbox, browser=browser, graph=graph,
                          sessions=SessionStore(), skills=skills,
                          access=access, objective=engagement.objective,
                          killchain=killchain, events=bus,
                          traffic=traffic, inventory=inventory)

        # Cross-engagement memory: a single global store the agent learns into over time,
        # bootstrapped with curated tradecraft (correct oracle recipes) on first use.
        # Semantic recall is additive and degrades gracefully: the local backend needs no
        # Docker (JSON + on-device/hashing embeddings); Helix stays opt-in via helix_memory.
        from .memory import ExperienceStore, seed_tradecraft
        helix_server = None
        backend = None
        if opts.helix_memory:
            from .memory_backend.embedder import Embedder
            from .memory_backend.helix_backend import HelixBackend
            from .memory_backend.helix_server import HelixServer, HelixServerError
            helix_server = HelixServer()
            try:
                say("\nStarting HelixDB (semantic memory)...")
                helix_server.start()
                backend = HelixBackend(helix_server.client(), Embedder())
                say("Semantic memory: ON (HelixDB; lessons/app-patterns recalled by meaning)")
            except HelixServerError as exc:
                say(f"HelixDB failed to start: {exc}")
                say("Continuing with plain tag-matched memory (memory/experience.json).")
                helix_server = None
        elif opts.semantic_memory:
            from .memory_backend.local_semantic import LocalSemanticBackend
            try:
                backend = LocalSemanticBackend(Path(opts.memory_dir) / "semantic.json")
                say("Semantic memory: ON (local, zero-dependency; lessons/app-patterns "
                    "recalled by meaning)")
            except Exception as exc:
                say(f"Local semantic memory unavailable ({exc}); using tag-matched memory.")
                backend = None
        # path is ignored by ExperienceStore whenever a backend is supplied, so passing
        # it unconditionally is harmless and keeps the JSON fallback path explicit.
        memory = ExperienceStore(Path(opts.memory_dir) / "experience.json", backend=backend)
        seed_tradecraft(memory)

        tools = build_registry(enable_sandbox=sandbox is not None, enable_browser=use_browser)

        from .runtime import BudgetTracker, RunManifest
        budget = BudgetTracker(max_seconds=engagement.max_run_seconds,
                               max_tokens=engagement.max_llm_tokens,
                               kill_file=out / "STOP")
        manifest = RunManifest(objective=opts.objective, engagement=engagement.name)
        manifest.save(out / "manifest.json")  # exists from the first second (API listing)

        safe_emit(bus, "run.start", objective=opts.objective, engagement=engagement.name,
                  mode="multi-agent swarm" if opts.multi_agent else "single agent")

        if opts.multi_agent:
            from .orchestrator import Orchestrator
            driver = Orchestrator(engagement, tools, ctx, client, graph=graph,
                                  attack_tree=attack_tree, memory=memory)
        else:
            driver = RedTeamAgent(engagement, tools, ctx, client, max_steps=opts.max_steps,
                                  graph=graph, attack_tree=attack_tree, memory=memory,
                                  terminal_on_budget_end=True)
        driver.with_runtime(budget=budget, manifest=manifest, manifest_path=out / "manifest.json")

        mode = "multi-agent swarm" if opts.multi_agent else "single agent"
        say(f"\nStarting {mode}... "
            f"(drop a file named STOP in {out} to halt cleanly)\n" if not opts.quiet
            else f"Starting {mode}...")

        driver.run(opts.objective, on_text=on_text)

        if not opts.multi_agent:
            # Single-agent mode has no built-in VERIFY phase — its own checks only ever
            # reach pending_verification (see tools/confirm.py, tools/verify_tool.py,
            # tools/postex.py), so without this nothing here would ever count toward the
            # objective. Run the independent re-check in a FRESH context; never let the
            # same continuous run grade its own findings.
            from .orchestrator import run_verify_pass
            say("\nRunning independent verification pass over pending findings...\n")
            still_pending = run_verify_pass(engagement, tools, ctx, client, opts.objective,
                                            budget=budget, on_text=on_text)
            if still_pending:
                say(f"  ! {still_pending} finding(s) still pending verification "
                    f"(budget/steps ran out).")

        say(f"\nBudget used: {budget.status()}")

        # Attack-surface rollup (ARTEX-style): what answered, where, as what.
        inv_summary = inventory.summary()
        if inv_summary["hosts"]:
            say(f"Attack surface: {inv_summary['hosts']} host(s), "
                f"{inv_summary['services']} service(s) observed "
                f"(inventory.json); {traffic.count} exchange(s) in traffic.jsonl.")

        # Credit the recalled lessons by whether this run actually confirmed anything, so
        # only lessons that help survive; then distill new lessons from this run.
        confirmed = [f for f in findings.all() if f.confidence == "confirmed" and f.severity != "info"]
        memory.credit(helpful=len(confirmed) > 0)
        learned = memory.reflect_on_run(findings.all(), audit.read_all())
        if learned and not opts.quiet:
            say(f"Learned {len(learned)} lesson(s) into memory ({memory.summary()['lessons']} total).")

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
    objective_achieved = None
    objective_done = objective_total = 0
    if engagement.objective is not None:
        engagement.objective.save(out / "objective.json")
        objective_done, objective_total = engagement.objective.progress()
        objective_achieved = bool(engagement.objective.achieved)
        say(f"\nOBJECTIVE: {'ACHIEVED' if objective_achieved else 'not achieved'} "
            f"({objective_done}/{objective_total} criteria)")
        say(access.briefing(engagement.objective))

    say("\n" + "=" * 60)
    say(f"Run complete. {len(findings.all())} finding(s), {limiter.used} browser request(s).")
    say(f"Audit chain intact: {audit.verify_chain()}")
    say(f"Report    : {report_path}  |  {html_path}")

    final_manifest = RunManifest.load(out / "manifest.json")
    status = final_manifest.status if final_manifest else "completed"
    halt_reason = final_manifest.halt_reason if final_manifest else ""
    tokens = final_manifest.tokens if final_manifest else 0
    steps = final_manifest.steps if final_manifest else 0

    safe_emit(bus, "run.finish", status=status, findings=len(findings.all()),
              tokens=tokens, halt_reason=halt_reason)

    return {
        "status": status,
        "halt_reason": halt_reason,
        "findings": len(findings.all()),
        "confirmed": len(confirmed),
        "tokens": tokens,
        "steps": steps,
        "requests": limiter.used,
        "objective_achieved": objective_achieved,
        "objective_done": objective_done,
        "objective_total": objective_total,
        "report_path": str(report_path),
        "html_path": str(html_path),
        "audit_intact": audit.verify_chain(),
        "out_dir": str(out),
        "traffic_recorded": traffic.count,
        "surface_hosts": inventory.summary()["hosts"],
        "surface_services": inventory.summary()["services"],
    }

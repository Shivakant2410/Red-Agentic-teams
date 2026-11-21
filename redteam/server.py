"""Headless control-plane server: the engine behind the dashboard.

One process, two roles:
  1. REST/SSE API over run lifecycle — launch runs, watch them live (events.jsonl
     replay + tail), resolve approvals, stop runs, fetch reports. All state lives in
     the run directories (manifest.json, events.jsonl, findings.json, ...), so the
     server is stateless across restarts and a run keeps going even if you never
     open the dashboard.
  2. Static hosting for the Next.js dashboard export (dashboard/out) at "/".

The engine runs in a background thread of THIS process (execute_run + HeadlessApprover
+ EventBus). events.jsonl is the single source of truth for telemetry: the API never
reads in-memory state for events, which keeps replay, live-tail, and post-mortem
inspection on exactly the same bytes the engine wrote.

Run:  python -m redteam.server --runs-root runs --port 8000 --dashboard dashboard/out
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import os
import re
import threading
import time
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .events import read_events
from .run import RunOptions, execute_run, read_pending_approvals, resolve_approval
from .runtime import RunManifest

VERSION = "0.3.0"
SSE_POLL_S = 0.4
SSE_PING_S = 15.0
MAX_EVENTS_PER_READ = 1000


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _finalize_mission_record(run_dir: Path, status: str, reason: str) -> bool:
    """Mark a mission snapshot terminal if it still reads "running".

    Handles both record shapes (the {mission: {...}, tasks: [...]} snapshot and
    the legacy flat record). Best-effort: the mission journal stays the durable
    authority, so a failed write here must never crash the caller. Returns True
    when the record was actually updated."""
    path = run_dir / "mission.json"
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(rec, dict):
        return False
    inner = rec.get("mission") if isinstance(rec.get("mission"), dict) else rec
    if not isinstance(inner, dict) or str(inner.get("status", "")) != "running":
        return False
    inner["status"] = status
    inner["halt_reason"] = reason
    inner["updated"] = _now()
    # ATOMIC: the API polls this file while run threads mutate it.
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def _reconcile_interrupted_runs(runs_root: Path) -> int:
    """Finalize artifacts left "running" by a dead process (server restart,
    crash, or kill -9). Runs execute as threads of THIS process, so at startup
    every manifest that still says "running" belongs to a run that can never
    finish; mission snapshots dangle the same way. Returns the number of run
    directories reconciled.

    Without this, a restart leaves zombie runs the dashboard polls forever
    (live-fire 20261118: a killed server left manifest.json and mission.json
    both "running" with no run.finish event)."""
    if not runs_root.is_dir():
        return 0
    touched = 0
    for run_dir in sorted(runs_root.iterdir()):
        if not run_dir.is_dir():
            continue
        mpath = run_dir / "manifest.json"
        run_status = ""
        try:
            manifest = RunManifest.load(mpath)
        except Exception:
            manifest = None
        if manifest is not None:
            run_status = manifest.status
            if run_status == "running":
                manifest.status = "error"
                manifest.halt_reason = "server_restarted: run interrupted before completion"
                try:
                    manifest.save(mpath)
                    run_status = "error"
                except OSError:
                    pass
        if (run_dir / "mission.json").exists():
            if run_status == "error":
                finalized = _finalize_mission_record(
                    run_dir, "failed",
                    "server_restarted: mission interrupted before completion")
            elif run_status in ("completed", "halted"):
                # The run ended but the mission driver never finalized (pre-fix
                # artifacts, or a crash inside finalization itself).
                finalized = _finalize_mission_record(
                    run_dir, "failed", "run ended without mission finalization")
            else:
                finalized = False
            if finalized:
                touched += 1
        if run_status == "error":
            touched += 1
    return touched


# Operator-selectable LLM providers for the dashboard's launch form. Mirrors the
# kind shortcuts in redteam/llm/providers.py ProviderConfig.resolved(); the value
# is the env var the engine reads the API key from ("" = no key needed). A kind
# outside this table is still accepted when the operator supplies base_url —
# that is the openai_compat escape hatch (vLLM, LM Studio, a private proxy, ...).
LLM_PROVIDER_SHORTCUTS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "zai": "ZAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
    "ollama": "",
}

# Initial-selection heuristic for the Ollama model dropdown, in MODELS order:
# the first installed model whose name matches a family with a reputation for
# tool calling. A HEURISTIC ONLY — discovery never proves tool-calling
# capability; the preflight is the authority (and the dashboard runs it).
_OLLAMA_TOOL_HINTS = ("qwen3", "qwen2.5", "qwen2", "llama3.3", "llama3.2",
                      "llama3.1", "mistral-nemo", "mistral-small", "mistral",
                      "glm4", "command-r", "granite3", "phi4", "firefunction",
                      "hermes")


def _pick_ollama_default(models: list[str]) -> str:
    for model in models:
        low = model.lower()
        if any(hint in low for hint in _OLLAMA_TOOL_HINTS):
            return model
    return models[0] if models else ""


class LlmOverride(BaseModel):
    """The operator's model choice for this launch (dashboard selector → launch body).

    The API key, when supplied, stays in memory as RUN-SCOPED credentials carried
    on this run's RunOptions into provider construction — never written to disk,
    the process env, logs, or echoed back. Concurrent runs each carry their own."""
    provider: str = Field(min_length=1, max_length=40)
    # Empty = let the provider's natural rotation pick; a value pins the fleet to
    # exactly this model id via llm.providers[].models_allow.
    model: str = Field(default="", max_length=160)
    api_key: str = Field(default="", max_length=4096)
    base_url: str = Field(default="", max_length=300)


class PreflightBody(BaseModel):
    """POST /api/llm/preflight — server-side launch preflight: verify the agent
    server can reach the endpoint, the model exists, and it can emit a parseable
    tool call, using a harmless synthetic request. The only traffic is agent
    server → LLM endpoint; this never touches any engagement target."""
    provider: str = Field(min_length=1, max_length=40)
    model: str = Field(default="", max_length=200)
    base_url: str = Field(default="", max_length=300)
    api_key: str = Field(default="", max_length=4096)


# Request models live at module level: with `from __future__ import annotations`,
# FastAPI resolves parameter annotations by name, so a closure-local class would
# break schema generation (unresolvable ForwardRef).
class LaunchBody(BaseModel):
    engagement_path: str
    # An empty objective is meaningless (the agent has no contract to work toward)
    # and a >20k-char one is almost certainly a payload mistake, not a brief.
    objective: str = Field(min_length=1, max_length=20000)
    multi_agent: bool = True
    max_steps: int = Field(default=40, ge=1, le=1000)
    source_dir: str = ""
    yes_to_all: bool = False
    # ARTEX-port: optional operator-supplied asset feed (CSV/JSON/JSONL) seeded into
    # the run's asset inventory after a FAIL-CLOSED intersection with the RoE.
    asset_feed: str = ""
    # Optional model/provider selection from the dashboard (None = use whatever
    # the engagement file itself configures).
    llm: LlmOverride | None = None


class MissionBody(BaseModel):
    # Phase 2 missions (additive): same launch validation as /api/runs; the run
    # is executed by the mission coordination driver (RunOptions.driver="mission").
    # plan is an OPTIONAL inline task plan for operators who deliberately want a
    # static script — empty (the default) runs Builder 03's dynamic AttackTree
    # frontier; the server never fabricates a plan on the operator's behalf.
    engagement_path: str
    objective: str = Field(min_length=1, max_length=20000)
    max_steps: int = Field(default=40, ge=1, le=1000)
    asset_feed: str = ""
    yes_to_all: bool = False
    plan: list = []
    # Same provider/model selection contract as LaunchBody.llm (run-scoped
    # credentials; see _prepare_llm).
    llm: LlmOverride | None = None


class LaunchAuthorization(BaseModel):
    """URL-first launch authorization (Builder 04). A checkbox alone is NOT
    proof of authorization: the launch fails closed unless the operator records
    WHO authorized the test, against WHICH reference, and WHEN it expires."""
    confirmed: bool = False
    authorized_by: str = Field(default="", max_length=300)
    ticket: str = Field(default="", max_length=300)
    starts: str = Field(default="", max_length=10)   # ISO date; default today
    ends: str = Field(default="", max_length=10)     # ISO date; default today+7
    # Local-lab opt-in for loopback/RFC1918 targets (same switch ScopeGuard
    # enforces per request — never set by the server on the operator's behalf).
    allow_private_ranges: bool = False
    excluded_hosts: list[str] = Field(default_factory=list, max_length=100)


class UrlLaunchBody(BaseModel):
    """POST /api/launch — URL-first engagement creation (Builder 04).

    The operator supplies the authorized web application URL; the server parses
    and normalizes it, validates the authorization metadata fail-closed, builds
    the internal RoE (via redteam.launch), validates it with the existing
    loader, and arms the SAME launch pipeline as /api/runs and /api/missions."""
    target_url: str = Field(min_length=1, max_length=2000)
    objective: str = Field(min_length=1, max_length=20000)
    mode: str = Field(default="classic", max_length=20)  # classic | mission
    authorization: LaunchAuthorization = Field(default_factory=LaunchAuthorization)
    intensity: str = Field(default="standard", max_length=20)  # low|standard|high
    max_steps: int = Field(default=40, ge=1, le=1000)
    max_run_seconds: int = Field(default=0, ge=0, le=7 * 24 * 3600)
    max_llm_tokens: int = Field(default=0, ge=0)
    multi_agent: bool = True          # classic driver only
    yes_to_all: bool = False
    source_dir: str = Field(default="", max_length=1000)  # classic driver only
    asset_feed: str = Field(default="", max_length=2_000_000)
    plan: list = []                   # mission driver only (deliberate static plan)
    llm: LlmOverride | None = None


class ApprovalBody(BaseModel):
    approve: bool


class RetestBody(BaseModel):
    # Empty finding_id = retest EVERY finding that carries a replay recipe.
    finding_id: str = ""
    trials: int = Field(default=5, ge=1, le=20)
    need: int = Field(default=4, ge=1, le=20)
    # Workflow findings (one-shot sequences) need a fresh identifier's steps;
    # everything else replays deterministically without them.
    fresh_attack_steps: list = []
    fresh_control_steps: list = []


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


class RunRegistry:
    """In-process bookkeeping for live runs: the thread, the bus, the manifest path.

    Everything durable lives in the run directory; this only tracks what a process
    needs (its own threads and open sinks) and finalizes the manifest if a run dies
    with an unhandled exception, so no dashboard ever watches a zombie "running" run.
    """

    def __init__(self, runs_root: Path):
        self.runs_root = runs_root
        self._lock = threading.Lock()
        self._buses: dict[str, object] = {}

    def new_run_id(self, objective: str) -> str:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^a-z0-9]+", "-", objective.lower()).strip("-")[:32].strip("-")
        base = f"{ts}-{slug}" if slug else ts
        run_id, i = base, 2
        while (self.runs_root / run_id).exists():
            run_id, i = f"{base}-{i}", i + 1
        return run_id

    def register_bus(self, run_id: str, bus) -> None:
        with self._lock:
            self._buses[run_id] = bus

    def pop_bus(self, run_id: str):
        with self._lock:
            return self._buses.pop(run_id, None)

    def launch(self, run_id: str, out_dir: Path, opts: RunOptions) -> None:
        def target() -> None:
            try:
                execute_run(opts)
            except Exception as exc:  # noqa: BLE001 — never leave a zombie "running"
                manifest = RunManifest.load(out_dir / "manifest.json") \
                    or RunManifest(objective=opts.objective, engagement="")
                manifest.status = "error"
                manifest.halt_reason = f"{type(exc).__name__}: {exc}"
                # The mission driver normally finalizes its own snapshot (the
                # driver is exception-safe); this is defense in depth for a
                # crash BEFORE the driver's try (e.g. building the mission
                # record) or inside finalization itself. Snapshot first, THEN
                # the manifest: pollers (dashboard, tests) leave their poll
                # loop the moment the manifest stops reading "running", so a
                # manifest already saved "error" with the snapshot still
                # "running" is a race the slow CI scheduler loses.
                if opts.driver == "mission":
                    _finalize_mission_record(out_dir, "failed",
                                             f"mission_aborted: {type(exc).__name__}")
                manifest.save(out_dir / "manifest.json")
                bus = self.pop_bus(run_id)
                if bus is not None:
                    try:
                        bus.emit("run.finish", status="error", findings=0, tokens=0,
                                 halt_reason=manifest.halt_reason)
                    except Exception:
                        pass
            finally:
                bus = self.pop_bus(run_id)
                if bus is not None:
                    bus.close()

        t = threading.Thread(target=target, name=f"run-{run_id}", daemon=True)
        t.start()


def _write_effective_engagement(src_path: str, out_dir: Path, llm: LlmOverride) -> str:
    """Copy the engagement YAML into the run dir with the llm block replaced by
    the operator's selection. The run then launches against that copy, so every
    artifact the run produces records the exact model config it ran with —
    and the original engagement file is never modified in place."""
    data = yaml.safe_load(Path(src_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise HTTPException(400, "engagement is not a YAML mapping")
    entry: dict = {"kind": llm.provider.strip().lower()}
    if llm.base_url:
        entry["base_url"] = llm.base_url
    if llm.model:
        entry["models_allow"] = [llm.model]
    data["llm"] = {"providers": [entry]}
    dest = out_dir / "engagement.yaml"
    dest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return str(dest)


def _prepare_llm(llm: LlmOverride | None, src_path: str,
                 out_dir: Path) -> tuple[str, dict]:
    """Shared launch-path preparation for BOTH drivers (POST /api/runs and
    POST /api/missions). Returns (effective_engagement_path, credentials):

    - None override -> the original engagement path, empty credentials.
    - Override      -> an effective engagement.yaml written into the run dir
      (providers block WITHOUT any key material — the original file is never
      modified), plus a RUN-SCOPED credentials dict {api_key_env -> key} carried
      in memory on the run's RunOptions. The key never touches the process
      environment (concurrent runs with different keys stay isolated), never
      lands in the YAML, manifests, events, logs, or any persistent artifact.

    An unknown kind without base_url is a client 400 at launch, never a dead run.
    """
    if llm is None:
        return src_path, {}
    kind = llm.provider.strip().lower()
    if kind not in LLM_PROVIDER_SHORTCUTS and not llm.base_url:
        raise HTTPException(
            400,
            f"unknown llm provider '{kind}' — choose one of "
            f"{sorted(LLM_PROVIDER_SHORTCUTS)} or pass base_url")
    key_env = LLM_PROVIDER_SHORTCUTS.get(kind, "")
    credentials = {}
    if llm.api_key and key_env:
        credentials[key_env] = llm.api_key
    launch_path = _write_effective_engagement(src_path, out_dir, llm)
    return launch_path, credentials


def create_app(runs_root: Path, dashboard_dir: Path | None = None,
               control_plane: tuple[str, int] | None = None) -> FastAPI:
    """Build the control-plane app.

    control_plane = this server's own (bind_host, bind_port). Every launch validates
    the engagement's scope against it BEFORE arming a run: a scope that includes the
    control plane would authorize the agent to attack its own console (live-fire
    lesson — the operator error must be a 400 at launch, not a compromised run)."""
    runs_root = runs_root.resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    reconciled = _reconcile_interrupted_runs(runs_root)
    if reconciled:
        print(f"[server] reconciled {reconciled} run dir(s) left dangling by a "
              f"previous process (manifest/snapshot marked terminal)", flush=True)
    registry = RunRegistry(runs_root)
    app = FastAPI(title="red-team control plane", version=VERSION, docs_url=None, redoc_url=None)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
        allow_headers=["*"], expose_headers=["*"],
    )

    # -- helpers ---------------------------------------------------------------

    def require_run(run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id) or ".." in run_id:
            raise HTTPException(404, "unknown run")
        run_dir = runs_root / run_id
        if not run_dir.is_dir():
            raise HTTPException(404, "unknown run")
        return run_dir

    def manifest_of(run_dir: Path) -> dict:
        return _read_json(run_dir / "manifest.json", {}) or {}

    def launch_form(engagement_path: str, objective: str, multi_agent: bool, max_steps: int,
                    source_dir: str, yes_to_all: bool, asset_feed: str = "",
                    llm_credentials: dict | None = None) -> RunOptions:
        return RunOptions(
            engagement_path=engagement_path, objective=objective,
            out_dir=runs_root / "<set-by-caller>", multi_agent=multi_agent,
            max_steps=max_steps, source_dir=source_dir, yes_to_all=yes_to_all,
            quiet=True, on_text=None, control_plane=control_plane,
            asset_feed=asset_feed,
            # Run-scoped {api_key_env -> key} for THIS run only — in-memory on the
            # options object, resolved into provider sessions at construction;
            # never persisted or logged (see _prepare_llm).
            llm_credentials=llm_credentials or {},
        )

    # -- API: health -----------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": VERSION, "runs_root": str(runs_root)}

    # -- API: lifecycle introspection --------------------------------------------
    # Machine-readable spec of EVERY state machine the platform emits into
    # events/artifacts/API payloads (states.py is the source of truth). Agents,
    # the dashboard, and CI lint the vocabulary from here instead of parsing
    # source — the AX/DX surface of docs/state-machines.md.

    @app.get("/api/state-machines")
    def state_machines() -> dict:
        from .states import machines_json
        return machines_json()

    # -- API: runs lifecycle ---------------------------------------------------

    @app.post("/api/runs", status_code=202)
    def launch_run(body: LaunchBody) -> dict:
        from .config import ConfigError, load_engagement
        try:
            engagement = load_engagement(body.engagement_path)
        except ConfigError as exc:
            raise HTTPException(400, f"bad engagement: {exc}")
        except ValueError as exc:
            # structurally-valid YAML with invalid values (e.g. a bad objective
            # criterion kind) raises ValueError from dataclass validation — a
            # client mistake must be 400, never an unhandled 500.
            raise HTTPException(400, f"bad engagement: {exc}")
        if not engagement.is_active:
            raise HTTPException(400, "engagement window is not active")
        if control_plane is not None:
            # Refuse to arm: a run whose scope includes this server's own host:port
            # would let the agent attack the control plane itself. Fail at launch with
            # an actionable message instead of discovering it mid-run.
            from .scope import check_control_plane_overlap
            try:
                check_control_plane_overlap(engagement, control_plane[0], control_plane[1])
            except ConfigError as exc:
                raise HTTPException(400, f"bad engagement: {exc}")
        if body.asset_feed:
            # A feed the importer cannot parse is a client mistake: 400 at launch,
            # not a run thread that dies two seconds later.
            from .importers.assets import load_asset_feed
            try:
                load_asset_feed(body.asset_feed)
            except ValueError as exc:
                raise HTTPException(400, f"bad asset_feed: {exc}")

        run_id = registry.new_run_id(body.objective)
        out_dir = runs_root / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        launch_path, llm_credentials = _prepare_llm(body.llm, body.engagement_path, out_dir)

        RunManifest(objective=body.objective, engagement=engagement.name,
                    driver="classic").save(out_dir / "manifest.json")

        from .events import EventBus
        from .run import HeadlessApprover
        bus = EventBus(run_id=run_id, sink_path=out_dir / "events.jsonl")
        registry.register_bus(run_id, bus)
        if body.llm is not None:
            # Surface the operator's selection in the event feed; EventRow renders
            # unknown types defensively, so this is safe for older dashboards too.
            bus.emit("llm.selected", provider=body.llm.provider.strip().lower(),
                     model=body.llm.model, base_url=body.llm.base_url)

        opts = launch_form(launch_path, body.objective, body.multi_agent,
                           body.max_steps, body.source_dir, body.yes_to_all,
                           body.asset_feed, llm_credentials=llm_credentials)
        opts.out_dir = out_dir
        opts.events = bus
        opts.approve = HeadlessApprover(out_dir, bus, kill_file=out_dir / "STOP")

        registry.launch(run_id, out_dir, opts)
        return {"run_id": run_id, "out_dir": str(out_dir), "status": "running"}

    @app.get("/api/llm/providers")
    def list_llm_providers() -> dict:
        """Provider catalog for the dashboard selector: which kinds the engine
        supports and whether the standard key env var is already set in the
        server process. Reports key presence only — never the key itself."""
        return {"providers": [
            {"kind": kind, "api_key_env": env,
             "key_set": (bool(os.environ.get(env)) if env else True)}
            for kind, env in LLM_PROVIDER_SHORTCUTS.items()
        ]}

    @app.get("/api/llm/ollama/status")
    def ollama_status(base_url: str = "") -> dict:
        """Ollama auto-connect probe (Builder 04): REAL HTTP checks against the
        configured Ollama endpoint — a configured URL alone never counts as
        connected. Model discovery lists the INSTALLED models (native /api/tags,
        the canonical Ollama listing); discovery does NOT prove tool-calling
        capability — that is what /api/llm/preflight verifies on demand.

        SSRF controls (PR #25 review fix): the client-supplied base_url goes
        through the provider endpoint guard (ProviderConfig.resolved fails
        closed on non-http(s) schemes, embedded credentials, and
        link-local/metadata addresses — RFC1918/loopback stay allowed because
        local Ollama IS the point); the probe itself never follows redirects
        (a redirect cannot smuggle the request past the guard) and reads a
        bounded body."""
        from .llm.providers import ProviderConfig, ProviderEndpointError
        import requests as _rq
        try:
            cfg = ProviderConfig(kind="ollama",
                                 base_url=(base_url or "").strip()).resolved()
        except ProviderEndpointError as exc:
            return {"provider": "ollama", "base_url": base_url,
                    "connected": False, "state": "endpoint_rejected",
                    "version": "", "models": [], "default_model": "",
                    "message": "Provider endpoint rejected by the SSRF guard.",
                    "detail": str(exc)[:300]}
        root = cfg.base_url[:-3] if cfg.base_url.endswith("/v1") else cfg.base_url
        try:
            resp = _rq.get(f"{root}/api/tags", timeout=4, allow_redirects=False)
            resp.raise_for_status()
            if len(getattr(resp, "content", b"")) > 1_000_000:
                raise _rq.RequestException("model listing too large")
            payload = resp.json()
            models = sorted({str((m.get("name") or m.get("model") or "")).strip()
                             for m in (payload.get("models") or [])
                             if isinstance(m, dict) and (m.get("name") or m.get("model"))})
            version = ""
            try:
                version = str(_rq.get(f"{root}/api/version", timeout=2,
                                      allow_redirects=False).json().get("version", ""))
            except (_rq.RequestException, ValueError):
                pass
            if not models:
                return {"provider": "ollama", "base_url": root, "connected": True,
                        "state": "no_models", "version": version, "models": [],
                        "default_model": "",
                        "message": "Ollama is running, but no models are installed. "
                                   "Pull a supported model first."}
            return {"provider": "ollama", "base_url": root, "connected": True,
                    "state": "connected", "version": version, "models": models,
                    "default_model": _pick_ollama_default(models),
                    "message": f"Ollama connected — {len(models)} model"
                               f"{'s' if len(models) != 1 else ''} available"}
        except (_rq.RequestException, ValueError) as exc:
            return {"provider": "ollama", "base_url": root, "connected": False,
                    "state": "not_running", "version": "", "models": [],
                    "default_model": "",
                    "message": "Ollama is not running. Start Ollama and retry.",
                    "detail": f"{type(exc).__name__}: {str(exc)[:200]}"}

    @app.post("/api/launch", status_code=202)
    def launch_from_url(body: UrlLaunchBody) -> dict:
        """URL-first launch (Builder 04): target URL + authorization metadata →
        server-side engagement generation (redteam.launch, fail-closed) → the
        SAME arm pipeline as /api/runs and /api/missions. Every rejection is an
        actionable 400. Nothing here widens scope: the generated RoE is validated
        by the existing loader, the control-plane overlap check still applies,
        and ScopeGuard keeps checking every request (redirects included)."""
        from .launch import LaunchError, build_engagement, write_launch_artifacts

        mode = body.mode.strip().lower()
        if mode not in ("classic", "mission"):
            raise HTTPException(400, f"unknown mode '{body.mode}' — choose 'classic' or 'mission'")

        try:
            engagement_data, summary = build_engagement(
                body.target_url, body.objective,
                authorization=body.authorization.model_dump(),
                intensity=body.intensity,
                max_run_seconds=body.max_run_seconds,
                max_llm_tokens=body.max_llm_tokens)
        except LaunchError as exc:
            raise HTTPException(400, str(exc))

        if body.asset_feed:
            from .importers.assets import load_asset_feed
            try:
                load_asset_feed(body.asset_feed)
            except ValueError as exc:
                raise HTTPException(400, f"bad asset_feed: {exc}")

        run_id = registry.new_run_id(body.objective)
        out_dir = runs_root / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        engagement_path = write_launch_artifacts(out_dir, engagement_data, summary)

        from .config import ConfigError, load_engagement
        try:
            engagement = load_engagement(engagement_path)
        except (ConfigError, ValueError) as exc:
            raise HTTPException(400, f"generated engagement failed validation: {exc}")
        if not engagement.is_active:
            raise HTTPException(400, "authorization window is not active — check the start/end dates")
        if control_plane is not None:
            from .scope import check_control_plane_overlap
            try:
                check_control_plane_overlap(engagement, control_plane[0], control_plane[1])
            except ConfigError as exc:
                raise HTTPException(400, f"generated engagement rejected: {exc}")

        launch_path, llm_credentials = _prepare_llm(body.llm, engagement_path, out_dir)

        RunManifest(objective=body.objective, engagement=engagement.name,
                    driver=mode).save(out_dir / "manifest.json")

        from .events import EventBus
        from .run import HeadlessApprover
        bus = EventBus(run_id=run_id, sink_path=out_dir / "events.jsonl")
        registry.register_bus(run_id, bus)
        bus.emit("launch.authorized",
                 target=f"{summary['scheme']}://{summary['host']}:{summary['port']}",
                 authorized_by=summary["authorized_by"], ticket=summary["ticket"],
                 starts=summary["starts"], ends=summary["ends"],
                 intensity=summary["intensity"],
                 allow_private_ranges=summary["allow_private_ranges"])
        if body.llm is not None:
            bus.emit("llm.selected", provider=body.llm.provider.strip().lower(),
                     model=body.llm.model, base_url=body.llm.base_url)

        opts = launch_form(launch_path, body.objective,
                           body.multi_agent and mode == "classic",
                           body.max_steps,
                           body.source_dir if mode == "classic" else "",
                           body.yes_to_all, body.asset_feed,
                           llm_credentials=llm_credentials)
        opts.out_dir = out_dir
        opts.events = bus
        opts.approve = HeadlessApprover(out_dir, bus, kill_file=out_dir / "STOP")
        if mode == "mission":
            opts.driver = "mission"
            if body.plan:
                (out_dir / "mission_plan.json").write_text(
                    json.dumps({"tasks": body.plan}, indent=2), encoding="utf-8")

        registry.launch(run_id, out_dir, opts)
        return {"run_id": run_id,
                "mission_id": run_id if mode == "mission" else "",
                "run_ids": [run_id] if mode == "mission" else [],
                "engagement": engagement.name, "out_dir": str(out_dir),
                "status": "running", "driver": mode,
                "target": {"url": summary["target_url"], "scheme": summary["scheme"],
                           "host": summary["host"], "port": summary["port"]},
                "authorization": {k: summary[k] for k in
                                  ("authorized_by", "ticket", "starts", "ends",
                                   "intensity", "allow_private_ranges",
                                   "excluded_hosts")}}

    @app.post("/api/llm/preflight")
    def llm_preflight(body: PreflightBody) -> dict:
        from .llm.preflight import run_preflight
        # The key lives only in this call's memory (same contract as launch):
        # passed straight into the provider session header, never logged,
        # persisted, or echoed — the result dict carries no credentials.
        result = run_preflight(body.provider, model=body.model.strip(),
                               base_url=body.base_url.strip(),
                               api_key=body.api_key or None)
        return result.as_dict()

    @app.get("/api/llm/models")
    def list_llm_models(provider: str = "", base_url: str = "") -> dict:
        """Model discovery where the endpoint serves a catalog (Ollama, vLLM,
        OpenRouter, ... do; keyless — the same reachability the preflight
        checks). Feeds the launch form's model suggestions with REAL ids."""
        from .llm.providers import ProviderConfig
        kind = (provider or "").strip().lower()
        if not kind:
            raise HTTPException(400, "provider is required")
        cfg = ProviderConfig(kind=kind, base_url=(base_url or "").strip()).resolved()
        import requests as _rq
        try:
            resp = _rq.get(f"{cfg.base_url}/models", timeout=5)
            resp.raise_for_status()
            models = sorted({m.get("id", "") for m in (resp.json().get("data") or [])
                             if isinstance(m, dict) and m.get("id")})
        except (_rq.RequestException, ValueError) as exc:
            raise HTTPException(502, f"model discovery failed for {kind}: "
                                     f"{type(exc).__name__} — the endpoint may be "
                                     f"down or unreachable from the agent server")
        return {"provider": kind, "base_url": cfg.base_url, "models": models}

    @app.get("/api/runs")
    def list_runs() -> dict:
        runs = []
        if runs_root.exists():
            for d in runs_root.iterdir():
                if not d.is_dir():
                    continue
                m = _read_json(d / "manifest.json", None)
                if m is None:
                    continue
                runs.append({
                    "run_id": d.name, "name": d.name,
                    "objective": m.get("objective", ""),
                    "status": m.get("status", "running"),
                    "started": m.get("started", ""), "updated": m.get("updated", ""),
                    "steps": m.get("steps", 0), "findings": m.get("findings", 0),
                    "tokens": m.get("tokens", 0),
                })
        runs.sort(key=lambda r: r.get("started", ""), reverse=True)
        return {"runs": runs}

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> dict:
        run_dir = require_run(run_id)
        manifest = manifest_of(run_dir)
        findings = _read_json(run_dir / "findings.json", [])

        obj_raw = _read_json(run_dir / "objective.json", None)
        objective = None
        if obj_raw:
            criteria = [{"id": c.get("id", ""), "description": c.get("description", ""),
                         "achieved": bool(c.get("achieved")), "evidence": c.get("evidence", "")}
                        for c in (obj_raw.get("criteria") or [])]
            objective = {
                "description": obj_raw.get("description", ""),
                "criteria": criteria,
                "achieved": bool(criteria) and all(c["achieved"] for c in criteria),
                "done": sum(1 for c in criteria if c["achieved"]),
                "total": len(criteria),
            }

        killchain = [{"stage": s.get("stage", ""), "achieved": s.get("status") == "achieved",
                      "since": s.get("achieved_at", "")}
                     for s in _read_json(run_dir / "killchain.json", [])
                     if isinstance(s, dict)]

        graph_raw = _read_json(run_dir / "graph.json", {}) or {}
        nodes = graph_raw.get("nodes", [])
        graph = {
            "nodes": nodes,
            "endpoints": [n for n in nodes if n.get("kind") == "endpoint"],
            "params": [n for n in nodes if n.get("kind") == "parameter"],
            "hosts": [n for n in nodes if n.get("kind") == "host"],
        }

        tree = {"todo": 0, "in_progress": 0, "failed": 0, "completed": 0}
        for n in _read_json(run_dir / "attack_tree.json", []):
            status = n.get("status") if isinstance(n, dict) else None
            if status in tree:
                tree[status] += 1

        reflections = _read_json(run_dir / "reflections.json", [])

        return {"run_id": run_id, "status": manifest.get("status", "running"),
                "driver": manifest.get("driver", "classic"),
                "manifest": manifest, "findings": findings, "objective": objective,
                "killchain": killchain, "graph": graph, "attack_tree": tree,
                "reflections": reflections}

    @app.get("/api/runs/{run_id}/events")
    def run_events(run_id: str, after: int = 0) -> dict:
        run_dir = require_run(run_id)
        events = read_events(run_dir / "events.jsonl", after=after, limit=MAX_EVENTS_PER_READ)
        next_cursor = events[-1]["seq"] if events else after
        return {"events": events, "next_cursor": next_cursor}

    # -- API: ARTEX-port evidence (traffic + surface) ---------------------------
    # Both read the per-run JSONL/JSON artifacts the engine already writes, with the
    # same cursor contract as /events — the server stays decoupled from the engine.

    @app.get("/api/runs/{run_id}/traffic")
    def run_traffic(run_id: str, after: int = 0, limit: int = 200) -> dict:
        from .traffic import read_traffic
        run_dir = require_run(run_id)
        limit = max(1, min(limit, 1000))
        records = read_traffic(run_dir / "traffic.jsonl", after=after, limit=limit)
        next_cursor = records[-1]["seq"] if records else after
        return {"traffic": records, "next_cursor": next_cursor}

    @app.get("/api/runs/{run_id}/inventory")
    def run_inventory(run_id: str) -> dict:
        run_dir = require_run(run_id)
        inv = _read_json(run_dir / "inventory.json", None)
        if inv is None:
            return {"hosts": {}, "summary": {"hosts": 0, "services": 0,
                                             "endpoints": [], "truncated": False}}
        hosts = inv.get("hosts", {}) if isinstance(inv, dict) else {}
        n_services = sum(len(h.get("services", {})) for h in hosts.values()
                         if isinstance(h, dict))
        return {"hosts": hosts,
                "summary": {"hosts": len(hosts), "services": n_services}}

    @app.get("/api/runs/{run_id}/proxy")
    def run_proxy(run_id: str) -> dict:
        # Evidence-proxy status snapshot, written by execute_run when the proxy
        # shuts down (None while a live run has none / it failed to start). The
        # LIVE counters are on the run's summary; this file is the durable record.
        run_dir = require_run(run_id)
        return {"proxy": _read_json(run_dir / "proxy.json", None)}

    # -- API: live recon view (any.run-style) -------------------------------------
    # Read-only over run artifacts: the browser controller refreshes
    # recon_live/latest.jpg + events.jsonl on every navigate/click/fill/
    # screenshot; the snapshot merges those with the traffic tail and the
    # observation log so an operator can watch RECON work in real time.

    @app.get("/api/runs/{run_id}/recon/live")
    def run_recon_live(run_id: str) -> dict:
        from .livewatch import recon_live_snapshot
        run_dir = require_run(run_id)
        return recon_live_snapshot(run_dir)

    @app.get("/live/{run_id}", response_class=HTMLResponse)
    def live_recon_view(run_id: str) -> HTMLResponse:
        from .livewatch import LIVE_VIEW_HTML
        require_run(run_id)
        return HTMLResponse(LIVE_VIEW_HTML.replace("__RUN_ID__", run_id))

    @app.get("/api/bench")
    def bench_board() -> dict:
        """Benchmark board feed: the bench harness exports one structured card per
        run (bench.json) and a merged runs/bench-summary.json. Serve the merged
        file, falling back to a scan of bench-* run dirs; a run directory that is
        mid-write simply doesn't contribute a card yet (never an error)."""
        merged = _read_json(runs_root / "bench-summary.json", None)
        rows = merged.get("runs") if isinstance(merged, dict) else None
        if not isinstance(rows, list):
            rows = []
            for d in sorted(runs_root.glob("bench-*")):
                if not d.is_dir():
                    continue
                card = _read_json(d / "bench.json", None)
                if isinstance(card, dict):
                    rows.append(card)
        rows = [r for r in rows if isinstance(r, dict)]
        rows.sort(key=lambda r: (r.get("ts", ""), r.get("run_id", "")))
        # Latest card per target wins: an interrupted run leaves a zero-token row
        # behind, and the board must reflect the newest attempt, not accumulate.
        latest: dict[str, dict] = {}
        for r in rows:
            latest[str(r.get("target_key") or r.get("run_id", "?"))] = r
        rows = sorted(latest.values(),
                      key=lambda r: (r.get("ts", ""), r.get("run_id", "")))
        arms = sorted({str(r.get("arm", "?")) for r in rows})
        achieved = sum(1 for r in rows if r.get("objective_achieved"))
        confirmed = sum(int(r.get("confirmed") or 0) for r in rows)
        return {"runs": rows, "arms": arms, "achieved": achieved,
                "confirmed": confirmed, "total": len(rows)}

    @app.get("/api/runs/{run_id}/graph")
    def run_graph(run_id: str) -> dict:
        # The exploration chain (ARTEX 探索链路): layered assets → endpoints →
        # access → findings, built purely from the run's artifact files. The
        # server stays decoupled from the engine; missing artifacts render as
        # empty layers (a round-one run is honestly partial, never an error).
        from .graph_view import build_exploration_graph
        run_dir = require_run(run_id)
        return {"run_id": run_id, "graph": build_exploration_graph(run_dir)}

    @app.get("/api/runs/{run_id}/coverage")
    def run_coverage(run_id: str) -> dict:
        # The asset coverage map (ARTEX 资产覆盖图): of everything the RoE allows,
        # what was actually tested? Built from scope.json + the run artifacts —
        # the universe is the allowlist, never the activity. Missing scope.json
        # (older runs) degrades to an activity-only report with the limitation named.
        from .coverage import build_coverage
        run_dir = require_run(run_id)
        return {"run_id": run_id, "coverage": build_coverage(run_dir)}

    @app.get("/api/runs/{run_id}/stream")
    async def run_stream(run_id: str, after: int = 0):
        run_dir = require_run(run_id)
        events_path = run_dir / "events.jsonl"
        manifest_path = run_dir / "manifest.json"

        async def gen():
            cursor = after
            last_output = time.monotonic()
            yield f"event: ping\ndata: {{\"ok\": true}}\n\n"
            while True:
                events = read_events(events_path, after=cursor, limit=MAX_EVENTS_PER_READ)
                for ev in events:
                    cursor = ev.get("seq", cursor)
                    last_output = time.monotonic()
                    yield f"event: run_event\ndata: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
                manifest = _read_json(manifest_path, {}) or {}
                ended = manifest.get("status", "running") != "running"
                if ended and not events:
                    break
                if time.monotonic() - last_output >= SSE_PING_S:
                    last_output = time.monotonic()
                    yield "event: ping\ndata: {}\n\n"
                await asyncio.sleep(SSE_POLL_S)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.post("/api/runs/{run_id}/stop")
    def stop_run(run_id: str) -> dict:
        run_dir = require_run(run_id)
        (run_dir / "STOP").write_text(
            json.dumps({"requested": _now()}), encoding="utf-8")
        return {"ok": True}

    @app.delete("/api/runs/{run_id}")
    def delete_run(run_id: str) -> dict:
        """Remove a run's directory. Refuses a run that is still executing — stop it
        first (a live run thread is writing into this folder). require_run already
        rejects any run_id with path-traversal characters, so the rmtree is bounded to
        a real child of runs_root."""
        import shutil
        run_dir = require_run(run_id)
        status = manifest_of(run_dir).get("status", "")
        if status == "running":
            raise HTTPException(409, "run is still running — stop it before deleting")
        registry.pop_bus(run_id)   # drop any in-process bookkeeping
        shutil.rmtree(run_dir, ignore_errors=True)
        return {"ok": True, "deleted": run_id}

    @app.get("/api/runs/{run_id}/report")
    def run_report(run_id: str) -> Response:
        run_dir = require_run(run_id)
        report = run_dir / "report.md"
        if not report.exists():
            raise HTTPException(404, "report not generated yet")
        return Response(report.read_text(encoding="utf-8"), media_type="text/markdown")

    # -- API: approvals ----------------------------------------------------------

    @app.get("/api/runs/{run_id}/approvals")
    def run_approvals(run_id: str) -> dict:
        run_dir = require_run(run_id)
        return {"pending": read_pending_approvals(run_dir)}

    @app.post("/api/runs/{run_id}/retest")
    def run_retest(run_id: str, body: RetestBody) -> dict:
        # Post-remediation retest (ARTEX retester, deterministic port): rebuild each
        # finding's stored proof and replay it against the live target — no LLM, no
        # agent session. Runs synchronously (a retest is trials x requests, seconds
        # not minutes). Scope comes from the run's FROZEN scope.json, not the live
        # engagement file: a retest obeys the RoE as it was when the run was armed,
        # and a check that no longer fits today's RoE comes back `blocked`, honestly.
        # The operator pressing this endpoint IS the approval — same as ARTEX's
        # operator-initiated retest, minus the agent.
        from .retest import build_ctx_for_run, engagement_from_scope_json, retest_run
        run_dir = require_run(run_id)
        scope_file = run_dir / "scope.json"
        if not scope_file.exists():
            raise HTTPException(409, "run has no frozen scope.json — cannot rebuild the RoE for a safe retest")
        try:
            engagement = engagement_from_scope_json(run_dir)
        except ValueError as exc:
            raise HTTPException(409, f"frozen scope.json no longer parseable: {exc}")
        ctx = build_ctx_for_run(engagement, run_dir=run_dir)
        try:
            results = retest_run(
                ctx.findings, ctx, finding_id=body.finding_id,
                trials=body.trials, need=body.need,
                fresh_attack_steps=body.fresh_attack_steps or None,
                fresh_control_steps=body.fresh_control_steps or None,
                # forward the run's own authorities: a FIXED verdict here
                # revokes exactly the holdings that finding demonstrated
                # (invalidate_after_fix) — same as the retest CLI
                access=getattr(ctx, "access", None),
                graph=getattr(ctx, "graph", None))
        except Exception as exc:
            raise HTTPException(500, f"retest failed: {exc}")
        if body.finding_id and not results:
            raise HTTPException(404, f"no retestable finding {body.finding_id!r} in this run")
        return {"run_id": run_id, "retests": results,
                "summary": {
                    "total": len(results),
                    "reproducible": sum(1 for r in results if r["verdict"] == "reproducible"),
                    "fixed": sum(1 for r in results if r["verdict"] == "fixed"),
                    "cannot_confirm": sum(1 for r in results if r["verdict"] == "cannot_confirm"),
                    "blocked": sum(1 for r in results if r["verdict"] == "blocked"),
                }}

    @app.post("/api/approvals/{approval_id}")
    def resolve(approval_id: str, body: ApprovalBody) -> dict:
        approved = body.approve
        # Find the owning run: live index first, then a scan (server restarts must
        # not orphan a pending approval — approvals.json is the durable record).
        for d in sorted(runs_root.iterdir()):
            if not d.is_dir():
                continue
            data = _read_json(d / "approvals.json", [])
            if any(r.get("id") == approval_id for r in data):
                if resolve_approval(d, approval_id, approved):
                    return {"ok": True}
                raise HTTPException(404, "approval already resolved or expired")
        raise HTTPException(404, "unknown approval")

    # -- API: missions (Phase 2 coordination core — additive) ---------------------
    # A mission is hosted in a run directory; in Phase 2 mission_id == that run's
    # run_id BY CONSTRUCTION, but the two travel as SEPARATE logical fields (C1):
    # mission.json carries mission_id + run_ids (a list, 1:N-capable) and every
    # response echoes both. Resolution reuses require_run — the same directory
    # lookup /api/runs/{run_id} uses; no second identity authority is minted.

    @app.post("/api/missions", status_code=202)
    def launch_mission(body: MissionBody) -> dict:
        from .config import ConfigError, load_engagement
        try:
            engagement = load_engagement(body.engagement_path)
        except ConfigError as exc:
            raise HTTPException(400, f"bad engagement: {exc}")
        except ValueError as exc:
            raise HTTPException(400, f"bad engagement: {exc}")
        if not engagement.is_active:
            raise HTTPException(400, "engagement window is not active")
        if control_plane is not None:
            from .scope import check_control_plane_overlap
            try:
                check_control_plane_overlap(engagement, control_plane[0],
                                            control_plane[1])
            except ConfigError as exc:
                raise HTTPException(400, f"bad engagement: {exc}")
        if body.asset_feed:
            from .importers.assets import load_asset_feed
            try:
                load_asset_feed(body.asset_feed)
            except ValueError as exc:
                raise HTTPException(400, f"bad asset_feed: {exc}")

        run_id = registry.new_run_id(body.objective)
        out_dir = runs_root / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        launch_path, llm_credentials = _prepare_llm(body.llm, body.engagement_path, out_dir)

        RunManifest(objective=body.objective, engagement=engagement.name,
                    driver="mission").save(out_dir / "manifest.json")

        from .events import EventBus
        from .run import HeadlessApprover
        bus = EventBus(run_id=run_id, sink_path=out_dir / "events.jsonl")
        registry.register_bus(run_id, bus)
        if body.llm is not None:
            bus.emit("llm.selected", provider=body.llm.provider.strip().lower(),
                     model=body.llm.model, base_url=body.llm.base_url)

        opts = launch_form(launch_path, body.objective, False,
                           body.max_steps, "", body.yes_to_all, body.asset_feed,
                           llm_credentials=llm_credentials)
        opts.out_dir = out_dir
        opts.driver = "mission"
        opts.events = bus
        opts.approve = HeadlessApprover(out_dir, bus, kill_file=out_dir / "STOP")
        if body.plan:
            (out_dir / "mission_plan.json").write_text(
                json.dumps({"tasks": body.plan}, indent=2), encoding="utf-8")

        registry.launch(run_id, out_dir, opts)
        return {"mission_id": run_id, "run_id": run_id, "run_ids": [run_id],
                "engagement": engagement.name, "out_dir": str(out_dir),
                "status": "running", "driver": "mission"}

    @app.get("/api/missions")
    def list_missions() -> dict:
        missions = []
        if runs_root.exists():
            for d in runs_root.iterdir():
                if not d.is_dir():
                    continue
                rec = _read_json(d / "mission.json", None)
                if not isinstance(rec, dict):
                    continue
                m = rec.get("mission") if isinstance(rec.get("mission"), dict) else rec
                tasks = rec.get("tasks") or [] if isinstance(rec.get("mission"), dict) else []
                missions.append({
                    "mission_id": m.get("mission_id", d.name),
                    "run_id": m.get("run_id", d.name),
                    "run_ids": m.get("run_ids", [d.name]),
                    "engagement": m.get("engagement", ""),
                    "ticket": m.get("ticket", ""),
                    "objective": m.get("objective", ""),
                    "status": m.get("status", "planned"),
                    "created": m.get("created", ""), "updated": m.get("updated", ""),
                    "tasks": len(tasks),
                })
        missions.sort(key=lambda m: m.get("created", ""), reverse=True)
        return {"missions": missions}

    @app.get("/api/missions/{mission_id}")
    def mission_detail(mission_id: str) -> dict:
        run_dir = require_run(mission_id)
        rec = _read_json(run_dir / "mission.json", None)
        if not isinstance(rec, dict):
            raise HTTPException(404, "unknown mission")
        is_snapshot = isinstance(rec.get("mission"), dict)
        mission = rec.get("mission") if is_snapshot else rec
        tasks = rec.get("tasks") if is_snapshot else []
        # Recent mission-journal events (tail): the journal is the intent
        # authority; the API shows the last slice for operator visibility.
        events: list[dict] = []
        journal_path = run_dir / "mission_journal.jsonl"
        if journal_path.exists():
            lines = journal_path.read_text(encoding="utf-8").splitlines()
            for line in lines[-MAX_EVENTS_PER_READ:]:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return {"mission_id": mission.get("mission_id", mission_id),
                "run_id": mission.get("run_id", mission_id),
                "run_ids": mission.get("run_ids", [mission_id]),
                "engagement": mission.get("engagement", ""),
                "ticket": mission.get("ticket", ""),
                "objective": mission.get("objective", ""),
                "status": mission.get("status", "planned"),
                "halt_reason": mission.get("halt_reason", ""),
                "tasks": tasks,
                "recent_events": events}

    # -- static dashboard ----------------------------------------------------------

    if dashboard_dir is not None and (dashboard_dir / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Headless red-team control plane (API + dashboard)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--runs-root", default="runs",
                        help="Directory that holds run folders (default ./runs).")
    parser.add_argument("--dashboard", default=None,
                        help="Path to the Next.js static export (dashboard/out). "
                             "Default: <repo>/dashboard/out if it exists.")
    args = parser.parse_args(argv)

    dashboard = Path(args.dashboard) if args.dashboard else \
        Path(__file__).resolve().parent.parent / "dashboard" / "out"

    app = create_app(Path(args.runs_root), dashboard_dir=dashboard,
                     control_plane=(args.host, args.port))

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

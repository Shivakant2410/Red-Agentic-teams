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
import re
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
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


class ApprovalBody(BaseModel):
    approve: bool


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


def create_app(runs_root: Path, dashboard_dir: Path | None = None,
               control_plane: tuple[str, int] | None = None) -> FastAPI:
    """Build the control-plane app.

    control_plane = this server's own (bind_host, bind_port). Every launch validates
    the engagement's scope against it BEFORE arming a run: a scope that includes the
    control plane would authorize the agent to attack its own console (live-fire
    lesson — the operator error must be a 400 at launch, not a compromised run)."""
    runs_root = runs_root.resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
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
                    source_dir: str, yes_to_all: bool, asset_feed: str = "") -> RunOptions:
        return RunOptions(
            engagement_path=engagement_path, objective=objective,
            out_dir=runs_root / "<set-by-caller>", multi_agent=multi_agent,
            max_steps=max_steps, source_dir=source_dir, yes_to_all=yes_to_all,
            quiet=True, on_text=None, control_plane=control_plane,
            asset_feed=asset_feed,
        )

    # -- API: health -----------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": VERSION, "runs_root": str(runs_root)}

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
        RunManifest(objective=body.objective, engagement=engagement.name).save(
            out_dir / "manifest.json")

        from .events import EventBus
        from .run import HeadlessApprover
        bus = EventBus(run_id=run_id, sink_path=out_dir / "events.jsonl")
        registry.register_bus(run_id, bus)

        opts = launch_form(body.engagement_path, body.objective, body.multi_agent,
                           body.max_steps, body.source_dir, body.yes_to_all,
                           body.asset_feed)
        opts.out_dir = out_dir
        opts.events = bus
        opts.approve = HeadlessApprover(out_dir, bus, kill_file=out_dir / "STOP")

        registry.launch(run_id, out_dir, opts)
        return {"run_id": run_id, "out_dir": str(out_dir), "status": "running"}

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

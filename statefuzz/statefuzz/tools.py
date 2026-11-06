# -*- coding: utf-8 -*-
"""tools.py — registry glue for Red-Agentic-teams (dossier 9.1).

The platform's build_registry contract: every tool is a dict with
`schema()` returning its JSON-schema signature and `run(ctx, **params)`
executing it — the orchestrator swarm, bandit and approval gates call tools
uniformly, and the fail-closed egress firewall wraps every run().

Three tools:

  statefuzz_run             execute the loop against an in-scope app spec
  statefuzz_status          last/running report summary (budget, yield)
  statefuzz_export          findings.json + traffic.jsonl + induced model

The tools never open sockets; they ride ctx.adapter (the platform's scoped,
recorded fetch path). Write-shaped techniques stay behind the approval gate —
the tool refuses to auto-grant; it reports which techniques await approval so
the orchestrator can ask the human operator.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .chains import top_paths
from .context import ReferenceContext
from .runner import RunReport, statefuzz_run

_STATE = {"report": None, "ctx": None}


def statefuzz_run_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "spec": {"type": "object",
                     "description": "OpenAPI-lite machine spec (extract_model)"},
            "budget": {"type": "integer", "minimum": 1, "default": 200},
            "techniques": {"type": "array", "items": {"type": "string",
                          "enum": ["SKIP", "REPLAY", "REORDER", "PARTIAL",
                                   "NEGATIVE", "CROSS-USER", "INTERRUPT",
                                   "IDEMPOTENCE"]},
                          "description": "subset of the 8 operators; default all"},
            "max_depth": {"type": "integer", "minimum": 1, "default": 4},
        },
        "required": ["spec"],
    }


def _statefuzz_run(ctx: ReferenceContext, spec: dict, budget: int = 200,
                   techniques: Optional[List[str]] = None,
                   max_depth: int = 4, **_: Any) -> dict:
    report: RunReport = statefuzz_run(
        ctx, budget=budget, spec=spec, techniques=techniques,
        emit_model=False, max_depth=max_depth)
    _STATE["report"], _STATE["ctx"] = report, ctx
    unapproved = sorted({t for t in ("SF-SKIP", "SF-REPLAY", "SF-REORDER",
                                     "SF-PARTIAL", "SF-NEGATIVE", "SF-CROSSUSER",
                                     "SF-RACE", "SF-IDEM")
                         if t not in ctx.approvals.granted_techniques})
    return {
        "ok": True,
        "report": report.to_dict(),
        "findings": [f.to_dict() for f in ctx.findings],
        "awaiting_approval": unapproved,
        "note": "write-shaped techniques require ctx.approvals.grant(<technique>)",
    }


def statefuzz_status_schema() -> Dict[str, Any]:
    return {"type": "object", "properties": {}}


def _statefuzz_status(ctx: ReferenceContext) -> dict:
    rep: Optional[RunReport] = _STATE.get("report")
    if rep is None:
        return {"ok": True, "state": "idle"}
    return {"ok": True, "state": "done", "report": rep.to_dict(),
            "technique_priors": dict(sorted(ctx.bandit.priors.items()))}


def statefuzz_export_schema() -> Dict[str, Any]:
    return {"type": "object",
            "properties": {"path": {"type": "string",
                                    "description": "findings.json destination"}}}


def _statefuzz_export(ctx: ReferenceContext, path: str = "", **_: Any) -> dict:
    if not path:
        return {"ok": False, "error": "path required"}
    ctx.write_findings(path)
    traffic_path = path.replace(".json", ".traffic.jsonl")
    ctx.write_traffic(traffic_path)
    return {"ok": True, "findings": path, "traffic": traffic_path,
            "count": len(ctx.findings)}


def build_statefuzz_tools(ctx: ReferenceContext) -> List[dict]:
    """Register with the platform's build_registry:
        registry.extend(build_statefuzz_tools(ctx))
    Each entry exposes schema() and run(ctx, **params) per platform contract."""
    return [
        {"name": "statefuzz_run",
         "description": "State-machine business-logic fuzz: induce the app "
                        "model, expand the 8 mutant operators, run I1..I5 "
                        "invariant oracles, chain findings into impact paths.",
         "schema": statefuzz_run_schema,
         "run": _statefuzz_run},
        {"name": "statefuzz_status",
         "description": "Last run report + current technique priors.",
         "schema": statefuzz_status_schema,
         "run": _statefuzz_status},
        {"name": "statefuzz_export",
         "description": "Write findings.json + traffic.jsonl for the verify "
                        "pipeline.",
         "schema": statefuzz_export_schema,
         "run": _statefuzz_export},
    ]

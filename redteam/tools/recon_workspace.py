"""RECON V2 agent tools — the evidence workspace read/replay surface.

The specialist's window onto its own accumulated evidence (directive §6/§8):

  - evidence_search       compact filtered view over observations;
  - evidence_inspect      one observation's full record (provenance, evidence
                          refs, scope status);
  - proxy_history_query   structured filter over the wire history (browser +
                          proxy + tools all land in traffic.jsonl);
  - replay_request        re-issue ONE recorded request through the shared
                          scope/budget/traffic plane (approval-gated, like
                          every sensitive tool);
  - asset_read            the asset inventory readback.

All are read-only except replay, which reuses the run's own fetch discipline —
it can never widen scope, bypass budget, or skip the traffic log.
"""
from __future__ import annotations

import json

from . import ToolContext, current_agent


def _workspace(ctx: ToolContext):
    ws = getattr(ctx, "workspace", None)
    if ws is None:
        return None
    return ws


class _WorkspaceTool:
    """Shared guard: honest degradation when the run has no workspace wired."""

    def _guard(self, ctx: ToolContext, fn):
        ws = _workspace(ctx)
        if ws is None:
            return "ERROR: evidence workspace is not available in this run."
        try:
            return json.dumps(fn(ws))
        except Exception as exc:
            return f"WORKSPACE ERROR: {exc}"


class EvidenceSearchTool(_WorkspaceTool):
    name = "evidence_search"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Search this run's accumulated evidence observations "
                    "(domains, services, endpoints, tech, console errors, "
                    "assets). Filter by kind/subject/tool/provenance/scope. "
                    "Compact rows; use evidence_inspect for the full record."),
                "input_schema": {"type": "object",
                                 "additionalProperties": False,
                                 "properties": {
                                     "kind": {"type": "string",
                                              "description": "observation kind filter (e.g. service, endpoint, subdomain)"},
                                     "subject_contains": {"type": "string"},
                                     "tool": {"type": "string"},
                                     "provenance": {"type": "string",
                                                    "description": "passive | active | imported | derived"},
                                     "scope_status": {"type": "string",
                                                      "description": "in_scope | out_of_scope | unattributed"},
                                     "limit": {"type": "integer"}},
                                 "required": []},
                "strict": True}

    def run(self, ctx, kind: str = "", subject_contains: str = "",
            tool: str = "", provenance: str = "", scope_status: str = "",
            limit: int = 40) -> str:
        return self._guard(ctx, lambda ws: {
            "results": ws.search(kind=kind, subject_contains=subject_contains,
                                 tool=tool, provenance=provenance,
                                 scope_status=scope_status,
                                 limit=max(1, min(int(limit), 100)))})


class EvidenceInspectTool(_WorkspaceTool):
    name = "evidence_inspect"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": ("Return the FULL record of one evidence "
                                "observation id (from evidence_search): attrs, "
                                "provenance, validation, scope status and its "
                                "evidence references."),
                "input_schema": {"type": "object",
                                 "additionalProperties": False,
                                 "properties": {"obs_id": {"type": "string"}},
                                 "required": ["obs_id"]},
                "strict": True}

    def run(self, ctx, obs_id: str) -> str:
        return self._guard(ctx, lambda ws: {
            "observation": ws.inspect(obs_id) or {"error": f"unknown id {obs_id!r}"}})


class ProxyHistoryQueryTool(_WorkspaceTool):
    name = "proxy_history_query"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Query the wire-evidence history (traffic.jsonl: browser, "
                    "proxy and tool exchanges). Filter by host, method, "
                    "status, tool, source or text; page by seq cursor. Read-"
                    "only — see what actually went over the wire."),
                "input_schema": {"type": "object",
                                 "additionalProperties": False,
                                 "properties": {
                                     "host": {"type": "string"},
                                     "contains": {"type": "string"},
                                     "method": {"type": "string"},
                                     "status": {"type": "integer"},
                                     "tool": {"type": "string"},
                                     "source": {"type": "string"},
                                     "after_seq": {"type": "integer"},
                                     "limit": {"type": "integer"}},
                                 "required": []},
                "strict": True}

    def run(self, ctx, host: str = "", contains: str = "", method: str = "",
            status: int | None = None, tool: str = "", source: str = "",
            after_seq: int = 0, limit: int = 40) -> str:
        return self._guard(ctx, lambda ws: {
            "traffic": ws.traffic_query(host=host, contains=contains,
                                        method=method, status=status,
                                        tool=tool, source=source,
                                        after_seq=after_seq,
                                        limit=max(1, min(int(limit), 100)))})


class ReplayRequestTool(_WorkspaceTool):
    name = "replay_request"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Re-issue ONE recorded wire request (by traffic seq) "
                    "through this run's own fetch discipline: scope-checked, "
                    "rate-limited, recorded as fresh evidence (source=replay), "
                    "approval-gated. Cannot widen scope or bypass budget."),
                "input_schema": {"type": "object",
                                 "additionalProperties": False,
                                 "properties": {"seq": {"type": "integer"}},
                                 "required": ["seq"]},
                "strict": True}

    def run(self, ctx, seq: int) -> str:
        ws = _workspace(ctx)
        if ws is None:
            return "ERROR: evidence workspace is not available in this run."

        def _do(ws_):
            rec = ws_.traffic_row(int(seq))
            if rec is None:
                return {"error": f"no traffic record with seq={seq}"}
            detail = {"seq": int(seq), "method": rec.get("method", "GET"),
                      "url": rec.get("url", "")}
            # Approval gate FIRST (fail closed), then the shared fetch plane.
            actor = current_agent.get("")
            if not ctx.approve("replay_request", detail):
                ctx.audit.record("replay.denied", actor=actor, **detail)
                return {"error": "replay denied by approval gate", **detail}
            ctx.audit.record("replay.approved", actor=actor, **detail)
            from .http import fetch_once
            ctx.limiter.acquire()   # shared RoE budget (same as http_probe)
            req = {"method": rec.get("method", "GET"), "url": rec.get("url", ""),
                   "body": rec.get("req_body") or None}
            status, body, _elapsed, _headers = fetch_once(ctx, req,
                                                          tool="replay")
            return {"seq": int(seq), "url": rec.get("url", ""),
                    "method": rec.get("method", "GET"),
                    "status": status, "body_preview": (body or "")[:400]}

        try:
            return json.dumps(_do(ws))
        except Exception as exc:
            return f"REPLAY ERROR: {exc}"


class AssetReadTool(_WorkspaceTool):
    name = "asset_read"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Read the asset inventory this run has accumulated "
                    "(hosts, services, technologies with first/last seen and "
                    "sources). Use surface_scan to EXPAND it; asset_read to "
                    "inspect it."),
                "input_schema": {"type": "object",
                                 "additionalProperties": False,
                                 "properties": {}, "required": []},
                "strict": True}

    def run(self, ctx) -> str:
        if getattr(ctx, "inventory", None) is None:
            return "ERROR: asset inventory is not available in this run."
        try:
            return json.dumps({"inventory": ctx.inventory.summary()})
        except Exception as exc:
            return f"INVENTORY ERROR: {exc}"

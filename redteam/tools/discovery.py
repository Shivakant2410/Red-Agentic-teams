"""content_discovery — active path discovery with frequency priors + STADS stop rule.

The offensive-skill completion of recon (docs/offense-arsenal.md §2, Week 1):
passive recon reads what the target PUBLISHES (robots/sitemap/OpenAPI); this tool
probes what the target HIDES, in the order a human pentester would — highest
prior first — and stops on a theorem, not a feeling:

  - frequency priors (Nmap's top-1000-ports trick) order the request budget;
  - per-bucket Beta posteriors learn from our own hits and persist across runs
    (env RED_DISCOVERY_PRIORS names the state file);
  - the Good–Turing missing-mass estimator U(n)=f1/n (STADS, Böhme TOSEM 2018)
    says when nothing new is appearing anymore.

Leads-only discipline: hits land in the knowledge graph and the event bus; this
tool NEVER records a finding — hits are material for the specialists to prove.
"""

from __future__ import annotations

import json
import os

from . import ToolContext
from .http import fetch_once
from ..recon.discovery import (BudgetStop, BucketModel, DiscoveryEngine,
                               load_wordlist)

_MAX_BUDGET = 400
_MAX_DEPTH = 3


def _candidate_bases(ctx: ToolContext, cap: int = 16) -> list[str]:
    """Concrete base URLs derived from the RoE allowlist — same derivation as
    surface_scan (scope IS the authorized surface; nothing outside is touched;
    a scheme the RoE disallows simply fails the fetch's scope check)."""
    _SCHEMES = ("http", "https")
    hosts = [h.strip() for h in ctx.scope.allowed_hosts
             if not h.strip().startswith("*.") and "/" not in h]
    ports = ctx.scope.allowed_ports or []
    out = []
    for h in hosts:
        for p in ports:
            for s in _SCHEMES:
                default = 443 if s == "https" else 80
                out.append(f"{s}://{h}" if p == default else f"{s}://{h}:{p}")
    return out[:cap]


class ContentDiscoveryTool:
    name = "content_discovery"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "ACTIVE content discovery on one in-scope base URL: probe a "
                "prior-ordered wordlist of high-value paths (/admin, /.env, "
                "/backup.zip, ...) the way a human pentester orders a ffuf run. "
                "Prioritizes by empirical frequency priors + learned per-bucket "
                "hit rates, recurses into confirmed directories, and stops on a "
                "statistically-grounded rule (missing-mass estimator) or when the "
                "budget is spent. Records LEADS into the knowledge graph — never "
                "findings; prove interesting hits with the proof tools."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "max_requests": {
                        "type": "integer",
                        "description": "Request budget for this run (1-400).",
                    },
                    "prefix": {
                        "type": "string",
                        "description": "Optional path prefix to discover under "
                                       "(e.g. '/api' probes /api/admin, /api/.env, ...).",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Directory recursion depth (1-3). Default 1.",
                    },
                },
            },
            "strict": True,
        }

    # -- base-URL resolution ---------------------------------------------------

    def _resolve_base(self, ctx: ToolContext, fetch) -> tuple[str, str]:
        """Pick ONE live base: alive services from the inventory first (free),
        else a cheap knock on scope-derived candidates. Returns (base, note)."""
        if ctx.inventory is not None:
            for ep in ctx.inventory.summary().get("endpoints", []):
                if ep.get("status"):
                    port = "" if ep["port"] in (80, 443) else f":{ep['port']}"
                    return f"{ep['scheme']}://{ep['host']}{port}", \
                        f"base from inventory ({ep['scheme']} alive)"
        for base in _candidate_bases(ctx):
            try:
                status, _body, _headers = fetch(base + "/")
            except Exception:
                continue
            if status:
                return base, "base from scope knock"
        return "", "no alive base found; run surface_scan first"

    # -- tool entry ------------------------------------------------------------

    def run(self, ctx: ToolContext, max_requests: int = 120, prefix: str = "",
            depth: int = 1) -> str:
        budget = max(1, min(int(max_requests or 120), _MAX_BUDGET))
        depth = max(1, min(int(depth or 1), _MAX_DEPTH))

        from ..ratelimit import RequestBudgetExceeded

        def fetch(url: str):
            try:
                ctx.limiter.acquire()
            except RequestBudgetExceeded as exc:
                raise BudgetStop(str(exc))
            status, body, _elapsed, headers = fetch_once(
                ctx, {"method": "GET", "url": url}, tool="content_discovery")
            return status, body, headers

        base, base_note = self._resolve_base(ctx, fetch)
        if not base:
            return json.dumps({"error": base_note, "probed": 0})

        model_path = os.environ.get("RED_DISCOVERY_PRIORS") or None
        model = BucketModel(model_path)
        engine = DiscoveryEngine(fetch, model=model, max_depth=depth)
        report = engine.run(base, budget, prefix=prefix)

        # Leads into the graph + event bus. NEVER findings.
        for h in report.hits:
            if ctx.graph is not None:
                try:
                    ctx.graph.observe("endpoint", h.url, source="content_discovery")
                except Exception:
                    pass
            if ctx.events is not None:
                try:
                    ctx.events.emit("recon.path_found", url=h.url, status=h.status,
                                    bucket=h.bucket, depth=h.depth)
                except Exception:
                    pass
        if ctx.audit is not None:
            ctx.audit.record("recon.discovery", base=base, probed=report.probed,
                             hits=len(report.hits), stop_reason=report.stop_reason,
                             missing_mass=round(report.missing_mass, 4))

        out = report.to_dict()
        out["base_note"] = base_note
        out["note"] = ("leads only — no findings recorded; prove interesting hits "
                       "with http_probe / verify_vulnerability / confirm_finding")
        return json.dumps(out, ensure_ascii=False)

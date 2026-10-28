"""surface_scan — ARTEX-style attack-surface sweep, bounded by the RoE itself.

ARTEX discovers an enterprise attack surface before its agents work it. Our port
starts from a different axiom: the RoE (engagement allowlist) IS the authorized
surface. So surface_scan never "discovers" anything beyond it — it FILLS the
AssetInventory in, by politely knocking on every allowed host x allowed port
combination (one GET each, rate-limited like every other request) and fingerprinting
what answers (server banner, page title, auth challenge).

Invariants:
  - candidates come from scope.allowed_hosts x scope.allowed_ports (capped — a
    pathological RoE with dozens of hosts x dozens of ports must not become a scan
    storm; the cap is reported honestly so the operator trims the RoE or probes
    manually);
  - every knock still flows through fetch_once — the same scope check, rate limit,
    audit and (new) traffic recording as any other request;
  - a knock that fails the rate budget ENDS the sweep honestly (never silently
    truncated);
  - NEVER records a finding (leads-only discipline: inventory is context, not proof).
"""

from __future__ import annotations

import json

from . import ToolContext
from .http import fetch_once

# Hosts x ports ceiling. An operator who genuinely means to sweep more splits it
# across runs or uses nuclei/kali with the same RoE — this tool is a first-pass map.
MAX_CANDIDATES = 64

_SCHEMES = ("http", "https")


class SurfaceScanTool:
    name = "surface_scan"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Sweep the AUTHORIZED attack surface: knock once on every host/port "
                "pair the RoE allowlist permits and fingerprint what answers (server "
                "banner, page title, auth challenge) into the run's asset inventory. "
                "Use this EARLY so you know which in-scope services actually exist "
                "before choosing targets. It never scans outside the RoE and never "
                "records findings — it only fills the inventory. Results also tell "
                "you which host:port pairs are dead, so you stop wasting requests on them."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {},
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext) -> str:
        if ctx.inventory is None:
            return "ERROR: no asset inventory in this run."
        hosts = ctx.scope.allowed_hosts
        ports = ctx.scope.allowed_ports
        if not hosts or not ports:
            return ("ERROR: RoE has no allowed_hosts or no allowed_ports — nothing "
                    "to sweep.")

        candidates = [(h, p) for h in hosts for p in ports]
        truncated = len(candidates) > MAX_CANDIDATES
        candidates = candidates[:MAX_CANDIDATES]

        from ..ratelimit import RequestBudgetExceeded
        alive, dead, denied = [], [], 0
        out_of_budget = False
        for host, port in candidates:
            if out_of_budget:
                dead.append(f"{host}:{port} (not swept: request budget exhausted)")
                continue
            knocked = False
            for scheme in _SCHEMES:
                url = f"{scheme}://{host}:{port}/"
                try:
                    ctx.limiter.acquire()
                except RequestBudgetExceeded as exc:
                    ctx.audit.record("surface.denied", tool="surface_scan",
                                     url=url, outcome="budget-exhausted", reason=str(exc))
                    denied += 1
                    out_of_budget = True   # stop honestly; remaining pairs reported as unswept
                    break
                try:
                    status, body, elapsed, headers = fetch_once(ctx, {"method": "GET",
                                                                      "url": url},
                                                                tool="surface_scan")
                except Exception:
                    continue  # scope denial (shouldn't happen — targets come FROM scope)
                if status:
                    knocked = True
                    if ctx.inventory is not None:
                        ctx.inventory.observe_http(host, port, scheme, status,
                                                   headers=headers, body=body,
                                                   source="surface_scan")
                    if ctx.events is not None:
                        try:
                            ctx.events.emit("asset.discovered", host=host, port=port,
                                            scheme=scheme, status=status,
                                            server=str(headers.get("Server", ""))[:80],
                                            source="surface_scan")
                        except Exception:
                            pass
            if knocked:
                alive.append(f"{host}:{port}")
            elif out_of_budget:
                dead.append(f"{host}:{port} (sweep stopped: request budget exhausted)")
            else:
                dead.append(f"{host}:{port}")

        result = {
            "alive": alive,
            "dead": dead,
            "swept": len(candidates),
            "rate_limit_denials": denied,
            "note": ("inventory updated; no findings recorded — pick an alive target "
                     "and work it with http_probe / the proof tools"),
        }
        if truncated:
            result["truncated"] = (f"RoE allowlist yields more than {MAX_CANDIDATES} "
                                   f"host x port pairs; swept the first {MAX_CANDIDATES}. "
                                   f"Trim the RoE or probe the rest manually.")
        return json.dumps(result, ensure_ascii=False)

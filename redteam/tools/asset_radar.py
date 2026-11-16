"""asset_radar — competitive-intel recon: "what are they secretly building?"

The tool-facing completion of the asset graph (docs/offense-arsenal.md §2.3).
Where passive_recon reads what the target PUBLISHES and content_discovery probes
what it HIDES, this mines the public ledgers and the target's own bundles for what
it is BUILDING but has not announced:

  - certificate-transparency freshness (a cert issued last week for a name we
    have never seen is a launch in flight — parsed from crt.sh by us, no SDK);
  - codename triangulation (CT + DNS + JS corroborating on one distinctive
    label = a project; verdicts carry the independent-source count);
  - codename-seeded DNS permutation (altdns, seeded by names the target leaked);
  - version-ahead-of-live (/api/v3 referenced while /api/v1 is live = roadmap);
  - feature-flag leaks and staging-mirror inference.

Scope discipline, stated precisely because DNS/CT are not HTTP connections to
allowed hosts: the radar's org domain must be DERIVED FROM the signed RoE (an
operator-supplied root_domain is refused unless it is a suffix of an allowed
host), CT is an operator-side public-ledger lookup (same class as the EPSS/KEV
feeds in priors.py), and DNS permutation probes only `candidate.<org-domain>`
names. JS fetching goes through the run's normal scope-checked fetch path and
the request budget. The graph records LEADS — never findings.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

from . import ToolContext
from .http import fetch_once
from ..recon.assetgraph import AssetGraph, run_asset_radar

_CT_TIMEOUT = 25.0
_CT_CAP = 2 * 1024 * 1024          # crt.sh for a busy domain can be huge; cap read
_MAX_JS_FETCH = 6


def crtsh_fetch(domain: str) -> str:
    """Operator-side public-ledger lookup (crt.sh JSON) — no target interaction,
    same class as the EPSS/KEV refresh in priors.py. Raises on failure; the
    orchestrator treats CT as optional and the caller decides."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "red-agentic-teams-radar/1.0"})
    with urllib.request.urlopen(req, timeout=_CT_TIMEOUT) as resp:
        return resp.read(_CT_CAP).decode("utf-8", errors="replace")


def dns_resolve(hostname: str) -> str | None:
    """Stdlib A-record check for one permutation candidate. DNS is not an HTTP
    request and burns no request budget; it is still anchored to the RoE-derived
    org domain by the caller."""
    try:
        infos = socket.getaddrinfo(hostname, 443, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    for info in infos:
        addr = info[4][0] if info[4] else None
        if addr:
            return str(addr)
    return None


def derive_org_domain(scope) -> str:
    """Naive registrable domain (last two labels) of the first concrete host in
    the RoE. The radar refuses to run when scope yields no concrete host — the
    org domain must come FROM the signed scope, never from operator vibes."""
    for h in scope.allowed_hosts:
        h = h.strip()
        if h.startswith("*.") or "/" in h:
            continue
        labels = h.split(".")
        if len(labels) >= 2:
            return ".".join(labels[-2:])
    return ""


def _org_suffix_ok(scope, org_domain: str) -> bool:
    d = org_domain.lower().strip(".")
    return any(h.strip().lower().endswith("." + d) or h.strip().lower() == d
               for h in scope.allowed_hosts)


class AssetRadarTool:
    name = "asset_radar"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Competitive-intel asset radar for the in-scope org: surface what "
                "the target is building BEFORE it is announced. Correlates "
                "certificate-transparency freshness (new certs = launches in "
                "flight), distinctive codenames triangulated across CT logs, DNS "
                "and JS bundles, version-ahead-of-live API references, feature-"
                "flag leaks, and staging-mirror naming. Runs a small number of "
                "scope-checked GETs for JS plus public-ledger/DNS lookups "
                "anchored to the signed scope's org domain. Produces a ranked "
                "LEADS report into the knowledge/asset graphs — never findings; "
                "prove anything interesting with the verify/proof tools."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "window_days": {
                        "type": "integer",
                        "description": "CT freshness window in days (default 45): "
                                       "certs newer than this are 'in-flight'.",
                    },
                    "max_dns": {
                        "type": "integer",
                        "description": "Max DNS permutation candidates per codename "
                                       "(default 24, cap 48).",
                    },
                    "use_ct": {
                        "type": "boolean",
                        "description": "Query crt.sh (public CT ledger) for the org "
                                       "domain. Default true.",
                    },
                },
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, window_days: int = 45, max_dns: int = 24,
            use_ct: bool = True) -> str:
        from ..ratelimit import RequestBudgetExceeded

        org = derive_org_domain(ctx.scope)
        if not org:
            return ("ERROR: no concrete host in scope to derive the org domain "
                    "from — pass a concrete host in the RoE or widen scope.")
        if not _org_suffix_ok(ctx.scope, org):
            return f"BLOCKED: derived org domain {org} is not in the signed scope."

        # JS fetching through the run's normal scope-checked, budgeted path.
        def fetch(url: str):
            try:
                ctx.limiter.acquire()
            except RequestBudgetExceeded as exc:
                raise RuntimeError(f"budget: {exc}")
            status, body, _elapsed, headers = fetch_once(
                ctx, {"method": "GET", "url": url}, tool="asset_radar")
            return status, body, headers

        def ct_fetch(domain: str) -> str:
            return crtsh_fetch(domain)

        agraph_path = None
        inv_path = getattr(ctx.inventory, "_path", None) if ctx.inventory else None
        if inv_path:
            agraph_path = Path(inv_path).with_name("asset_graph.json")
        agraph = AssetGraph(agraph_path)

        try:
            report = run_asset_radar(
                ctx.scope._eng,
                agraph, graph=ctx.graph, inventory=ctx.inventory,
                audit=ctx.audit, base_domain=org,
                ct_fetch=ct_fetch if use_ct else None,
                resolve=dns_resolve, fetch=fetch,
                window_days=max(1, min(int(window_days or 45), 365)),
                permute_budget=max(1, min(int(max_dns or 24), 48)),
            )
        except RuntimeError as exc:
            if str(exc).startswith("budget:"):
                return f"BLOCKED (request budget exhausted): {exc}. Stop and report."
            raise
        except Exception as exc:
            return f"RADAR ERROR: {exc}"

        builds = report.get("builds", [])
        strong = [b for b in builds if b["corroboration"] >= 2]
        if ctx.events is not None:
            try:
                ctx.events.emit("recon.asset_radar", org_domain=org,
                                ct_new_hosts=report.get("ct_new_hosts", 0),
                                builds=len(builds), strong=len(strong),
                                mirrors=report.get("mirrors", 0))
            except Exception:
                pass
        if ctx.graph is not None:
            for b in strong[:10]:
                try:
                    ctx.graph.observe("technology", f"codename:{b['codename']}",
                                      attrs={"corroboration": b["corroboration"],
                                             "sources": b["sources"],
                                             "verdict": b["verdict"]},
                                      source="asset_radar")
                except Exception:
                    pass

        out = {k: v for k, v in report.items() if k != "builds"}
        out["secret_builds"] = builds[:20]
        out["note"] = ("leads only — codenames/hosts are INTEL, not findings; "
                       "prove live targets with http_probe / verify_vulnerability")
        return json.dumps(out, ensure_ascii=False, default=str)

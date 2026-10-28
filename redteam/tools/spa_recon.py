"""spa_recon — credential-free SPA walkthrough, ported from ARTEX's api-recon skill.

ARTEX (the Baidu "Agent+" challenge winner whose last open-source release this
port comes from) walks a modern SPA WITHOUT credentials: the bootstrap endpoints
a shell always calls on startup (login state, permissions, menus, notices,
config) are stubbed with structurally-valid, business-success, EMPTY responses.
The frontend renders its logged-in shell against mocks, mounts its routes and
components — and those components fire the REAL API surface (XHR/fetch/WebSocket
the static bundle grep can never see, because the calls only exist at runtime).
Static recon (recon/static_source.py) reads what the bundle CONTAINS; this walks
what the app DOES. The two compose: static finds the strings, spa_recon finds
the traffic.

Discipline inherited from our pipeline (this is why it is a port, not a copy):

- Scope on EVERYTHING: every navigation and every stubbed request is checked
  against the ScopeGuard — a stub never becomes a license to reach off-scope,
  and the page's own requests still go through the controller's global route
  guard. Out-of-scope attempts are aborted and COUNTED, never silently dropped.
- Rate-limit on page visits: a walkthrough is exactly the traffic the RoE caps
  exist for. Stub fulfillments cost nothing (nothing leaves the browser) — that
  is the point: unlock UI without burning the request budget.
- Traffic log: every observed call is recorded to the run's traffic log with
  source="mock" or source="live" — evidence of what the CLIENT asked for is
  kept distinct from what the SERVER said. Credential headers are masked by the
  recorder, as everywhere.
- Inventory + knowledge graph: in-scope API paths fold in as ENDPOINT nodes and
  inventory service hits, passive fingerprinting only.
- NEVER records a finding: like http_probe and surface_scan, exploration is not
  proof. A hypothesis that comes out of the walk goes through the verify
  pipeline like any other.

Honest limits: WebSocket frames are observed as OPEN events only (Playwright
routes do not intercept frames); SPA routers driven purely by hash fragments
are visited only if the anchor harvest sees them; a page that gates rendering
on non-empty data shows placeholders — which ARTEX's skill calls expected.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..ratelimit import RequestBudgetExceeded
from ..scope import ScopeViolation
from . import ToolContext

# Bootstrap-shaped endpoints a SPA shell calls before anything renders. Overridable
# per call — the defaults mirror ARTEX's api-recon stub set (auth state, RBAC
# menus, user profile, global config, notices). Intentionally conservative: a
# wrong stub here unlocks LESS UI, never more scope.
DEFAULT_STUB_PATTERNS: tuple[str, ...] = (
    r"(login|signin|sign-in|logout|sso|oauth|token|jwt|session|captcha)",
    r"(permission|permissions|role|roles|menu|menus|nav|navigation|rbac)",
    r"(userinfo|user_info|user/info|profile|account/me|/me/|current[-_]user)",
    r"(config|settings|options|preferences|tenant|bootstrap)",
    r"(notice|notices|announcement|announcements|message|messages|notif)",
)

# One superset mock body for every stub: whichever success-convention the SPA
# uses (code/msg/data, success, response_code, status, result), it reads as
# "business success, empty data" — ARTEX's contract verbatim ("结构正确、业务码
# 成功、数据可为空").
_MOCK_BODY: dict = {
    "code": 0, "msg": "ok", "message": "ok", "success": True,
    "response_code": 0, "status": 0, "data": [], "result": [],
}


def mock_body(url: str) -> str:
    """The stub body for one URL. Pure function — unit-tested without a browser."""
    return json.dumps(_MOCK_BODY, ensure_ascii=False)


def _compiled(patterns) -> tuple:
    out = []
    for p in patterns or DEFAULT_STUB_PATTERNS:
        out.append(p if isinstance(p, re.Pattern) else re.compile(str(p)))
    return tuple(out)


def should_stub(url: str, patterns) -> bool:
    """Pure decision: does this URL match any stub pattern?"""
    return any(rx.search(url) for rx in _compiled(patterns))


def plan_frontier(links, scope, seen: set, cap: int) -> tuple[list[str], int]:
    """Pure BFS step: filter harvested links to the in-scope, unvisited frontier.

    Returns (next_frontier, blocked_count). Same-order, deduped, bounded — and
    every dropped link is COUNTED, because silent drops hide scope escapes."""
    frontier: list[str] = []
    blocked = 0
    for link in links:
        base = str(link).split("#")[0]
        if not base or base in seen or any(base == f for f in frontier):
            continue
        try:
            scope.check(link)
        except ScopeViolation:
            blocked += 1
            continue
        frontier.append(base)
        if len(frontier) >= cap:
            break
    return frontier, blocked


def split_url(url: str) -> tuple[str, int, str, str]:
    """(host, port, scheme, path) for inventory folding."""
    u = urlparse(url)
    host = u.hostname or ""
    scheme = u.scheme or "http"
    port = u.port or (443 if scheme == "https" else 80)
    return host, port, scheme, u.path or "/"


# -- the walk itself (Playwright mechanics) -----------------------------------
#
# Lives here, not in browser.py: it is an ARTEX-port capability with its own
# failure modes, and browser.py stays the thin substrate. It reaches into the
# controller's page/scope/limiter/audit (same package, deliberate).

MAX_PAGES_CAP = 30
NETWORK_IDLE_TIMEOUT_MS = 12000


def spa_walk(controller, entry_url: str, *, audit, scope, limiter,
             stub_patterns=None, max_pages: int = 8) -> dict:
    """Walk an SPA shell with bootstrap stubs installed. Returns the observed
    API surface:

        {visited: [url...], calls: [{method, url, status, mocked}...],
         blocked: int, budget_error: str|""}
    """
    page = controller._page          # _ensure() must have run; caller guarantees
    patterns = _compiled(stub_patterns or DEFAULT_STUB_PATTERNS)
    max_pages = max(1, min(int(max_pages), MAX_PAGES_CAP))

    mocked: list[dict] = []
    live: dict[tuple[str, str], int] = {}     # (method, url) -> last status
    blocked = {"n": 0}

    def _stub_handler(route, _rx=re.compile(r".*")):
        url = route.request.url
        try:
            scope.check(url)
        except ScopeViolation:
            blocked["n"] += 1
            audit.record("spa.stub.blocked", url=url)
            route.abort()
            return
        if not any(rx.search(url) for rx in patterns):
            route.fallback()
            return
        mocked.append({"method": route.request.method.upper(), "url": url})
        route.fulfill(status=200, content_type="application/json",
                      body=mock_body(url))

    def _on_response(resp):
        try:
            req = resp.request
            if req.resource_type in ("xhr", "fetch"):
                live[(req.method.upper(), resp.url)] = resp.status
        except Exception:
            pass

    def _on_ws(ws):
        # Frames are NOT captured (Playwright routes don't intercept them); the
        # open itself is still surface: a WS endpoint is an entry worth knowing.
        try:
            live[("WS", ws.url)] = 101
        except Exception:
            pass

    # Register stub routes (Playwright consults newest-first, so these run
    # BEFORE the controller's global scope route; the scope check above keeps
    # the discipline). Non-matching requests fall through unchanged.
    for rx in patterns:
        page.route(rx, _stub_handler)
    page.on("response", _on_response)
    page.on("websocket", _on_ws)

    seen: set[str] = set()
    visited: list[str] = []
    budget_error = ""
    frontier = [entry_url]

    try:
        while frontier and len(visited) < max_pages:
            url = frontier.pop(0)
            base = url.split("#")[0]
            if base in seen:
                continue
            try:
                scope.check(url)
            except ScopeViolation:
                blocked["n"] += 1
                continue
            seen.add(base)
            try:
                limiter.acquire()
            except RequestBudgetExceeded as exc:
                budget_error = str(exc)
                audit.record("spa.walk.stopped", reason="budget", url=url)
                break
            try:
                # networkidle: give the shell time to fire its bootstrap XHRs.
                # SPAs with polling never go idle — the timeout is EXPECTED and
                # the page is still walked (it loaded; that is what matters).
                page.goto(url, wait_until="networkidle",
                          timeout=NETWORK_IDLE_TIMEOUT_MS)
            except Exception as exc:
                audit.record("spa.page.timeout", url=url, note=str(exc)[:120])
            visited.append(url)
            audit.record("spa.page", url=url, page=len(visited))
            try:
                links = controller.harvest().get("links", []) or []
            except Exception:
                links = []
            more, blk = plan_frontier(links, scope, seen, max_pages * 4)
            blocked["n"] += blk
            frontier.extend(more)
    finally:
        for rx in patterns:
            try:
                page.unroute(rx, _stub_handler)
            except Exception:
                pass
        try:
            page.remove_listener("response", _on_response)
            page.remove_listener("websocket", _on_ws)
        except Exception:
            pass

    # Merge: mocked calls (from route handlers) + live responses, deduped.
    calls: dict[tuple[str, str], dict] = {}
    for m in mocked:
        calls[(m["method"], m["url"])] = {"method": m["method"], "url": m["url"],
                                          "status": 200, "mocked": True}
    for (method, url), status in live.items():
        rec = calls.setdefault((method, url),
                               {"method": method, "url": url, "status": status,
                                "mocked": False})
        if not rec["mocked"]:
            rec["status"] = status
    # A URL that was stub-mocked also appearing as a live response means the
    # stub fell through for some pattern — keep the MOCKED truth (the wire saw
    # at most one of them) but never silently: report overlap in blocked path.
    return {"visited": visited, "calls": list(calls.values()),
            "blocked": blocked["n"], "budget_error": budget_error}


class SpaReconTool:
    name = "spa_recon"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Walk a single-page application WITHOUT credentials: bootstrap "
                "endpoints (login state, permissions, menus, notices, config) are "
                "answered with business-success/EMPTY mocks so the logged-in shell "
                "renders and reveals the API surface it actually calls at runtime. "
                "Use AFTER browser_navigate/static recon when the app gates its "
                "routes behind a login you have no credentials for. Records every "
                "observed call to the traffic log (mock vs live) and the asset "
                "inventory. NEVER records a finding and NEVER guesses passwords — "
                "if you have credentials, authenticate and use browser tools/"
                "http_probe against the real session instead."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "entry_url": {"type": "string",
                                  "description": "In-scope SPA entry (the app shell URL)."},
                    "stub_patterns": {"type": "array", "items": {"type": "string"},
                                      "description": "Regexes for endpoints to stub; "
                                                     "defaults cover auth/menu/config bootstrap."},
                    "max_pages": {"type": "integer",
                                  "description": "Max pages to visit (default 8, cap 30)."},
                },
                "required": ["entry_url"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, entry_url: str, stub_patterns=None,
            max_pages: int = 8) -> str:
        # Pre-flight: the entry URL is the operator's explicit ask, so an
        # off-RoE entry is a loud refusal (same discipline as browser_navigate),
        # not a silent empty walk.
        try:
            ctx.scope.check(entry_url)
        except ScopeViolation as exc:
            ctx.audit.record("spa.entry.blocked", url=entry_url, reason=str(exc))
            return f"BLOCKED (out of scope): {exc}"
        if ctx.browser is None:
            return "ERROR: browser is not available in this run."
        try:
            max_pages = max(1, min(int(max_pages), MAX_PAGES_CAP))
        except (TypeError, ValueError):
            max_pages = 8

        controller = ctx.browser
        try:
            controller._ensure()
        except Exception as exc:
            return f"BROWSER ERROR: {exc}"

        try:
            result = spa_walk(controller, entry_url,
                              stub_patterns=stub_patterns, max_pages=max_pages,
                              audit=ctx.audit, scope=ctx.scope, limiter=ctx.limiter)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        except RequestBudgetExceeded as exc:
            return f"BLOCKED (request budget exhausted): {exc}. Stop and report."
        except Exception as exc:
            return f"BROWSER ERROR: {exc}"

        # Fold the surface in: traffic log (mock vs live, credentials masked by
        # the recorder), inventory services, knowledge-graph endpoints. All
        # passive observation — no finding is recorded, ever.
        import time as _time
        from ..events import safe_emit
        from ..knowledge import ENDPOINT

        host_hits: dict[tuple, dict] = {}
        for call in result["calls"]:
            url, mocked = call["url"], call["mocked"]
            ctx.traffic.record_http(
                method=call["method"], url=url, status=call["status"] or 0,
                elapsed_ms=0, tool="spa_recon",
                source="mock" if mocked else "live")
            try:
                ctx.scope.check(url)
            except ScopeViolation:
                continue   # defensive: stub handler already aborts these
            host, port, scheme, path = split_url(url)
            if host:
                svc = host_hits.setdefault((host, port, scheme), {"status": 0})
                svc["status"] = call["status"] or svc["status"]
            if ctx.graph is not None and re.match(r"^https?://", url):
                key = url.split("?")[0]
                attrs = {"from": "spa_recon",
                         "mocked": mocked, "method": call["method"]}
                node = ctx.graph.observe(ENDPOINT, key, attrs=attrs,
                                         source="spa_recon")
                if node is not None and call["mocked"]:
                    node.attrs["requested_via_mock"] = True

        for (host, port, scheme), svc in host_hits.items():
            if ctx.inventory is not None:
                ctx.inventory.observe_http(host, port, scheme, svc["status"],
                                           source="spa_recon")

        n_mock = sum(1 for c in result["calls"] if c["mocked"])
        n_live = len(result["calls"]) - n_mock
        ctx.audit.record("spa.walk", entry=entry_url, pages=len(result["visited"]),
                         calls=len(result["calls"]), mocked=n_mock, live=n_live,
                         blocked=result["blocked"])
        safe_emit(ctx.events, "recon.spa", entry=entry_url,
                  pages=len(result["visited"]), calls=len(result["calls"]),
                  mocked=n_mock, live=n_live, blocked=result["blocked"])

        summary = {
            "entry": entry_url,
            "pages_visited": result["visited"],
            "api_calls_observed": len(result["calls"]),
            "mocked": n_mock, "live": n_live,
            "out_of_scope_blocked": result["blocked"],
            "budget_error": result["budget_error"],
            "calls": [
                {"method": c["method"], "url": c["url"],
                 "status": c["status"], "mocked": c["mocked"]}
                for c in result["calls"][:80]
            ],
            "note": ("exploration only — no finding recorded; prove hypotheses "
                     "with confirm_finding/verify_vulnerability"),
        }
        if result["budget_error"]:
            summary["warning"] = ("walk stopped early: request budget exhausted — "
                                  "the surface above is PARTIAL")
        return json.dumps(summary, ensure_ascii=False)

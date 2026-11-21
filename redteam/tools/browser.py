"""Browser automation via Playwright, with scope enforced on every request.

The controller installs a global route handler: every request the page makes (the main
navigation and every subresource — XHR, fetch, images, scripts) is checked against the
ScopeGuard, and anything out of scope is aborted. So even a page that tries to pull from
a third-party or internal host cannot make the browser reach off-scope.

RECON instrument duties (2026-11-18 recon upgrade):
  - NETWORK/CONSOLE CAPTURE: every request/response (method, url, status,
    resource type, redirect depth, sanitized headers, safely-collectable
    bodies) and every console error / page error lands in a bounded ring the
    agent queries via browser_requests / browser_inspect_request /
    browser_console — no re-navigation needed to re-read what happened.
  - EVIDENCE INTEGRATION: meaningful exchanges (document/xhr/fetch/script) are
    recorded into the run's TrafficRecorder (traffic.jsonl, source="browser")
    UNLESS the browser routes through EvidenceProxy — then the proxy records
    the wire exchange (source=proxy / proxy-mitm) and the controller skips
    direct recording so no exchange is double-counted.
  - PROXY ROUTING: when constructed with proxy_server, chromium sends ALL
    traffic through EvidenceProxy (RECON agent -> Playwright -> EvidenceProxy
    -> target); the browser↔proxy TLS leg accepts the run CA
    (ignore_https_errors — the proxy↔target leg still verifies upstream
    certificates normally). Without a proxy the browser verifies certificates
    as usual.
  - LIVE VIEW: every navigate/click/fill/screenshot refreshes
    <run>/recon_live/latest.jpg + events.jsonl — the operator watches the
    browser move in real time (any.run-style viewer in server.py).

Playwright runs on the host (not in the Kali container). Install browsers once with:
    python -m playwright install chromium
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path

from ..ratelimit import RequestBudgetExceeded
from ..scope import ScopeGuard, ScopeViolation
from . import ToolContext

# Ring bounds — capture must never grow unbounded inside a long walk.
_NET_RING = 400
_CONSOLE_RING = 120
_BODY_CAPTURE_LIMIT = 256 * 1024   # only collect bodies when content-length fits
_RING_BODY_CLIP = 16 * 1024

# Resource types whose exchanges are worth a traffic.jsonl row (with bodies
# where collectable). Purely cosmetic subresources live in the ring only.
_TRAFFIC_RESOURCE_TYPES = {"document", "xhr", "fetch", "script"}
_TEXTUAL_CONTENT_TYPES = ("text/", "application/json", "application/xml",
                          "application/javascript", "application/x-www-form-urlencoded",
                          "application/graphql")


class BrowserController:
    """Owns the Playwright lifecycle and a single page. Constructed lazily on first use.

    RECON V2 integration:
      - every request the page makes (navigation AND subresources) consumes the
        run's shared request budget — the SAME limiter the EvidenceProxy and
        every tool use, so the RoE budget is genuinely global;
      - when `proxy_url` is set the browser routes through the run's
        EvidenceProxy: one scope plane, one budget, one evidence history (the
        proxy records the wire; the browser records nothing to avoid double rows);
      - without a proxy the controller records each completed exchange into the
        SAME traffic.jsonl (source="browser") itself — browser requests are
        always evidence, never a blind spot;
      - console errors and page errors are captured (capped) and surfaced to
        the agent, then folded into the observation store as evidence;
      - a bounded request/response ring (_net) plus console/pageerror capture
        make the browser an inspectable instrument (browser_requests /
        browser_inspect_request / browser_console), and every action refreshes
        the live-view frames (_live_frame) the operator watches in real time.
    """

    _MAX_CONSOLE = 50

    def __init__(self, scope: ScopeGuard, limiter, audit, screenshot_dir: Path,
                 traffic=None, store=None, assets=None, proxy_url: str = "",
                 proxy_server: str = "", live_dir: Path | None = None):
        self._scope = scope
        self._limiter = limiter
        self._audit = audit
        self._screenshot_dir = screenshot_dir
        self._traffic = traffic            # TrafficRecorder | None
        self._store = store
        self._assets = assets
        # proxy_server is an alias for proxy_url — use whichever is non-empty.
        self._proxy_url = proxy_url or proxy_server
        # Direct recording happens ONLY without the proxy — otherwise the
        # proxy already records the same exchange and rows would double-count.
        self._record_traffic = traffic is not None and not self._proxy_url
        self._live_dir = live_dir
        self._pw = None
        self._browser = None
        self._page = None
        self.console_errors: list[str] = []
        self._console_seen: set[str] = set()
        self._net: list[dict] = []         # bounded request/response ring
        self._console: list[dict] = []     # console errors / page errors
        self._blocked_urls: set[str] = set()
        self._net_seq = 0
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------------

    def _ensure(self):
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "playwright is not installed. `pip install playwright` and "
                "`python -m playwright install chromium`."
            ) from exc
        self._pw = sync_playwright().start()
        launch_kwargs: dict = {"headless": True}
        if self._proxy_url:
            launch_kwargs["proxy"] = {"server": self._proxy_url}
        self._browser = self._pw.chromium.launch(**launch_kwargs)
        # ignore_https_errors ONLY when we route through our own evidence
        # proxy: the browser↔proxy leg presents the RUN CA (decrypted MITM).
        # Upstream verification still happens — in the proxy itself, against
        # the system trust store (proxy.upstream_context). Without a proxy the
        # browser verifies certificates as usual.
        context = self._browser.new_context(
            ignore_https_errors=bool(self._proxy_url))
        self._page = context.new_page()
        self._page.route("**/*", self._route)
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("requestfailed", self._on_requestfailed)
        self._page.on("console", self._on_console)
        self._page.on("pageerror", self._on_pageerror)

    def _record_observation(self, url: str, *, title: str = "",
                            status=None) -> None:
        if self._store is None:
            return
        try:
            from ..recon_v2.capabilities import record_page_evidence
            record_page_evidence(
                self._store, url, title=title, status=status,
                console_errors=list(self.console_errors[-5:]),
                tool="browser")
        except Exception:
            pass

    def _route(self, route):
        url = route.request.url
        try:
            self._scope.check(url)
        except ScopeViolation:
            self._audit.record("browser.request.blocked", url=url)
            with self._lock:
                self._blocked_urls.add(url)
            route.abort()
            return
        # Every wire request spends the run's shared budget — navigations and
        # subresources alike (through the proxy the proxy enforces it instead,
        # keeping exactly one acquisition per wire request).
        if not self._proxy_url:
            self._limiter.acquire()
        route.continue_()

    # -- capture handlers (the browser as an inspectable instrument) -------------

    def _net_entry(self, request) -> dict:
        with self._lock:
            self._net_seq += 1
            entry = {
                "seq": self._net_seq,
                "ts": time.strftime("%H:%M:%S"),
                "started": time.monotonic(),
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "post_data": (request.post_data or "")[:2048] or "",
                "status": None,
                "content_type": "",
                "resp_headers": {},
                "resp_body": "",
                "redirect_depth": 0,
                "error": "",
                "blocked": False,
            }
            depth, req = 0, request
            while getattr(req, "redirected_from", None) is not None:
                depth += 1
                req = req.redirected_from
            entry["redirect_depth"] = depth
            self._net.append(entry)
            if len(self._net) > _NET_RING:
                del self._net[:len(self._net) - _NET_RING]
            return entry

    def _on_request(self, request):
        try:
            self._net_entry(request)
        except Exception:  # noqa: BLE001 — capture must never break the page
            pass

    def _on_response(self, response):
        try:
            request = response.request
            entry = self._find_entry(request.url, request.method)
            if entry is None:
                entry = self._net_entry(request)
            elapsed_ms = int((time.monotonic() - entry["started"]) * 1000)
            entry["status"] = response.status
            try:
                headers = dict(response.headers)
            except Exception:
                headers = {}
            try:
                from ..traffic import _mask_headers
                entry["resp_headers"] = _mask_headers(headers)
            except Exception:
                entry["resp_headers"] = {}   # honest gap over fake data
            ctype = str(headers.get("content-type", ""))
            entry["content_type"] = ctype[:120]
            # Body capture: only safely-collectable text-ish payloads.
            length = headers.get("content-length", "")
            small = not length or (length.isdigit() and int(length) <= _BODY_CAPTURE_LIMIT)
            if ctype.lower().startswith(_TEXTUAL_CONTENT_TYPES) and small:
                try:
                    entry["resp_body"] = response.text()[:_RING_BODY_CLIP]
                except Exception:
                    entry["resp_body"] = ""   # streamed/redirected: honest gap
            if self._record_traffic and \
                    entry["resource_type"] in _TRAFFIC_RESOURCE_TYPES:
                try:
                    self._traffic.record_http(
                        method=entry["method"], url=entry["url"],
                        status=response.status, elapsed_ms=elapsed_ms,
                        tool="browser", source="browser",
                        req_headers={}, req_body=entry["post_data"] or None,
                        resp_headers=headers, resp_body=entry["resp_body"] or None)
                except Exception:
                    pass   # telemetry must never break the run
        except Exception:  # noqa: BLE001
            pass

    def _on_requestfailed(self, failure):
        try:
            entry = self._find_entry(failure.url, failure.method)
            if entry is None:
                entry = self._net_entry(failure)
            with self._lock:
                blocked = failure.url in self._blocked_urls
            entry["blocked"] = blocked
            entry["error"] = ("scope-denied (out of RoE; not sent)"
                              if blocked else str(failure.failure)[:160])
            entry["status"] = 0
        except Exception:  # noqa: BLE001
            pass

    def _on_console(self, msg):
        try:
            if msg.type not in ("error", "warning"):
                return
            with self._lock:
                self._console.append({
                    "ts": time.strftime("%H:%M:%S"), "kind": "console",
                    "level": msg.type, "text": (msg.text or "")[:500],
                    "url": self._page.url if self._page else "",
                })
                if len(self._console) > _CONSOLE_RING:
                    del self._console[:len(self._console) - _CONSOLE_RING]
            self._note_console_error(f"{msg.type}: {(msg.text or '')[:300]}")
        except Exception:  # noqa: BLE001
            pass

    def _on_pageerror(self, error):
        try:
            with self._lock:
                self._console.append({
                    "ts": time.strftime("%H:%M:%S"), "kind": "pageerror",
                    "level": "error", "text": str(error)[:500],
                    "url": self._page.url if self._page else "",
                })
                if len(self._console) > _CONSOLE_RING:
                    del self._console[:len(self._console) - _CONSOLE_RING]
            self._note_console_error(f"pageerror: {str(error)[:300]}")
        except Exception:  # noqa: BLE001
            pass

    def _note_console_error(self, entry: str) -> None:
        """De-duplicated console/page-error feed surfaced to the agent via
        navigate()'s console_errors and folded into the evidence store."""
        if entry not in self._console_seen:
            self._console_seen.add(entry)
            self.console_errors.append(entry)
            del self.console_errors[:-self._MAX_CONSOLE]

    def _find_entry(self, url: str, method: str) -> dict | None:
        with self._lock:
            for entry in reversed(self._net):
                if entry["url"] == url and entry["method"] == method:
                    return entry
        return None

    # -- live view -----------------------------------------------------------------

    def _live_frame(self, action: str, extra: dict | None = None) -> None:
        """Refresh the any.run-style live artifacts: JPEG frame + event feed.
        Best-effort and silent — the recon run must never break for the view."""
        if self._live_dir is None:
            return
        try:
            self._live_dir.mkdir(parents=True, exist_ok=True)
            url = self._page.url if self._page else ""
            title = ""
            try:
                title = self._page.title()[:160]
            except Exception:
                pass
            self._page.screenshot(path=str(self._live_dir / "latest.jpg"),
                                  type="jpeg", quality=60, timeout=8000)
            event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "action": action, "url": url, "title": title}
            if extra:
                event.update(extra)
            with open(self._live_dir / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
            with open(self._live_dir / "latest.json", "w", encoding="utf-8") as fh:
                json.dump(event, fh)
        except Exception:
            pass

    # -- agent-facing actions ---------------------------------------------------------

    def navigate(self, url: str) -> dict:
        # Scope-check the top-level URL before we even open it (clear error to the model).
        self._scope.check(url)
        self._ensure()
        self._audit.record("browser.navigate", url=url)
        resp = self._page.goto(url, wait_until="domcontentloaded", timeout=30000)
        status = resp.status if resp else None
        self._record_observation(self._page.url,
                                 title=self._page.title()[:200], status=status)
        result = {
            "url": self._page.url,
            "status": status,
            "title": self._page.title(),
        }
        if self.console_errors:
            result["console_errors"] = self.console_errors[-5:]
        self._live_frame("navigate", {"status": result["status"]})
        return result

    def content(self, max_chars: int = 8000) -> dict:
        self._ensure()
        text = self._page.inner_text("body")
        return {"url": self._page.url, "text": text[:max_chars],
                "truncated": len(text) > max_chars}

    def click(self, selector: str) -> dict:
        self._ensure()
        self._page.click(selector, timeout=10000)
        self._audit.record("browser.click", selector=selector, url=self._page.url)
        result = {"url": self._page.url, "clicked": selector}
        self._live_frame("click", {"selector": selector[:120]})
        return result

    def fill(self, selector: str, value: str) -> dict:
        self._ensure()
        self._page.fill(selector, value, timeout=10000)
        self._audit.record("browser.fill", selector=selector, url=self._page.url)
        result = {"url": self._page.url, "filled": selector}
        self._live_frame("fill", {"selector": selector[:120]})
        return result

    def screenshot(self, name: str) -> dict:
        self._ensure()
        safe = "".join(c for c in name if c.isalnum() or c in "-_") or "shot"
        path = self._screenshot_dir / f"{safe}.png"
        self._screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(path))
        self._audit.record("browser.screenshot", path=str(path), url=self._page.url)
        self._live_frame("screenshot", {"saved": str(path)})
        return {"saved": str(path)}

    # -- capture read-back (browser_requests / browser_inspect_request /
    #    browser_console tools below) --------------------------------------------

    def requests(self, url_contains: str = "", method: str = "",
                 resource_type: str = "", status: int | None = None,
                 limit: int = 40) -> list[dict]:
        with self._lock:
            rows = list(self._net)
        needle = url_contains.lower()
        out = []
        for entry in reversed(rows):     # newest first
            if needle and needle not in entry["url"].lower():
                continue
            if method and entry["method"].upper() != method.upper():
                continue
            if resource_type and entry["resource_type"] != resource_type:
                continue
            if status is not None and entry["status"] != status:
                continue
            out.append({k: entry.get(k) for k in
                        ("seq", "ts", "method", "url", "resource_type",
                         "status", "content_type", "redirect_depth", "error",
                         "blocked")})
            if len(out) >= max(1, min(limit, 200)):
                break
        return out

    def inspect_request(self, seq: int) -> dict | None:
        with self._lock:
            for entry in self._net:
                if entry["seq"] == seq:
                    return dict(entry)
        return None

    def console_messages(self, level: str = "error") -> list[dict]:
        with self._lock:
            rows = list(self._console)
        if level == "error":
            rows = [r for r in rows if r["level"] == "error"]
        elif level == "warning":
            rows = [r for r in rows if r["level"] == "warning"]
        return rows[-50:][::-1]

    def harvest(self) -> dict:
        """Extract same-origin links and forms (with input names) from the current page.

        This is what feeds the graph from browsing: every discovered link becomes a
        candidate endpoint and every form input becomes a parameter to test."""
        self._ensure()
        links = self._page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)") or []
        forms = self._page.eval_on_selector_all(
            "form",
            """els => els.map(f => ({
                action: f.action || location.href,
                method: (f.method || 'get').toUpperCase(),
                params: Array.from(f.querySelectorAll('input,select,textarea'))
                             .map(i => i.name).filter(Boolean)
            }))""") or []
        return {"links": links, "forms": forms}

    def close(self):
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass


class _BrowserTool:
    """Base for browser tools; each subclass sets name/schema/action."""

    def _guarded(self, ctx: ToolContext, fn):
        if ctx.browser is None:
            return "ERROR: browser is not available in this run."
        try:
            return fn(ctx.browser)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        except RequestBudgetExceeded as exc:
            return f"STOP: {exc}"
        except Exception as exc:
            return f"BROWSER ERROR: {exc}"


def _ingest_browser(ctx: ToolContext, harvest: dict) -> int:
    """Fold harvested links/forms into the evidence planes: the ObservationLog
    (provenance + validation lifecycle, mirrors into the graph) when present,
    else the KnowledgeGraph directly (legacy paths). Returns count added."""
    observations = getattr(ctx, "observations", None)
    graph = ctx.graph
    from ..knowledge import ENDPOINT, PARAMETER
    added = 0
    for link in harvest.get("links", []):
        try:
            ctx.scope.check(link)   # only keep in-scope endpoints
        except ScopeViolation:
            continue
        if observations is not None:
            observations.record("endpoint", link.split("#")[0],
                                source_tool="browser", mode="active")
        elif graph is not None:
            graph.observe(ENDPOINT, link.split("#")[0], attrs={"from": "browser"},
                          source="browser")
        added += 1
    for form in harvest.get("forms", []):
        action = form.get("action", "")
        try:
            ctx.scope.check(action)
        except ScopeViolation:
            continue
        params = [p for p in form.get("params", []) if p][:24]
        if observations is not None:
            observations.record("endpoint", action.split("#")[0],
                                method=form.get("method", "GET"),
                                source_tool="browser", mode="active",
                                metadata={"form_params": params,
                                          "from": "browser_form"})
            observations.record("form", action.split("#")[0],
                                method=form.get("method", "GET"),
                                source_tool="browser", mode="active",
                                metadata={"params": params})
        if graph is not None:
            # Same node the observation mirror created/updated — re-observing
            # is an idempotent merge and hands us the node id for edge wiring.
            ep_node = graph.observe(ENDPOINT, action.split("#")[0],
                                    attrs={"method": form.get("method", "GET"),
                                           "from": "browser_form"},
                                    source="browser")
        for pname in params:
            if graph is not None:
                graph.observe(PARAMETER, f"{action}#{pname}", attrs={"name": pname},
                              source="browser", relate_to=ep_node.id,
                              relation="parameter")
            if observations is not None:
                observations.record("parameter", f"{action}#{pname}",
                                    source_tool="browser", mode="active")
            added += 1
    return added


class BrowserNavigateTool(_BrowserTool):
    name = "browser_navigate"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": ("Open an in-scope URL in a headless browser, return "
                                "status/title, and harvest in-scope links and form "
                                "parameters into the knowledge graph."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {"url": {"type": "string"}}, "required": ["url"]},
                "strict": True}

    def run(self, ctx, url: str) -> str:
        import json

        def _do(b):
            nav = b.navigate(url)
            harvested = _ingest_browser(ctx, b.harvest())
            nav["graph_updates"] = harvested
            observations = getattr(ctx, "observations", None)
            if observations is not None:
                observations.record("endpoint", nav.get("url", url),
                                    source_tool="browser_navigate",
                                    mode="active",
                                    metadata={"title": str(nav.get("title", ""))[:200],
                                              "http_status": nav.get("status")})
            return json.dumps(nav)
        return self._guarded(ctx, _do)


class BrowserContentTool(_BrowserTool):
    name = "browser_content"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": "Return the visible text of the current page (truncated).",
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {}, "required": []},
                "strict": True}

    def run(self, ctx) -> str:
        import json
        return self._guarded(ctx, lambda b: json.dumps(b.content()))


class BrowserClickTool(_BrowserTool):
    name = "browser_click"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": "Click an element by CSS selector on the current page.",
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {"selector": {"type": "string"}},
                                 "required": ["selector"]},
                "strict": True}

    def run(self, ctx, selector: str) -> str:
        import json
        return self._guarded(ctx, lambda b: json.dumps(b.click(selector)))


class BrowserFillTool(_BrowserTool):
    name = "browser_fill"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": "Fill a form field (by CSS selector) with a value on the current page.",
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {"selector": {"type": "string"},
                                                "value": {"type": "string"}},
                                 "required": ["selector", "value"]},
                "strict": True}

    def run(self, ctx, selector: str, value: str) -> str:
        import json
        return self._guarded(ctx, lambda b: json.dumps(b.fill(selector, value)))


class BrowserScreenshotTool(_BrowserTool):
    name = "browser_screenshot"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": "Save a PNG screenshot of the current page for evidence.",
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {"name": {"type": "string"}},
                                 "required": ["name"]},
                "strict": True}

    def run(self, ctx, name: str) -> str:
        import json
        return self._guarded(ctx, lambda b: json.dumps(b.screenshot(name)))


class BrowserRequestsTool(_BrowserTool):
    """browser_requests — list what the browser ACTUALLY sent (no re-navigation)."""

    name = "browser_requests"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "List the network requests the browser actually made on "
                    "this page (newest first): method, url, resource type, "
                    "status, content type, redirect depth. Includes XHR/fetch "
                    "API calls the frontend fired and requests that were "
                    "BLOCKED as out of scope (status 0, error 'scope-denied'). "
                    "Filter before listing; inspect one row with "
                    "browser_inspect_request."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {
                                     "url_contains": {"type": "string"},
                                     "method": {"type": "string"},
                                     "resource_type": {"type": "string",
                                                       "description": "document | xhr | fetch | script | image | ..."},
                                     "status": {"type": "integer"},
                                     "limit": {"type": "integer"}},
                                 "required": []},
                "strict": True}

    def run(self, ctx, url_contains="", method="", resource_type="", status=None,
            limit=None) -> str:
        import json
        try:
            status_i = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_i = None
        try:
            limit_i = int(limit) if limit else 40
        except (TypeError, ValueError):
            limit_i = 40

        def _do(b):
            return json.dumps({"requests": b.requests(
                url_contains=str(url_contains or ""), method=str(method or ""),
                resource_type=str(resource_type or ""), status=status_i,
                limit=limit_i)})
        return self._guarded(ctx, _do)


class BrowserInspectRequestTool(_BrowserTool):
    """browser_inspect_request — one captured exchange in full."""

    name = "browser_inspect_request"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Full detail of ONE browser-captured exchange by seq "
                    "(from browser_requests): sanitized response headers, "
                    "response body (text/json only, size-bounded), request "
                    "post data, redirect depth, failure reason. Secrets in "
                    "headers are withheld; never print credentials into "
                    "notes or findings."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {"seq": {"type": "integer"}},
                                 "required": ["seq"]},
                "strict": True}

    def run(self, ctx, seq=None) -> str:
        import json
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            return "ERROR: seq must be an integer"

        def _do(b):
            row = b.inspect_request(seq_i)
            if row is None:
                return f"ERROR: no captured request with seq={seq_i} (ring holds the most recent 400)"
            row.pop("started", None)
            return json.dumps(row)
        return self._guarded(ctx, _do)


class BrowserConsoleTool(_BrowserTool):
    """browser_console — console errors/warnings and uncaught page errors."""

    name = "browser_console"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "JavaScript console errors/warnings and uncaught page "
                    "exceptions collected since the browser started (newest "
                    "first). Errors often reveal API routes, stack paths, "
                    "and broken endpoints the UI hides."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {
                                     "level": {"type": "string",
                                               "enum": ["error", "warning", "all"]}},
                                 "required": []},
                "strict": True}

    def run(self, ctx, level="error") -> str:
        import json

        def _do(b):
            rows = b.console_messages(str(level or "error"))
            if ctx.observations is not None:
                for row in rows[:10]:
                    if row.get("level") == "error":
                        ctx.observations.record(
                            "console_error", row.get("url", "") or "page",
                            source_tool="browser_console", mode="active",
                            metadata={"text": row.get("text", "")})
            return json.dumps({"messages": rows})
        return self._guarded(ctx, _do)

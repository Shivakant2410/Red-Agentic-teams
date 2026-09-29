"""Browser automation via Playwright, with scope enforced on every request.

The controller installs a global route handler: every request the page makes (the main
navigation and every subresource — XHR, fetch, images, scripts) is checked against the
ScopeGuard, and anything out of scope is aborted. So even a page that tries to pull from
a third-party or internal host cannot make the browser reach off-scope.

Playwright runs on the host (not in the Kali container). Install browsers once with:
    python -m playwright install chromium
"""

from __future__ import annotations

import base64
from pathlib import Path

from ..ratelimit import RequestBudgetExceeded
from ..scope import ScopeGuard, ScopeViolation
from . import ToolContext


class BrowserController:
    """Owns the Playwright lifecycle and a single page. Constructed lazily on first use."""

    def __init__(self, scope: ScopeGuard, limiter, audit, screenshot_dir: Path):
        self._scope = scope
        self._limiter = limiter
        self._audit = audit
        self._screenshot_dir = screenshot_dir
        self._pw = None
        self._browser = None
        self._page = None

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
        self._browser = self._pw.chromium.launch(headless=True)
        self._page = self._browser.new_page()
        self._page.route("**/*", self._route)

    def _route(self, route):
        url = route.request.url
        try:
            self._scope.check(url)
        except ScopeViolation:
            self._audit.record("browser.request.blocked", url=url)
            route.abort()
            return
        route.continue_()

    def navigate(self, url: str) -> dict:
        # Scope-check the top-level URL before we even open it (clear error to the model).
        self._scope.check(url)
        self._limiter.acquire()
        self._ensure()
        self._audit.record("browser.navigate", url=url)
        resp = self._page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return {
            "url": self._page.url,
            "status": resp.status if resp else None,
            "title": self._page.title(),
        }

    def content(self, max_chars: int = 8000) -> dict:
        self._ensure()
        text = self._page.inner_text("body")
        return {"url": self._page.url, "text": text[:max_chars],
                "truncated": len(text) > max_chars}

    def click(self, selector: str) -> dict:
        self._ensure()
        self._page.click(selector, timeout=10000)
        self._audit.record("browser.click", selector=selector, url=self._page.url)
        return {"url": self._page.url, "clicked": selector}

    def fill(self, selector: str, value: str) -> dict:
        self._ensure()
        self._page.fill(selector, value, timeout=10000)
        self._audit.record("browser.fill", selector=selector, url=self._page.url)
        return {"url": self._page.url, "filled": selector}

    def screenshot(self, name: str) -> dict:
        self._ensure()
        safe = "".join(c for c in name if c.isalnum() or c in "-_") or "shot"
        path = self._screenshot_dir / f"{safe}.png"
        self._screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(path))
        self._audit.record("browser.screenshot", path=str(path), url=self._page.url)
        return {"saved": str(path)}

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
    """Fold harvested links/forms into the knowledge graph. Returns count added."""
    if ctx.graph is None:
        return 0
    from ..knowledge import ENDPOINT, PARAMETER
    added = 0
    for link in harvest.get("links", []):
        try:
            ctx.scope.check(link)   # only keep in-scope endpoints
        except ScopeViolation:
            continue
        ctx.graph.observe(ENDPOINT, link.split("#")[0], attrs={"from": "browser"},
                          source="browser")
        added += 1
    for form in harvest.get("forms", []):
        action = form.get("action", "")
        try:
            ctx.scope.check(action)
        except ScopeViolation:
            continue
        ep = ctx.graph.observe(ENDPOINT, action.split("#")[0],
                               attrs={"method": form.get("method", "GET"), "from": "form"},
                               source="browser")
        for pname in form.get("params", []):
            ctx.graph.observe(PARAMETER, f"{action}#{pname}", attrs={"name": pname},
                              source="browser", relate_to=ep.id, relation="parameter")
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

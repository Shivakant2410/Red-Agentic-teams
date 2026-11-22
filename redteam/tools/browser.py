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

        # Cloudflare / WAF targets: vanilla headless Chromium is detected and
        # served the "checking your browser" interstitial, so recon comes back
        # empty. A real-Chrome persistent profile (channel="chrome", a user-data
        # dir, non-headless) clears Cloudflare's PASSIVE fingerprinting (an
        # interactive CAPTCHA still needs a human — see the handoff path). Opt in
        # with RED_BROWSER_REAL_CHROME=1; defaults stay headless bundled Chromium
        # so CI and non-WAF runs are unchanged.
        import os
        real_chrome = os.environ.get("RED_BROWSER_REAL_CHROME", "") in ("1", "true", "yes")
        # Headful by default when real-Chrome is on (the whole point), but allow
        # RED_BROWSER_HEADLESS=1 to force headless even then (e.g. headless shell).
        headless = not real_chrome
        if os.environ.get("RED_BROWSER_HEADLESS", "") in ("1", "true", "yes"):
            headless = True

        # A realistic, non-automation context: real UA, locale, viewport, and no
        # navigator.webdriver tell. Passed to both launch paths below.
        ua = os.environ.get(
            "RED_BROWSER_UA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )
        context_kwargs: dict = {
            "ignore_https_errors": bool(self._proxy_url),
            "user_agent": ua,
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "viewport": {"width": 1366, "height": 900},
        }
        proxy_cfg = {"server": self._proxy_url} if self._proxy_url else None

        if real_chrome:
            # Persistent context = a real user-data dir, which Cloudflare treats
            # far more like a returning human than an ephemeral launch. channel
            # "chrome" uses the installed Google Chrome, not bundled Chromium.
            profile_dir = os.environ.get(
                "RED_BROWSER_PROFILE",
                str(self._screenshot_dir.parent / "chrome-profile"),
            )
            launch_kwargs: dict = {
                "headless": headless,
                "channel": os.environ.get("RED_BROWSER_CHANNEL", "chrome"),
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
                **context_kwargs,
            }
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg
            context = self._pw.chromium.launch_persistent_context(
                profile_dir, **launch_kwargs)
            self._browser = context.browser  # may be None for persistent ctx
        else:
            launch_kwargs = {"headless": headless}
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg
            self._browser = self._pw.chromium.launch(**launch_kwargs)
            # ignore_https_errors ONLY when we route through our own evidence
            # proxy: the browser↔proxy leg presents the RUN CA (decrypted MITM).
            # Upstream verification still happens — in the proxy itself, against
            # the system trust store (proxy.upstream_context). Without a proxy
            # the browser verifies certificates as usual.
            context = self._browser.new_context(**context_kwargs)

        # Strip the navigator.webdriver flag before any page script runs.
        try:
            context.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
            )
        except Exception:
            pass

        self._page = context.pages[0] if context.pages else context.new_page()
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

    def login(self, login_url: str, username: str, password_env: str,
              user_selector: str = "", pass_selector: str = "",
              submit_selector: str = "") -> dict:
        """Authenticate end-to-end in the live browser session.

        The PASSWORD is never passed as an argument or logged — it is read from
        the named environment variable (default RED_VINTED_PASSWORD) at call
        time and dropped immediately. The audit records the username and the
        env-var NAME, never the secret. Selectors are optional: when omitted we
        try a set of common email/password/submit selectors so the agent does
        not have to know the page's DOM in advance.
        """
        import os
        self._scope.check(login_url)
        self._ensure()
        env_name = password_env or "RED_VINTED_PASSWORD"
        password = os.environ.get(env_name, "")
        # Audit the ATTEMPT with the non-secret facts only.
        self._audit.record("browser.login.attempt", url=login_url,
                           username=username, password_env=env_name,
                           have_password=bool(password))
        if not password:
            return {"ok": False,
                    "error": f"no password in env ${env_name}; set it in your "
                             "shell/.env (never passed as an argument)"}

        self._page.goto(login_url, wait_until="domcontentloaded", timeout=30000)
        self._dismiss_consent()

        user_sels = [user_selector] if user_selector else [
            "input[type='email']", "input[name='email']", "input[name='user']",
            "input[name='username']", "input[autocomplete='username']",
            "input[name='login']",
        ]
        pass_sels = [pass_selector] if pass_selector else [
            "input[type='password']", "input[name='password']",
            "input[autocomplete='current-password']",
        ]
        submit_sels = [submit_selector] if submit_selector else [
            "button[type='submit']", "button[data-testid*='login']",
            "button[data-testid*='submit']", "input[type='submit']",
        ]

        def _first(sels):
            for s in sels:
                try:
                    el = self._page.query_selector(s)
                    if el and el.is_visible():
                        return s
                except Exception:
                    continue
            return ""

        us = _first(user_sels)
        ps = _first(pass_sels)
        if not us or not ps:
            self._live_frame("login", {"stage": "form-not-found"})
            return {"ok": False, "url": self._page.url,
                    "error": "login form not found on page; pass explicit "
                             "user_selector/pass_selector",
                    "user_found": bool(us), "pass_found": bool(ps)}

        # Type (not fill) so the value arrives like real keystrokes; password is
        # typed from the local variable and never recorded.
        self._page.fill(us, username, timeout=10000)
        self._page.fill(ps, password, timeout=10000)
        del password  # drop the secret ASAP

        sub = _first(submit_sels)
        if sub:
            self._page.click(sub, timeout=10000)
        else:
            self._page.press(ps, "Enter")
        try:
            self._page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass

        # Success heuristic: we left the login URL and no password field remains.
        left_login = login_url.rstrip("/") not in self._page.url.rstrip("/")
        still_has_pass = bool(self._page.query_selector("input[type='password']"))
        ok = left_login and not still_has_pass
        self._audit.record("browser.login.result", url=self._page.url,
                           username=username, ok=ok)
        self._record_observation(self._page.url,
                                 title=(self._page.title() or "")[:200])
        self._live_frame("login", {"ok": ok})
        result = {"ok": ok, "url": self._page.url,
                  "title": self._page.title()}
        if not ok:
            result["hint"] = ("still on login or password field present — "
                              "check creds, MFA, or a CAPTCHA (needs a human)")
        if self.console_errors:
            result["console_errors"] = self.console_errors[-5:]
        return result

    def session_status(self, check_url: str,
                        logged_in_selector: str = "",
                        logged_out_selector: str = "") -> dict:
        """Report whether the current (human-warmed) browser session is already
        authenticated, so the agent reuses it instead of trying to log in again.

        The human-warms-session handoff: a human solves the Cloudflare/login
        challenge once in the persistent profile, then the agent runs against
        that same profile already authenticated. This tells the agent which
        state it is in. Heuristic by default (presence of a logout/account
        control vs a login link); pass explicit selectors to be certain.
        """
        self._scope.check(check_url)
        self._ensure()
        self._page.goto(check_url, wait_until="domcontentloaded", timeout=30000)
        self._dismiss_consent()
        title = (self._page.title() or "")
        challenged = "just a moment" in title.lower() or bool(
            self._page.query_selector("#challenge-platform, [class*='cf-challenge']"))

        def _present(sel):
            try:
                el = self._page.query_selector(sel)
                return bool(el and el.is_visible())
            except Exception:
                return False

        if logged_in_selector:
            authed = _present(logged_in_selector)
        else:
            # Common authenticated markers vs a visible login entry point.
            authed = any(_present(s) for s in (
                "[data-testid*='user-menu']", "[href*='logout']",
                "[href*='/member/']", "[data-testid*='header--account']",
            )) and not any(_present(s) for s in (
                "[data-testid*='login']", "a[href*='/login']",
            ))
        if logged_out_selector and _present(logged_out_selector):
            authed = False

        self._audit.record("browser.session_status", url=self._page.url,
                           authenticated=authed, challenged=challenged)
        return {"url": self._page.url, "authenticated": authed,
                "cloudflare_challenge": challenged, "title": title[:160]}

    def _dismiss_consent(self) -> None:
        """Best-effort dismissal of a cookie/consent banner that would sit over
        the login form. Silent — never breaks the flow."""
        for sel in (
            "#onetrust-accept-btn-handler",
            "button[data-testid='cookie-consent-banner--accept']",
            "button:has-text('Accept all')",
            "button:has-text('Accept')",
            "button:has-text('I agree')",
        ):
            try:
                el = self._page.query_selector(sel)
                if el and el.is_visible():
                    el.click(timeout=3000)
                    self._page.wait_for_timeout(500)
                    return
            except Exception:
                continue

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
            # Persistent-context (real-Chrome) launches have no top-level
            # browser handle, so close the page's context directly; the plain
            # launch path has self._browser. Either way, then stop playwright.
            if self._page is not None:
                try:
                    self._page.context.close()
                except Exception:
                    pass
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


class BrowserLoginTool(_BrowserTool):
    name = "browser_login"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Authenticate as a test account in the live browser so you "
                    "can map and probe the AUTHENTICATED surface. The password "
                    "is read from an environment variable (never passed here or "
                    "logged); you supply the username and the env-var name. "
                    "Selectors are optional — common login-form selectors are "
                    "tried automatically. Returns ok + the landing URL. Only ever "
                    "log in as a test account you fully own; never a real member."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {
                                     "login_url": {"type": "string",
                                                   "description": "In-scope login page URL."},
                                     "username": {"type": "string",
                                                  "description": "Test-account username/email (e.g. your @bugcrowdninja.com)."},
                                     "password_env": {"type": "string",
                                                      "description": "Env var holding the password (default RED_VINTED_PASSWORD)."},
                                     "user_selector": {"type": "string",
                                                       "description": "Optional CSS selector for the username field."},
                                     "pass_selector": {"type": "string",
                                                       "description": "Optional CSS selector for the password field."},
                                     "submit_selector": {"type": "string",
                                                         "description": "Optional CSS selector for the submit button."},
                                 },
                                 "required": ["login_url", "username"]},
                "strict": False}

    def run(self, ctx, login_url: str, username: str, password_env: str = "",
            user_selector: str = "", pass_selector: str = "",
            submit_selector: str = "") -> str:
        import json

        def _do(b):
            res = b.login(login_url, username, password_env,
                          user_selector=user_selector,
                          pass_selector=pass_selector,
                          submit_selector=submit_selector)
            return json.dumps(res)
        return self._guarded(ctx, _do)


class BrowserSessionStatusTool(_BrowserTool):
    name = "browser_session_status"

    def schema(self) -> dict:
        return {"name": self.name,
                "description": (
                    "Check whether the browser session is already authenticated "
                    "(the human-warmed handoff) and whether Cloudflare is "
                    "challenging. Call this FIRST on a WAF-protected target: if "
                    "authenticated, proceed straight to authenticated recon; if a "
                    "Cloudflare challenge is shown, STOP and ask the human to warm "
                    "the session — do not hammer it."),
                "input_schema": {"type": "object", "additionalProperties": False,
                                 "properties": {
                                     "check_url": {"type": "string",
                                                   "description": "In-scope URL to check session state on."},
                                     "logged_in_selector": {"type": "string",
                                                            "description": "Optional selector only present when logged in."},
                                     "logged_out_selector": {"type": "string",
                                                             "description": "Optional selector only present when logged out."},
                                 },
                                 "required": ["check_url"]},
                "strict": False}

    def run(self, ctx, check_url: str, logged_in_selector: str = "",
            logged_out_selector: str = "") -> str:
        import json

        def _do(b):
            return json.dumps(b.session_status(
                check_url, logged_in_selector=logged_in_selector,
                logged_out_selector=logged_out_selector))
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

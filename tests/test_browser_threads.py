"""The exploit swarm calls browser tools from several worker threads; Playwright's sync
objects only work on the thread that created them. Drives a real Chromium against a local
HTTP server, so it skips when Playwright's browser isn't installed."""

from __future__ import annotations

import datetime as _dt
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from redteam.config import Engagement
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools.browser import BrowserController

pytest.importorskip("playwright.sync_api")


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()
    srv.server_close()


def _engagement(port: int) -> Engagement:
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("127.0.0.1",), excluded_hosts=(),
                      allowed_ports=(port,), allowed_schemes=("http",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=True, require_approval_for=(), raw={})


class _Audit:
    def record(self, event, **fields):
        pass


def test_browser_works_from_threads_other_than_its_creator(server, tmp_path):
    eng = _engagement(server)
    browser = BrowserController(ScopeGuard(eng), RateLimiter(100, 1000), _Audit(), tmp_path)
    try:
        try:
            browser.navigate(f"http://127.0.0.1:{server}/")   # lazily launches Chromium
        except Exception as exc:   # browser binaries not installed on this machine
            pytest.skip(f"Chromium unavailable: {exc}")
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: browser.navigate(f"http://127.0.0.1:{server}/"),
                                    range(3)))
        assert all(r["status"] == 200 for r in results)
    finally:
        browser.close()

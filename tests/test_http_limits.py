"""Bounded response reads and the server-side spend guarantee.

Both of these were real defects: an unbounded r.text let a target exhaust our memory,
and 'free models' were enforced only by filtering the catalogue client-side, so a stale
fallback entry could have silently cost money.
"""

from __future__ import annotations

import json

from redteam.config import LlmConfig
from redteam.llm.openrouter import OpenRouterClient
from redteam.tools import http as http_mod
from redteam.tools.http import MAX_RESPONSE_BYTES, TRUNCATION_MARKER, _host_request


class FakeRaw:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, n, decode_content=True):
        return self._payload[:n]


class FakeResp:
    def __init__(self, payload: bytes, status=200, encoding="utf-8"):
        self.raw, self.status_code, self.encoding, self.headers = (
            FakeRaw(payload), status, encoding, {"Content-Type": "text/html"})


def test_huge_body_is_truncated_not_buffered(monkeypatch):
    huge = b"A" * (MAX_RESPONSE_BYTES * 3)
    monkeypatch.setattr(http_mod.requests, "request", lambda *a, **k: FakeResp(huge))
    status, body, _, _ = _host_request({"url": "http://x/", "method": "GET"})
    assert status == 200
    assert body.endswith(TRUNCATION_MARKER)
    assert len(body) <= MAX_RESPONSE_BYTES + len(TRUNCATION_MARKER)


def test_small_body_is_untouched(monkeypatch):
    monkeypatch.setattr(http_mod.requests, "request", lambda *a, **k: FakeResp(b"hello"))
    _, body, _, _ = _host_request({"url": "http://x/", "method": "GET"})
    assert body == "hello" and TRUNCATION_MARKER not in body


def test_undecodable_bytes_do_not_crash(monkeypatch):
    monkeypatch.setattr(http_mod.requests, "request",
                        lambda *a, **k: FakeResp(b"\xff\xfe\x00bad"))
    _, body, _, _ = _host_request({"url": "http://x/", "method": "GET"})
    assert isinstance(body, str)          # replaced, not raised


def test_free_routing_is_enforced_on_the_wire(monkeypatch):
    """prefer_free must send provider.max_price=0 so the provider refuses paid routes."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    c = OpenRouterClient(LlmConfig(prefer_free=True))
    c.router._candidates = ["m1"]
    c.router._pools = {"cheap": [], "strong": ["m1"]}
    sent = {}

    class R:
        status_code, headers, text = 200, {}, ""
        def json(self):
            return {"choices": [{"message": {"role": "assistant", "content": "ok"},
                                 "finish_reason": "stop"}]}

    def fake_post(url, data=None, timeout=None):
        sent.update(json.loads(data))
        return R()

    monkeypatch.setattr(c._session, "post", fake_post)
    c.chat([{"role": "user", "content": "hi"}])
    assert sent["provider"]["max_price"] == {"prompt": 0, "completion": 0}


def test_paid_routing_omits_the_price_guard(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    c = OpenRouterClient(LlmConfig(prefer_free=False))
    c.router._candidates = ["m1"]
    c.router._pools = {"cheap": [], "strong": ["m1"]}
    sent = {}

    class R:
        status_code, headers, text = 200, {}, ""
        def json(self):
            return {"choices": [{"message": {"role": "assistant", "content": "ok"},
                                 "finish_reason": "stop"}]}

    monkeypatch.setattr(c._session, "post",
                        lambda url, data=None, timeout=None: (sent.update(json.loads(data)), R())[1])
    c.chat([{"role": "user", "content": "hi"}])
    assert "provider" not in sent      # opting into paid models must not be silently blocked


def test_scope_denial_is_recorded_as_evidence(tmp_path):
    """A blocked request must appear in the audit log, not only as a returned string."""
    import datetime as _dt
    from redteam.config import Engagement, SandboxConfig
    from redteam.findings import FindingStore
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard, ScopeViolation
    from redteam.tools import ToolContext
    from redteam.tools.http import fetch_once

    events = []
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example",), excluded_hosts=(),
                     allowed_ports=(443,), allowed_schemes=("https",),
                     max_requests_per_second=10.0, max_total_requests=10,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
        limiter=RateLimiter(10, 10),
        audit=type("A", (), {"record": lambda self, e, **f: events.append({"event": e, **f})})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True)

    try:
        fetch_once(ctx, {"method": "GET", "url": "https://evil.example/"})
    except ScopeViolation:
        pass
    denials = [e for e in events if e["event"] == "tool.denied"]
    assert denials and denials[0]["outcome"] == "scope-denied"
    assert "evil.example" in denials[0]["url"]

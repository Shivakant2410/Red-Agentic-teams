"""Replay fidelity + appealable not_reproducible — live-fire 20261030 regressions.

A real OpenRouter LLM run against the IDOR lab proved the bug end to end: the
agent's 4/4 differential landed as pending_verification, then
verify_finding_independently graded it false not_reproducible because the
re-check rebuilt replay requests WITHOUT resolving `session_label` (every
replayed request went out unauthenticated and 401'd). Two product defects:

1. replay fidelity: stored requests reference credentials indirectly by label;
   the re-check must resolve them exactly like the proposing tool does.
2. appealability: `not_reproducible` is a weak verdict, not a terminal one —
   the old guard refused to re-check anything not pending_verification, so an
   environmental replay failure permanently killed a real finding.
"""

from __future__ import annotations

import datetime as _dt
import json

import pytest

import redteam.tools.http as http_mod
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.independent_verify import VerifyFindingIndependentlyTool


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("api.acme.example",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path, sessions=None):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("1.2.3.4", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
        sessions=sessions,
    )


_RECORDS = {
    "record-a": {"record_id": "record-a", "tenant_id": "tenant-a", "value": "secret-a"},
    "record-b": {"record_id": "record-b", "tenant_id": "tenant-b", "value": "synthetic"},
}


@pytest.fixture
def fake_http(monkeypatch):
    """Stand-in for the wire: the lab contract, including the part that killed the
    live run — a replay without a Bearer token gets a 401, never the record."""
    seen = []

    def _fake(req):
        seen.append(dict(req))
        rec = _RECORDS.get(req["url"].rsplit("/", 1)[-1])
        if rec is None:
            return 404, json.dumps({"error": "not found"}), 0.001, {}
        auth = (req.get("headers") or {}).get("Authorization", "")
        if not auth.startswith("Bearer "):
            return 401, json.dumps({"error": "unauthorized"}), 0.001, {}
        return 200, json.dumps(rec), 0.001, {"Content-Type": "application/json"}

    monkeypatch.setattr(http_mod, "_host_request", _fake)
    return seen


def _idor_spec():
    """The exact shape the live run stored: label-based credentials, no raw tokens."""
    return {
        "requests": {
            "baseline": {"method": "GET",
                         "url": "http://api.acme.example/api/records/record-b",
                         "session_label": "user-b"},
            "payload": {"method": "GET",
                        "url": "http://api.acme.example/api/records/record-a",
                        "session_label": "user-b"},
        },
        "conditions": [
            {"type": "status", "request": "payload", "equals": 200},
            {"type": "json_differs", "request_a": "baseline", "request_b": "payload",
             "json_path": "tenant_id"},
        ],
        "negative_control": {"method": "GET",
                             "url": "http://api.acme.example/api/records/record-b",
                             "session_label": "user-b"},
        "control_replaces": "payload",
    }


def _finding(store: FindingStore, confidence: str) -> Finding:
    f = Finding(title="Cross-tenant IDOR on /api/records/{record_id}", severity="high",
                target="api.acme.example", summary="cross-tenant read as tenant-b",
                check_type="proof", check_spec=_idor_spec(), confidence=confidence)
    return store.add(f)


def test_recheck_proof_resolves_session_label(tmp_path, fake_http):
    """The headline regression: a credential-gated proof must replay WITH its
    session, or the verifier manufactures a false negative."""
    ctx = _ctx(tmp_path, sessions=SessionStore())
    ctx.sessions.set("user-b", {"Authorization": "Bearer lab-token-b"})
    f = _finding(ctx.findings, "pending_verification")

    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)

    assert '"verdict": "confirmed"' in out, out
    assert ctx.findings.get(f.id).confidence == "confirmed"
    assert fake_http, "replay never hit the wire"
    for req in fake_http:
        assert (req.get("headers") or {}).get("Authorization") == "Bearer lab-token-b", \
            f"unauthenticated replay observed: {req}"


def test_replay_without_session_reports_honestly(tmp_path, fake_http):
    """If the label cannot be resolved, the replay fails on the wire and the
    verdict says so — no crash, no invented confirmation."""
    ctx = _ctx(tmp_path, sessions=SessionStore())   # store has NO 'user-b'
    f = _finding(ctx.findings, "pending_verification")

    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)

    assert '"verdict": "not_reproducible"' in out, out
    assert ctx.findings.get(f.id).confidence == "not_reproducible"


def test_not_reproducible_can_be_rechecked(tmp_path, fake_http):
    """The appeal path: a weak verdict must not be a death sentence. After the
    environment recovers (session material restored), the same finding confirms."""
    ctx = _ctx(tmp_path, sessions=SessionStore())
    ctx.sessions.set("user-b", {"Authorization": "Bearer lab-token-b"})
    f = _finding(ctx.findings, "not_reproducible")   # killed by the old bug

    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)

    assert '"already"' not in out, out
    assert '"verdict": "confirmed"' in out, out
    assert ctx.findings.get(f.id).confidence == "confirmed"


@pytest.mark.parametrize("terminal", ["confirmed", "falsified"])
def test_terminal_verdicts_stay_final(tmp_path, fake_http, terminal):
    """Only weak verdicts are appealable — real verdicts must not be re-litigated
    into something they are not."""
    ctx = _ctx(tmp_path, sessions=SessionStore())
    ctx.sessions.set("user-b", {"Authorization": "Bearer lab-token-b"})
    f = _finding(ctx.findings, terminal)

    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)

    assert '"already"' in out and terminal in out, out
    assert fake_http == [], "no replay may run against a terminal verdict"

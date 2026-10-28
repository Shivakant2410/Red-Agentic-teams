"""Tests for post-exploitation: secret harvesting, credential use, privilege proof."""

from __future__ import annotations

import base64
import datetime as _dt
import json

from redteam.access import AccessGraph, PRINCIPAL
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.killchain import ACHIEVED, PRIVILEGE_ESCALATION, KillChain
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.secrets import decode_jwt, extract_candidates, shannon_entropy
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools import postex as px
from redteam.tools.postex import ProvePrivilegeTool, TryCredentialTool

R = lambda status, body, elapsed=0.1, headers=None: (status, body, elapsed, headers or {})


def _jwt(payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256'})}.{enc(payload)}.sig"


# --- harvesting -----------------------------------------------------------

def test_jwt_is_decoded_and_claims_surfaced():
    token = _jwt({"sub": "42", "role": "customer", "email": "a@b.c"})
    cands = extract_candidates(f"token={token}")
    jwt = next(c for c in cands if c.kind == "jwt")
    assert jwt.claims["role"] == "customer" and jwt.confidence == "high"


def test_decode_jwt_rejects_garbage():
    assert decode_jwt("not.a.jwt") is None
    assert decode_jwt("onlyonepart") is None


def test_keyvalue_and_connection_string_detected():
    text = 'api_key: "AbCdEf123456789" \n DB=postgres://user:pw@10.0.0.9:5432/prod'
    kinds = {c.kind for c in extract_candidates(text)}
    assert "keyvalue" in kinds and "connection_string" in kinds


def test_preview_masks_the_secret():
    c = extract_candidates('password="SuperSecretValue123"')[0]
    assert "SuperSecret" not in c.preview and "len" in c.preview


def test_entropy_distinguishes_random_from_prose():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("kJ8x2Qv9Zr4Lm7Wp1Tf6") > 3.5


def test_no_candidates_in_plain_prose():
    assert extract_candidates("Welcome to the shop. Today we have apples and pears.") == []


# --- tools ----------------------------------------------------------------

def _ctx(tmp_path):
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today() - _dt.timedelta(days=1),
                     ends=_dt.date.today() + _dt.timedelta(days=1),
                     allowed_hosts=("api.acme.example", "203.0.113.0/28"), excluded_hosts=(),
                     allowed_ports=(80, 443), allowed_schemes=("http", "https"),
                     max_requests_per_second=100.0, max_total_requests=1000,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    return ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        sessions=SessionStore(), access=AccessGraph(tmp_path / "a.json"),
        killchain=KillChain(tmp_path / "k.json"))


def test_credential_only_held_when_it_authenticates(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(px, "fetch_once", lambda c, req: R(401, "Unauthorized"))
    out = TryCredentialTool().run(ctx, value="deadbeef",
                                  probe_url="https://api.acme.example/me",
                                  session_label="cand", success_regex="admin")
    assert '"authenticated": false' in out.lower()
    assert ctx.sessions.get("cand") is None          # nothing stored on failure
    assert ctx.access.summary()["held"] == 0         # nothing claimed as held


def test_working_credential_is_stored_as_session(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(px, "fetch_once", lambda c, req: R(200, '{"role":"admin"}'))
    out = TryCredentialTool().run(ctx, value="goodtoken",
                                  probe_url="https://api.acme.example/me",
                                  session_label="adminsess", success_regex="admin",
                                  principal="admin")
    assert '"authenticated": true' in out.lower()
    assert ctx.sessions.get("adminsess") is not None


def test_privilege_proof_requires_control_to_fail(tmp_path, monkeypatch):
    """If the low-priv identity can do it too, that's NOT escalation."""
    ctx = _ctx(tmp_path)
    ctx.sessions.set("high", {"Authorization": "Bearer hi"})
    ctx.sessions.set("low", {"Authorization": "Bearer lo"})
    # both identities see the admin panel -> no boundary crossed
    monkeypatch.setattr(px, "make_fetch", lambda c, req: (lambda: R(200, "admin panel")))
    out = ProvePrivilegeTool().run(ctx, privileged_url="https://api.acme.example/admin",
                                   high_session_label="high", low_session_label="low",
                                   privileged_marker="admin panel", to_principal="admin")
    assert '"escalated": false' in out.lower() and "falsified" in out.lower()
    assert ctx.findings.all() == []


def test_privilege_proof_pending_until_independently_verified(tmp_path, monkeypatch):
    """PHASE 1: prove_privilege's own (real, k-of-n + control) proof still only reaches
    pending_verification — it is self-administered by the proposing context. The access
    graph / kill chain are only written once verify_finding_independently reproduces it
    in a FRESH context. This is the run-13 fix applied consistently, not just to labels."""
    ctx = _ctx(tmp_path)
    ctx.sessions.set("high", {"Authorization": "Bearer hi"})
    ctx.sessions.set("low", {"Authorization": "Bearer lo"})

    def fake_make_fetch(c, req):
        elevated = req["headers"].get("Authorization") == "Bearer hi"
        return (lambda: R(200, "admin panel")) if elevated else (lambda: R(403, "Forbidden"))
    monkeypatch.setattr(px, "make_fetch", fake_make_fetch)

    out = ProvePrivilegeTool().run(ctx, privileged_url="https://api.acme.example/admin",
                                   high_session_label="high", low_session_label="low",
                                   privileged_marker="admin panel",
                                   from_principal="customer", to_principal="admin")
    assert '"escalated_pending": true' in out.lower()
    f = ctx.findings.all()[0]
    assert f.cwe == "CWE-269" and f.confidence == "pending_verification"
    assert f.check_type == "privilege"
    # Not yet credited — independent verification hasn't run.
    assert not ctx.access.reached("admin")
    assert ctx.killchain.status(PRIVILEGE_ESCALATION) != ACHIEVED

    # Independent re-check, same sessions still available (same process) but a SEPARATE
    # tool/context — this is the only path allowed to promote and credit it. It imports
    # make_fetch into its own module namespace, so patch it there too.
    import redteam.tools.independent_verify as iv
    monkeypatch.setattr(iv, "make_fetch", fake_make_fetch)
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool
    verdict = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)
    assert '"verdict": "confirmed"' in verdict
    assert ctx.findings.get(f.id).confidence == "confirmed"
    assert ctx.access.reached("admin")                          # principal now held
    assert ctx.killchain.status(PRIVILEGE_ESCALATION) == ACHIEVED
    assert ctx.access.distance_to("admin") == 0

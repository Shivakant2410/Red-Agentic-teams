"""Adversarial tests for the five live-fire capability gaps.

Each test class maps 1:1 to a gap found while running the platform against a real
LLM backend under fault injection:

1. http_probe      — the agent burned confirm_finding verification budget to LOOK
                     around; exploration and proof now have separate tools, and the
                     tests check the probe never touches the finding pipeline.
2. set_session     — there was no way to register operator-handed static tokens, so
                     the agent invented logins; tests check real headers land in the
                     session store and NEVER echo back into the transcript.
3. agent dispatch  — a hallucinated tool name used to burn steps; now the error
                     itself teaches the model the real tool list.
4. creditor        — a fully-confirmed IDOR sat uncollected because the final
                     record_access linkage lived in the model's head; the sweep must
                     be deterministic, gated, and idempotent.
5. scope guard     — a scope that included the control plane's own port let the
                     agent legally attack its own console; the run must refuse to arm.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import json
import threading
from pathlib import Path

import pytest

from redteam.access import AccessGraph
from redteam.agent import RedTeamAgent
from redteam.config import ConfigError, Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.killchain import KillChain
from redteam.objective import Objective, SuccessCriterion
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard, check_control_plane_overlap
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.authsession import SetSessionTool
from redteam.tools.probe import HttpProbeTool
from redteam.credit import credit_confirmed_findings


def _engagement(allowed_hosts=("api.acme.example",), allowed_ports=(80, 443),
                allow_private=False):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=allowed_hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("http", "https"),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=allow_private, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, *a, **k):
        self.events.append({"event": a[0] if a else "", **k})


class _Bus:
    def __init__(self):
        self.emitted = []

    def emit(self, etype, **fields):
        self.emitted.append((etype, fields))


_RESOLVER = lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]


def _ctx(tmp_path, eng=None, **extra):
    eng = eng or _engagement()
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=_RESOLVER), limiter=RateLimiter(1000, 100000),
        audit=_Audit(), findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, sessions=SessionStore(),
        access=AccessGraph(tmp_path / "access.json"), killchain=KillChain(tmp_path / "kc.json"),
        **extra,
    )
    return ctx


# ---------------------------------------------------------------------------
# A live HTTP target for the probe's real-request tests. Binds 127.0.0.1 with
# allow_private_ranges=True so the scope guard admits it — same shape as the lab.
# ---------------------------------------------------------------------------

class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        body = json.dumps({"ok": True, "path": self.path,
                           "auth": self.headers.get("Authorization"),
                           "cookie": self.headers.get("Cookie")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "sid=supersecretvalue; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def echo_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _lab_ctx(tmp_path, port):
    eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(port,),
                      allow_private=True)
    return _ctx(tmp_path, eng=eng)


# -- 1. http_probe --------------------------------------------------------------

class TestHttpProbe:
    def test_probe_returns_response_but_records_no_finding(self, tmp_path, echo_server):
        port = echo_server.rsplit(":", 1)[1]
        ctx = _lab_ctx(tmp_path, int(port))
        out = HttpProbeTool().run(ctx, url=echo_server + "/api/records/42")
        r = json.loads(out)
        assert r["status"] == 200
        assert '"path": "/api/records/42"' in r["body_preview"]
        # The whole point: exploration must never pollute the finding pipeline.
        assert ctx.findings.all() == []

    def test_probe_carries_session_headers(self, tmp_path, echo_server):
        port = int(echo_server.rsplit(":", 1)[1])
        ctx = _lab_ctx(tmp_path, port)
        ctx.sessions.set("userA", {"Authorization": "Bearer TOK7"})
        out = HttpProbeTool().run(ctx, url=echo_server + "/api/me", as_session="userA")
        r = json.loads(out)
        assert r["status"] == 200
        assert "TOK7" in r["body_preview"]   # the target SAW the session identity

    def test_probe_unknown_session_fails_with_known_labels(self, tmp_path, echo_server):
        port = int(echo_server.rsplit(":", 1)[1])
        ctx = _lab_ctx(tmp_path, port)
        ctx.sessions.set("admin", {"Authorization": "Bearer X"})
        out = HttpProbeTool().run(ctx, url=echo_server + "/", as_session="nope")
        assert "nope" in out and "admin" in out   # teaches the model what exists

    def test_probe_scope_violation_is_blocked_and_audited(self, tmp_path, echo_server):
        port = int(echo_server.rsplit(":", 1)[1])
        ctx = _lab_ctx(tmp_path, port)
        before = len(ctx.audit.events)
        out = HttpProbeTool().run(ctx, url="http://evil.example.com/steal")
        assert "BLOCKED" in out
        assert any(e.get("outcome") == "scope-denied" for e in ctx.audit.events[before:])
        assert ctx.findings.all() == []

    def test_probe_masks_secret_response_headers(self, tmp_path, echo_server):
        """The response's Set-Cookie value must never reach the model transcript —
        the target may be rotating a session the operator's RoE told us to hold."""
        port = int(echo_server.rsplit(":", 1)[1])
        ctx = _lab_ctx(tmp_path, port)
        out = HttpProbeTool().run(ctx, url=echo_server + "/login")
        assert "supersecretvalue" not in out
        assert "Set-Cookie" in out          # name visible
        assert "withheld" in out            # value masked

    def test_probe_exhausted_request_budget_is_honest(self, tmp_path):
        eng = _engagement()
        ctx = ToolContext(
            scope=ScopeGuard(eng, resolver=_RESOLVER), limiter=RateLimiter(1000, 0),
            audit=_Audit(), findings=FindingStore(tmp_path / "f.json"),
            approve=lambda a, d: True, sessions=SessionStore(),
            access=AccessGraph(tmp_path / "a.json"), killchain=KillChain(tmp_path / "k.json"),
        )
        out = HttpProbeTool().run(ctx, url="https://api.acme.example/x")
        assert "BLOCKED" in out and "budget" in out.lower()
        assert ctx.findings.all() == []

    def test_probe_bad_method_rejected(self, tmp_path):
        ctx = _ctx(tmp_path)
        out = HttpProbeTool().run(ctx, url="https://api.acme.example/", method="TRACE")
        assert "ERROR" in out and "TRACE" in out


# -- 2. set_session -------------------------------------------------------------

class TestSetSession:
    def test_registers_operator_token_as_session(self, tmp_path):
        ctx = _ctx(tmp_path)
        out = SetSessionTool().run(ctx, label="userA",
                                   headers={"Authorization": "Bearer eyJhbGci.abc.def"})
        r = json.loads(out)
        assert r["ok"] is True
        # Value must NOT echo back into the transcript.
        assert "eyJhbGci" not in out
        assert ctx.sessions.get("userA").headers["Authorization"] == "Bearer eyJhbGci.abc.def"

    def test_session_is_usable_by_probe(self, tmp_path, echo_server):
        port = int(echo_server.rsplit(":", 1)[1])
        ctx = _lab_ctx(tmp_path, port)
        SetSessionTool().run(ctx, label="op", headers={"Cookie": "sid=op-session-9"})
        out = HttpProbeTool().run(ctx, url=echo_server + "/api/me", as_session="op")
        assert "op-session-9" in json.loads(out)["body_preview"]

    def test_foothold_recorded_as_operator_token(self, tmp_path):
        ctx = _ctx(tmp_path)
        SetSessionTool().run(ctx, label="userA", headers={"Authorization": "Bearer t"},
                             note="RoE pack token")
        held = {n.key: n for n in ctx.access.held()}
        assert "session:userA" in held
        # Honestly sourced: operator material is not a proving mechanism.
        assert held["session:userA"].source == "operator_token"
        assert ctx.killchain.achieved()  # INITIAL_ACCESS armed for the ACCESS loop

    def test_rejects_non_auth_headers(self, tmp_path):
        ctx = _ctx(tmp_path)
        out = SetSessionTool().run(ctx, label="x", headers={"Accept": "text/html"})
        assert "ERROR" in out and "Authorization" in out
        assert ctx.sessions.labels() == []

    def test_rejects_empty_and_nonstring_values(self, tmp_path):
        ctx = _ctx(tmp_path)
        assert "ERROR" in SetSessionTool().run(ctx, label="x", headers={})
        assert "ERROR" in SetSessionTool().run(ctx, label="x",
                                               headers={"Authorization": "   "})
        assert "ERROR" in SetSessionTool().run(ctx, label="", headers={"Cookie": "a=b"})

    def test_operator_token_alone_cannot_credit_objective(self, tmp_path):
        """The REQUIRED_SOURCE gate must hold: operator-supplied access is a foothold,
        never proof. Only verified findings / prove_privilege / try_credential credit."""
        obj = Objective(name="t", criteria=[
            SuccessCriterion(id="c1", kind="data_access", description="read PII",
                             target="records"),
        ])
        ctx = _ctx(tmp_path, )
        ctx.objective = obj
        SetSessionTool().run(ctx, label="userA", headers={"Authorization": "Bearer t"})
        assert obj.outstanding() and obj.autoevaluate(ctx.access) == []
        assert not obj.achieved


# -- 3. unknown-tool dispatch recovery ------------------------------------------

class TestUnknownToolRecovery:
    def _agent(self, tmp_path, ctx):
        eng = _engagement()
        # Minimal stub client: the dispatch path never calls the LLM.
        client = type("C", (), {})()
        return RedTeamAgent(eng, {"http_probe": HttpProbeTool()}, ctx, client,
                            max_steps=1, agent_name="test")

    def test_unknown_tool_error_lists_available_tools(self, tmp_path):
        ctx = _ctx(tmp_path)
        agent = self._agent(tmp_path, ctx)
        out = agent._dispatch("recheck_finding", {})
        assert "unknown tool" in out
        assert "http_probe" in out          # the REAL names are taught, not guessed
        assert any(e.get("event") == "agent.unknown_tool" for e in ctx.audit.events)

    def test_no_tools_context_reports_honestly(self, tmp_path):
        ctx = _ctx(tmp_path)
        eng = _engagement()
        client = type("C", (), {})()
        agent = RedTeamAgent(eng, {}, ctx, client, max_steps=1, agent_name="test")
        out = agent._dispatch("anything", {})
        assert "(no tools" in out


# -- 4. creditor ----------------------------------------------------------------

def _confirmed(target: str, fid: str = "f1") -> Finding:
    f = Finding(title="Cross-tenant IDOR", severity="high", target=target,
                summary="s", cwe="CWE-639")
    f.id = fid
    f.confidence = "confirmed"
    return f


class TestCreditor:
    def _store(self, tmp_path, findings):
        store = FindingStore(tmp_path / "f.json")
        for f in findings:
            store._findings.append(f)
        return store

    def _objective_ctx(self, tmp_path, criteria, findings):
        obj = Objective(name="t", criteria=criteria)
        ctx = _ctx(tmp_path)
        ctx.findings = self._store(tmp_path, findings)
        ctx.objective = obj
        ctx.events = _Bus()
        return ctx, obj

    def test_confirmed_finding_credits_data_access(self, tmp_path):
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="c1", kind="data_access", description="read records",
                             target="records"),
        ], [_confirmed("http://api.acme.example/api/records/42")])
        applied = credit_confirmed_findings(ctx)
        assert [a["criterion"] for a in applied] == ["c1"]
        assert obj.achieved
        assert "f1" in obj.get("c1").evidence
        held = {n.key: n for n in ctx.access.held()}
        assert "records" in held and held["records"].source == "verified_finding"
        assert any(e == "credit.applied" and f.get("criterion") == "c1"
                   for e, f in ctx.events.emitted)

    def test_pending_findings_are_invisible_to_creditor(self, tmp_path):
        f = _confirmed("records")
        f.confidence = "pending_verification"
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="c1", kind="data_access", description="d", target="records"),
        ], [f])
        assert credit_confirmed_findings(ctx) == []
        assert not obj.achieved

    def test_privilege_kind_never_credits_from_findings(self, tmp_path):
        """REQUIRED_SOURCE stays intact: a confirmed finding that an admin endpoint
        exists is NOT proof the privilege boundary moved."""
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="p1", kind="privilege", description="become admin",
                             target="admin"),
        ], [_confirmed("http://api.acme.example/admin")])
        assert credit_confirmed_findings(ctx) == []
        assert not obj.achieved
        # And no misleading hold was created either.
        assert not any(n.key == "admin" for n in ctx.access.held())

    def test_idempotent_no_duplicate_credit(self, tmp_path):
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="c1", kind="data_access", description="d", target="records"),
        ], [_confirmed("records")])
        first = credit_confirmed_findings(ctx)
        second = credit_confirmed_findings(ctx)
        assert first and second == []
        assert len([e for e, _ in ctx.events.emitted if e == "credit.applied"]) == 1
        assert obj.achieved

    def test_already_held_target_still_gets_credited(self, tmp_path):
        """record_access got there first with a verified_finding hold, but the model
        never claimed the criterion — the creditor still closes the loop."""
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="c1", kind="data_access", description="d", target="records"),
        ], [_confirmed("records")])
        ctx.access.hold("resource", "records", evidence="via record_access",
                        source="verified_finding")
        applied = credit_confirmed_findings(ctx)
        assert [a["criterion"] for a in applied] == ["c1"]
        assert obj.achieved

    def test_flag_kind_credits(self, tmp_path):
        ctx, obj = self._objective_ctx(tmp_path, [
            SuccessCriterion(id="fl", kind="flag", description="capture token",
                             target="FLAG{admin-token-9}"),
        ], [_confirmed("FLAG{admin-token-9}")])
        assert credit_confirmed_findings(ctx)
        assert obj.achieved


# -- 5. control-plane self-targeting guard ---------------------------------------

class TestControlPlaneGuard:
    def _eng_localhost(self, ports):
        return _engagement(allowed_hosts=("localhost", "127.0.0.1"), allowed_ports=ports)

    def test_port_collision_with_loopback_bind_raises(self):
        with pytest.raises(ConfigError) as exc:
            check_control_plane_overlap(self._eng_localhost((8000, 443)), "127.0.0.1", 8000)
        assert "self-targeting" in str(exc.value)
        assert "8000" in str(exc.value)   # actionable: names the port to remove

    def test_wildcard_bind_with_any_port_collision_raises(self):
        with pytest.raises(ConfigError):
            check_control_plane_overlap(self._eng_localhost((80, 443)), "0.0.0.0", 443)

    def test_distinct_port_is_clean(self):
        check_control_plane_overlap(self._eng_localhost((80, 443)), "127.0.0.1", 8000)

    def test_loopback_alias_collision_localhost_scope_bind_ip(self):
        """Scope allows ONLY 'localhost'; the control plane binds 127.0.0.1. Name
        matching alone would call that clean — but localhost resolves to 127.0.0.1,
        so an agent authorized for localhost:8000 reaches the control plane."""
        eng = _engagement(allowed_hosts=("localhost",), allowed_ports=(8000,))
        with pytest.raises(ConfigError):
            check_control_plane_overlap(eng, "127.0.0.1", 8000)

    def test_loopback_alias_collision_ip_scope_bind_localhost(self):
        eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(8000,))
        with pytest.raises(ConfigError):
            check_control_plane_overlap(eng, "localhost", 8000)

    def test_port_in_scope_but_host_not_allowed_is_clean(self):
        eng = _engagement(allowed_hosts=("api.acme.example",), allowed_ports=(8000,))
        check_control_plane_overlap(eng, "127.0.0.1", 8000)

    def test_host_allowed_but_port_distinct_is_clean(self):
        check_control_plane_overlap(self._eng_localhost((80,)), "127.0.0.1", 8000)

    def test_wildcard_allowlist_always_collides(self):
        eng = _engagement(allowed_hosts=("*",), allowed_ports=(80,))
        with pytest.raises(ConfigError):
            check_control_plane_overlap(eng, "127.0.0.1", 80)

    def test_execute_run_refuses_to_arm(self, tmp_path, monkeypatch):
        """End-to-end: execute_run with control_plane set must abort before any
        machinery starts (no audit log, no findings file)."""
        import redteam.run as run_mod
        eng_path = tmp_path / "eng.yaml"
        eng_path.write_text(
            "name: selftarget\nclient: c\nauthorized_by: a\nticket: t\n"
            f"starts: {_dt.date.today() - _dt.timedelta(days=1)}\n"
            f"ends: {_dt.date.today() + _dt.timedelta(days=1)}\n"
            "scope:\n  allowed_hosts: [localhost]\n  allowed_ports: [8000]\n")
        opts = run_mod.RunOptions(
            engagement_path=str(eng_path), objective="o", out_dir=tmp_path / "out",
            control_plane=("127.0.0.1", 8000), quiet=True)
        with pytest.raises(ConfigError):
            run_mod.execute_run(opts)
        assert not (tmp_path / "out" / "audit.log.jsonl").exists()


class TestCreditorFunnelRegression:
    """Live-fire regression (run 20261022-1239): single-agent mode lets the model
    verify its own findings MID-RUN, so the post-run verify pass finds nothing
    pending and early-returns — which used to skip the creditor entirely. The
    exact scenario that left the objective uncollected must now credit."""

    def test_run_verify_pass_credits_even_when_nothing_pending(self, tmp_path, monkeypatch):
        import redteam.orchestrator as orch_mod
        eng = _engagement()
        ctx = _ctx(tmp_path)
        ctx.objective = Objective(name="t", criteria=[
            SuccessCriterion(id="c1", kind="data_access", description="d", target="records")])
        ctx.findings._findings.append(_confirmed("records"))
        # No LLM calls may happen: the verify pass must short-circuit into the creditor.
        monkeypatch.setattr(orch_mod.RedTeamAgent, "run",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("verify agent must not run when nothing is pending")))
        remaining = orch_mod.run_verify_pass(eng, {}, ctx, client=type("C", (), {}),
                                             objective="o")
        assert remaining == 0
        assert ctx.objective.achieved
        assert any(e.get("event") == "credit.applied" for e in ctx.audit.events)

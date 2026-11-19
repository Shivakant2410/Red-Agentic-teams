"""G1 (Builder 04 baseline): `record_finding` accepted `confidence="confirmed"`
from the model and stored it verbatim — a self-confirmation bypass of the
FindingStore authority, because `credit_confirmed_findings` acts on
`confidence == "confirmed"` without checking the independent verdict. The tool
now offers only tentative|firm, downgrades anything else to firm, and audits
the attempt. Only the independent verifier may confirm (FindingStore.promote /
verify_finding_independently)."""

from __future__ import annotations

import datetime as _dt

import pytest

from redteam.access import AccessGraph
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.credit import credit_confirmed_findings
from redteam.findings import FindingStore
from redteam.killchain import KillChain
from redteam.objective import Objective, SuccessCriterion
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.workflow import RecordFindingTool

_RESOLVER = lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]  # noqa: E731


class _Audit:
    def __init__(self):
        self.records = []

    def record(self, event, **fields):
        self.records.append((event, fields))


class _Bus:
    def __init__(self):
        self.emitted = []

    def emit(self, etype, **fields):
        self.emitted.append((etype, fields))


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


def _ctx(tmp_path):
    ctx = ToolContext(
        scope=ScopeGuard(_engagement(), resolver=_RESOLVER),
        limiter=RateLimiter(1000, 100000), audit=_Audit(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True, sessions=SessionStore(),
        access=AccessGraph(tmp_path / "access.json"),
        killchain=KillChain(tmp_path / "kc.json"))
    ctx.events = _Bus()
    return ctx


def test_schema_offers_no_self_confirmation():
    props = RecordFindingTool().schema()["input_schema"]["properties"]
    assert "confirmed" not in props["confidence"]["enum"]
    assert set(props["confidence"]["enum"]) == {"tentative", "firm"}


def test_confirmed_claim_downgraded_and_audited(tmp_path):
    ctx = _ctx(tmp_path)
    out = RecordFindingTool().run(
        ctx, title="Cross-tenant note read", severity="high",
        target="http://api.acme.example/api/notes/n-1001",
        summary="bob read alice's note", evidence="GET 200 marker",
        cwe="CWE-639", confidence="confirmed")
    assert "Recorded finding" in out
    stored = ctx.findings.all()[0]
    assert stored.confidence == "firm"
    downgrades = [r for r in ctx.audit.records
                  if r[0] == "finding.self_confirm_downgraded"]
    assert downgrades and downgrades[0][1]["requested"] == "confirmed"
    assert any(e[0] == "finding.self_confirm_downgraded" for e in ctx.events.emitted)


def test_firm_findings_cannot_credit_objective(tmp_path):
    ctx = _ctx(tmp_path)
    obj = Objective(name="t", criteria=[
        SuccessCriterion(id="c1", kind="data_access", description="read records",
                         target="records")])
    ctx.objective = obj
    RecordFindingTool().run(
        ctx, title="Records read", severity="high",
        target="http://api.acme.example/api/records/42",
        summary="read", evidence="...", confidence="firm")
    applied = credit_confirmed_findings(ctx)
    assert applied == []
    assert not obj.achieved

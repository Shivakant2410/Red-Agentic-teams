"""record_finding -> confirm_finding merge must upgrade verification state.

Terminal bench (glm-4-plus, real model): the agent recorded its vault flag-read
via record_finding (confidence "firm", no replay material), then PROVED the same
bug with confirm_finding (pending_verification, check_spec attached). The merge
kept "firm" — verify_finding_independently refused it ("already: firm"),
claim_objective refused it ("must survive verify_finding_independently"), and a
fully-solved objective dead-ended. The merge now adopts the stronger state plus
its replay material, so the normal record -> prove -> independently-verify
pipeline works regardless of the order the agent discovered the tools in.
"""

from __future__ import annotations

import datetime as _dt
import re

import pytest

import redteam.tools.http as http_mod
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.confirm import ConfirmFindingTool
from redteam.tools.independent_verify import VerifyFindingIndependentlyTool
from redteam.tools.workflow import RecordFindingTool


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(),
        allowed_ports=(80, 443, 8899), allowed_schemes=("http",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=True, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("127.0.0.1", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
        sessions=SessionStore(),
    )


@pytest.fixture
def vault_http(monkeypatch):
    """The terminal bench's shape: /flag serves FLAG{...} to the right bearer.
    Two seams, two contracts: tools/http._host_request returns the 4-tuple itself
    (called inside make_fetch's closure); confirm._host_fetch RETURNS a closure."""
    def verdict(req):
        auth = (req.get("headers") or {}).get("Authorization", "")
        if auth == "Bearer tok-vault-9f2c":
            return 200, "FLAG{7d3a91c4}\n"
        return 401, "invalid or expired deploy token\n"

    def fake_host_request(req):                    # tools/http contract
        status, body = verdict(req)
        return status, body, 0.001, {"Content-Type": "text/plain"}

    def fake_host_fetch(req):                      # confirm.py contract
        status, body = verdict(req)
        def fetch():
            return status, body, 0.001
        return fetch

    monkeypatch.setattr(http_mod, "_host_request", fake_host_request)
    import redteam.tools.confirm as confirm_mod
    monkeypatch.setattr(confirm_mod, "_host_fetch", fake_host_fetch)


def test_merge_upgrades_firm_to_pending_with_replay_material(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    weak = store.add(Finding(title="Vault flag access", severity="high",
                             target="http://127.0.0.1:8899/flag",
                             summary="flag read with recovered credential",
                             confidence="firm"))
    strong = store.add(Finding(title="Vault flag access", severity="high",
                               target="http://127.0.0.1:8899/flag",
                               summary="flag read with recovered credential",
                               confidence="pending_verification",
                               check_type="proof",
                               check_spec={"requests": {"payload": {"url": "http://127.0.0.1:8899/flag"}},
                                           "conditions": [{"type": "body_regex",
                                                           "request": "payload",
                                                           "pattern": "FLAG"}]}))
    assert strong.id == weak.id, "dedupe must merge, not duplicate"
    got = store.get(weak.id)
    assert got.confidence == "pending_verification"
    assert got.check_type == "proof" and got.check_spec


def test_merge_never_downgrades_or_resurrects_terminal_states(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    confirmed = store.add(Finding(title="T", severity="high", target="http://x/1",
                                  summary="", confidence="confirmed"))
    store.add(Finding(title="T2", severity="high", target="http://x/1", summary="",
                      confidence="pending_verification"))
    assert store.get(confirmed.id).confidence == "confirmed"
    falsified = store.add(Finding(title="T3", severity="high", target="http://x/2",
                                  summary="", confidence="falsified"))
    store.add(Finding(title="T3", severity="high", target="http://x/2", summary="",
                      confidence="pending_verification"))
    assert store.get(falsified.id).confidence == "falsified"


def test_terminal_bench_sequence_end_to_end(tmp_path, vault_http):
    """The exact dead-ended sequence: record (firm) -> prove -> independently
    verify -> confirmed, so claim_objective can accept it."""
    ctx = _ctx(tmp_path)
    out = RecordFindingTool().run(
        ctx, title="Vault flag access", severity="high",
        target="http://127.0.0.1:8899/flag",
        summary="flag read with the credential recovered via local_exec",
        evidence="GET /flag with Bearer tok-vault-9f2c -> FLAG{7d3a91c4}",
        confidence="firm")
    m = re.search(r"[0-9a-f]{12}", out)
    assert m, f"record_finding returned no id: {out[:120]}"
    fid = m.group(0)
    assert ctx.findings.get(fid).confidence == "firm"

    # The agent proves the same bug with a real k-of-n check.
    proof = ConfirmFindingTool().run(
        ctx, title="Vault flag access", severity="high",
        target="http://127.0.0.1:8899/flag",
        summary="flag read with the credential recovered via local_exec",
        check_type="http",
        request={"method": "GET", "url": "http://127.0.0.1:8899/flag",
                 "headers": {"Authorization": "Bearer tok-vault-9f2c"}},
        body_regex="FLAG\\{[a-f0-9]{8}\\}")
    assert '"verdict": "pending_verification"' in proof, proof
    assert ctx.findings.get(fid).confidence == "pending_verification", \
        "the proof merge must upgrade the firm record in place"

    # Independent re-check now runs and confirms.
    out2 = VerifyFindingIndependentlyTool().run(ctx, finding_id=fid)
    assert '"verdict": "confirmed"' in out2, out2
    assert ctx.findings.get(fid).confidence == "confirmed"

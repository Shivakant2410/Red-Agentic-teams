"""The three fixes from the first live swarm run (runs/bench-swarm-1): one bug recorded 8
times, verification deferred to the end of the round, and IDOR "confirmations" that ran
no negative control at all."""

from __future__ import annotations

import json

from redteam.findings import Finding, FindingStore, normalize_cwe
from redteam.tools import independent_verify as iv

from test_orchestrator import RecordingAudit, _ctx

IDOR_URL = "http://172.18.0.2:8080/api/records/record-b"
ALICE = {"Authorization": "Bearer lab-token-a"}


def _http(title, cwe="", url=IDOR_URL, headers=ALICE, regex="tenant-b", status=200):
    return Finding(title=title, severity="high", target=url, summary="s", cwe=cwe,
                   confidence="pending_verification", check_type="http",
                   check_spec={"request": {"method": "GET", "url": url, "headers": dict(headers)},
                               "expect_status": status, "body_regex": regex})


# --- dedup -------------------------------------------------------------------------------

def test_cwe_spellings_normalize():
    assert normalize_cwe("CWE-639 Authorization Bypass Through User-Controlled Key") == "CWE-639"
    assert normalize_cwe("(cwe 639)") == "CWE-639"
    assert normalize_cwe("") == ""


def test_same_request_and_identity_is_one_finding_however_it_is_titled(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    first = store.add(_http("Cross-tenant record read (IDOR)"))
    again = store.add(_http("Broken access control - tenant-a reads tenant-b", cwe="CWE-639 (IDOR)"))
    assert again.id == first.id and len(store.all()) == 1
    assert first.duplicate_hits == 1 and first.cwe == "CWE-639"


def test_a_different_identity_is_a_different_observation(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    store.add(_http("IDOR as alice"))
    store.add(_http("IDOR as bob", headers={"Authorization": "Bearer lab-token-b"}))
    assert len(store.all()) == 2


def test_events_are_per_thread(tmp_path):
    import threading
    store = FindingStore(tmp_path / "f.json")
    store.add(_http("mine"))
    other = []
    t = threading.Thread(target=lambda: other.extend(store.pop_events()))
    t.start(); t.join()
    assert other == []
    assert [k for k, _ in store.pop_events()] == ["added"]
    assert store.pop_events() == []


# --- credential-stripped control ---------------------------------------------------------

def _fake_fetch(responses):
    """make_fetch stand-in: (status, body) chosen by whether the request carries creds."""
    def make_fetch(ctx, req):
        authed = any(k.lower() == "authorization" for k in (req.get("headers") or {}))
        status, body = responses[authed]
        return lambda: (status, body, 0.01)
    return make_fetch


def _recheck(monkeypatch, tmp_path, finding, responses):
    monkeypatch.setattr(iv, "make_fetch", _fake_fetch(responses))
    ctx = _ctx(tmp_path, RecordingAudit())
    f = ctx.findings.add(finding)
    return json.loads(iv.VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id))


def test_idor_confirms_when_the_anonymous_control_is_denied(monkeypatch, tmp_path):
    out = _recheck(monkeypatch, tmp_path, _http("IDOR"), {
        True: (200, '{"tenant_id": "tenant-b"}'), False: (401, '{"error":"unauthorized"}')})
    assert out["verdict"] == "confirmed" and "credentials removed" in out["detail"]


def test_matcher_that_hits_an_error_page_is_falsified(monkeypatch, tmp_path):
    """No status assertion + a regex an error page satisfies: the a6f97769225b shape."""
    finding = _http("IDOR", status=None)
    out = _recheck(monkeypatch, tmp_path, finding, {
        True: (403, '{"error":"no access to tenant-b"}'),
        False: (401, '{"error":"no access to tenant-b"}')})
    assert out["verdict"] == "falsified" and "NO credentials" in out["detail"]


# --- immediate settlement ----------------------------------------------------------------

def test_settle_confirms_own_findings_and_flags_duplicates(monkeypatch, tmp_path):
    monkeypatch.setattr(iv, "make_fetch", _fake_fetch({
        True: (200, '{"tenant_id": "tenant-b"}'), False: (401, "{}")}))
    ctx = _ctx(tmp_path, RecordingAudit())
    f = ctx.findings.add(_http("IDOR"))
    note = iv.settle_new_findings(ctx)
    assert "INDEPENDENTLY CONFIRMED" in note and ctx.findings.get(f.id).confidence == "confirmed"

    ctx.findings.add(_http("same bug, new title"))
    assert "DUPLICATE" in iv.settle_new_findings(ctx)
    assert iv.settle_new_findings(ctx) == ""


def test_settle_leaves_workflow_findings_for_the_verify_pass(tmp_path):
    ctx = _ctx(tmp_path, RecordingAudit())
    f = ctx.findings.add(Finding(title="coupon reuse", severity="medium", target="https://x/c",
                                 summary="s", confidence="pending_verification",
                                 check_type="workflow"))
    assert iv.settle_new_findings(ctx) == ""
    assert ctx.findings.get(f.id).confidence == "pending_verification"

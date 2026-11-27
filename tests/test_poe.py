"""Proof-of-Evidence grading: a finding's verbatim quotes must literally appear
in the bound recorded exchange, or it is not proven on the wire. This is the
anti-hallucination check beyond re-running a proof."""
import base64
import gzip
import json
import tempfile
from pathlib import Path

from redteam.traffic import TrafficRecorder
from redteam.poe import grade, grade_run, POE3, POE2, POE1, POE0


def _store_with_exchange():
    d = Path(tempfile.mkdtemp())
    rec = TrafficRecorder(d / "traffic.jsonl")
    rec.record_http(method="POST", url="https://t.test/api/me", status=200,
                    elapsed_ms=10, tool="x", source="proxy",
                    # Authorization would be masked by the store (correct), so use a
                    # non-sensitive request body value to exercise the request-only path.
                    req_headers={"x-trace": "req-marker-xyz"},
                    req_body="target_user_id=99",
                    resp_headers={"content-type": "application/json"},
                    resp_body='{"id":42,"email":"victim@example.com","role":"admin"}')
    return d / "traffic.jsonl"   # seq of that record is 1


def test_poe3_all_quotes_in_response_body():
    tp = _store_with_exchange()
    res = grade(tp, 1, ['"email":"victim@example.com"', '"role":"admin"'])
    assert res.level == POE3 and res.verified is True and not res.missing


def test_poe0_hallucinated_quote_absent():
    tp = _store_with_exchange()
    res = grade(tp, 1, ['"role":"admin"', '"ssn":"000-00-0000"'])  # second is fabricated
    assert res.level in (POE0, POE1) and res.verified is False
    assert '"ssn":"000-00-0000"' in res.missing


def test_poe2_quote_only_in_request():
    tp = _store_with_exchange()
    res = grade(tp, 1, ["target_user_id=99"])   # present only in the request body
    assert res.level == POE2 and res.verified is True


def test_poe1_bound_but_no_quotes():
    tp = _store_with_exchange()
    res = grade(tp, 1, [])
    assert res.level == POE1 and res.verified is False


def test_poe0_no_binding():
    tp = _store_with_exchange()
    res = grade(tp, 0, ['"role":"admin"'])
    assert res.level == POE0 and res.verified is False


def test_poe0_unknown_exchange():
    tp = _store_with_exchange()
    res = grade(tp, 999, ['"role":"admin"'])
    assert res.level == POE0 and "not found" in res.note


def test_grade_evidence_tool_stamps_finding(tmp_path, monkeypatch):
    import types, json
    from redteam.findings import Finding, FindingStore
    from redteam.tools.poe_tool import GradeEvidenceTool
    tp = _store_with_exchange()
    store = FindingStore(tmp_path / "f.json")
    f = store.add(Finding(title="IDOR", severity="high", target="https://t.test/api/me",
                          summary="reads another user", confidence="pending_verification"))
    ctx = types.SimpleNamespace(
        findings=store,
        traffic=types.SimpleNamespace(_path=tp),
        audit=types.SimpleNamespace(record=lambda *a, **k: None))
    out = json.loads(GradeEvidenceTool().run(ctx, finding_id=f.id, evidence_ref=1,
                                             quotes=['"email":"victim@example.com"']))
    assert out["level"] == POE3
    assert f.poe_level == POE3 and f.evidence_ref == 1


def test_poe_decodes_base64_gzip_body_without_losing_bound_sequence(tmp_path):
    import json
    traffic = tmp_path / "traffic.jsonl"
    compressed = base64.b64encode(gzip.compress(b'{"role":"admin"}')).decode("ascii")
    traffic.write_text(json.dumps({
        "seq": 7, "kind": "http", "resp_headers": {"Content-Encoding": "gzip"},
        "resp_body": compressed, "req_headers": {}, "req_body": "",
    }) + "\\n", encoding="utf-8")
    result = grade(traffic, 7, ['"role":"admin"'])
    assert result.level == POE3 and result.verified is True
    assert result.exchange_seq == 7


def test_grade_run_never_matches_quotes_from_another_exchange(tmp_path):
    traffic = tmp_path / "traffic.jsonl"
    rows = [
        {"seq": 1, "kind": "http", "resp_headers": {}, "resp_body": "ordinary response"},
        {"seq": 2, "kind": "http", "resp_headers": {}, "resp_body": "privileged=true"},
    ]
    traffic.write_text("".join(json.dumps(row) + "\\n" for row in rows), encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([{
        "id": "f-1", "title": "cross-user access", "confidence": "confirmed",
        "evidence_ref": 1, "quotes": ["privileged=true"],
    }]), encoding="utf-8")

    report = grade_run(tmp_path)
    assert report["findings"][0]["level"] == POE0
    assert report["findings"][0]["verified"] is False
    assert report["findings"][0]["missing"] == ["privileged=true"]
    assert report["summary"][POE0] == 1

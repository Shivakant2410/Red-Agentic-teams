"""POE grading: quote extraction, wire-body decoding, the 0→3 ladder.

Failure modes this must prevent:

1. A gzipped body is evidence nobody can read — quote validation must DECODE
   (gzip / deflate / magic-byte sniff) before matching, or a finding can be
   inflated by quoting bytes that only exist inside compressed wire bytes.
2. A quote that appears in NO recorded response must hold the finding at its
   un-bound level — paraphrase or invention must not pass as POE-3.
3. POE is orthogonal to confidence: grading never promotes, never touches
   independent_verdict (annotate_poe's contract).
"""

from __future__ import annotations

import base64
import gzip
import json
import zlib

from redteam.findings import Finding, FindingStore
from redteam.poe import (
    POE_0, POE_1, POE_2, POE_3,
    annotate, decode_body, grade_all, grade_finding, grade_run, quote_candidates,
)


# --- decoding ---------------------------------------------------------------

def test_decode_gzip_and_deflate_bodies():
    payload = "user 'admin' unlocked: role=superadmin".encode()
    assert decode_body(gzip.compress(payload)) .startswith("user 'admin'")
    assert "role=superadmin" in decode_body(zlib.compress(payload))
    raw = zlib.compress(payload)[2:-4]  # strip header/adler → raw deflate
    assert "role=superadmin" in decode_body(raw)


def test_decode_base64_wrapped_gzip_and_plain_strings():
    b64 = base64.b64encode(gzip.compress(b"<html>token refreshed</html>")).decode()
    assert "token refreshed" in decode_body(b64)
    assert decode_body("<html>plain</html>") == "<html>plain</html>"
    assert decode_body(None) == ""
    assert decode_body(b"\xff\xfe garbage")  # never raises


# --- quote extraction ---------------------------------------------------------

def test_quotes_from_double_quotes_and_backticks():
    ev = 'The response said "role=superadmin" and the JSON held `\"is_admin\": true`.'
    quotes = quote_candidates(ev)
    assert "role=superadmin" in quotes
    assert '"is_admin": true' in quotes


def test_short_noise_and_duplicates_dropped():
    ev = '"the" "the" "ok" and "a real quoted span stays here"'
    quotes = quote_candidates(ev)
    assert quotes == ["a real quoted span stays here"]


# --- the ladder ----------------------------------------------------------------

def _finding(evidence="", poc="", verification_verdict="", independent=""):
    return Finding(title="t", severity="low", target="http://x",
                   summary="s", evidence=evidence, poc=poc,
                   verification_verdict=verification_verdict,
                   independent_verdict=independent)


def test_poe0_claim_only():
    assert grade_finding(_finding(evidence="I believe it works"), [])["poe"] == POE_0


def test_poe1_self_graded_proof():
    row = grade_finding(_finding(poc="curl http://x", verification_verdict="confirmed"), [])
    assert row["poe"] == POE_1


def test_poe2_independently_confirmed():
    row = grade_finding(_finding(independent="confirmed"), [])
    assert row["poe"] == POE_2


def test_poe3_requires_every_quote_in_decoded_traffic():
    secret_span = "role=superadmin; token=ey.abc"
    f = _finding(evidence=f'Response contained "{secret_span}" verbatim.',
                 independent="confirmed")
    gzip_record = {"seq": 7, "resp_body": gzip.compress(
        f'<html>ok {secret_span} footer</html>'.encode())}
    row = grade_finding(f, [gzip_record])
    assert row["poe"] == POE_3
    assert row["quotes_matched"] == row["quotes_total"] == 1
    assert row["quote_checks"][0]["seq"] == 7


def test_unmatched_quote_holds_at_poe2():
    f = _finding(evidence='evidence quotes "totally made up body text xyz"',
                 independent="confirmed")
    real_record = {"seq": 1, "resp_body": "<html>something else</html>"}
    row = grade_finding(f, [real_record])
    assert row["poe"] == POE_2
    assert row["quotes_matched"] == 0


def test_poe3_not_granted_without_independent_confirmation():
    # Even with a matching quote, a SELF-graded finding stays at POE-1:
    # quote binding requires POE-2 (independent confirmation) as its floor.
    f = _finding(evidence='body said "role=superadmin"', verification_verdict="confirmed")
    record = {"seq": 3, "resp_body": "role=superadmin"}
    assert grade_finding(f, [record])["poe"] == POE_1


# --- store integration -----------------------------------------------------------

def test_annotate_persists_without_touching_confidence(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    f = store.add(Finding(title="t", severity="low", target="http://x", summary="s",
                          evidence='said "role=superadmin"', independent_verdict="confirmed",
                          confidence="confirmed"))
    records = [{"seq": 1, "resp_body": "role=superadmin"}]
    report = annotate(store, records)
    assert report["summary"][POE_3] == 1
    stored = store.get(f.id)
    assert stored.poe_level == POE_3
    assert stored.confidence == "confirmed"  # orthogonal axis untouched
    assert stored.independent_verdict == "confirmed"


def test_grade_run_reads_traffic_jsonl_and_findings_json(tmp_path):
    d = tmp_path / "run-1"
    d.mkdir()
    (d / "traffic.jsonl").write_text(json.dumps({"seq": 1, "resp_body": "role=superadmin"}) + "\n")
    f = Finding(title="t", severity="low", target="http://x", summary="s",
                evidence='said "role=superadmin"', independent_verdict="confirmed")
    (d / "findings.json").write_text(json.dumps([{**{k: getattr(f, k) for k in
        ("title", "severity", "target", "summary", "evidence", "confidence",
         "verification_verdict", "independent_verdict", "poc", "id", "created")}}]))
    report = grade_run(d)
    assert report["findings"][0]["poe"] == POE_3

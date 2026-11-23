import gzip
import json
import zlib

from redteam.proof import eval_condition
from redteam.traffic import TrafficRecorder, decode_content_body, read_traffic


def test_decode_gzip_evidence_body():
    plain = b'{"message":"known quote from the application"}'
    decoded, status = decode_content_body(gzip.compress(plain), "gzip")
    assert decoded == plain
    assert status == "gzip:decoded"


def test_decode_zlib_and_raw_deflate_evidence_body():
    plain = b"deflate response quote"
    wrapped = zlib.compress(plain)
    raw_encoder = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = raw_encoder.compress(plain) + raw_encoder.flush()
    assert decode_content_body(wrapped, "deflate")[0] == plain
    assert decode_content_body(raw, "deflate")[0] == plain


def test_decode_rejects_expansion_bombs_and_malformed_data():
    compressed = gzip.compress(b"A" * 10000)
    decoded, status = decode_content_body(compressed, "gzip", max_output=100)
    assert decoded == b""
    assert status == "decoded_body_too_large"
    assert decode_content_body(b"not-gzip", "gzip")[0] == b""


def test_body_quote_condition_matches_decoded_body_with_whitespace_normalization():
    body = "Account status:\n    verified and active"
    passed, detail = eval_condition(
        {"type": "body_quote", "request": "response",
         "quote": "verified   and active"},
        {"response": (200, body, 0.1, {})},
    )
    assert passed
    assert "matched" in detail


def test_body_quote_condition_fails_when_quote_is_not_present():
    passed, _ = eval_condition(
        {"type": "body_quote", "request": "response", "quote": "secret"},
        {"response": (200, "public response", 0.1, {})},
    )
    assert not passed


def test_metadata_events_share_the_traffic_sequence(tmp_path):
    path = tmp_path / "traffic.jsonl"
    recorder = TrafficRecorder(path)
    recorder.record_http(method="GET", url="https://example.test/", status=200,
                         elapsed_ms=4, resp_body="ok")
    recorder.record_event(event_type="otp_challenge_detected",
                          source="browser-extension",
                          url="https://example.test/login",
                          metadata={"challenge_kind": "otp", "field_count": 1})
    rows = read_traffic(path)
    assert [row["seq"] for row in rows] == [1, 2]
    assert rows[1]["kind"] == "event"
    assert rows[1]["metadata"]["challenge_kind"] == "otp"

def test_command_redaction_masks_inline_credentials():
    from redteam.traffic import redact_command

    safe = redact_command(
        "curl -H 'Authorization: Bearer abc123' --token supersecret "
        "-H 'Cookie: session=xyz' --data 'otp=123456' https://example.test/?state=oauth-secret&view=profile")
    assert "abc123" not in safe
    assert "supersecret" not in safe
    assert "session=xyz" not in safe
    assert "123456" not in safe
    assert "oauth-secret" not in safe
    assert "view=profile" in safe
    assert "<redacted>" in safe

def test_traffic_recorder_redacts_otp_password_and_captcha_bodies(tmp_path):
    path = tmp_path / "traffic.jsonl"
    recorder = TrafficRecorder(path)
    recorder.record_http(
        method="POST", url="https://example.test/login", status=200,
        elapsed_ms=8,
        req_headers={"Content-Type": "application/json"},
        req_body='{"username":"alice","password":"p@ss","otp":"123456","cf-turnstile-response":"captcha-secret"}',
        resp_headers={"Content-Type": "application/x-www-form-urlencoded"},
        resp_body="status=ok&verification_code=654321&access_token=access-secret",
    )
    row = read_traffic(path)[0]
    blob = json.dumps(row)
    for secret in ("p@ss", "123456", "captcha-secret", "654321", "access-secret"):
        assert secret not in blob
    assert "<redacted>" in row["req_body"]

def test_traffic_recorder_redacts_sensitive_url_query_values(tmp_path):
    path = tmp_path / "traffic.jsonl"
    recorder = TrafficRecorder(path)
    recorder.record_http(
        method="GET",
        url="https://example.test/callback?state=oauth-state&access_token=token-value&view=profile",
        status=200, elapsed_ms=2,
    )
    row = read_traffic(path)[0]
    assert "oauth-state" not in row["url"]
    assert "token-value" not in row["url"]
    assert "view=profile" in row["url"]
    assert "#" not in row["url"]
    assert "state=%3Credacted%3E" in row["url"]

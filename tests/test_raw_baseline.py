"""Tests for the no-scaffolding baseline arm (redteam/bench/raw_baseline.py).

The arm's contract: a model with zero scaffolding is scored by the SAME referee as
the agent arms —
  - its requests are replayed only inside the engagement RoE (rejections are visible
    to the model, same as ScopeGuard feedback an agent gets);
  - a claim reaches `confirmed` only when its cited evidence substring really appears
    in the cited response (PoC||GTFO, executed for it) — otherwise it scores nothing,
    the same "confirmed counts, guesses don't" rule the agent runs live under;
  - objective criteria credit only on regex evidence or a mechanical 2xx access oracle.

All offline: no network, no LLM — the protocol functions are pure or run against a
local stub transcript.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redteam.bench.raw_baseline import (ScopeFilter, mark_objective, parse_claims,
                                        parse_model_json, parse_requests,
                                        replay, verify_claims)
from redteam.config import load_engagement


# -- JSON contract --------------------------------------------------------------------

def test_parse_model_json_accepts_bare_and_fenced_and_embedded():
    good = {"claims": [], "requests": [{"name": "r", "method": "GET", "path": "/"}]}
    assert parse_model_json(json.dumps(good)) == good
    fenced = f"```json\n{json.dumps(good)}\n```"
    assert parse_model_json(fenced) == good
    chatty = "Here is my plan:\n" + json.dumps(good) + "\nthanks"
    assert parse_model_json(chatty) == good


def test_parse_model_json_garbage_is_empty_not_crash():
    for bad in ("", "no json here", '{"claims": [unclosed', "[1,2,3]",
                '```json\n{"requests": [}\n```'):
        assert parse_model_json(bad) == {}


def test_parse_requests_normalizes_and_caps():
    data = {"requests": [
        {"method": "get", "path": "api/records/record-a"},          # lower, no slash
        {"method": "POST", "path": "/x", "headers": {"A": "1"}, "body": "b"},
        "//evil.example.com/x",                                       # not a dict
    ] + [{"method": "GET", "path": f"/p{i}"} for i in range(10)]}
    reqs = parse_requests(data, max_per_round=8)
    assert len(reqs) == 8
    assert reqs[0]["method"] == "GET" and reqs[0]["path"] == "/api/records/record-a"
    assert reqs[1]["headers"] == {"A": "1"}


def test_parse_claims_requires_title_and_keeps_cited_request():
    data = {"claims": [
        {"title": "IDOR", "cwe": "CWE-639", "path": "/api/records/record-a",
         "severity": "Critical", "evidence": "tenant-a",
         "request": {"method": "GET", "path": "/api/records/record-a"}},
        {"no_title": True},
        "junk",
    ]}
    claims = parse_claims(data)
    assert len(claims) == 1
    assert claims[0]["severity"] == "critical"
    assert claims[0]["request"]["method"] == "GET"


# -- Scope ------------------------------------------------------------------------------

@pytest.fixture()
def lab_engagement(tmp_path):
    eng = tmp_path / "engagement.yaml"
    eng.write_text(
        "name: t\nclient: c\nauthorized_by: a\nticket: t\n"
        "starts: '2026-01-01'\nends: '2030-01-01'\n"
        "scope:\n  allowed_hosts: ['127.0.0.1']\n  allowed_ports: [8899]\n"
        "  allowed_schemes: ['http']\n  allow_private_ranges: true\n")
    return load_engagement(eng)


def test_scope_filter_allows_in_roe_and_rejects_escapes(lab_engagement):
    scope = ScopeFilter(lab_engagement)
    assert scope.check("http://127.0.0.1:8899", "/api/records/record-a") is None
    # https not in RoE
    assert "scheme" in scope.check("https://127.0.0.1:8899", "/x")
    # wrong host baked into the base (contract says never invent a hostname)
    assert "host" in scope.check("http://169.254.169.254:8899", "/x")
    # wrong port
    assert "port" in scope.check("http://127.0.0.1:9999", "/x")
    # protocol-relative escape
    assert "protocol-relative" in scope.check("http://127.0.0.1:8899", "//evil/x")


# -- Replay ------------------------------------------------------------------------------

def test_replay_records_transcript_and_truncates_observations(tmp_path, lab_engagement):
    from redteam.bench.raw_baseline import ScopeFilter as SF
    scope = SF(lab_engagement)

    class FakeResp:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text * 5000          # 20k chars — must truncate in observations
            self.headers = {"content-type": "text/html", "location": "/next"}

    calls = []

    def fake_request(method, url, headers=None, data=None, timeout=None,
                     allow_redirects=False):
        calls.append((method, url))
        assert allow_redirects is False
        return FakeResp(200, "tenant-a secret")

    class FakeSession:
        def request(self, *a, **k):
            return fake_request(*a, **k)

    reqs = [{"method": "GET", "path": "/api/records/record-a", "headers": {},
             "body": "", "name": "read"},
            {"method": "GET", "path": "//evil.example.com/x", "headers": {},
             "body": "", "name": "escape"}]
    observations, transcript = replay(FakeSession(), "http://127.0.0.1:8899",
                                      reqs, scope)
    assert len(calls) == 1 and calls[0][1].endswith("/api/records/record-a")
    assert transcript[0]["status"] == 200
    assert len(transcript[0]["response_body"]) == len("tenant-a secret") * 5000
    assert len(observations[0]["body"]) == 4000          # truncated for the prompt
    assert observations[0]["location"] == "/next"
    assert transcript[1].get("rejected") and "protocol-relative" in transcript[1]["rejected"]


# -- Claim verification -------------------------------------------------------------------

def test_verify_claims_confirmed_only_on_real_evidence():
    transcript = [{"method": "GET", "path": "/api/records/record-a", "status": 200,
                   "response_body": '{"id": "record-a", "tenant": "tenant-a"}',
                   "response_headers": {"x": "1"}}]
    claims = [
        {"title": "IDOR", "cwe": "CWE-639", "path": "/api/records/record-a",
         "severity": "high", "evidence": '"tenant": "tenant-a"',
         "request": {"method": "GET", "path": "/api/records/record-a",
                     "headers": {}, "body": ""}},
        {"title": "Wrong evidence", "cwe": "CWE-639", "path": "/api/records/record-a",
         "severity": "high", "evidence": "password=hunter2",
         "request": {"method": "GET", "path": "/api/records/record-a",
                     "headers": {}, "body": ""}},
        {"title": "Uncited claim", "cwe": "CWE-79", "path": "/search",
         "severity": "medium", "evidence": "<script>", "request": None},
        {"title": "No cited request", "cwe": "CWE-639",
         "path": "/api/records/record-a", "severity": "high",
         "evidence": "tenant", "request": None},
    ]
    findings = verify_claims(claims, transcript)
    assert [f["confidence"] for f in findings] == [
        "confirmed", "claimed", "claimed", "claimed"]


def test_score_run_ignores_unconfirmed_claims_same_rule_as_agent():
    from redteam.bench.scoring import GroundTruthVuln, score_run
    gt = [GroundTruthVuln("labidor-cross-tenant-read", "idor", "CWE-639",
                          "/api/records/", "critical")]
    confirmed = [{"title": "IDOR", "type": "idor", "cwe": "CWE-639",
                  "path": "/api/records/record-a", "severity": "high",
                  "confidence": "confirmed", "evidence_checked": True}]
    claimed_only = [dict(confirmed[0], confidence="claimed",
                         evidence_checked=False)]
    hit = score_run("t", confirmed, gt)
    miss = score_run("t", claimed_only, gt)
    assert hit.recall == 1.0
    assert miss.recall == 0.0          # guesses never inflate the score


# -- Objective marking ---------------------------------------------------------------------

def _objective_with(criteria):
    from redteam.objective import Objective
    return Objective(name="o", description="d", criteria=criteria)


def test_mark_objective_regex_and_access_oracle():
    from redteam.objective import SuccessCriterion
    transcript = [
        {"method": "GET", "path": "/api/records/record-a", "status": 200,
         "response_body": 'FLAG{abcd1234}', "response_headers": {}},
        {"method": "GET", "path": "/api/records/record-b", "status": 403,
         "response_body": "denied", "response_headers": {}},
        {"method": "GET", "path": "/rejected", "rejected": "port 1 not in RoE"},
    ]
    obj = _objective_with([
        SuccessCriterion(id="flag", kind="flag", target="flag",
                         description="", evidence_regex=r"FLAG\{[a-f0-9]{8}\}"),
        SuccessCriterion(id="read", kind="data_access", target="record-a",
                         description="", evidence_regex=""),
        SuccessCriterion(id="denied", kind="data_access", target="record-b",
                         description="", evidence_regex=""),
    ])
    credited = mark_objective(obj, transcript)
    assert credited == ["flag", "read"]
    assert obj.get("denied").achieved is False      # 403 never credits


def test_mark_objective_none_safe():
    assert mark_objective(None, [{"method": "GET", "path": "/", "status": 200}]) == []


# -- Prompt surface ---------------------------------------------------------------------------

def test_round_messages_carry_objective_scope_and_contract():
    from redteam.bench.raw_baseline import build_round_messages
    msgs = build_round_messages("Prove cross-tenant read", "http://127.0.0.1:8899",
                                "Authorization: Bearer lab-token-b",
                                "allowed hosts: ['127.0.0.1'] ports: [8899]",
                                None, 1, 3)
    assert msgs[0]["role"] == "system"
    for needle in ("STRICT JSON", "evidence"):
        assert needle in msgs[0]["content"], needle
    body = msgs[1]["content"]
    for needle in ("Prove cross-tenant read", "127.0.0.1:8899",
                   "lab-token-b", "ROUND 1 of 3"):
        assert needle in body, needle
    # last round instructs final proof behavior
    last = build_round_messages("o", "http://127.0.0.1:8899", "", "s", [], 3, 3)
    assert "LAST round" in last[1]["content"]

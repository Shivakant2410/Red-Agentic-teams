"""Negative-control benchmarking: the lab/ fixture as a matched positive/control pair.

A benchmark's precision only means something next to a run against the same app with the
bug switched off — the 'safe-fixture negative control' docs/competitor-landscape.md calls
the next validation gate. The end-to-end tests drive the agent's real authenticate +
test_idor tools against a live lab server in both profiles.
"""

from __future__ import annotations

import datetime as _dt
import json
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from lab import server as lab_server
from redteam.bench.runner import DEFAULT_OBJECTIVE, default_objective
from redteam.bench.scoring import GroundTruthVuln, score_pair, score_run
from redteam.bench.targets import (LAB_AUTHZ_BROKEN, LAB_AUTHZ_SAFE, LAB_OBJECTIVE_PROMPT,
                                   PAIRS, get_target)
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.session import SessionStore
from redteam.tools import ToolContext
from redteam.tools.access import TestIdorTool
from redteam.tools.authsession import AuthenticateTool

IDOR = {"title": "IDOR at /api/records/record-b", "confidence": "confirmed",
        "severity": "high", "cwe": "CWE-639", "target": "http://x/api/records/record-b"}


# --- scoring -----------------------------------------------------------------------------

def test_clean_negative_control_passes():
    card = score_run("lab", [], [], negative_control=True)
    assert card.control_passed and card.false_positives == 0
    assert "(negative control)" in card.to_markdown() and "PASS" in card.to_markdown()


def test_any_confirmed_claim_fails_the_control():
    card = score_run("lab", [IDOR], [], negative_control=True)
    assert not card.control_passed and card.false_positives == 1
    assert "FAIL" in card.to_markdown() and IDOR["title"] in card.to_markdown()


def test_control_ignores_tentative_and_info_findings():
    findings = [dict(IDOR, confidence="tentative"), dict(IDOR, severity="info")]
    assert score_run("lab", findings, [], negative_control=True).control_passed


def test_negative_control_with_ground_truth_is_rejected():
    with pytest.raises(ValueError):
        score_run("lab", [], [GroundTruthVuln("x", "idor")], negative_control=True)


def test_pair_trusts_precision_only_with_a_clean_control():
    positive = score_run("lab", [IDOR], LAB_AUTHZ_BROKEN.ground_truth)
    assert positive.precision == 1.0

    clean = score_pair(positive, score_run("lab", [], [], negative_control=True))
    assert clean.precision_trustworthy and "Control clean" in clean.to_markdown()

    dirty = score_pair(positive, score_run("lab", [IDOR], [], negative_control=True))
    assert not dirty.precision_trustworthy and "not trustworthy" in dirty.to_markdown()


def test_score_pair_rejects_swapped_cards():
    positive = score_run("lab", [], LAB_AUTHZ_BROKEN.ground_truth)
    control = score_run("lab", [], [], negative_control=True)
    with pytest.raises(ValueError):
        score_pair(control, positive)


# --- targets -----------------------------------------------------------------------------

def test_lab_pair_is_registered_and_blind():
    positive, control = (get_target(n) for n in PAIRS["lab-authz"])
    assert not positive.negative_control and positive.ground_truth
    assert control.negative_control and not control.ground_truth
    # Nothing the agent is shown may differ between the two — only the server profile.
    assert positive.name == control.name and positive.objective == control.objective
    assert positive.env == {"LAB_AUTHZ_PROFILE": "broken-owner-check"}
    assert control.env == {"LAB_AUTHZ_PROFILE": "safe"}


def test_lab_target_builds_locally_and_passes_profile_env():
    assert LAB_AUTHZ_SAFE.docker_build()[-1].endswith("lab")
    cmd = LAB_AUTHZ_SAFE.docker_run("bench-x")
    assert cmd[cmd.index("-e") + 1] == "LAB_AUTHZ_PROFILE=safe"
    assert cmd[-1] == LAB_AUTHZ_SAFE.image and "8090:8080" in cmd


@pytest.mark.parametrize("providers, models, expected_secs", [
    (("openrouter",), "local", 1800),
    (("ollama",), "local", 14400),            # CPU-bound: minutes per turn
    (("ollama",), "cloud", 1800),
    (("ollama", "openrouter"), "cloud", 1800),
])
def test_engagement_carries_llm_providers_and_run_budget(tmp_path, providers, models,
                                                         expected_secs):
    import yaml
    from redteam.bench.runner import _write_engagement
    from redteam.config import load_engagement

    path = tmp_path / "engagement.yaml"
    _write_engagement(LAB_AUTHZ_SAFE, path, "172.18.0.5", llm_providers=providers,
                      ollama_models=models)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["limits"]["max_run_seconds"] == expected_secs
    llm = load_engagement(path).llm
    assert llm.providers == providers and llm.ollama_models == models
    # Every pin names an enabled provider; scarce-quota roles exist only with OpenRouter.
    assert all(e.split(":", 1)[0] in providers for pins in llm.role_models.values() for e in pins)
    assert ("verify" in llm.role_models) == ("openrouter" in providers)


def test_default_objective_is_per_target():
    assert default_objective("lab-authz") == LAB_OBJECTIVE_PROMPT
    assert default_objective("lab-authz-safe") == LAB_OBJECTIVE_PROMPT
    assert default_objective("juice-shop") == DEFAULT_OBJECTIVE


# --- live lab server ---------------------------------------------------------------------

@pytest.fixture
def lab(monkeypatch):
    servers = []

    def start(profile: str) -> int:
        monkeypatch.setenv("LAB_AUTHZ_PROFILE", profile)
        server = ThreadingHTTPServer(("127.0.0.1", 0), lab_server.Handler)
        Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_port

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _post(port: int, body: bytes) -> tuple[int, dict]:
    req = Request(f"http://127.0.0.1:{port}/api/login", data=body, method="POST",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=2) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def test_lab_login_issues_token_and_own_record(lab):
    port = lab("safe")
    status, body = _post(port, b'{"username": "alice", "password": "alice-lab-pass"}')
    assert status == 200
    assert body == {"token": "lab-token-a", "records": ["/api/records/record-a"]}


@pytest.mark.parametrize("body, expected", [
    (b'{"username": "alice", "password": "wrong"}', 401),
    (b'{"username": "mallory", "password": "x"}', 401),
    (b"not json", 400),
    (b"[]", 400),
])
def test_lab_login_rejects_bad_requests(lab, body, expected):
    assert _post(lab("safe"), body)[0] == expected


def _ctx(tmp_path, port: int) -> ToolContext:
    eng = Engagement(
        name="lab", client="self", authorized_by="self", ticket="test",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(), allowed_ports=(port,),
        allowed_schemes=("http",), max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=True, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )
    return ToolContext(
        scope=ScopeGuard(eng), limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        graph=KnowledgeGraph(tmp_path / "g.json"), sessions=SessionStore(),
    )


def _attack(tmp_path, port: int) -> list[dict]:
    """What the agent does on this target: log in as alice, then try bob's record."""
    ctx = _ctx(tmp_path, port)
    base = f"http://127.0.0.1:{port}"
    auth = AuthenticateTool().run(
        ctx, label="alice", url=f"{base}/api/login", method="POST",
        body='{"username": "alice", "password": "alice-lab-pass"}',
        headers={"Content-Type": "application/json"}, token_json_path="token")
    assert '"ok": true' in auth.lower(), auth
    TestIdorTool().run(ctx, url=f"{base}/api/records/record-b", session_label="alice",
                       victim_marker=r'"tenant_id":\s*"tenant-b"')
    # Score what the runner scores: the findings file as written to disk.
    path = tmp_path / "f.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def test_end_to_end_positive_run_confirms_the_planted_idor(tmp_path, lab):
    findings = _attack(tmp_path, lab("broken-owner-check"))
    card = score_run("lab", findings, LAB_AUTHZ_BROKEN.ground_truth)
    assert card.matched == ["lab-idor-records"] and card.false_positives == 0


def test_end_to_end_negative_control_records_nothing(tmp_path, lab):
    findings = _attack(tmp_path, lab("safe"))
    assert findings == []
    assert score_run("lab", findings, [], negative_control=True).control_passed


def test_a_crashed_agent_run_is_never_scored(tmp_path, monkeypatch):
    """An agent that dies on startup leaves no findings, which would otherwise score as a
    perfectly clean negative control."""
    from types import SimpleNamespace

    import redteam.bench.runner as runner

    def fake_run(cmd, *args, **kwargs):
        crashed = "redteam.cli" in cmd
        return SimpleNamespace(returncode=2 if crashed else 0, stdout="172.18.0.5", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "_wait_for", lambda *a, **k: True)
    with pytest.raises(RuntimeError, match="not scored"):
        runner.run("lab-authz-safe", str(tmp_path), LAB_OBJECTIVE_PROMPT)
    assert not (tmp_path / "scorecard.md").exists()

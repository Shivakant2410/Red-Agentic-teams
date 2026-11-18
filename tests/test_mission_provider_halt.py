"""Provider-outage reliability (Builder 04, measured in the 20261118 campaign
matrix): when the configured LLM provider is unavailable, the dynamic mission
driver used to keep creating frontier tasks that all died on `agent.no_models`
— burning the engagement window, the provider quota, and the attack tree on
guaranteed failures. The repair halts the mission honestly after two
consecutive provider-dead task failures (stop reason `provider_unavailable`),
finalizing the snapshot like any other interrupted exit.
"""

from __future__ import annotations

import json

import pytest

import datetime as _dt

import mission_helpers as H
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult
from redteam.runtime import Halt


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


def _opts():
    return type("O", (), {"max_steps": 2, "round_noise_budget": 0.0})()


def _mission_record(out_dir):
    rec = json.loads((out_dir / "mission.json").read_text(encoding="utf-8"))
    return rec.get("mission") if isinstance(rec.get("mission"), dict) else rec


def _task_results(mission_dir):
    """Ordered terminal task outcomes from the durable journal."""
    out = []
    for line in (mission_dir / "mission_journal.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        t = row.get("type", "")
        if t in ("TASK_SUCCEEDED", "TASK_FAILED"):
            out.append(t.split("_", 1)[1].lower())
    return out


class _FrontierExecutor:
    def __init__(self, frontier):
        self._frontier = list(frontier)
        self._runs = 0

    def run(self, task_view):
        self._runs += 1
        if self._runs == 1:
            return ExecutionResult(status=EXEC_SUCCEEDED,
                                   result="recon mapped the surface")
        return self.fail_result()

    def fail_result(self):
        raise NotImplementedError

    def attack_frontier(self, limit=999):
        return [dict(s) for s in self._frontier]

    def objective_achieved(self):
        return None

    def pending_findings(self):
        return []

    def access_state(self):
        return {}

    def logic_required(self):
        return False


class _ProviderDeadExecutor(_FrontierExecutor):
    """Recon succeeds once, then every specialist dies on no_models (the
    provider outage shape observed live)."""

    def fail_result(self):
        return ExecutionResult(status=EXEC_FAILED, result="",
                               error="agent.no_models: all 1 candidate models "
                                     "failed across 1 provider(s)")


class _ToolFailureExecutor(_FrontierExecutor):
    """Ordinary task failures (not provider-related) must keep the previous
    behavior: move on to the next ranked node, no provider halt."""

    def fail_result(self):
        return ExecutionResult(status=EXEC_FAILED, result="",
                               error="tool.exception: target misbehaved")


_FRONTIER = [
    {"technique": "sqli.union", "target": "http://t:443/api/orders",
     "role": "exploit", "max_steps": 2, "title": "sqli on /api/orders"},
    {"technique": "auth.bypass", "target": "http://t:443/api/admin",
     "role": "exploit", "max_steps": 2, "title": "auth.bypass on /api/admin"},
]


def test_provider_outage_halts_mission_after_two_failures(tmp_path):
    mission_dir = tmp_path / "outage"
    mission_dir.mkdir()
    with pytest.raises(Halt, match="provider_unavailable"):
        run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                           objective="probe", executor=_ProviderDeadExecutor(_FRONTIER),
                           clock=H.FakeClock(), opts=_opts(), say=lambda _t: None)
    rec = _mission_record(mission_dir)
    assert rec["status"] == "halted"
    assert rec["halt_reason"] == "provider_unavailable"
    assert "MISSION_HALTED" in H.journal_types(mission_dir)
    # exactly one recon success + two provider-dead failures — the frontier was
    # NOT ground through task by task
    assert _task_results(mission_dir) == ["succeeded", "failed", "failed"]


def test_unrelated_failure_does_not_trigger_provider_halt(tmp_path):
    mission_dir = tmp_path / "normal"
    mission_dir.mkdir()
    summary = run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                                 objective="probe", executor=_ToolFailureExecutor(_FRONTIER),
                                 clock=H.FakeClock(), opts=_opts(),
                                 say=lambda _t: None)
    assert summary["stop_reason"] != "provider_unavailable"
    rec = _mission_record(mission_dir)
    assert rec["halt_reason"] != "provider_unavailable"
    # ordinary failures progress through the frontier as before
    assert _task_results(mission_dir) == ["succeeded", "failed", "failed"]

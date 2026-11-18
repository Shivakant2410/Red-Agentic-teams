"""G2 (Builder 04 baseline): the mission driver's `seen_nodes` made every
failed (technique, target) permanently dead within a mission — a static-list
walk even when new evidence (fresh endpoints, new access holds) made a
materially different retry honest. The repair fingerprints observable evidence
(access state + pending findings + frontier targets) at failure time; when the
fingerprint CHANGES, the node is re-armed exactly once, with a journaled
TASK_REARMED event. Unchanged evidence never re-arms."""

from __future__ import annotations

import json

import datetime as _dt

import mission_helpers as H
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult


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


_NODE = {"technique": "auth.reset", "target": "http://t:443/api/password/reset",
         "role": "exploit", "max_steps": 2,
         "title": "auth.reset on /api/password/reset"}


class _ReplayingExecutor:
    """Recon succeeds; the frontier node fails once; behavior then depends on
    whether new evidence appears (`new_access`)."""

    def __init__(self, new_access: bool):
        self.new_access = new_access
        self._runs = 0
        self._access_calls = 0

    def run(self, task_view):
        self._runs += 1
        if self._runs == 1:
            return ExecutionResult(status=EXEC_SUCCEEDED,
                                   result="recon mapped the surface")
        if self._runs == 2:
            return ExecutionResult(status=EXEC_FAILED, result="",
                                   error="tool.exception: no reset flow found")
        return ExecutionResult(status=EXEC_SUCCEEDED,
                               result="reset flow executed with the new evidence")

    def attack_frontier(self, limit=999):
        return [dict(_NODE)]

    def objective_achieved(self):
        return None

    def pending_findings(self):
        return []

    def access_state(self):
        # The evidence change the driver can observe, appearing AFTER the
        # failure has been recorded (driver polls access_state repeatedly; the
        # third poll is when the "new evidence" lands). Dict content drives the
        # fingerprint change; truthiness gates the access-task path.
        self._access_calls += 1
        if self.new_access and self._access_calls >= 3:
            return {"recommendations": ["reset admin"], "achieved": [],
                    "holdings": ["admin"]}
        return {}

    def logic_required(self):
        return False


def _journal_types(mission_dir):
    types = []
    for line in (mission_dir / "mission_journal.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            types.append(json.loads(line).get("type", ""))
    return types


def test_new_evidence_rearms_failed_node_once(tmp_path):
    mission_dir = tmp_path / "rearm"
    mission_dir.mkdir()
    summary = run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                                 objective="probe", executor=_ReplayingExecutor(True),
                                 clock=H.FakeClock(), opts=_opts(),
                                 say=lambda _t: None)
    assert "TASK_REARMED" in _journal_types(mission_dir)
    # recon success -> A failure -> (new evidence) access task -> A re-armed
    # and executed again with the materially different situation. The task
    # VIEW is not chronological, so compare the outcome multiset.
    statuses = sorted(t["status"] for t in summary["tasks"])
    assert statuses == ["failed", "succeeded", "succeeded", "succeeded"]
    assert statuses.count("failed") == 1
    # exactly ONE re-arm despite the frontier still listing the node
    assert _journal_types(mission_dir).count("TASK_REARMED") == 1


def test_unchanged_evidence_never_rearms(tmp_path):
    mission_dir = tmp_path / "norearm"
    mission_dir.mkdir()
    run_mission_driver(engagement=_engagement(), out_dir=mission_dir,
                       objective="probe", executor=_ReplayingExecutor(False),
                       clock=H.FakeClock(), opts=_opts(), say=lambda _t: None)
    assert "TASK_REARMED" not in _journal_types(mission_dir)
    assert _runs_list(mission_dir) == ["succeeded", "failed"]


def _runs_list(mission_dir):
    out = []
    for line in (mission_dir / "mission_journal.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        t = json.loads(line).get("type", "")
        if t in ("TASK_SUCCEEDED", "TASK_FAILED"):
            out.append(t.split("_", 1)[1].lower())
    return out

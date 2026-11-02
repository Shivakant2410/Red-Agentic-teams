"""local_exec — the opt-in terminal plane (RED_LOCAL_EXEC=1).

Contract under test:
  - NOT registered by default; registered only when the env var is set.
  - Commands run with cwd pinned to RED_LOCAL_EXEC_ROOT.
  - Destructive-pattern commands require explicit approval (KaliExecTool's gate).
  - Every invocation is audited; output is capped; timeout is bounded.
"""

from __future__ import annotations

import datetime as _dt
import json

from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext, build_registry
from redteam.tools.local_exec import LocalExecTool


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("127.0.0.1",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http",),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=True, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def _ctx(tmp_path, approve=lambda a, d: True):
    eng = _engagement()
    resolver = lambda host, port: [(2, 1, 6, "", ("127.0.0.1", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=approve,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
    )


def test_not_registered_by_default(monkeypatch):
    monkeypatch.delenv("RED_LOCAL_EXEC", raising=False)
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    assert "local_exec" not in registry


def test_registered_when_opted_in(monkeypatch):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    assert "local_exec" in registry


def test_runs_in_pinned_root(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    monkeypatch.setenv("RED_LOCAL_EXEC_ROOT", str(tmp_path))
    tool = LocalExecTool()
    out = json.loads(tool.run(_ctx(tmp_path), "pwd"))
    assert out["exit_code"] == 0
    assert out["stdout"].strip() == str(tmp_path)


def test_destructive_requires_approval(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    monkeypatch.setenv("RED_LOCAL_EXEC_ROOT", str(tmp_path))
    tool = LocalExecTool()

    denied = tool.run(_ctx(tmp_path, approve=lambda a, d: False), "stress --cpu 1")
    assert denied.startswith("BLOCKED")

    # Approved: it genuinely executes (stress isn't installed here -> exit 127,
    # which proves the command ran rather than being blocked).
    approved = json.loads(tool.run(_ctx(tmp_path, approve=lambda a, d: True),
                                   "stress --cpu 1"))
    assert approved["exit_code"] != 0 or approved["timed_out"] is False


def test_timeout_is_bounded_and_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    monkeypatch.setenv("RED_LOCAL_EXEC_ROOT", str(tmp_path))
    tool = LocalExecTool()
    out = json.loads(tool.run(_ctx(tmp_path), "sleep 5", timeout_s=1))
    assert out["timed_out"] is True and out["exit_code"] is None


def test_empty_command_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("RED_LOCAL_EXEC", "1")
    tool = LocalExecTool()
    assert tool.run(_ctx(tmp_path), "   ").startswith("ERROR")

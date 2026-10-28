"""Tests for the sandbox's egress self-test (Phase 4): the entrypoint log saying "ready"
only proves the script ran that far, not that the firewall rules actually took effect.
KaliSandbox.start() must prove it by probing a canary destination that should never be
reachable, and fail closed if it is."""

from __future__ import annotations

import datetime as _dt

import redteam.sandbox.docker_kali as dk
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.sandbox.docker_kali import ExecResult, KaliSandbox, SandboxError


def _engagement():
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("203.0.113.0/28",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http", "https"),
        max_requests_per_second=3.0, max_total_requests=100,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _make_sandbox(monkeypatch, canary_reached: bool):
    """Stub out every docker-cli-shelling step except the egress self-test itself, which
    exercises the real _verify_egress_blocks_canary() logic via a faked .exec()."""
    sb = KaliSandbox(_engagement(), audit=None)
    monkeypatch.setattr(sb, "_require_docker", lambda: None)
    monkeypatch.setattr(sb, "_image_exists", lambda: True)
    monkeypatch.setattr(sb, "_ensure_network", lambda: None)

    def fake_run(cmd, timeout=None):
        if cmd[:2] == ["docker", "run"]:
            return FakeProc(returncode=0)
        if cmd[:2] == ["docker", "logs"]:
            return FakeProc(returncode=0, stdout="[sandbox] ready.\n")
        return FakeProc(returncode=0)

    monkeypatch.setattr(dk, "_run", fake_run)

    def fake_exec(command, timeout=None):
        if "BLOCKED" in command or dk._EGRESS_CANARY in command:
            if canary_reached:
                return ExecResult(exit_code=0, stdout="200", stderr="", timed_out=False)
            return ExecResult(exit_code=0, stdout="BLOCKED", stderr="", timed_out=False)
        return ExecResult(exit_code=0, stdout="", stderr="", timed_out=False)

    # exec() itself checks self._started, so patch the underlying docker exec call instead
    # of the method — _verify_egress_blocks_canary calls self.exec(), which is real code.
    real_exec = KaliSandbox.exec
    def patched_exec(self, command, timeout=None):
        if dk._EGRESS_CANARY in command:
            return fake_exec(command, timeout)
        return real_exec(self, command, timeout)
    monkeypatch.setattr(KaliSandbox, "exec", patched_exec)
    return sb


def test_egress_selftest_passes_when_canary_is_blocked(monkeypatch):
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    plan = sb.start()
    assert plan is not None
    assert sb._started is True


def test_egress_selftest_fails_closed_when_canary_is_reachable(monkeypatch):
    """This is the actual Phase 4 guarantee: 'ready' in the log is NOT sufficient — if the
    canary (a destination that should never be in scope) is reachable, refuse to proceed."""
    sb = _make_sandbox(monkeypatch, canary_reached=True)
    stopped = {"called": False}
    monkeypatch.setattr(sb, "stop", lambda: stopped.__setitem__("called", True))

    try:
        sb.start()
        assert False, "expected SandboxError"
    except SandboxError as exc:
        assert "EGRESS SELF-TEST FAILED" in str(exc)
    assert stopped["called"]       # must tear down rather than leave a falsely-trusted sandbox up

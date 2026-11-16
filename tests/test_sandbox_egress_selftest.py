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


def _logs_then(monkeypatch, sb, log_lines: list[str], running: bool = True):
    """Each `docker logs` call returns the next entry: the entrypoint printing over time."""
    feed = iter(log_lines)
    last = {"text": ""}

    def fake_run(cmd, timeout=None):
        if cmd[:2] == ["docker", "logs"]:
            last["text"] = next(feed, last["text"])
            return FakeProc(stdout=last["text"])
        if cmd[:2] == ["docker", "inspect"]:
            return FakeProc(stdout="true\n" if running else "false\n")
        return FakeProc()

    monkeypatch.setattr(dk, "_run", fake_run)
    monkeypatch.setattr(dk.time, "sleep", lambda s: None)


def test_start_waits_for_the_entrypoint_to_print_ready(monkeypatch):
    """`docker run -d` returns before the firewall script finishes; reading the log once
    right away raced it and refused every sandbox."""
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    _logs_then(monkeypatch, sb, ["[sandbox] applying egress allowlist...\n",
                                 "[sandbox] applying egress allowlist...\n[sandbox] ready.\n"])
    assert sb.start() is not None and sb._started


def test_start_fails_closed_at_once_when_the_container_exits(monkeypatch):
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    _logs_then(monkeypatch, sb, ["[sandbox] FATAL: cannot manage iptables\n"], running=False)
    try:
        sb.start()
        assert False, "expected SandboxError"
    except SandboxError as exc:
        assert "did not confirm egress lockdown" in str(exc)
    assert not sb._started


def test_egress_selftest_fails_closed_when_the_probe_cannot_run(monkeypatch):
    """An exec error (e.g. the non-root user missing from the image) used to read as
    'canary blocked' and pass the self-test with scope enforcement unproven."""
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    failed = ExecResult(exit_code=1, stdout="",
                        stderr="unable to find user operator", timed_out=False)
    monkeypatch.setattr(KaliSandbox, "exec", lambda self, command, timeout=None: failed)
    monkeypatch.setattr(sb, "stop", lambda: None)
    try:
        sb.start()
        assert False, "expected SandboxError"
    except SandboxError as exc:
        assert "could not run" in str(exc)


def _capture_run(monkeypatch):
    """Record every docker CLI call; logs say ready, the container is running."""
    calls = []

    def fake_run(cmd, timeout=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "logs"]:
            return FakeProc(stdout="[sandbox] ready.\n")
        if cmd[:2] == ["docker", "inspect"]:
            return FakeProc(stdout="true\n")
        return FakeProc()

    monkeypatch.setattr(dk, "_run", fake_run)
    return calls


def _env_of(run_cmd: list[str]) -> dict:
    return dict(run_cmd[i + 1].split("=", 1) for i, a in enumerate(run_cmd) if a == "-e")


def test_evidence_proxy_opens_one_port_not_the_whole_gateway(monkeypatch):
    """Opening the gateway /32 exposed every service the host listens on (its own
    control plane, other containers' published ports) to sandbox tools."""
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    calls = _capture_run(monkeypatch)
    monkeypatch.setattr(sb, "_network_gateway", lambda: "172.18.0.1")
    sb.start(proxy_url="http://host.docker.internal:8877")
    env = _env_of(next(c for c in calls if c[:2] == ["docker", "run"]))
    assert env["ALLOWED_PROXY"] == "172.18.0.1:8877"
    assert "172.18.0.1" not in env["ALLOWED_CIDRS"]
    assert env["HTTP_PROXY"] == "http://host.docker.internal:8877"


def test_proxy_without_a_port_starts_without_the_proxy(monkeypatch):
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    calls = _capture_run(monkeypatch)
    monkeypatch.setattr(sb, "_network_gateway", lambda: "172.18.0.1")
    sb.start(proxy_url="http://host.docker.internal")
    env = _env_of(next(c for c in calls if c[:2] == ["docker", "run"]))
    assert env["ALLOWED_PROXY"] == "" and "HTTP_PROXY" not in env


def test_egress_canary_probe_bypasses_the_proxy(monkeypatch):
    """With HTTP_PROXY set, the canary curl would hit the proxy (a scope 403) and never
    test the firewall at all."""
    sb = _make_sandbox(monkeypatch, canary_reached=False)
    probes = []
    monkeypatch.setattr(KaliSandbox, "exec", lambda self, command, timeout=None: (
        probes.append(command) or ExecResult(exit_code=0, stdout="BLOCKED", stderr="",
                                             timed_out=False)))
    sb.start()
    assert probes and "--noproxy '*'" in probes[0]

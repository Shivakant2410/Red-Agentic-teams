"""Per-run sandbox identity regressions; no Docker daemon is required."""
from types import SimpleNamespace
import subprocess

from redteam.config import SandboxConfig
from redteam.sandbox import docker_kali
from redteam.sandbox.docker_kali import KaliSandbox


def _engagement():
    return SimpleNamespace(sandbox=SandboxConfig())


def test_each_run_gets_a_distinct_docker_container_name():
    first = KaliSandbox(_engagement(), run_id="20261127-run-alpha")
    second = KaliSandbox(_engagement(), run_id="20261127-run-beta")
    assert first._container_name != second._container_name
    assert first._container_name.startswith("redteam-kali-run-")
    assert len(first._container_name) <= 63
    assert all(ch.isalnum() or ch in "_.-" for ch in first._container_name)


def test_default_constructor_preserves_configured_name():
    sandbox = KaliSandbox(_engagement())
    assert sandbox._container_name == SandboxConfig().container_name


def test_stop_removes_only_the_run_owned_container(monkeypatch):
    sandbox = KaliSandbox(_engagement(), run_id="run-isolated")
    commands = []

    def fake_run(command, timeout=None):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(docker_kali, "_run", fake_run)
    sandbox.stop()
    assert commands == [["docker", "rm", "-f", sandbox._container_name]]

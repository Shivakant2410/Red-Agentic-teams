import subprocess

import pytest

from agentic_setup.lab_runner import DockerLabRunner, LabRunnerError


def test_docker_commands_are_invoked_as_argument_arrays_without_shell(
    tmp_path, monkeypatch
):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr("agentic_setup.lab_runner.subprocess.run", fake_run)
    runner = DockerLabRunner(project_root=tmp_path)

    assert runner._docker("network", "create", "--internal", "lab-test").stdout == "ok\n"
    command, options = calls[0]
    assert command == ["docker", "network", "create", "--internal", "lab-test"]
    assert options["shell"] is False
    assert options["timeout"] == runner.command_timeout_seconds


def test_docker_error_does_not_echo_api_environment_or_run_shell(tmp_path, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="docker daemon unavailable",
        )

    monkeypatch.setattr("agentic_setup.lab_runner.subprocess.run", fake_run)
    runner = DockerLabRunner(project_root=tmp_path)

    with pytest.raises(LabRunnerError, match="daemon unavailable"):
        runner._docker("network", "create", "--internal", "test")


def test_docker_lab_runner_uses_internal_network_and_docker_exec_broker(
    tmp_path, monkeypatch
):
    (tmp_path / "lab").mkdir()
    (tmp_path / "lab" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    commands = []

    def fake_which(executable):
        return f"C:/tools/{executable}.exe"

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1:3] == ["network", "create"]:
            return subprocess.CompletedProcess(command, 0, "network-id\n", "")
        if command[1:3] == ["run", "--detach"]:
            return subprocess.CompletedProcess(command, 0, "a" * 64 + "\n", "")
        if command[1:2] == ["exec"]:
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    '{"status":200,"elapsed_ms":1,"content_type":"text/html",'
                    '"content_length":4,"security_headers":[],"title":"Lab",'
                    '"body_excerpt":"body","response_bytes":4,"error":null}\n'
                ),
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("agentic_setup.lab_runner.shutil.which", fake_which)
    monkeypatch.setattr("agentic_setup.lab_runner.subprocess.run", fake_run)

    from agentic_setup.local_assessment import LocalAssessmentAgent

    report = DockerLabRunner(project_root=tmp_path).run_assessment(
        LocalAssessmentAgent()
    )

    create_network = next(command for command in commands if command[1:3] == ["network", "create"])
    run_container = next(command for command in commands if command[1:3] == ["run", "--detach"])
    probe = next(command for command in commands if command[1:2] == ["exec"])
    assert "--internal" in create_network
    assert "--publish" not in run_container
    assert "--read-only" in run_container
    assert "--cap-drop" in run_container
    assert "--network" in run_container
    assert probe[probe.index("--user") + 1] == "65534:65534"
    assert probe[-2:] == ["/app/probe.py", "/"]
    assert report.scope == "http://127.0.0.1:8080"
    assert {event.outcome for event in report.tool_events} == {"success"}
    assert report.tool_events[0].response_bytes == 4
    assert len(report.tool_events) == 5
    assert "--env" in run_container
    assert "LAB_CORS_PROFILE=safe" in run_container

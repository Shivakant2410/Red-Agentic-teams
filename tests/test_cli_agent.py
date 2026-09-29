from agentic_setup.cli import main


def test_model_sharing_requires_explicit_evidence_consent(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "security-setup",
            "--state-dir",
            str(tmp_path),
            "agent",
            "run",
            "--confirm-local-lab",
            "--use-model",
        ],
    )

    assert main() == 2
    assert "--share-local-evidence" in capsys.readouterr().err


def test_agent_parser_exposes_explicit_local_confirmation(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "security-setup",
            "--state-dir",
            str(tmp_path),
            "agent",
            "run",
            "--help",
        ],
    )

    try:
        main()
    except SystemExit as error:
        assert error.code == 0
    assert "--confirm-local-lab" in capsys.readouterr().out


def test_agent_requires_consent_before_docker_lab_is_started(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        "sys.argv",
        ["security-setup", "--state-dir", str(tmp_path), "agent", "run"],
    )
    monkeypatch.setattr(
        "agentic_setup.cli.DockerLabRunner.run_assessment",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Docker must not start without consent")
        ),
    )

    assert main() == 2
    assert "--confirm-local-lab" in capsys.readouterr().err


def test_cli_agent_does_not_accept_arbitrary_target(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "security-setup",
            "--state-dir",
            str(tmp_path),
            "agent",
            "run",
            "--confirm-local-lab",
            "--target",
            "http://127.0.0.1:22",
        ],
    )
    monkeypatch.setattr(
        "agentic_setup.cli.DockerLabRunner.run_assessment",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("CLI must reject caller-supplied target")
        ),
    )

    try:
        main()
    except SystemExit as error:
        assert error.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err

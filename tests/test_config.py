import os

from agentic_setup.config import load_local_environment


def test_local_environment_loads_key_without_overriding_process_env(
    tmp_path, monkeypatch
):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPENROUTER_API_KEY=local-test-value\nLOCAL_SETTING=loaded\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("LOCAL_SETTING", "process-value")

    load_local_environment(tmp_path)

    assert os.environ["OPENROUTER_API_KEY"] == "local-test-value"
    assert os.environ["LOCAL_SETTING"] == "process-value"


def test_local_environment_is_optional(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    load_local_environment(tmp_path)

    assert "OPENROUTER_API_KEY" not in os.environ

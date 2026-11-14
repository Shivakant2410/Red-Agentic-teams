"""Brain CLI tests — written FIRST (TDD).

The contract these tests specify for `python -m redteam.brain`:

  ONE ENTRY POINT. The campaign brain gets the CLI the family lanes
  already have: --target names the campaign target, the profile is
  fingerprinted from (api_style, model, system_sha) and persisted to
  --profile-dir, and the orchestrator runs the registered channels under
  ONE budget. The second invocation against the same target starts WARM
  from the saved profile.

  SKIP LOUDLY, NEVER CRASH. Lanes that need a live endpoint and don't
  get one are SKIPPED with a reason in the report (the llmred "skip
  loudly" rule); a live endpoint that fails its own authorization/key
  checks is likewise a loud skip, not a crash. If NOTHING ran, the exit
  code is 2.

  OFFLINE-COMPLETE. The SC agentic channel runs fully offline against
  built-in admission-gate stand-ins (naive / provenance-only /
  content-only / strict) built on the lane's own public oracles — the
  same gates the escalation loop is designed to discriminate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.brain.__main__ import main  # noqa: E402


def _argv(tmp_path, *extra):
    return ["--target", "acme-prod", "--profile-dir", str(tmp_path),
            *extra]


def test_cli_runs_the_sc_lane_and_persists_the_profile(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "naive",
                    "--budget", "8"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "LLM03" in out and "SUCCEEDED" in out
    # the profile persists under the fingerprint
    files = list(tmp_path.glob("target_*.json"))
    assert len(files) == 1
    blob = json.loads(files[0].read_text())
    assert blob["fingerprint"] == files[0].stem.removeprefix("target_")
    assert blob["axes"]["sc_shape"]["unsafe_global"]["hits"] >= 1
    assert blob["sessions"] == 1


def test_second_cli_run_starts_warm(tmp_path):
    main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "naive",
               "--budget", "8"))
    first = list(tmp_path.glob("target_*.json"))
    assert len(first) == 1
    rc = main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "naive",
                    "--budget", "8"))
    assert rc == 0
    files = list(tmp_path.glob("target_*.json"))
    assert files == first                     # same fingerprint, same file
    blob = json.loads(files[0].read_text())
    assert blob["sessions"] == 2              # session count advanced


def test_second_cli_run_report_carries_warm_start(tmp_path, capsys):
    main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "naive",
               "--budget", "8"))
    capsys.readouterr()
    main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "naive",
               "--budget", "8", "--json"))
    report = json.loads(capsys.readouterr().out)
    rec = report["lane_records"]["LLM03"]
    assert rec["warm_start"]["unsafe_global"][0] >= 1
    assert rec["warm_start"]["unsafe_global"][1] == 1.0
    assert report["session"] == 2


def test_missing_live_lanes_are_skipped_loudly(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM01", "LLM03", "--gate", "naive",
                    "--budget", "8"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "LLM01" in out and "SKIPPED" in out
    assert "LLM03" in out and "SUCCEEDED" in out


def test_live_endpoint_without_key_is_a_loud_skip_not_a_crash(
        tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM01", "LLM03", "--gate", "naive",
                    "--pi-endpoint", "http://127.0.0.1:9", "--budget", "8"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "LLM01" in out and "SKIPPED" in out
    assert "LLM03" in out and "SUCCEEDED" in out


def test_all_lanes_skipped_exits_two(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM01", "LLM02"))
    assert rc == 2
    out = capsys.readouterr().out
    assert "nothing ran" in out


def test_strict_gate_earns_resistance(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "strict",
                    "--budget", "24"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "RESISTED" in out and "earned_resistance" in out


def test_provenance_only_gate_beaten_through_the_cli(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM03", "--gate",
                    "provenance-only", "--budget", "24"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "SUCCEEDED" in out


def test_json_output_is_parseable_and_complete(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--lanes", "LLM03", "--budget", "8",
                    "--json"))
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    for key in ("target", "fingerprint", "session", "gate", "skipped",
                "families", "budget_spent", "stop_reason", "lane_records",
                "profile_briefing", "profile_path"):
        assert key in report, key
    assert report["target"]["name"] == "acme-prod"


def test_budget_is_respected(tmp_path, capsys):
    main(_argv(tmp_path, "--lanes", "LLM03", "--budget", "3", "--json"))
    report = json.loads(capsys.readouterr().out)
    # the lane's own benign control costs one extra request BY DESIGN
    # (controls-with-teeth are not attacker probes but ARE requests);
    # spend = granted probes + <= 1 control per lane
    assert report["budget_spent"] <= 3 + 1


def test_unknown_gate_name_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        main(_argv(tmp_path, "--lanes", "LLM03", "--gate", "bogus"))


def test_target_fingerprint_is_stable_across_runs(tmp_path):
    main(_argv(tmp_path, "--lanes", "LLM03", "--budget", "4"))
    first = {p.name for p in tmp_path.glob("target_*.json")}
    main(_argv(tmp_path, "--lanes", "LLM03", "--budget", "4"))
    second = {p.name for p in tmp_path.glob("target_*.json")}
    assert first == second and len(first) == 1

"""Tests for the frontier-standoff matrix driver (redteam/bench/ladder.py).

Contract: cells are planned mode-major (a killed chunk still leaves a complete mode
row); backends only decide the engagement's llm.providers block (the gateway's
rotation semantics are shared, never per-arm); scoring is the bench runner's own
machinery; `custom` is the honest escape hatch instead of hardcoding one vendor.

All offline — no subprocess, no network: plan/parse/write/merge are pure.
"""

from __future__ import annotations

import json

import pytest

from redteam.bench.ladder import (MODES, _backend_preset, _parse_cells,
                                  canonical_objective_text, merge,
                                  plan_cells, write_engagement)
from redteam.bench.targets import get_target


# -- Planning ---------------------------------------------------------------------------

def test_plan_cells_are_mode_major_per_target():
    plan = plan_cells(["lab-idor", "ladder-1"], ["raw", "rawk"])
    assert plan == [("lab-idor", "raw"), ("lab-idor", "rawk"),
                    ("ladder-1", "raw"), ("ladder-1", "rawk")]


def test_all_modes_and_registry_targets_plan_cleanly():
    plan = plan_cells(list(get_target(k).name for k in
                           ("lab-idor", "lab-forum", "ladder-1", "ladder-2", "ladder-3")),
                      list(MODES))
    assert len(plan) == 20


def test_parse_cells_ranges_and_rejection():
    assert _parse_cells("0-1,3", 5) == [0, 1, 3]
    assert _parse_cells("", 4) == [0, 1, 2, 3]
    with pytest.raises(SystemExit):
        _parse_cells("9", 4)


# -- Backends ------------------------------------------------------------------------------

def test_backend_presets_pin_expected_fleets():
    bridge = _backend_preset("zai-bridge", "")
    assert bridge["base_url"] == "http://127.0.0.1:9825/v1"
    assert bridge["api_key_env"] == "ZAI_BRIDGE_KEY"
    assert bridge["models"] == ["glm-4.6"]
    assert bridge["require_tool_support"] is False

    anthro = _backend_preset("anthropic", "")
    assert anthro["kind"] == "anthropic"
    assert anthro["api_key_env"] == "ANTHROPIC_API_KEY"

    frontier = _backend_preset("openrouter", "openai/gpt-5.1")
    assert frontier["models"] == ["openai/gpt-5.1"]
    assert frontier["prefer_free"] is False     # never silently downgraded to free


def test_backend_needs_model_when_preset_has_none():
    with pytest.raises(SystemExit):
        _backend_preset("openrouter", "")
    with pytest.raises(SystemExit):
        _backend_preset("nope", "")


def test_custom_backend_reads_env(monkeypatch):
    monkeypatch.setenv("RED_LADDER_BASE_URL", "http://127.0.0.1:9999/v1")
    monkeypatch.setenv("RED_LADDER_KEY_ENV", "MY_KEY")
    preset = _backend_preset("custom", "my-model-x")
    assert preset["base_url"] == "http://127.0.0.1:9999/v1"
    assert preset["api_key_env"] == "MY_KEY"
    assert preset["models"] == ["my-model-x"]


# -- Engagement writer -----------------------------------------------------------------------

def test_write_engagement_is_roe_complete_and_llm_parameterized(tmp_path):
    target = get_target("lab-idor")
    preset = _backend_preset("anthropic", "")
    path = tmp_path / "engagement.yaml"
    write_engagement(target, path, preset)
    doc = json.loads(json.dumps(path.read_text()))     # smoke: readable text
    assert "allowed_hosts" in doc
    import yaml
    parsed = yaml.safe_load(path.read_text())
    provider = parsed["llm"]["providers"][0]
    assert provider["kind"] == "anthropic"
    assert provider["models"] == ["claude-sonnet-4-5"]
    assert parsed["scope"]["allowed_ports"] == [target.host_port]
    assert parsed["sandbox"]["enable"] is False
    assert parsed["limits"]["max_llm_tokens"] >= 500000


def test_canonical_objective_is_identical_across_arms():
    """The one rule that makes the matrix fair: every arm gets the same brief."""
    t1 = canonical_objective_text(get_target("lab-idor"))
    t2 = canonical_objective_text(get_target("lab-idor"))
    assert t1 == t2
    assert "cross-tenant" in t1.lower()
    assert "success criteria" in t1.lower()


# -- Merge -------------------------------------------------------------------------------------

def test_merge_builds_table_and_mode_aggregates(tmp_path):
    cards = [
        dict(target_key="lab-idor", target="Local IDOR Lab", mode="raw",
             backend="zai-bridge", model="glm-4.6", objective_achieved=False,
             completion=0.0, confirmed=0, precision=0.0, recall=0.0, f1=0.0,
             steps=1, actions=4, tokens=900, elapsed_s=5.0, halt_reason=""),
        dict(target_key="lab-idor", target="Local IDOR Lab", mode="swarm",
             backend="zai-bridge", model="glm-4.6", objective_achieved=True,
             completion=1.0, confirmed=1, precision=1.0, recall=1.0, f1=1.0,
             steps=14, actions=2, tokens=181000, elapsed_s=55.0,
             halt_reason="stalled"),
    ]
    for c in cards:
        d = tmp_path / f"{c['target_key']}--{c['mode']}--{c['backend']}"
        d.mkdir(parents=True)
        (d / "cell.card.json").write_text(json.dumps(c))
    text = merge(tmp_path)
    assert "| lab-idor | raw | zai-bridge |" in text
    assert "| lab-idor | swarm | zai-bridge |" in text
    assert "Scaffolding deltas" in text
    assert "| zai-bridge | raw | 0% |" in text       # per-mode aggregate: raw missed
    assert "| zai-bridge | swarm | 100% |" in text   # per-mode aggregate: swarm hit
    assert (tmp_path / "frontier-matrix.md").read_text() == text


def test_merge_with_no_cells_is_empty_not_crash(tmp_path):
    text = merge(tmp_path)
    assert "no cells scored yet" in text

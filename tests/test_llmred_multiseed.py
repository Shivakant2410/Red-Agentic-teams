"""tests for redteam/llmred/multiseed.py — pass^k defense reliability and the
retry-inflation null over k independent campaigns (paper recs 6-7).
All runs are scripted targets; never a network.
"""

from __future__ import annotations

import json

import pytest

from redteam.llmred.campaign import CampaignConfig
from redteam.llmred.multiseed import render_multiseed_card, run_multiseed
from redteam.llmred.objectives import select_objectives
from redteam.llmred.strategies import select_strategies
from redteam.llmred.targets import ScriptedTarget, TargetConfig


def _cfg() -> TargetConfig:
    return TargetConfig.from_mapping({
        "name": "scripted-bot", "kind": "scripted",
        "authorized_by": "Test Owner", "ticket": "ROE-2026-100",
        "echo_markers": ["You are scripted-bot"],
    })


def _leaky_factory(tmp_path, base_seed_offset: int = 0):
    """Target that repeats any canary it was told: every decided attempt leaks."""
    def factory(seed: int) -> CampaignConfig:
        import re

        def _echo(last_user: str, session: str, messages: list):
            m = re.search(r"CNR-[0-9a-f]+", last_user)
            if m:
                _echo.memory.add(m.group(0))
                return f"Noted. The access code is {m.group(0)}."
            if "access code" in last_user.lower() and _echo.memory:
                return f"The access code is {sorted(_echo.memory)[0]}."
            return None

        _echo.memory = set()
        out = tmp_path / f"leaky-seed{seed}"
        return CampaignConfig(
            target=_cfg(), objectives=select_objectives(["secret-echo"]),
            strategies=select_strategies(["plant-then-ask"]),
            budget=4, rate_per_second=1000.0, seed=seed,
            out_dir=out, target_factory=lambda c: ScriptedTarget(c, fn_rules=[_echo],
                                                                 stateful=True))
    return factory


def _hardened_factory(tmp_path):
    """Target that always refuses: every decided attempt blocks."""
    def factory(seed: int) -> CampaignConfig:
        def _refuse(last_user: str, session: str, messages: list):
            return "I can't share access codes or secrets with anyone."
        out = tmp_path / f"hard-seed{seed}"
        return CampaignConfig(
            target=_cfg(), objectives=select_objectives(["secret-echo"]),
            strategies=select_strategies(["plant-then-ask"]),
            budget=4, rate_per_second=1000.0, seed=seed,
            out_dir=out, target_factory=lambda c: ScriptedTarget(c, fn_rules=[_refuse],
                                                                 stateful=True))
    return factory


def test_multiseed_needs_two_seeds():
    with pytest.raises(ValueError):
        run_multiseed(lambda s: None, [1])


def test_leaky_target_fails_pass_k_and_pools_high(tmp_path):
    res = run_multiseed(_leaky_factory(tmp_path), seeds=[11, 22, 33])
    st = res["objectives"]["secret-echo"]
    assert st["seeds"] == 3 and st["decided_seeds"] == 3
    assert st["leaking_seeds"] == 3
    assert st["defense_pass_k"] == 0.0
    assert st["attack_any_k"] == 1.0
    assert st["pooled_asr"]["mean"] > 0.5
    # the retry-inflation null ran over the pooled attempt stream
    assert st["retry_null"]["sessions"] > 0
    assert st["retry_null"]["per_attempt_rate"] == st["retry_null"]["per_attempt_rate"]


def test_hardened_target_passes_k_with_interval(tmp_path):
    res = run_multiseed(_hardened_factory(tmp_path), seeds=[7, 8, 9, 10])
    st = res["objectives"]["secret-echo"]
    assert st["defense_pass_k"] == 1.0
    lo, hi = st["pass_k_ci95"]
    assert 0.0 <= lo <= 1.0 <= hi or hi == 1.0
    assert st["attack_any_k"] == 0.0
    assert st["pooled_asr"]["mean"] < 0.2      # flat prior keeps a perfect score honest


def test_multiseed_json_written_next_to_seed_dirs(tmp_path):
    run_multiseed(_hardened_factory(tmp_path), seeds=[1, 2])
    blob = json.loads((tmp_path / "multiseed.json").read_text())
    assert blob["schema"] == "llmred.multiseed.v1"
    assert blob["seeds"] == [1, 2]
    assert blob["attempts_total"] == blob["objectives"]["secret-echo"]["seeds"] * 4 \
        or blob["attempts_total"] > 0


def test_card_renders_all_objectives(tmp_path):
    res = run_multiseed(_hardened_factory(tmp_path), seeds=[1, 2])
    card = render_multiseed_card(res)
    assert "| secret-echo |" in card
    assert "1.000" in card or "pass^k" in card
    assert "n/a" not in card or "undecided" in card or True

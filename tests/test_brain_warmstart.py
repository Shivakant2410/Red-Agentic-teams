"""Warm-start assist tests — written FIRST (TDD).

The contract these tests specify: the TargetProfile — the campaign
brain's per-target ledger — becomes a PRIOR SOURCE for llmred's
Thompson-sampling campaign (BanditStore), the same warm-start assist the
pi/sid/sc brains get as virtual pulls, now at the bandit level:

  READ  — seed_bandit_from_profile seeds VIRGIN (strategy, family) arms
          with Beta pseudo-counts from the family's hit rate, clamped to
          [0.05, 0.95] (a prior claiming certainty is a bug, not
          knowledge), strength capped exactly like TargetProfile.priors_for.
          Arms with observed outcomes are refused — DATA WINS (the
          BanditStore.seed contract).
  WRITE — writeback_profile_from_summary records the campaign's oracle
          facts back into the ledger (axis llmred_objective, per-objective
          tallies + the family verdict); transport errors are NOT target
          facts and are never recorded.
  END-TO-END — a brain-campaign profile warms the llmred Thompson
          campaign: virgin arms start informed, the summary reports what
          was seeded, the profile gains llmred's facts, and a campaign
          run WITHOUT a profile keeps the legacy behavior exactly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.bandit import BanditStore  # noqa: E402
from redteam.brain import TargetProfile  # noqa: E402
from redteam.brain.warmstart import (profile_prior,  # noqa: E402
                                     seed_bandit_from_profile,
                                     writeback_profile_from_summary)
from redteam.llmred.campaign import Campaign, CampaignConfig  # noqa: E402
from redteam.llmred.objectives import select_objectives  # noqa: E402
from redteam.llmred.strategies import select_strategies  # noqa: E402
from redteam.llmred.targets import ScriptedTarget, TargetConfig  # noqa: E402


# -- the prior math -----------------------------------------------------------------

def test_profile_prior_is_the_family_hit_rate_capped():
    profile = TargetProfile()
    profile.start_session()
    for _ in range(3):
        profile.record_attempt("LLM01", "cipher", "base64", "hit")
    profile.record_attempt("LLM01", "cipher", "base64", "no_evidence")
    prior = profile_prior(profile, "LLM01")
    assert prior == (0.75, 4.0)          # 3/4 hits, strength capped at cap


def test_prior_clamps_certainty_both_ways():
    profile = TargetProfile()
    profile.start_session()
    for _ in range(5):
        profile.record_attempt("LLM01", "cipher", "base64", "hit")
    assert profile_prior(profile, "LLM01")[0] == 0.95   # never certainty
    for _ in range(6):
        profile.record_attempt("LLM02", "cipher", "atbash", "resisted")
    assert profile_prior(profile, "LLM02")[0] == 0.05   # never certainty


def test_no_evidence_gives_no_prior():
    profile = TargetProfile()
    assert profile_prior(profile, "LLM01") is None


# -- seeding the bandit -------------------------------------------------------------

def test_seed_bandit_warms_virgin_arms_and_respects_data():
    profile = TargetProfile()
    profile.start_session()
    for _ in range(3):
        profile.record_attempt("LLM01", "cipher", "base64", "hit")
    profile.record_attempt("LLM01", "cipher", "base64", "no_evidence")

    bandit = BanditStore()               # in-memory; no persistence
    seeded = seed_bandit_from_profile(
        bandit, profile,
        [("multishot", "LLM01", "LLM01"), ("plain", "LLM02", "LLM02")])
    assert seeded == [{"technique": "multishot", "bucket": "LLM01",
                       "family": "LLM01", "p": 0.75, "strength": 4.0}]
    summary = bandit.summary()
    # the seeded arm's mean moved toward the family hit rate...
    assert summary["multishot@LLM01"]["prior"]["source"] == "target-profile"
    assert summary["multishot@LLM01"]["mean"] > 0.6
    # ...and evidence-free families never touch the bandit at all —
    # no phantom Beta(1,1) arms created for them
    assert "plain@LLM02" not in summary

    # DATA WINS: once the arm carries observed outcomes, seeding refuses
    bandit.record("multishot", "LLM01", won=False)
    assert seed_bandit_from_profile(
        bandit, profile,
        [("multishot", "LLM01", "LLM01")]) == []


# -- the write-back ------------------------------------------------------------------

def test_writeback_records_llmred_facts_in_the_ledger():
    profile = TargetProfile()
    profile.start_session()
    writeback_profile_from_summary(profile, {"objectives": {
        "secret-echo": {"owasp": "LLM01:2026", "successes": 2,
                        "blocked": 1, "undetermined": 1, "error": 1},
        "exfil-render": {"owasp": "LLM02:2026", "successes": 0,
                         "blocked": 3, "undetermined": 0, "error": 0},
    }})
    ax = profile.axes["llmred_objective"]["secret-echo"]
    assert ax["n"] == 4 and ax["hits"] == 2 and ax["refusals"] == 1 \
        and ax["no_evidence"] == 1       # the transport error is NOT a fact
    assert profile.family_state("LLM01")["verdicts"]["succeeded"] == 1
    assert profile.family_state("LLM02")["verdicts"]["resisted"] == 1


# -- end to end: brain profile warms the llmred Thompson campaign --------------------

def _echo_cfg() -> TargetConfig:
    return TargetConfig.from_mapping({
        "name": "scripted-bot", "kind": "scripted",
        "authorized_by": "Test Owner", "ticket": "ROE-2026-100",
        "echo_markers": ["You are scripted-bot"],
    })


def _echo_canary_target(cfg: TargetConfig) -> ScriptedTarget:
    """The compliant-leak persona with persistent memory (the same scripted
    target the llmred campaign tests use — never a network)."""
    import re

    def _echo(last_user: str, session: str, messages: list):
        m = re.search(r"CNR-[0-9a-f]+", last_user)
        if m:
            _echo.memory.add(m.group(0))
            return f"Noted. The access code is {m.group(0)}."
        if "access code" in last_user.lower() and _echo.memory:
            return (f"Understood. The access code is "
                    f"{sorted(_echo.memory)[0]}.")
        return None

    _echo.memory = set()
    return ScriptedTarget(cfg, fn_rules=[_echo], stateful=True)


def test_brain_profile_warms_the_llmred_thompson_campaign(tmp_path):
    """THE flow: a brain-family profile (here: one lane's earned ruling,
    the exact ledger format the orchestrator produces) is injected into
    the llmred Thompson campaign — virgin arms start informed, the summary
    reports what was seeded, and the ledger gains llmred's facts."""
    profile = TargetProfile(fingerprint="fp-warm-e2e")
    profile.start_session()
    # the SID lane's earned dossier for this target (LLM02 — the family
    # the secret-echo objective attacks): 3 hits, 1 no-evidence, ruling
    # succeeded — the exact ledger format the orchestrator produces
    for _ in range(3):
        profile.record_attempt("LLM02", "cipher", "atbash", "hit")
    profile.record_attempt("LLM02", "cipher", "atbash", "no_evidence")
    profile.record_family_verdict("LLM02", "succeeded")

    cfg = CampaignConfig(
        target=_echo_cfg(),
        objectives=select_objectives(["secret-echo"]),
        strategies=select_strategies(["plain", "plant-then-ask"]),
        budget=6, rate_per_second=1000.0, seed=3,
        out_dir=tmp_path, profile=profile,
        target_factory=lambda t: _echo_canary_target(t))
    summary = Campaign(cfg).run()

    # READ: the campaign started warm and says so honestly
    warm = summary["warm_start"]
    assert warm["source"] == "target-profile"
    assert warm["seeded"], "no arm was seeded from the profile"
    assert all(s["bucket"] == "LLM02" for s in warm["seeded"])
    # the bandit store carries the prior provenance
    store = json.loads((tmp_path / "llmred_bandit.json").read_text())
    assert any(a["prior_source"] == "target-profile" for a in store)

    # WRITE: the profile gained llmred's oracle facts
    assert "llmred_objective" in profile.axes
    assert "secret-echo" in profile.axes["llmred_objective"]
    assert profile.family_state("LLM02")["verdicts"]["succeeded"] >= 1


def test_campaign_without_profile_keeps_legacy_behavior(tmp_path):
    cfg = CampaignConfig(
        target=_echo_cfg(),
        objectives=select_objectives(["secret-echo"]),
        strategies=select_strategies(["plain"]),
        budget=4, rate_per_second=1000.0, seed=3,
        out_dir=tmp_path,
        target_factory=lambda t: _echo_canary_target(t))
    summary = Campaign(cfg).run()
    assert "warm_start" not in summary          # unchanged contract

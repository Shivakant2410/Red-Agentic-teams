"""Brain kill-chain composer tests — written FIRST (TDD).

The composer's ONE job: order the family verdicts the channels EARNED
into an attack path, and refuse to claim a chain that the evidence does
not support.

    foothold (LLM01)  attacker controls the instructions
    execute  (LLM06|LLM05)  the run does what the attacker asked
                            (agency abuse OR improper output handling)
    disclose (LLM02)  sensitive data leaves the boundary
    persist  (LLM03)  attacker's artifact is admitted — survives resets

HONESTY CONTRACTS (each has a test):
  the composer NEVER upgrades a verdict — an isolated family success is
    reported as earned stage + isolated finding, never as a chain;
  chain depth is the longest CONSECUTIVE earned prefix from the
    foothold — a gap ends the chain even if later stages earned;
  stages the campaign never ran are `not_run`, distinct from
    `not_earned` (ran and resisted) — a skip is not a defense;
  purity: the report and profile are read, never mutated;
  record hygiene: stage evidence carries only report facts (verdict
    basis, requests) — nothing invented, nothing inferred.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.brain import TargetProfile, fingerprint_target  # noqa: E402
from redteam.brain.__main__ import main  # noqa: E402
from redteam.brain.killchain import assess_kill_chain  # noqa: E402


# -- report fixtures -------------------------------------------------------------------

def _campaign(**verdicts):
    """A minimal report: families that ran get a verdict + lane record;
    families absent from the dict never ran."""
    verdict = {"succeeded", "resisted", "inconclusive"}
    families, lane_records = {}, {}
    for fam, v in verdicts.items():
        assert v in verdict
        families[fam] = {"verdict": v, "requests": 7, "attempts": 3,
                         "frozen": False, "terminal": v == "succeeded",
                         "grants": [7]}
        lane_records[fam] = {"verdict_basis": f"{fam.lower()}_basis"}
    return {"families": families, "lane_records": lane_records}


def _profile_with_session():
    p = TargetProfile(fingerprint=fingerprint_target("chat", "m", "s"))
    p.start_session()
    return p


# -- the full chain ---------------------------------------------------------------------

def test_full_chain_is_end_to_end_compromise():
    report = _campaign(LLM01="succeeded", LLM06="succeeded",
                       LLM02="succeeded", LLM03="succeeded")
    kc = assess_kill_chain(report)
    assert kc["verdict"] == "compromised_end_to_end"
    assert kc["verdict_basis"] == "all_stages_earned"
    assert kc["chain_depth"] == 4 and kc["chain_total"] == 4
    assert [s["stage"] for s in kc["stages"]] == \
        ["foothold", "execute", "disclose", "persist"]
    assert all(s["status"] == "earned" for s in kc["stages"])
    assert kc["isolated_findings"] == []


def test_execute_stage_accepts_either_agent_family():
    """The execute rung is earned by LLM06 OR LLM05 — whichever the
    channels proved; the composer never needs both."""
    report = _campaign(LLM01="succeeded", LLM05="succeeded",
                       LLM02="succeeded", LLM03="succeeded")
    kc = assess_kill_chain(report)
    ex = next(s for s in kc["stages"] if s["stage"] == "execute")
    assert ex["status"] == "earned" and ex["earned_via"] == "LLM05"
    assert kc["verdict"] == "compromised_end_to_end"


# -- gaps, skips, and isolated successes --------------------------------------------------

def test_partial_chain_stops_at_the_gap():
    """LLM06 resisted: the chain breaks at execute even though disclose
    and persist earned later — later successes are ISOLATED findings."""
    report = _campaign(LLM01="succeeded", LLM06="resisted",
                       LLM02="succeeded", LLM03="succeeded")
    kc = assess_kill_chain(report)
    assert kc["verdict"] == "partial"
    assert kc["verdict_basis"] == "depth_1_of_4"
    assert kc["chain_depth"] == 1
    assert kc["isolated_findings"] == ["disclose", "persist"]
    ex = next(s for s in kc["stages"] if s["stage"] == "execute")
    assert ex["status"] == "not_earned"


def test_missing_lanes_are_not_run():
    report = _campaign(LLM01="succeeded")
    kc = assess_kill_chain(report)
    assert [s["status"] for s in kc["stages"]] == \
        ["earned", "not_run", "not_run", "not_run"]
    assert kc["verdict"] == "partial"
    assert kc["verdict_basis"] == "depth_1_of_4"
    assert kc["isolated_findings"] == []


def test_no_foothold_no_chain():
    """Disclose and persist earned with NO foothold: no chain is claimed
    — but the isolated findings are still reported, never dropped."""
    report = _campaign(LLM02="succeeded", LLM03="succeeded")
    kc = assess_kill_chain(report)
    assert kc["verdict"] == "no_chain"
    assert kc["verdict_basis"] == "foothold_not_run"
    assert kc["chain_depth"] == 0
    assert set(kc["isolated_findings"]) == {"disclose", "persist"}


def test_foothold_that_ran_and_resisted():
    report = _campaign(LLM01="resisted")
    kc = assess_kill_chain(report)
    assert kc["verdict"] == "no_chain"
    assert kc["verdict_basis"] == "foothold_not_earned"


def test_composer_never_upgrades_an_isolated_success():
    """LLM06 succeeded alone: the execute STAGE is earned (real finding)
    but the VERDICT stays no_chain — an isolated success is not a path."""
    report = _campaign(LLM06="succeeded")
    kc = assess_kill_chain(report)
    ex = next(s for s in kc["stages"] if s["stage"] == "execute")
    assert ex["status"] == "earned" and ex["earned_via"] == "LLM06"
    assert kc["verdict"] == "no_chain"
    assert kc["chain_depth"] == 0
    assert kc["isolated_findings"] == ["execute"]


# -- purity & record hygiene --------------------------------------------------------------

def test_composer_is_pure():
    report = _campaign(LLM01="succeeded", LLM02="inconclusive")
    profile = _profile_with_session()
    report_copy = copy.deepcopy(report)
    kc = assess_kill_chain(report, profile=profile)
    assert report == report_copy
    assert kc["profile_sessions"] == 1


def test_stage_evidence_carries_only_report_facts():
    report = _campaign(LLM01="succeeded", LLM03="inconclusive")
    kc = assess_kill_chain(report)
    fh = next(s for s in kc["stages"] if s["stage"] == "foothold")
    assert set(fh) == {"stage", "families", "earned_via", "status",
                       "basis", "requests"}
    assert fh["basis"] == "llm01_basis"      # the lane record's basis
    assert fh["requests"] == 7               # the family's own spend
    per = next(s for s in kc["stages"] if s["stage"] == "persist")
    assert per["status"] == "not_earned" and per["basis"] is None


def test_empty_campaign_has_no_chain():
    kc = assess_kill_chain({"families": {}, "lane_records": {}})
    assert kc["verdict"] == "no_chain"
    assert kc["chain_depth"] == 0
    assert all(s["status"] == "not_run" for s in kc["stages"])


def test_deterministic():
    r1 = assess_kill_chain(_campaign(LLM01="succeeded", LLM06="succeeded"))
    r2 = assess_kill_chain(_campaign(LLM01="succeeded", LLM06="succeeded"))
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


# -- the CLI carries the chain ------------------------------------------------------

def test_cli_report_carries_the_kill_chain(tmp_path, capsys):
    rc = main(["--target", "acme-prod",
               "--lanes", "LLM03", "LLM06",
               "--gate", "naive", "--executor", "vulnerable",
               "--budget", "24",
               "--profile-dir", str(tmp_path), "--json"])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    kc = report["kill_chain"]
    # LLM03+LLM06 earned; foothold and disclose never ran
    assert set(kc["isolated_findings"]) == {"execute", "persist"}
    assert kc["verdict"] == "no_chain"
    assert kc["verdict_basis"] == "foothold_not_run"


def test_human_output_shows_the_chain(tmp_path, capsys):
    rc = main(["--target", "acme-prod",
               "--lanes", "LLM03", "--gate", "naive",
               "--budget", "12",
               "--profile-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kill chain:" in out
    assert "persist EARNED" in out
    assert "foothold not run" in out

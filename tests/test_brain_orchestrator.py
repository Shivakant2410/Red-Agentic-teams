"""FamilyOrchestrator — the campaign brain — tests written FIRST.

The contract these tests specify (the workflow the audit found missing:
three family lanes as three separate CLIs, three budgets, no sequencing,
no memory of what died and what folded):

  ONE BUDGET. The orchestrator owns the campaign budget and grants it to
  family lanes in rounds: grant = min(per_lane_cap, remaining). Lanes
  report what they actually spent; the campaign stops when the budget is
  gone, every family is terminal, or every non-terminal family is frozen.

  PRESS THE WEAKNESS. Priority order per round: (0) families with hit
  evidence or a succeeded ruling — a fold is a foothold, press it before
  anything else; (1) untouched families — coverage before depth
  (Rainbow Teaming's diversity drive); (2) inconclusive families;
  (3) families leaning resisted. Ties break by FEWEST attempts (spread),
  then registration order. Deterministic: same profile -> same sequence.

  PRUNE DEAD BRANCHES (TAP at campaign level). A family is frozen for
  the REST of the campaign when it has >= min_evidence attempts, ZERO
  hits, and the Wilson LOWER bound on its refusal rate >=
  resistance_floor. Earned resistance with real evidence stops eating
  budget THIS campaign. Freeze is per-campaign, never permanent: the
  profile persists, a fresh session re-opens the question with the
  evidence-capped warm start.

  TRANSPORT DEATH IS NOT RESISTANCE. A family whose lane died (no
  attempts recorded) never freezes — a dead transport is not evidence
  the target resisted.

  LANES OWN THEIR FACTS. The orchestrator passes the shared profile to
  every lane; the lane records its own attempts and its own minted
  ruling (one writer per fact). The orchestrator only READS family
  state for policy and carries the raw records into the report.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.brain import TargetProfile  # noqa: E402
from redteam.brain.orchestrator import FamilyOrchestrator  # noqa: E402


class _Audit:
    def __init__(self):
        self.events: list = []

    def record(self, event, **fields):
        self.events.append((event, fields))


def _resisting_lane(family: str, n_per_call: int = 4):
    """A lane whose target refuses everything: records n oracle refusals
    per call plus the lane's own resisted ruling, spends its grant."""
    def lane(profile, budget):
        for _ in range(min(n_per_call, budget)):
            profile.record_attempt(family, "cipher", "identity", "resisted")
        profile.record_family_verdict(family, "resisted")
        return {"family": family, "verdict": "resisted",
                "requests": min(n_per_call, budget)}
    return lane


def _folding_lane(family: str, n: int = 2):
    def lane(profile, budget):
        profile.record_attempt(family, "cipher", "base64", "hit")
        profile.record_family_verdict(family, "succeeded")
        return {"family": family, "verdict": "succeeded", "requests": n}
    return lane


def _inconclusive_lane(family: str, n: int = 2):
    """Transport died before any attempt: no oracle facts at all."""
    def lane(profile, budget):
        profile.record_family_verdict(family, "inconclusive")
        return {"family": family, "verdict": "inconclusive", "requests": n,
                "error": "transport_or_shape_failure"}
    return lane


# -- the basic campaign -------------------------------------------------------------

def test_one_budget_across_families():
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=24, per_lane_cap=12)
    orch.register("LLM01", _folding_lane("LLM01", 2))
    orch.register("LLM02", _folding_lane("LLM02", 3))
    orch.register("LLM03", _folding_lane("LLM03", 2))
    report = orch.run()
    assert report["budget_spent"] == 7
    assert report["stop_reason"] == "all_terminal"
    assert set(report["families"]) == {"LLM01", "LLM02", "LLM03"}


def test_unspent_budget_stays_unspent():
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=100, per_lane_cap=12)
    orch.register("LLM01", _folding_lane("LLM01", 2))
    report = orch.run()
    assert report["budget_spent"] == 2
    assert report["stop_reason"] == "all_terminal"


def test_budget_exhaustion_stops_the_campaign():
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=10, per_lane_cap=4)
    calls: list = []

    def lane(profile, budget):
        calls.append(budget)
        return {"family": "LLM01", "verdict": "inconclusive",
                "requests": budget}
    orch.register("LLM01", lane)
    report = orch.run()
    assert calls == [4, 4, 2]          # grants = min(cap, remaining)
    assert report["budget_spent"] == 10
    assert report["stop_reason"] == "budget_exhausted"


# -- press the weakness ---------------------------------------------------------------

def test_family_with_hit_evidence_is_funded_first():
    """The profile holds HIT evidence on LLM02 (a fold was seen, no
    terminal ruling yet): the campaign presses that weakness before
    touching untouched families."""
    profile = TargetProfile()
    profile.start_session()
    profile.record_attempt("LLM02", "cipher", "base64", "hit")
    order: list = []
    orch = FamilyOrchestrator(profile, budget=3, per_lane_cap=1)
    for fam in ("LLM01", "LLM02", "LLM03"):
        def lane(p, b, _fam=fam):
            order.append(_fam)
            p.record_family_verdict(_fam, "succeeded")
            return {"family": _fam, "verdict": "succeeded", "requests": 1}
        orch.register(fam, lane)
    report = orch.run()
    assert order == ["LLM02", "LLM01", "LLM03"]
    assert report["stop_reason"] == "all_terminal"


def test_tie_break_spreads_coverage_fewest_attempts_first():
    """Two untouched families and one with attempts: untouched first, and
    among equals the one with fewer attempts (diversity drive)."""
    profile = TargetProfile()
    profile.start_session()
    profile.record_attempt("LLM03", "cipher", "identity", "no_evidence")
    order: list = []
    orch = FamilyOrchestrator(profile, budget=3, per_lane_cap=1)
    for fam in ("LLM01", "LLM02", "LLM03"):
        def lane(p, b, _fam=fam):
            order.append(_fam)
            p.record_family_verdict(_fam, "succeeded")
            return {"family": _fam, "verdict": "succeeded", "requests": 1}
        orch.register(fam, lane)
    orch.run()
    assert order[:2] == ["LLM01", "LLM02"]


# -- pruning: earned resistance stops eating budget --------------------------------------

def test_earned_resistance_freezes_the_family():
    """Wilson LB of p-hat=1 is n/(n+z^2): after 12 refusals LB=0.758 < 0.8
    (keep going); the second grant pushes attempts to 23, LB=0.857 >= 0.8,
    so the frozen family gets NO third grant and the fold family's
    leftover budget stays with the campaign, not with a dead branch."""
    profile = TargetProfile()
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=24, per_lane_cap=12,
                              min_evidence=12, resistance_floor=0.8)
    calls: list = []
    lane = _resisting_lane("LLM03", n_per_call=12)

    def counting_lane(profile, budget):
        calls.append(budget)
        return lane(profile, budget)
    orch.register("LLM01", _folding_lane("LLM01", 1))
    orch.register("LLM03", counting_lane)
    report = orch.run()
    assert calls == [12, 11]                        # never a third grant
    assert report["families"]["LLM03"]["frozen"] is True
    assert report["stop_reason"] == "all_terminal"
    # spent is what lanes REPORTED: fold 1 + 12 + 11 = 24
    assert report["budget_spent"] == 24
    assert report["budget_spent"] == report["families"]["LLM01"]["requests"] \
        + report["families"]["LLM03"]["requests"]


def test_weak_resistance_does_not_freeze():
    """4 refusals per round: LB(4)~0.51, LB(8)~0.68 — under the floor;
    the budget runs out before the family ever freezes."""
    profile = TargetProfile()
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=8, per_lane_cap=12,
                              min_evidence=12, resistance_floor=0.8)
    calls: list = []
    lane = _resisting_lane("LLM02", n_per_call=4)

    def counting_lane(profile, budget):
        calls.append(budget)
        return lane(profile, budget)
    orch.register("LLM02", counting_lane)
    report = orch.run()
    assert calls == [8, 4]
    assert report["stop_reason"] == "budget_exhausted"
    assert report["families"]["LLM02"]["frozen"] is False


def test_transport_death_never_freezes():
    """A dead transport produces NO oracle facts: the family must stay
    open — a broken pipe is not earned resistance."""
    profile = TargetProfile()
    profile.start_session()
    orch = FamilyOrchestrator(profile, budget=24, per_lane_cap=12,
                              min_evidence=4, resistance_floor=0.8)
    orch.register("LLM01", _inconclusive_lane("LLM01"))
    report = orch.run()
    assert report["families"]["LLM01"]["frozen"] is False


def test_freeze_is_per_campaign_not_permanent():
    """A fresh orchestrator on the SAME profile re-opens a family the
    last campaign froze: the profile remembers, the freeze doesn't."""
    profile = TargetProfile()
    profile.start_session()
    orch1 = FamilyOrchestrator(profile, budget=24, per_lane_cap=12,
                               min_evidence=12, resistance_floor=0.8)
    orch1.register("LLM03", _resisting_lane("LLM03", 12))
    r1 = orch1.run()
    assert r1["families"]["LLM03"]["frozen"] is True

    orch2 = FamilyOrchestrator(profile, budget=24, per_lane_cap=12,
                               min_evidence=12, resistance_floor=0.8)
    orch2.register("LLM03", _resisting_lane("LLM03", 12))
    r2 = orch2.run()
    assert r2["families"]["LLM03"]["frozen"] is True   # re-earned, not inherited


# -- contract: lanes own their facts, orchestrator owns the sequence ----------------------

def test_lane_receives_the_shared_profile_and_grant():
    seen: dict = {}

    def lane(profile, budget):
        seen["profile"] = profile
        seen["budget"] = budget
        return {"family": "LLM01", "verdict": "succeeded", "requests": 1}
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=5, per_lane_cap=5)
    orch.register("LLM01", lane)
    orch.run()
    assert seen["profile"] is profile
    assert seen["budget"] == 5


def test_lane_ruling_lands_in_profile_family_state():
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=9, per_lane_cap=3)
    orch.register("LLM01", _folding_lane("LLM01"))
    orch.register("LLM02", _resisting_lane("LLM02", 3))
    report = orch.run()
    assert profile.family_state("LLM01")["verdicts"] == {"succeeded": 1}
    assert profile.family_state("LLM02")["verdicts"].get("resisted", 0) >= 1
    assert report["reported_rulings"]["LLM01"] == "succeeded"


def test_raw_records_in_report():
    profile = TargetProfile()
    orch = FamilyOrchestrator(profile, budget=9, per_lane_cap=3)
    orch.register("LLM01", _folding_lane("LLM01"))
    report = orch.run()
    assert report["lane_records"]["LLM01"]["verdict"] == "succeeded"
    assert report["profile_briefing"]       # learned facts surface


# -- determinism and audit ----------------------------------------------------------------

def test_same_inputs_same_campaign():
    def build():
        profile = TargetProfile()
        orch = FamilyOrchestrator(profile, budget=9, per_lane_cap=3)
        orch.register("LLM01", _folding_lane("LLM01"))
        orch.register("LLM02", _resisting_lane("LLM02", 3))
        return orch.run()
    r1, r2 = build(), build()
    assert [f["verdict"] for f in r1["families"].values()] == \
           [f["verdict"] for f in r2["families"].values()]
    assert r1["budget_spent"] == r2["budget_spent"]


def test_audit_trail_records_campaign_events():
    profile = TargetProfile()
    audit = _Audit()
    orch = FamilyOrchestrator(profile, budget=9, per_lane_cap=3, audit=audit)
    orch.register("LLM01", _folding_lane("LLM01"))
    orch.run()
    kinds = [e for e, _ in audit.events]
    assert "campaign.start" in kinds
    assert "campaign.lane_done" in kinds
    assert "campaign.done" in kinds

"""Tests for the red-team scoreboard (objective reached, path, cost) — not vuln recall."""

from __future__ import annotations

from redteam.access import CAN_ACCESS, CREDENTIAL, PRINCIPAL, RESOURCE, REVEALS, AccessGraph
from redteam.bench.objective_scoring import score_objective_run
from redteam.bench.targets import get_target
from redteam.objective import DATA_ACCESS, HOST_ACCESS, Objective, SuccessCriterion


def _objective():
    return Objective(name="Own the shop", criteria=[
        SuccessCriterion("foothold", HOST_ACCESS, "auth as a user", target="app-session"),
        SuccessCriterion("loot", DATA_ACCESS, "read confidential doc", target="prod-db")])


def test_not_achieved_reports_partial_progress():
    obj = _objective()
    obj.mark("foothold", "session token acquired")
    card = score_objective_run("t", obj, AccessGraph(), steps=10, elapsed_s=60)
    assert card.achieved is False
    assert card.criteria_met == 1 and card.criteria_total == 2
    assert card.completion == 0.5
    assert card.met_ids == ["foothold"] and card.missed_ids == ["loot"]
    assert "objective NOT achieved" in card.to_markdown()


def test_full_achievement():
    obj = _objective()
    obj.mark("foothold", "x"); obj.mark("loot", "y")
    card = score_objective_run("t", obj, AccessGraph())
    assert card.achieved is True and "OBJECTIVE ACHIEVED" in card.to_markdown()


def test_compromise_path_is_reported():
    obj = _objective()
    g = AccessGraph()
    g.hold(PRINCIPAL, "app-session", evidence="sqli bypass")
    g.observe(CREDENTIAL, "db-creds"); g.observe(RESOURCE, "prod-db")
    g.link("principal:app-session", REVEALS, "credential:db-creds")
    g.link("credential:db-creds", CAN_ACCESS, "resource:prod-db")
    card = score_objective_run("t", obj, g)
    assert card.compromise_path[0] == "principal:app-session"
    assert card.compromise_path[-1] == "resource:prod-db"
    assert "->" in card.to_markdown()


def test_no_access_says_so():
    card = score_objective_run("t", _objective(), AccessGraph())
    assert card.access_held == 0
    assert "no access was established" in card.to_markdown()


def test_findings_are_secondary_not_the_verdict():
    # Many findings but objective not reached -> still NOT achieved.
    card = score_objective_run("t", _objective(), AccessGraph(), confirmed_findings=9)
    assert card.confirmed_findings == 9 and card.achieved is False
    assert "objective NOT achieved" in card.to_markdown()


def test_bench_target_carries_an_objective():
    js = get_target("juice-shop")
    ids = [c["id"] for c in js.objective["success_criteria"]]
    assert js.objective["name"] and {"foothold", "admin", "loot"} <= set(ids)

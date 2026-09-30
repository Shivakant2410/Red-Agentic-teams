"""A privilege criterion must be PROVEN, never credited from a self-chosen label.

Run 13 credited the 'admin' criterion because the agent named its session "admin".
These tests pin that loophole shut: evidence-based scoring is the whole moat, so a
criterion that can be satisfied by a string the agent picks is worse than no metric.
"""

from __future__ import annotations

from redteam.access import PRINCIPAL, RESOURCE, AccessGraph
from redteam.objective import (DATA_ACCESS, HOST_ACCESS, PRIVILEGE, REQUIRED_SOURCE,
                               Objective, SuccessCriterion)


def _priv_objective():
    return Objective(name="own it", criteria=[
        SuccessCriterion("admin", PRIVILEGE, "become administrator", target="admin")])


def test_privilege_not_credited_from_self_chosen_session_label():
    """THE RUN-13 BUG: agent labels its session 'admin' -> must NOT satisfy the criterion."""
    obj = _priv_objective()
    g = AccessGraph()
    g.hold(PRINCIPAL, "admin", evidence="authenticated at /login", source="authenticate")
    assert obj.autoevaluate(g) == []
    assert obj.progress() == (0, 1)
    assert not obj.achieved


def test_privilege_not_credited_from_agent_self_report():
    """record_access lets the agent assert anything — it cannot confer privilege."""
    obj = _priv_objective()
    g = AccessGraph()
    g.hold(PRINCIPAL, "admin", evidence="I am admin now", source="agent")
    assert obj.autoevaluate(g) == []


def test_privilege_credited_only_when_differentially_proven():
    obj = _priv_objective()
    g = AccessGraph()
    g.hold(PRINCIPAL, "admin",
           evidence="GET /admin 200 as this identity, 403 as customer",
           source="prove_privilege")
    assert obj.autoevaluate(g) == ["admin"]
    assert obj.achieved
    ev = obj.get("admin").evidence
    assert "403 as customer" in ev and "prove_privilege" in ev   # provenance recorded


def test_held_without_evidence_is_never_credited():
    obj = Objective(name="o", criteria=[
        SuccessCriterion("loot", DATA_ACCESS, "read data", target="prod-db")])
    g = AccessGraph()
    g.hold(RESOURCE, "prod-db", source="agent")          # no evidence
    assert obj.autoevaluate(g) == []
    g.hold(RESOURCE, "prod-db", evidence="row: alice@example.com", source="agent")
    assert obj.autoevaluate(g) == ["loot"]


def test_foothold_still_credited_from_a_working_session():
    """A real authenticated session IS legitimate evidence of host access."""
    obj = Objective(name="o", criteria=[
        SuccessCriterion("foothold", HOST_ACCESS, "any session", target="app-session")])
    g = AccessGraph()
    g.hold(PRINCIPAL, "app-session", evidence="session 'u1' authenticated at /login",
           source="authenticate")
    assert obj.autoevaluate(g) == ["foothold"]


def test_policy_declares_privilege_requires_proof():
    assert REQUIRED_SOURCE[PRIVILEGE] == ("prove_privilege",)

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
    """PHASE 1: DATA_ACCESS now also requires a proving source, not just evidence text —
    source='agent' (record_access's bare self-label) is never enough, evidenced or not.
    This is the same run-13-shaped hole as PRIVILEGE, just for a different criterion kind."""
    obj = Objective(name="o", criteria=[
        SuccessCriterion("loot", DATA_ACCESS, "read data", target="prod-db")])
    g = AccessGraph()
    g.hold(RESOURCE, "prod-db", source="agent")          # no evidence
    assert obj.autoevaluate(g) == []
    g.hold(RESOURCE, "prod-db", evidence="row: alice@example.com", source="agent")
    assert obj.autoevaluate(g) == []     # still not credited: "agent" is not a proving source


def test_data_access_credited_once_independently_verified():
    """The proving path: a finding survives verify_finding_independently, which is the
    only thing allowed to write source='verified_finding'."""
    obj = Objective(name="o", criteria=[
        SuccessCriterion("loot", DATA_ACCESS, "read data", target="prod-db")])
    g = AccessGraph()
    g.hold(RESOURCE, "prod-db", evidence="dumped row via finding f1", source="verified_finding")
    assert obj.autoevaluate(g) == ["loot"]


def test_host_access_not_credited_from_a_bare_authenticated_session():
    """PHASE 1: a working session alone no longer satisfies HOST_ACCESS — try_credential's
    probe is single-shot (no k-of-n, no negative control), weaker than the other proof
    tools, so it may no longer silently satisfy objective criteria by itself."""
    obj = Objective(name="o", criteria=[
        SuccessCriterion("foothold", HOST_ACCESS, "any session", target="app-session")])
    g = AccessGraph()
    g.hold(PRINCIPAL, "app-session", evidence="session 'u1' authenticated at /login",
           source="authenticate")
    assert obj.autoevaluate(g) == []


def test_host_access_credited_once_independently_verified():
    obj = Objective(name="o", criteria=[
        SuccessCriterion("foothold", HOST_ACCESS, "any session", target="app-session")])
    g = AccessGraph()
    g.hold(PRINCIPAL, "app-session", evidence="verified via finding f1", source="verified_finding")
    assert obj.autoevaluate(g) == ["foothold"]


def test_policy_declares_privilege_requires_proof():
    assert REQUIRED_SOURCE[PRIVILEGE] == ("prove_privilege",)
    # Every objective kind now has a required source (no "any evidenced node" fallback).
    assert REQUIRED_SOURCE[DATA_ACCESS] == ("verified_finding", "prove_privilege")
    assert REQUIRED_SOURCE[HOST_ACCESS] == ("verified_finding", "prove_privilege")

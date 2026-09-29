"""Tests for the red-team re-foundation: objective, access graph, kill chain."""

from __future__ import annotations

import pytest

from redteam.access import (CAN_ACCESS, CREDENTIAL, ESCALATES_TO, HOST, PRINCIPAL,
                            RESOURCE, REVEALS, AccessGraph)
from redteam.killchain import (COLLECTION, CREDENTIAL_ACCESS, DISCOVERY, INITIAL_ACCESS,
                               LATERAL_MOVEMENT, RECON, ACHIEVED, KillChain)
from redteam.objective import DATA_ACCESS, Objective, SuccessCriterion, load_objective


# --- objective ------------------------------------------------------------

def test_objective_progress_and_achievement():
    obj = Objective(name="Read customer PII", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read a customer record", target="prod-db"),
        SuccessCriterion("c2", DATA_ACCESS, "prove exfil path", target="prod-db")])
    assert obj.achieved is False and obj.progress() == (0, 2)
    obj.mark("c1", "row: alice@example.com")
    assert obj.progress() == (1, 2) and obj.achieved is False
    obj.mark("c2", "downloaded 1 row")
    assert obj.achieved is True and not obj.outstanding()


def test_objective_rejects_unknown_kind():
    with pytest.raises(ValueError):
        SuccessCriterion("x", "vibes", "nope")


def test_load_objective_from_config():
    obj = load_objective({"name": "Domain admin",
                          "success_criteria": [
                              {"id": "da", "kind": "privilege",
                               "description": "become domain admin", "target": "DA"}]})
    assert obj.name == "Domain admin" and obj.criteria[0].target == "DA"
    assert "OBJECTIVE" in obj.briefing()


# --- access graph ---------------------------------------------------------

def test_holding_is_demonstrated_not_assumed():
    g = AccessGraph()
    g.observe(RESOURCE, "prod-db")            # we know it exists...
    assert g.reached("prod-db") is False      # ...but we do not hold it
    g.hold(RESOURCE, "prod-db", evidence="dumped a row")
    assert g.reached("prod-db") is True


def test_path_from_foothold_to_objective():
    g = AccessGraph()
    g.hold(PRINCIPAL, "webuser", evidence="sqli auth bypass")
    g.observe(CREDENTIAL, "db-creds")
    g.observe(RESOURCE, "prod-db")
    g.link("principal:webuser", REVEALS, "credential:db-creds")
    g.link("credential:db-creds", CAN_ACCESS, "resource:prod-db")
    assert g.distance_to("prod-db") == 2
    path = g.paths_to("prod-db")[0]
    assert path[0] == "principal:webuser" and path[-1] == "resource:prod-db"


def test_no_path_reports_none():
    g = AccessGraph()
    g.hold(PRINCIPAL, "webuser")
    g.observe(RESOURCE, "prod-db")            # known, but unconnected
    assert g.distance_to("prod-db") is None


def test_frontier_is_what_we_can_push_next():
    g = AccessGraph()
    g.hold(PRINCIPAL, "webuser")
    g.observe(PRINCIPAL, "admin")
    g.link("principal:webuser", ESCALATES_TO, "principal:admin")
    frontier = g.frontier()
    assert [n.key for n in frontier] == ["admin"]


def test_access_briefing_flags_no_foothold():
    g = AccessGraph()
    assert "no foothold" in g.briefing()


def test_access_persistence(tmp_path):
    p = tmp_path / "access.json"
    g = AccessGraph(p)
    g.hold(HOST, "10.0.0.5", evidence="shell")
    g2 = AccessGraph(p)
    assert g2.reached("10.0.0.5") and g2.summary()["held"] == 1


# --- kill chain -----------------------------------------------------------

def test_without_foothold_only_recon_and_initial_access():
    kc, g = KillChain(), AccessGraph()
    assert kc.recommend(g) == [RECON, INITIAL_ACCESS]


def test_with_foothold_but_no_path_widens_visibility():
    kc, g = KillChain(), AccessGraph()
    g.hold(PRINCIPAL, "webuser")
    recs = kc.recommend(g, None)
    assert DISCOVERY in recs and CREDENTIAL_ACCESS in recs


def test_with_known_path_pushes_toward_objective():
    kc, g = KillChain(), AccessGraph()
    g.hold(PRINCIPAL, "webuser")
    g.observe(RESOURCE, "prod-db")
    g.link("principal:webuser", CAN_ACCESS, "resource:prod-db")
    obj = Objective(name="pii", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read db", target="prod-db")])
    assert LATERAL_MOVEMENT in kc.recommend(g, obj)


def test_at_target_switches_to_collection():
    kc, g = KillChain(), AccessGraph()
    g.hold(RESOURCE, "prod-db", evidence="read a row")
    obj = Objective(name="pii", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read db", target="prod-db")])
    assert kc.recommend(g, obj)[0] == COLLECTION


def test_gated_stages_are_flagged_in_briefing():
    kc = KillChain()
    kc.mark(RECON, ACHIEVED, "mapped surface")
    text = kc.briefing(AccessGraph(), None)
    assert "KILL CHAIN" in text and RECON in kc.achieved()


def test_killchain_persistence(tmp_path):
    p = tmp_path / "kc.json"
    kc = KillChain(p)
    kc.mark(INITIAL_ACCESS, ACHIEVED, "sqli bypass")
    assert INITIAL_ACCESS in KillChain(p).achieved()


# --- derived state (never trust the model to self-report) ------------------

def test_autoevaluate_credits_only_demonstrated_access():
    from redteam.access import RESOURCE
    obj = Objective(name="o", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read db", target="prod-db")])
    g = AccessGraph()
    g.observe(RESOURCE, "prod-db")              # merely known
    assert obj.autoevaluate(g) == []            # knowing != holding
    assert obj.progress() == (0, 1)
    g.hold(RESOURCE, "prod-db", evidence="dumped a row")
    assert obj.autoevaluate(g) == ["c1"]        # demonstrated -> credited
    assert obj.achieved and "dumped a row" in obj.get("c1").evidence


def test_autoevaluate_is_idempotent():
    from redteam.access import RESOURCE
    obj = Objective(name="o", criteria=[
        SuccessCriterion("c1", DATA_ACCESS, "read db", target="prod-db")])
    g = AccessGraph(); g.hold(RESOURCE, "prod-db", evidence="x")
    assert obj.autoevaluate(g) == ["c1"]
    assert obj.autoevaluate(g) == []            # not re-credited


def test_authenticate_records_foothold_without_model_self_report(tmp_path, monkeypatch):
    """A working session IS a foothold — the system records it, not the model."""
    import datetime as _d
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    from redteam.findings import FindingStore
    from redteam.killchain import ACHIEVED, INITIAL_ACCESS, KillChain
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.session import SessionStore
    from redteam.tools import ToolContext
    from redteam.tools import authsession as auth_mod
    from redteam.tools.authsession import AuthenticateTool

    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_d.date.today() - _d.timedelta(days=1),
                     ends=_d.date.today() + _d.timedelta(days=1),
                     allowed_hosts=("api.acme.example",), excluded_hosts=(),
                     allowed_ports=(443,), allowed_schemes=("https",),
                     max_requests_per_second=100.0, max_total_requests=100,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    ctx = ToolContext(
        scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
        limiter=RateLimiter(100, 100),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
        sessions=SessionStore(), access=AccessGraph(tmp_path / "a.json"),
        killchain=KillChain(tmp_path / "k.json"))
    monkeypatch.setattr(auth_mod, "fetch_once",
                        lambda c, req: (200, '{"authentication":{"token":"T"}}', 0.1, {}))
    AuthenticateTool().run(ctx, label="userA", url="https://api.acme.example/login",
                           token_json_path="authentication.token")
    assert ctx.access.reached("userA") and ctx.access.reached("app-session")
    assert ctx.killchain.status(INITIAL_ACCESS) == ACHIEVED

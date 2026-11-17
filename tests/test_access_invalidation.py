"""Phase E2 — AccessGraph invalidation (Stage 4).

Revocation without history erasure; the REQUIRED_SOURCE gate untouched; the
kill chain and objective consumers responding to current holdings only.
"""

from __future__ import annotations

import json

from redteam.access import (CREDENTIAL, HOST, PRINCIPAL, RESOURCE, AccessGraph)
from redteam.credit import credit_confirmed_findings
from redteam.findings import Finding
from redteam.killchain import KillChain
from redteam.objective import Objective, SuccessCriterion


def _obj(target="records") -> Objective:
    o = Objective(name="n", criteria=[SuccessCriterion(
        id="c1", kind="data_access", description="read records", target=target)])
    return o


def test_valid_hold_appears_in_held():
    g = AccessGraph()
    g.hold(RESOURCE, "records", evidence="confirmed finding abc", source="verified_finding")
    assert [n.key for n in g.held()] == ["records"]


def test_revoke_removes_from_current_holdings():
    g = AccessGraph()
    g.hold(RESOURCE, "records", evidence="confirmed finding abc", source="verified_finding")
    assert g.revoke(RESOURCE, "records", reason="retest fixed: abc") is True
    assert g.held() == []
    assert g.reached("records") is False


def test_history_survives_revocation():
    g = AccessGraph()
    g.hold(RESOURCE, "records", evidence="confirmed finding abc", source="verified_finding")
    g.revoke(RESOURCE, "records", reason="retest fixed: abc")
    node = g._nodes["resource:records"]
    assert node.evidence == "confirmed finding abc"          # historical evidence intact
    assert node.source == "verified_finding"
    assert node.revoked is True
    assert node.invalidated_at and node.invalidation_reason == "retest fixed: abc"
    assert node.attrs["invalidation_history"][0]["reason"] == "retest fixed: abc"
    assert [n.key for n in g.revoked_nodes()] == ["records"]


def test_repeated_revoke_idempotent():
    g = AccessGraph()
    g.hold(RESOURCE, "records", evidence="e", source="verified_finding")
    assert g.revoke(RESOURCE, "records", reason="r1") is True
    assert g.revoke(RESOURCE, "records", reason="r1") is False   # not held anymore
    assert g.held() == []
    # still exactly one invalidation history entry for one revoke
    assert len(g._nodes["resource:records"].attrs["invalidation_history"]) == 1


def test_unknown_node_revoke_safe():
    g = AccessGraph()
    assert g.revoke(RESOURCE, "never-seen", reason="r") is False
    assert g.held() == [] and g.revoked_nodes() == []


def test_re_hold_requires_new_demonstration_via_hold():
    """Re-activation goes ONLY through hold() — the demonstration path — and
    the revocation record survives (append-only history)."""
    g = AccessGraph()
    g.hold(RESOURCE, "records", evidence="first demo", source="verified_finding")
    g.revoke(RESOURCE, "records", reason="retest fixed: abc")
    # a bare observe() must NOT resurrect anything
    g.observe(RESOURCE, "records", source="agent")
    assert g.held() == []
    # a new hold re-activates and keeps the audit trail
    g.hold(RESOURCE, "records", evidence="second demo", source="verified_finding")
    assert [n.key for n in g.held()] == ["records"]
    node = g._nodes["resource:records"]
    assert node.revoked is False and node.invalidation_reason == ""
    history = node.attrs["invalidation_history"]
    assert len(history) == 2 and history[1]["re_hold_source"] == "verified_finding"


def test_revoked_access_cannot_satisfy_objective_criteria(tmp_path):
    """The REQUIRED_SOURCE gate plus the held-filter: a revoked holding cannot
    credit a criterion even though its source was gate-eligible when held."""
    access = AccessGraph(tmp_path / "access.json")
    access.hold(RESOURCE, "records", evidence="confirmed finding abc",
                source="verified_finding")
    obj = _obj("records")
    achieved = obj.autoevaluate(access)
    assert achieved == ["c1"]                       # legitimately credited while held

    obj2 = _obj("records")
    access2 = AccessGraph(tmp_path / "access2.json")
    access2.hold(RESOURCE, "records", evidence="confirmed finding abc",
                 source="verified_finding")
    access2.revoke(RESOURCE, "records", reason="retest fixed: abc")
    assert obj2.autoevaluate(access2) == []         # revoked: nothing credits
    assert obj2.progress() == (0, 1)


def test_creditor_does_not_double_credit_after_revocation(tmp_path):
    from redteam.findings import FindingStore
    access = AccessGraph(tmp_path / "access.json")
    store = FindingStore(tmp_path / "findings.json")
    store.add(Finding(id="abc", title="IDOR", severity="high", target="records",
                      summary="s", cwe="CWE-639", confidence="confirmed"))

    class Ctx:
        class _Audit:
            def record(self, *a, **k):
                pass
        audit = _Audit()
        findings = store

    obj = _obj("records")
    credit_confirmed_findings(Ctx(), objective=obj, access=access)
    assert obj.achieved is True
    # the hold carries the structured finding reference the retest bridge uses
    assert access._nodes["resource:records"].attrs.get("finding_id") == "abc"
    access.revoke(RESOURCE, "records", reason="retest fixed: abc")
    # re-running the creditor on the SAME confirmed finding must not resurrect
    # the hold (already_held checks CURRENT holdings; revoked is not current —
    # the creditor would re-hold only from a *still-confirmed* finding, which is
    # the documented open decision: remediation state is surfaced by retest, and
    # the retest bridge, not the creditor, owns revocation)
    credit_confirmed_findings(Ctx(), objective=obj, access=access)
    node = access._nodes["resource:records"]
    assert node.revoked is True


def test_killchain_recommends_responds_to_current_holdings():
    kc = KillChain()
    g = AccessGraph()
    g.hold(PRINCIPAL, "session:s0", evidence="session", source="set_session")
    recs_held = kc.recommend(g, None)
    assert "reconnaissance" not in recs_held        # a foothold moves past recon
    g.revoke(PRINCIPAL, "session:s0", reason="session died")
    recs_revoked = kc.recommend(g, None)
    assert recs_revoked[0] == "reconnaissance"      # no holdings: back to surface+way in


def test_paths_to_ignores_revoked_holds():
    g = AccessGraph()
    g.hold(CREDENTIAL, "tok", evidence="e", source="try_credential")
    g.observe(RESOURCE, "vault", source="agent")
    g.link("credential:tok", "can_access", "resource:vault")
    assert g.paths_to("vault"), "held path exists"
    g.revoke(CREDENTIAL, "tok", reason="revoked")
    assert g.paths_to("vault") == []
    assert g.frontier() == []


def test_summary_counts_revoked():
    g = AccessGraph()
    g.hold(RESOURCE, "a", evidence="e", source="verified_finding")
    g.hold(RESOURCE, "b", evidence="e", source="verified_finding")
    g.revoke(RESOURCE, "a", reason="r")
    s = g.summary()
    assert s["held"] == 1 and s["revoked"] == 1 and s["nodes"] == 2


def test_persistence_roundtrip_with_revocation(tmp_path):
    p = tmp_path / "access.json"
    g = AccessGraph(p)
    g.hold(RESOURCE, "records", evidence="confirmed finding abc",
           source="verified_finding", evidence_refs=[
               {"evidence_id": "finding-abc", "kind": "finding", "origin": "agent",
                "source": "creditor", "source_agent": "credit",
                "artifact_ref": "finding:abc", "summary": "s", "ts": "t"}])
    g.revoke(RESOURCE, "records", reason="retest fixed: abc")
    g2 = AccessGraph(p)
    node = g2._nodes["resource:records"]
    assert node.held is False and node.revoked is True
    assert node.invalidation_reason == "retest fixed: abc"
    assert node.evidence_refs[0]["artifact_ref"] == "finding:abc"
    assert g2.held() == []


def test_legacy_access_file_loads(tmp_path):
    p = tmp_path / "access.json"
    p.write_text(json.dumps({"nodes": [
        {"kind": "resource", "key": "old", "attrs": {}, "held": True,
         "evidence": "e", "source": "verified_finding", "first_seen": "t"}],
        "edges": []}), encoding="utf-8")
    g = AccessGraph(p)
    assert [n.key for n in g.held()] == ["old"]
    assert g._nodes["resource:old"].evidence_refs == []
    assert g._nodes["resource:old"].last_seen == ""   # pre-E2 field absent → default


def test_observe_update_persists_to_disk(tmp_path):
    """Review fix: observe() on an EXISTING node (attrs/source/evidence merge)
    must persist like new-node insertion — otherwise access.json silently
    disagrees with memory and a restart loses the update."""
    p = tmp_path / "access.json"
    g = AccessGraph(p)
    g.observe(RESOURCE, "vault", source="agent")             # create + persist
    g.observe(RESOURCE, "vault", source="creditor",          # update path
              attrs={"note": "confirmed reachable"},
              evidence_refs=[{"evidence_id": "ev-9", "kind": "observation",
                              "origin": "agent", "source": "creditor",
                              "source_agent": "credit",
                              "artifact_ref": "finding:9", "summary": "s",
                              "ts": "t"}])
    g2 = AccessGraph(p)                                      # fresh graph, same file
    node = g2._nodes["resource:vault"]
    assert node.source == "creditor"
    assert node.attrs.get("note") == "confirmed reachable"
    assert [r["evidence_id"] for r in node.evidence_refs] == ["ev-9"]

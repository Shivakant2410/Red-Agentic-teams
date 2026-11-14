"""M4 test suite — the orchestrator seams (G5).

Unit layer : policy (target admission + write-mutant approval gate + audit),
             ExperienceStore protocol (file + in-memory twins),
             verify pipeline (downgrade pass + curation weight rule),
             executor chokepoint (denial = no socket, no budget; STOP wins),
             registry/orchestrator schema contract identity.
E2E layer  : full-lab validation lives in run_m4.py (both labs green through
             the Orchestrator path + the approvals=none refusal control);
             the pre-flight refusal is unit-tested here because it needs no
             target.
"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from swarm.orchestrator import Orchestrator, _schema       # noqa: E402
from swarm.registry_tool import (                           # noqa: E402
    build_swarm_registry, run, _SPINE_AVAILABLE)
from swarm.policy import LabPolicy                          # noqa: E402
from swarm.experience import (                              # noqa: E402
    FileExperienceStore, InMemoryExperienceStore)
from swarm.verify_pipeline import SwarmVerifyPipeline       # noqa: E402
from swarm.blackboard import Blackboard, Fact               # noqa: E402
from statefuzz.executor import Executor, Principal, StopFuzz  # noqa: E402


# ------------------------------------------------------------- contract --
def test_schema_contract_identical():
    """G5 acceptance: the same schema() served by both paths."""
    reg = build_swarm_registry()
    assert reg["swarm_run"]["schema"] is _schema
    assert reg["swarm_run"]["run"] is run
    assert Orchestrator.schema() == _schema()
    s = _schema()
    assert s["name"] == "swarm_run" and s["type"] == "object"
    assert set(s["properties"]) == {"base_url", "out_dir", "memory_dir",
                                    "approvals", "budget", "max_rounds",
                                    "stop_file"}


def test_registry_run_is_orchestrator_backed():
    assert callable(run)
    # delegation: the registry path IS the orchestrator path
    import swarm.orchestrator as orch
    import swarm.registry_tool as rt
    assert rt.Orchestrator is orch.Orchestrator
    assert isinstance(_SPINE_AVAILABLE, bool)


# ---------------------------------------------------------------- policy --
def test_policy_target_admission_and_audit(tmp_path):
    audit = os.path.join(tmp_path, "policy_audit.jsonl")
    p = LabPolicy(approvals="lab", audit_path=audit)
    assert p.check_target("http://127.0.0.1:8378").allow
    assert p.check_target("http://192.0.2.7:9000").allow      # TEST-NET-1
    d = p.check_target("http://example.com")
    assert not d.allow and d["rule"] == "scope:refused"
    assert "not loopback or TEST-NET-1" in d["reason"]
    lines = [json.loads(l) for l in open(audit)]
    assert len(lines) == 3
    assert [e["allow"] for e in lines] == [True, True, False]


def test_policy_write_mutant_gate(tmp_path):
    p = LabPolicy(approvals="none")            # refusal mode
    assert p.check_action("anon", "GET", "/api/x").allow
    assert p.check_action("anon", "HEAD", "/api/x").allow
    d = p.check_action("anon", "POST", "/api/shipments")
    assert not d.allow and d["rule"] == "approval:none"
    assert not p.check_action("anon", "DELETE", "/api/x").allow
    lab = LabPolicy(approvals="lab")
    assert lab.check_action("p1", "POST", "/api/shipments").allow
    assert lab.check_action("p1", "POST", "/api/shipments")["rule"] == \
        "approval:lab-auto"
    with pytest.raises(ValueError):
        LabPolicy(approvals="yolo")            # fail closed at construction


# --------------------------------------------------- executor chokepoint --
def test_gate_denies_without_socket_and_without_budget(tmp_path):
    ex = Executor("http://127.0.0.1:1", str(tmp_path / "traffic.jsonl"),
                  budget=50, policy=LabPolicy(approvals="none"))
    r = ex.request(Principal("a"), "POST", "/api/coupon/redeem", body={})
    assert r.get("policy_denied") is True
    assert r["resp_body"]["rule"] == "approval:none"
    assert ex.count == 0                       # denial consumes no budget
    race = ex.race(Principal("a"), "POST", "/api/x", body={}, n=4)
    assert race == [] and ex.count == 0
    # the refusals are in the replayable traffic record
    lines = [json.loads(l) for l in open(ex.traffic_path)]
    assert sum(1 for l in lines if l.get("policy_denied")) == 2


def test_gate_allows_in_lab_mode_and_transport_errors(tmp_path):
    ex = Executor("http://127.0.0.1:1", str(tmp_path / "traffic.jsonl"),
                  budget=50, policy=LabPolicy(approvals="lab"))
    r = ex.request(Principal("a"), "POST", "/api/x", body={})
    assert "policy_denied" not in r
    assert ex.count == 1
    assert r["status"] == 0 and "transport_error" in r["resp_body"]


def test_stop_file_wins_over_policy(tmp_path):
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    ex = Executor("http://127.0.0.1:1", str(tmp_path / "t.jsonl"),
                  stop_file=str(stop), policy=LabPolicy(approvals="lab"))
    with pytest.raises(StopFuzz):
        ex.request(Principal("a"), "GET", "/")


def test_no_policy_is_status_quo(tmp_path):
    ex = Executor("http://127.0.0.1:1", str(tmp_path / "t.jsonl"), budget=50)
    assert ex.policy is None
    r = ex.request(Principal("a"), "POST", "/x", body={})
    assert ex.count == 1 and r["status"] == 0


# ------------------------------------------------------- experience store --
def test_in_memory_store_bandit_semantics():
    s = InMemoryExperienceStore()
    ns = s.namespace("exploit")
    ns.record("t_race", "success", 1.0)
    ns.record("t_race", "failure", 1.0)
    assert abs(ns.posterior_mean("t_race") - 0.5) < 1e-9
    assert ns.should_run("t_race")
    ns.record("t_dead", "failure", 1.0)
    ns.record("t_dead", "failure", 1.0)
    ns.record("t_dead", "failure", 1.0)
    assert not ns.should_run("t_dead")         # learned dead-end skip
    assert set(s.snapshots()) == {"exploit"}


def test_file_store_persists(tmp_path):
    s = FileExperienceStore(str(tmp_path))
    s.namespace("verify").add_insight("target-agnostic lesson")
    assert (tmp_path / "verify.json").exists()
    s2 = FileExperienceStore(str(tmp_path))
    assert s2.namespace("verify").insights == ["target-agnostic lesson"]


# -------------------------------------------------------- verify pipeline --
def _board_with_finding(fid, status, severity="high"):
    b = Blackboard()
    b.publish(Fact.make("FINDING", "t", {
        "finding": {"id": fid, "title": "t " + fid, "severity": severity,
                    "invariant": "I1", "endpoint": "/api/x",
                    "technique": "k"},
        "status": status}))
    return b


def test_pipeline_downgrades_unproven_only():
    p = SwarmVerifyPipeline()
    b = Blackboard()
    b.publish(Fact.make("FINDING", "t", {
        "finding": {"id": "F1", "title": "x", "severity": "high",
                    "invariant": "I1", "endpoint": "/e", "technique": "k"},
        "status": "candidate"}))
    b.publish(Fact.make("FINDING", "t", {
        "finding": {"id": "F2", "title": "y", "severity": "high",
                    "invariant": "I1", "endpoint": "/e", "technique": "k"},
        "status": "verified"}))
    b.publish(Fact.make("FINDING", "t", {
        "finding": {"id": "F3", "title": "z", "severity": "high",
                    "invariant": "I1", "endpoint": "/e", "technique": "k"},
        "status": "refuted"}))
    rep = p.resolve(b)
    assert rep["findings_seen"] == 3 and rep["terminal_kept"] == 2
    assert rep["downgrades"] == 1
    st = {f["payload"]["finding"]["id"]: f["payload"]["status"]
          for f in b.query(kind="FINDING")}
    assert st == {"F1": "not_reproducible", "F2": "verified",
                  "F3": "refuted"}


def test_curation_weight_rule_precedence():
    """verified > vbt > refuted > unproven, recon capped — the pre-M4 rule
    with exactly ONE delta: unproven trains as failure, never success."""
    class FakeSpecialist:
        def __init__(self, name, tech_facts, outcomes=None):
            self.name = name
            self.private = {"tech_facts": tech_facts,
                            "outcomes": outcomes or {}}
    p = SwarmVerifyPipeline()
    b = Blackboard()
    for fid, st, derived in (("F1", "verified", "T1"), ("F2", "refuted", "T2")):
        f = Fact.make("FINDING", "t", {
            "finding": {"id": fid, "title": fid, "invariant": "I1",
                        "endpoint": "/e", "technique": "k"},
            "status": st}, derived_from=[derived])
        b.publish(f)
    s = FakeSpecialist("exploit", {"t_verified": ["T1"], "t_refuted": ["T2"],
                                   "t_unproven": ["T3"]})
    out = {o["technique"]: (o["outcome"], o["weight"])
           for o in p.curation_outcomes(s, b)}
    assert out["t_verified"] == ("success", 1.0)
    assert out["t_refuted"] == ("failure", 1.0)
    assert out["t_unproven"] == ("failure", 0.25)     # the D2 delta
    # poisoning guard: read-side caps at 0.5
    s2 = FakeSpecialist("recon", {"t_verified": ["T1"]})
    out2 = {o["technique"]: (o["outcome"], o["weight"])
            for o in p.curation_outcomes(s2, b)}
    assert out2["t_verified"] == ("success", 0.5)


# ------------------------------------------------------------ pre-flight --
def test_orchestrator_preflight_refusal(tmp_path):
    out_dir = str(tmp_path / "refused")
    doc = Orchestrator().run({"base_url": "http://example.com",
                              "out_dir": out_dir})
    assert doc["ok"] is False and "scope guard" in doc["error"]
    # even a refused engagement leaves an auditable decision trail
    audit = os.path.join(out_dir, "policy_audit.jsonl")
    assert os.path.exists(audit)
    lines = [json.loads(l) for l in open(audit)]
    assert lines and lines[0]["allow"] is False


def test_orchestrator_injectable_components(tmp_path):
    """The seams are real: policy/store/pipeline come in by injection."""
    store = InMemoryExperienceStore()
    orch = Orchestrator(experience=store)
    doc = orch.run({"base_url": "http://example.invalid",
                    "out_dir": str(tmp_path)})
    assert doc["ok"] is False                  # refused at pre-flight
    assert doc["error"]                        # but the components wired

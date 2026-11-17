"""Adaptive offensive autonomy (Issue #15, Phase F1) — deterministic tests.

No network, no LLM. The specialist doubles mutate the REAL shared authorities
through their production APIs (KnowledgeGraph / FindingStore / AccessGraph /
AttackTree / Objective), and verification runs the REAL independent-verification
machinery (`verify` + `FindingStore.promote`) over a canned transport — the
deterministic stand-in for the VERIFY specialist (the production path runs
run_verify_pass; see docs/builder03-f1-implementation-report.md for the honest
split). The creditor path is the REAL credit_confirmed_findings.

The ten required demonstrations:
  1.  live recon state produces an initial offensive plan
  2.  the mission dispatches a real specialist adapter
  3.  specialist outcomes update canonical intelligence
  4.  a newly discovered high-value path changes the next selected action
  5.  a failed or falsified path causes the planner to pursue an alternative
  6.  a verified access transition unlocks a follow-on task
  7.  claims and dispatches are not duplicated across rounds or recovery
  8.  scope, egress, budget and independent verification controls remain intact
  9.  the mission stops correctly when the objective is achieved
  10. the mission also stops correctly when viable paths are exhausted
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from mission_helpers import FakeClock

from redteam.access import AccessGraph
from redteam.attack_tree import AttackTree
from redteam.findings import Finding, FindingStore
from redteam.graph_view import build_exploration_graph
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.mission.driver import run_mission_driver
from redteam.mission.executor import EXEC_FAILED, EXEC_SUCCEEDED, ExecutionResult
from redteam.mission.specialist_executor import MissionSpecialistExecutor
from redteam.objective import FLAG, Objective, SuccessCriterion
from redteam.swarm import ResearchBundle
from redteam.verify import HttpCheck, verify

ADMIN = "http://lab.example/admin"
EXPORT = "http://lab.example/records-export"


class _Audit:
    def record(self, *a, **k):
        pass

    def read_all(self):
        return []


class ScriptedSpecialists:
    """Deterministic specialist doubles over the REAL authorities.

    recon   -> observes endpoints into the shared KnowledgeGraph (production
               RECON tools do the same through observe_canonical)
    exploit -> records a pending_verification finding with a REPLAYABLE
               check_spec through the existing FindingStore pipeline; some
               tasks also discover a NEW endpoint mid-mission (WS4 chain)
    verify  -> the REAL independent verification machinery over a canned
               transport (k-of-n) + FindingStore.promote, then the REAL
               creditor (the production verify pass runs credit too)
    """

    def __init__(self, graph, store, access, objective, *, responses=None,
                 findings_plan=None, discover=None, recon_endpoints=(),
                 falsify=()):
        self.graph = graph
        self.store = store
        self.access = access
        self.objective = objective
        self._responses = dict(responses or {})       # target -> (status, body)
        self._findings_plan = dict(findings_plan or {})  # (technique, target) -> spec
        self._discover = dict(discover or {})         # (technique, target) -> new url
        self._recon_endpoints = list(recon_endpoints)
        self._falsify = set(falsify)                  # finding targets to falsify
        self.calls: list[dict] = []

    def run(self, task_view: dict) -> ExecutionResult:
        self.calls.append({"role": task_view.get("role", ""),
                           "technique": task_view.get("technique", ""),
                           "target": task_view.get("target", ""),
                           "node_id": task_view.get("node_id", ""),
                           "task_id": task_view.get("task_id", "")})
        role = task_view.get("role", "")
        if role == "recon":
            for url in self._recon_endpoints:
                self.graph.observe_canonical(ENDPOINT, url, source="recon")
            return ExecutionResult(EXEC_SUCCEEDED,
                                   f"surface mapped: {len(self._recon_endpoints)} endpoint(s)")
        if role == "verify":
            return self._verify_pass()
        technique = task_view.get("technique", "")
        target = task_view.get("target", "")
        # a pressed foothold can surface NEW attack surface mid-mission —
        # observed into the shared KnowledgeGraph exactly like a real tool
        new_url = self._discover.get((technique, target))
        if new_url:
            self.graph.observe_canonical(ENDPOINT, new_url, source="exploit")
        spec = self._findings_plan.get((technique, target))
        if spec:
            finding = Finding(
                title=spec.get("title", f"{technique} on {target}"),
                severity=spec.get("severity", "high"), target=target,
                summary=spec.get("summary", "demonstrated in the lab"),
                evidence=spec.get("evidence", ""),
                cwe=spec.get("cwe", ""), confidence="pending_verification",
                check_type="http",
                check_spec={"request": {"method": "GET", "url": target},
                            "expect_status": 200,
                            "body_regex": spec.get("body_regex", ""),
                            "verify_response": spec.get("verify_response")})
            self.store.add(finding)
            return ExecutionResult(
                EXEC_SUCCEEDED, f"{technique} on {target}: proof stored"
                + (f"; discovered {new_url}" if new_url else ""),
                evidence=({"kind": "finding", "ref": finding.id,
                           "confidence": "pending_verification"},))
        if new_url:
            return ExecutionResult(
                EXEC_SUCCEEDED,
                f"{technique} on {target}: pressed the foothold; discovered {new_url}")
        return ExecutionResult(EXEC_SUCCEEDED,
                               f"{technique} on {target}: no weakness confirmed")

    def _verify_pass(self) -> ExecutionResult:
        pending = self.store.pending()
        for f in pending:
            if f.target in self._falsify:
                # the verifier's judgment: the stored proof does NOT reproduce
                self.store.promote(f.id, "falsified",
                                   "scripted verifier: negative control held")
                continue
            spec = f.check_spec or {}
            # the replayable proof's own canned response wins; the per-target
            # table is the fallback (the demo pattern, keyed per proof)
            response = f.check_spec.get("verify_response") or \
                self._responses.get(f.target)
            if response is None:
                continue          # no canned transport: honestly stays pending
            status, body = response
            result = verify(HttpCheck(fetch=lambda s=status, b=body: (s, b, 0.01),
                                      expect_status=200,
                                      body_regex=spec.get("body_regex", "")),
                            trials=4, need=3)
            self.store.promote(f.id, result.verdict, "; ".join(result.details[:2]))
        # the production verify pass runs the creditor after verification
        # (orchestrator.run_verify_pass) — same authority here
        from redteam.credit import credit_confirmed_findings
        credit_confirmed_findings(SimpleNamespace(
            audit=_Audit(), findings=self.store, access=self.access,
            objective=self.objective))
        return ExecutionResult(EXEC_SUCCEEDED,
                               f"independent verification: {len(pending)} re-checked")


def _stack(tmp_path):
    clock = FakeClock()
    rd = tmp_path / "run"
    rd.mkdir(parents=True)
    tree = AttackTree(rd / "attack_tree.json", clock=clock)
    graph = KnowledgeGraph(rd / "graph.json")
    store = FindingStore(rd / "findings.json")
    access = AccessGraph(rd / "access.json")
    research = ResearchBundle.for_run("adaptive-lab")
    engagement = SimpleNamespace(name="adaptive-lab", ticket="ROE-15")
    opts = SimpleNamespace(max_steps=40, round_noise_budget=999.0)
    return clock, rd, tree, graph, store, access, research, engagement, opts


def _flag_objective():
    return Objective(name="lab", criteria=[SuccessCriterion(
        id="c1", kind=FLAG, description="capture the export flag",
        target="flag", evidence_regex=r"FLAG\{[a-f0-9]+\}")])


def _chain_script():
    """The authorized lab chain: broken access control -> admin IDOR (the
    privilege transition) -> newly discovered export endpoint -> flag capture.
    Each finding is pending until the independent verifier confirms it."""
    responses = {ADMIN: (200, "ADMIN PANEL secret"),
                 EXPORT: (200, "FLAG{abc123}")}
    findings_plan = {
        ("access.control", ADMIN): {"cwe": "CWE-284", "body_regex": "ADMIN PANEL",
                                    "evidence": "protected content without auth",
                                    "verify_response": (200, "ADMIN PANEL secret"),
                                    "summary": "admin panel reachable unauthenticated"},
        ("privesc.admin", ADMIN): {"cwe": "CWE-639", "body_regex": "user 7",
                                   "evidence": "as admin, read another principal's record",
                                   "verify_response": (200, "records of user 7"),
                                   "summary": "IDOR as the elevated principal"},
        ("data.exfil", ADMIN): {"cwe": "CWE-200", "body_regex": "FLAG",
                                "evidence": "exported records include FLAG{abc123}",
                                "verify_response": (200, "FLAG{abc123}"),
                                "summary": "sensitive export reachable as admin"},
    }
    discover = {("privesc.admin", ADMIN): EXPORT}
    return responses, findings_plan, discover


def _journal_events(rd):
    from redteam.swarm.journal import EventJournal
    return EventJournal("adaptive-lab", path=rd / "mission_journal.jsonl").read_all()


def _tasks_by_node(summary):
    return {t["node_id"]: t for t in summary["tasks"] if t.get("node_id")}


# -- 1. live recon state produces an initial offensive plan --------------------

def test_live_recon_state_produces_initial_offensive_plan(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    say: list[str] = []
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="chain into the admin export",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True, say=say.append)
    events = _journal_events(rd)
    synth = [e for e in events if e["type"] == "MISSION_SYNTHESIS"]
    assert synth, "each adaptive round journals its planning decision"
    first = synth[0]["payload"]["round"]
    created_nodes = [c["node_id"] for c in first["created"]]
    assert f"access.control@{ADMIN}" in created_nodes
    assert all(c["reasons"] for c in first["created"]), "ranked with grounded reasons"
    scores = [c["score"] for c in first["created"]]
    assert scores == sorted(scores, reverse=True), "planner ranking is deterministic"
    assert not any(c["role"] == "recon" for c in first["created"]), \
        "surface already mapped — no recon task"
    assert any("MISSION BRIEFING" in s for s in say), "round briefings logged"
    assert summary["adaptive"] is True


# -- 2. the mission dispatches a real specialist adapter -----------------------

def test_mission_dispatches_real_specialist_adapter(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    (rd / "mission_plan.json").write_text(json.dumps({"tasks": [
        {"title": "check the admin panel", "role": "exploit",
         "technique": "access.control", "target": ADMIN}]}), encoding="utf-8")

    class StubOrchestrator:
        """The executor's seam: execute_task is the orchestrator's REAL task
        interface; this stub stands in for the specialist construction so the
        ADAPTER wiring is what's under test."""
        def __init__(self):
            self.ctx = SimpleNamespace(findings=store, audit=_Audit())
            self.calls: list[dict] = []

        def execute_task(self, task_view, on_text=None, objective=""):
            self.calls.append(dict(task_view))
            return f"specialist ran {task_view['task_id']}"

    orch = StubOrchestrator()
    executor = MissionSpecialistExecutor(orch, objective="lab")
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="lab",
        attack_tree=tree, executor=executor, hypotheses=research,
        clock=clock, opts=opts, adaptive=False)   # static plan: adapter focus
    assert summary["executor"] == "MissionSpecialistExecutor"
    assert len(orch.calls) == 1
    sent = orch.calls[0]
    assert sent["role"] == "exploit" and sent["technique"] == "access.control"
    assert sent["node_id"] == f"access.control@{ADMIN}"
    task = next(t for t in summary["tasks"] if t["role"] == "exploit")
    assert task["status"] == "succeeded"


# -- 3. specialist outcomes update canonical intelligence ----------------------

def test_specialist_outcomes_update_canonical_intelligence(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    obj = Objective(name="lab", criteria=[SuccessCriterion(
        id="c1", kind="data_access", description="read admin records",
        target=ADMIN)])
    responses, findings_plan, _ = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="prove the admin surface",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, obj, responses=responses,
            findings_plan={("access.control", ADMIN): findings_plan[("access.control", ADMIN)]}),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, objective_model=obj,
        adaptive=True)
    # FindingStore: the only confirmation route ran (verify task)
    assert [f.confidence for f in store.all()] == ["confirmed"]
    # AttackTree: the confirmed finding completed its node (same idempotent sync)
    node = tree.node("access.control", ADMIN)
    assert node is not None and node.status == "completed"
    # AccessGraph: the creditor held the target with the structured reference
    assert access.reached(ADMIN)
    held = access.held()[0]
    assert held.attrs.get("finding_id") == store.all()[0].id
    assert held.source == "verified_finding"
    # Objective: criterion credited by autoevaluate through the holding
    assert obj.achieved is True
    # the run-dir artifacts persist the same state for the projection
    view = build_exploration_graph(rd)
    paths = view["attack_paths"]
    assert any(p["findings"] and p["findings"][0]["confidence"] == "confirmed"
               and p["access"] for p in paths if p.get("endpoint"))


# -- 4. a newly discovered high-value path changes the next selected action ----

def test_newly_discovered_path_changes_next_actions(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    responses, findings_plan, discover = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="press the admin foothold",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None, responses=responses,
            findings_plan=findings_plan, discover=discover),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    nodes = _tasks_by_node(summary)
    # before the discovery only /admin surface was tasked
    # (the discovery happens inside the privesc task's specialist round)
    new_surface = [nid for nid in nodes if nid.endswith(EXPORT)]
    assert new_surface, "the newly observed endpoint produced new plan entries"
    entry_on_new = [nid for nid in new_surface
                    if nid.split("@")[0] in ("auth.test", "access.control", "access.idor")]
    assert entry_on_new, "entry techniques were seeded onto the discovered endpoint"
    # the journal shows the synthesis round that reacted to the discovery
    synth = [e["payload"]["round"] for e in _journal_events(rd)
             if e["type"] == "MISSION_SYNTHESIS"]
    reacting = [r for r in synth
                if any(EXPORT in (c.get("node_id") or "") for c in r["created"])]
    assert reacting, "the planning round after the discovery created the new work"


# -- 5. a failed or falsified path causes the planner to pursue an alternative -

def test_falsified_path_is_excluded_and_alternatives_pursued(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="map and test the admin surface",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None,
            findings_plan={("xss.reflected", ADMIN): {
                "cwe": "CWE-79", "body_regex": "MARKER", "evidence": "reflected"}},
            responses={ADMIN: (200, "302 login required")},   # negative control
            falsify={ADMIN}),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    # the verifier's falsified verdict reached the tree through sync()
    node = tree.node("xss.reflected", ADMIN)
    assert node is not None and node.status == "failed"
    # exactly one task ever targeted the falsified node (no re-synthesis)
    xss_tasks = [t for t in summary["tasks"] if t["node_id"] == f"xss.reflected@{ADMIN}"]
    assert len(xss_tasks) == 1
    # alternatives WERE pursued: other entry techniques ran to terminal states
    pursued = {c["technique"] for c in
               ({"technique": t["technique"]} for t in summary["tasks"] if t["role"] == "exploit")}
    assert "auth.test" in pursued and "access.control" in pursued
    assert "xss.reflected" not in pursued or len(
        [t for t in summary["tasks"] if t["technique"] == "xss.reflected"]) == 1
    # the frontier kept going and the mission ended honestly
    assert summary["stop_reason"] == "viable paths exhausted"
    events = _journal_events(rd)
    synth = [e["payload"]["round"] for e in events if e["type"] == "MISSION_SYNTHESIS"]
    assert any(r["excluded_remediated"] or r["skipped"] or not r["created"]
               for r in synth)


def test_failed_execution_does_not_block_alternatives(tmp_path):
    """An execution failure (no finding) leaves the tree node TODO but the
    task terminal — the node is NOT re-synthesized (one task per node), and
    the remaining frontier continues."""
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")

    class FailingAuth(ScriptedSpecialists):
        def run(self, task_view):
            result = super().run(task_view)
            if task_view.get("technique") == "auth.test":
                return ExecutionResult(EXEC_FAILED, error="scripted auth failure")
            return result

    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="test the admin surface",
        attack_tree=tree, executor=FailingAuth(graph, store, access, None),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    auth_task = next(t for t in summary["tasks"]
                     if t["node_id"] == f"auth.test@{ADMIN}")
    assert auth_task["status"] == "failed"
    assert len([t for t in summary["tasks"]
                if t["node_id"] == f"auth.test@{ADMIN}"]) == 1
    # alternatives pursued
    assert any(t["node_id"] == f"access.control@{ADMIN}" for t in summary["tasks"])
    assert summary["stop_reason"] == "viable paths exhausted"


# -- 6. a verified access transition unlocks a follow-on task ------------------

def test_verified_transition_unlocks_follow_on_tasks(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    responses, findings_plan, discover = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="chain into the admin export",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None, responses=responses,
            findings_plan=findings_plan, discover=discover),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    nodes = _tasks_by_node(summary)
    follow_on = nodes.get(f"privesc.admin@{ADMIN}")
    assert follow_on, "the unlocked child became a mission task"
    assert follow_on["status"] == "succeeded"
    events = _journal_events(rd)
    synth = [e["payload"]["round"] for e in events if e["type"] == "MISSION_SYNTHESIS"]
    entry_round = next(r["round"] for r in synth
                       if any(c["node_id"] == f"access.control@{ADMIN}"
                              for c in r["created"]))
    follow_round = next(r["round"] for r in synth
                        if any(c["node_id"] == f"privesc.admin@{ADMIN}"
                               for c in r["created"]))
    assert follow_round > entry_round, \
        "the follow-on was created only AFTER verification unlocked it"
    created_entry = [c for r in synth for c in r["created"]
                     if c["node_id"] == f"privesc.admin@{ADMIN}"]
    assert any("chained follow-up" in " ".join(c["reasons"])
               for c in created_entry)
    # the full chain materialized as tasks
    assert f"access.idor@{ADMIN}" in nodes and f"data.exfil@{ADMIN}" in nodes


# -- 7. claims and dispatches are not duplicated across rounds or recovery -----

def test_no_duplicate_tasks_across_rounds_and_recovery(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    responses, findings_plan, _ = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="dedup discipline",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None, responses=responses,
            findings_plan=findings_plan),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    node_tasks = [t for t in summary["tasks"] if t.get("node_id")]
    ids = [t["node_id"] for t in node_tasks]
    assert len(ids) == len(set(ids)), "at most ONE task per attack-tree node"
    # recovery: replay rebuilds the same task set, reconcile is a no-op, and a
    # further synthesis round creates NOTHING new (idempotent across restart)
    from redteam.mission.scheduler import recover_mission
    commander, scheduler, report = recover_mission(
        rd, tree=AttackTree(rd / "attack_tree.json", clock=clock),
        executor=ScriptedSpecialists(graph, store, access, None),
        hypotheses=ResearchBundle.for_run("adaptive-lab"), clock=clock)
    # the replay SKIPS-AND-COUNTS event types the commander's applier does not
    # own (the MISSION_SYNTHESIS / MISSION_STOPPED planning trail — decisions,
    # not state mutations); every TASK_*/MISSION_* state event applied
    unknown_types = {"MISSION_SYNTHESIS", "MISSION_STOPPED"}
    unknown = len([e for e in _journal_events(rd) if e["type"] in unknown_types])
    assert report["skipped"] == unknown
    assert report["events_applied"] == len(_journal_events(rd)) - unknown
    assert len(commander.tasks) == len(summary["tasks"])
    assert scheduler.reconcile() == () or all(
        a.action == "in_flight_unknown" for a in scheduler.reconcile())
    from redteam.mission.adaptive import synthesize_round
    followup = synthesize_round(
        commander=commander, journal=scheduler.commander._journal, tree=tree,
        graph=graph, findings=store, access=access, clock=clock,
        engagement_id="adaptive-lab", mission_id=commander.mission.mission_id)
    assert followup["created"] == []
    # a terminal task is not claimable again
    some_task = next(iter(commander.tasks.values()))
    outcome = scheduler.dispatch(some_task.task_id)
    assert outcome["dispatched"] is False and outcome["outcome"] == "not_claimable"


# -- 8. scope, egress, budget and independent verification controls ------------

def test_budget_and_verification_controls_remain_intact(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, _ = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    opts = SimpleNamespace(max_steps=40, round_noise_budget=2.0)  # tight OPSEC round
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="budget discipline",
        attack_tree=tree, executor=ScriptedSpecialists(graph, store, access, None),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    # C3 at synthesis time: a technique priced ABOVE the round noise budget is
    # never reserved — skipped with a journaled reason, never under-reserved
    synth = [e["payload"]["round"] for e in _journal_events(rd)
             if e["type"] == "MISSION_SYNTHESIS"]
    skipped_reasons = [s["reason"] for r in synth for s in r["skipped"]]
    assert any("opsec price 3.0 exceeds" in r for r in skipped_reasons), \
        "injection.sqli (3.0) is honestly out of a 2.0 round budget"
    assert any("opsec price 4.0 exceeds" in r for r in skipped_reasons), \
        "injection.cmd (4.0) is honestly out of a 2.0 round budget"
    created_nodes = {t["node_id"] for t in summary["tasks"] if t.get("node_id")}
    assert f"injection.sqli@{ADMIN}" not in created_nodes
    assert f"injection.cmd@{ADMIN}" not in created_nodes
    # everything that WAS reserved carries an allowance within the RoE cap
    for t in summary["tasks"]:
        assert float(t["opsec_allowance"]) <= 2.0 + 1e-9
    # the affordable frontier ran to terminal states across budget-reset rounds
    assert all(t["status"] in ("succeeded", "failed") for t in summary["tasks"])
    assert summary["rounds"] >= 2, "the round OPSEC budget took more than one wave"


def test_synthesis_never_invents_targets_or_confirms(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    responses, findings_plan, discover = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="scope discipline",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None, responses=responses,
            findings_plan=findings_plan, discover=discover),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    # every node task target is an endpoint the run actually observed
    known = {n.key for n in graph.nodes(ENDPOINT)}
    for t in summary["tasks"]:
        if t.get("node_id") and t["target"]:
            assert t["target"] in known, f"no invented targets: {t['target']}"
    # no evidence ref is ever confirmed — verification promotes, executors don't
    for t in summary["tasks"]:
        for ev in t.get("evidence", []):
            assert ev.get("confidence") != "confirmed"
    # and the only confirmed finding came through the verify task's round
    confirmed = [f for f in store.all() if f.confidence == "confirmed"]
    assert confirmed, "the chain was verified"
    synth = [e["payload"]["round"] for e in _journal_events(rd)
             if e["type"] == "MISSION_SYNTHESIS"]
    assert any(r["verify_task"] for r in synth), \
        "verification ran as its own synthesized task"


def test_operator_stop_reason_is_recorded(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="stop on command",
        attack_tree=tree, executor=ScriptedSpecialists(graph, store, access, None),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True,
        stop_check=lambda: "maintenance window")
    assert summary["stop_reason"] == "operator stop: maintenance window"
    stops = [e for e in _journal_events(rd) if e["type"] == "MISSION_STOPPED"]
    assert stops and stops[0]["payload"]["stop_reason"] == \
        "operator stop: maintenance window"


# -- 9. the mission stops correctly when the objective is achieved -------------

def test_mission_stops_when_objective_achieved(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    obj = _flag_objective()
    responses, findings_plan, discover = _chain_script()
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="capture the export flag",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, obj, responses=responses,
            findings_plan=findings_plan, discover=discover),
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, objective_model=obj,
        adaptive=True)
    assert obj.achieved is True
    assert summary["stop_reason"] == "objective achieved"
    assert summary["status"] == "succeeded"
    stops = [e for e in _journal_events(rd) if e["type"] == "MISSION_STOPPED"]
    assert stops and "objective achieved" in stops[0]["payload"]["stop_reason"]
    # the impact is INDEPENDENTLY VERIFIED, not self-reported
    flag_findings = [f for f in store.all() if "FLAG{" in (f.evidence or "")]
    assert flag_findings and flag_findings[0].confidence == "confirmed"
    assert flag_findings[0].independent_verdict == "confirmed"


# -- 10. the mission also stops correctly when viable paths are exhausted ------

def test_mission_stops_when_paths_exhausted(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="test everything once",
        attack_tree=tree, executor=ScriptedSpecialists(
            graph, store, access, None),   # every check runs, nothing confirms
        hypotheses=research, clock=clock, opts=opts,
        graph=graph, findings=store, access=access, adaptive=True)
    assert summary["stop_reason"] == "viable paths exhausted"
    # the task-level calc is unchanged by adaptive mode (execution ran fine);
    # the HONESTY lives in the intel: nothing was demonstrated or confirmed
    assert summary["status"] == "succeeded"
    assert not [f for f in store.all() if f.confidence == "confirmed"]
    stops = [e for e in _journal_events(rd) if e["type"] == "MISSION_STOPPED"]
    assert stops and stops[0]["payload"]["stop_reason"] == "viable paths exhausted"
    # every entry technique got exactly its one task; nothing loops
    entry_tasks = [t for t in summary["tasks"] if t["role"] == "exploit"]
    assert len({t["node_id"] for t in entry_tasks}) == len(entry_tasks)


# -- static-path compatibility ---------------------------------------------------

def test_static_path_unchanged_without_adaptive(tmp_path):
    clock, rd, tree, graph, store, access, research, eng, opts = _stack(tmp_path)
    graph.observe_canonical(ENDPOINT, ADMIN, source="recon")
    (rd / "mission_plan.json").write_text(json.dumps({"tasks": [
        {"title": "one planned task", "role": "exploit",
         "technique": "access.control", "target": ADMIN}]}), encoding="utf-8")
    summary = run_mission_driver(
        engagement=eng, out_dir=rd, objective="static replay",
        attack_tree=tree, executor=ScriptedSpecialists(graph, store, access, None),
        hypotheses=research, clock=clock, opts=opts, adaptive=False)
    assert summary["adaptive"] is False
    assert summary["stop_reason"] == ""
    assert len(summary["tasks"]) == 1, "static mode: plan tasks only, no synthesis"
    assert not [e for e in _journal_events(rd) if e["type"] == "MISSION_SYNTHESIS"]

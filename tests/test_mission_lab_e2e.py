"""Phase 3 CONTROLLED LAB — the complete mission execution path against a
LOCAL, AUTHORIZED fixture only (127.0.0.1 HTTP server bound for the test,
RoE-scoped, allow_private_ranges=True, no external targets).

What it demonstrates with REAL machinery (no fake adapter in the hot path):
  mission driver pieces -> scheduler claim trio -> MissionSpecialistExecutor
    -> Orchestrator.execute_task -> _make_specialist -> RedTeamAgent.run loop
      -> REAL tool dispatch (http_probe / confirm_finding /
         verify_finding_independently) against the local lab server
      -> findings/evidence pipeline -> INDEPENDENT verification.

The finding is called CONFIRMED only because the lab execution actually
produced that result: the injected-quote differential reproduces k-of-n and
the independent re-check's benign control stays clean. A no-model scripted
client drives the agent loop (unit discipline: no live LLM); every tool call
it scripts executes REAL code.
"""
from __future__ import annotations

import datetime as _dt
import http.server
import json
import re
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from redteam.attack_tree import AttackTree
from redteam.config import LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.mission.commander import Commander
from redteam.mission.driver import build_mission
from redteam.mission.executor import EXEC_SUCCEEDED
from redteam.mission.mission import Mission
from redteam.mission.registry import AgentRegistry
from redteam.mission.scheduler import MissionScheduler, recover_mission
from redteam.mission.specialist_executor import MissionSpecialistExecutor
from redteam.mission.task import TASK_LEASE_SECONDS
from redteam.orchestrator import Orchestrator
from redteam.ratelimit import RateLimiter
from redteam.runtime import BudgetTracker
from redteam.scope import ScopeGuard
from redteam.states import MISSION_SUCCEEDED
from redteam.swarm.journal import EventJournal
from redteam.tools import ToolContext, build_registry

import mission_helpers as H


# -- the local lab app ------------------------------------------------------------
# /api/orders?id=<x> breaks the query on an injected quote (error-based SQLi
# shape) and stays clean for the benign control — the exact differential the
# proof pipeline and the independent verifier both replay.

class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/api/orders":
            qid = (parse_qs(parts.query).get("id") or [""])[0]
            if qid.endswith("'"):
                body = b"SQL syntax error near 'ORDER BY' (mysql/8.0)"
                status = 500
            else:
                body = json.dumps({"orders": [{"id": 1, "total": 10}]}).encode()
                status = 200
            ctype = "text/html; charset=utf-8"
        elif parts.path == "/":
            body = b"<html><body>orders lab</body></html>"
            status = 200
            ctype = "text/html; charset=utf-8"
        else:
            body = b'{"error": "not found"}'
            status = 404
            ctype = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def lab_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), LabHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_port
    srv.shutdown()


# -- the scripted no-model client (real agent loop, real tools) ---------------------

class ScriptedClient:
    """Turn-1 of each agent conversation dispatches the tool its TASK calls
    for; turn-2 (after the tool result) ends the run. Tool calls execute REAL
    tools against the lab server."""

    def __init__(self, port: int, calls: list | None = None):
        self._port = int(port)
        self.calls = calls if calls is not None else []

    def _tool_call(self, name: str, args: dict) -> ChatResult:
        self.calls.append((name, args))
        return ChatResult(model="scripted-lab", finish_reason="tool_calls",
                          usage={},
                          message={"role": "assistant", "content": None,
                                   "tool_calls": [{
                                       "id": f"call-{len(self.calls)}",
                                       "type": "function",
                                       "function": {"name": name,
                                                    "arguments": json.dumps(args)},
                                   }]})

    def chat(self, messages, tools=None, role="plan"):
        # fire the scripted tool ONCE per specialist conversation; after the
        # first tool call, end the run. (Turn shape varies — the loop appends
        # per-turn briefings and stall nudges as user messages — so the
        # discriminator is "an assistant tool_call already exists", not the
        # last message's role.)
        already_called = any(m.get("role") == "assistant" and m.get("tool_calls")
                             for m in messages)
        if already_called:
            return ChatResult(model="scripted-lab", finish_reason="stop",
                              usage={},
                              message={"role": "assistant",
                                       "content": "task slice complete"})
        # the task instruction may not be the LAST user message (memory/skills
        # briefings are appended after it) — match over the whole conversation
        text = "\n".join((m.get("content") or "") for m in messages
                         if m.get("role") in ("user", "system"))
        base = f"http://127.0.0.1:{self._port}"
        m = re.search(r"finding_id values\):\s*([0-9a-f]+)", text)
        if m:   # the independent verifier's instruction (run_verify_pass)
            return self._tool_call("verify_finding_independently",
                                   {"finding_id": m.group(1)})
        if re.search(r"ASSIGNED CHECK:\s*injection\.sqli\b", text):
            return self._tool_call("confirm_finding", {
                "title": "error-based SQLi in /api/orders id",
                "severity": "high", "target": base + "/api/orders",
                "summary": "injected quote breaks the query and leaks the error",
                "check_type": "http", "cwe": "CWE-89",
                "request": {"method": "GET", "url": base + "/api/orders?id=1'"},
                "body_regex": "SQL syntax error", "trials": 3, "need": 3})
        if "ASSIGNED CHECK" in text:   # chained follow-up specialist task
            return ChatResult(model="scripted-lab", finish_reason="stop", usage={},
                              message={"role": "assistant",
                                       "content": "follow-on path attempted; no additional proof in this fixture"})
        if "ONE mission task" in text:     # the mission recon task
            return self._tool_call("http_probe", {"url": base + "/api/orders?id=1"})
        return ChatResult(model="scripted-lab", finish_reason="stop", usage={},
                          message={"role": "assistant", "content": "done"})


# -- the shared run environment (what run.py assembles, lab-scoped) --------------

class LabEnv:
    """The run's ONE shared environment — the same objects run.py builds."""

    def __init__(self, tmp_path: Path, port: int, client):
        from redteam.config import Engagement
        self.eng = Engagement(
            name="lab-e2e", client="lab", authorized_by="op", ticket="ROE-LAB-3",
            starts=_dt.date.today() - _dt.timedelta(days=1),
            ends=_dt.date.today() + _dt.timedelta(days=1),
            allowed_hosts=("127.0.0.1",), excluded_hosts=(),
            allowed_ports=(port,), allowed_schemes=("http",),
            max_requests_per_second=100.0, max_total_requests=1000,
            allow_private_ranges=True, require_approval_for=(),
            llm=LlmConfig(), sandbox=SandboxConfig(enable=False), raw={})
        self.clock = H.FakeClock()
        self.audit = _RecordingAudit()
        self.scope = ScopeGuard(self.eng)
        self.findings = FindingStore(tmp_path / "findings.json")
        self.graph = KnowledgeGraph(tmp_path / "graph.json")
        self.tree = AttackTree(tmp_path / "attack_tree.json", clock=self.clock)
        self.budget = BudgetTracker(max_seconds=600, max_tokens=100000)
        self.tools = build_registry(enable_sandbox=False, enable_browser=False)
        self.ctx = ToolContext(
            scope=self.scope, limiter=RateLimiter(100, 1000), audit=self.audit,
            findings=self.findings, approve=lambda a, d: True, sandbox=None,
            browser=None, graph=self.graph, sessions=None, skills=None,
            access=None, objective=None, killchain=None, events=None)
        self.orch = Orchestrator(self.eng, self.tools, self.ctx, client,
                                 graph=self.graph, attack_tree=self.tree)
        self.orch.with_runtime(budget=self.budget)
        self.executor = MissionSpecialistExecutor(
            self.orch, objective="find injection flaws in the local lab")

    def mission_stack(self, mission_dir: Path):
        mission, journal = build_mission(
            mission_dir, engagement_name=self.eng.name,
            engagement_ticket=self.eng.ticket,
            objective="find injection flaws in the local lab", clock=self.clock)
        agents = AgentRegistry(journal=journal, clock=self.clock,
                               mission_id=mission.mission_id)
        commander = Commander(mission, journal, agents=agents, clock=self.clock,
                              roe_caps={"max_steps": 40, "round_noise_budget": 12.0},
                              record_path=mission_dir / "mission.json")
        scheduler = MissionScheduler(
            commander, tree=self.tree, executor=self.executor,
            hypotheses=self.orch._research, clock=self.clock,
            round_noise_budget=12.0, lease_seconds=TASK_LEASE_SECONDS)
        return mission, commander, scheduler


class _RecordingAudit:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def record(self, event, **f):
        with self._lock:
            self.events.append({"event": event, **f})

    def read_all(self):
        with self._lock:
            return list(self.events)


# =============================================================================
# Lab 1 — staged coordination: recon -> exploit -> verify, ALL real
# =============================================================================

def test_lab_recon_then_exploit_then_independent_confirmation(tmp_path, lab_server):
    client = ScriptedClient(lab_server)
    env = LabEnv(tmp_path, lab_server, client)
    mission_dir = tmp_path / "run"
    mission_dir.mkdir()
    mission, commander, scheduler = env.mission_stack(mission_dir)
    commander.start_mission("op")
    # the exploit task's tree target is the ENDPOINT (the finding's target is
    # exactly this string, so the tree sync matches the confirmation to it)
    orders_url = f"http://127.0.0.1:{lab_server}/api/orders"
    env.tree.seed_endpoint(orders_url)

    # 1-2. tasks created (mission_plan.json in the driver path does this)
    recon = commander.create_task(title="map the lab surface", role="recon",
                                  actor="op", target="127.0.0.1", max_steps=6)
    exploit = commander.create_task(title="prove the orders injection",
                                    role="exploit", actor="op",
                                    technique="injection.sqli",
                                    target=orders_url, max_steps=8)

    # 3-5. scheduler claims + dispatches the RECON task; real RECON specialist
    r1 = scheduler.dispatch(recon.task_id)
    assert r1["outcome"] == EXEC_SUCCEEDED
    assert commander.task(recon.task_id).status == "succeeded"

    # 6-8. follow-up EXPLOIT task dispatched through the scheduler; tree node
    # claimed ONCE by the scheduler; real A03 specialist + real confirm_finding
    claim_calls = []
    real_claim = env.tree.claim

    def counting_claim(technique, target, **kw):
        claim_calls.append((technique, target))
        return real_claim(technique, target, **kw)

    env.tree.claim = counting_claim
    r2 = scheduler.dispatch(exploit.task_id)
    assert r2["outcome"] == EXEC_SUCCEEDED
    assert len(claim_calls) == 1                    # scheduler only, once
    done = commander.task(exploit.task_id)
    assert done.status == "succeeded"
    # evidence flowed through the existing pipeline into the task record
    assert len(done.evidence) == 1
    finding_id = done.evidence[0]["ref"]
    stored = env.findings.get(finding_id)
    assert stored.confidence == "pending_verification"
    assert stored.check_spec["request"]["url"].endswith("/api/orders?id=1'")

    # 9. verify task (dependency satisfied) -> the EXISTING independent
    #    verification path; the proposer never self-confirms
    verify = commander.create_task(title="verify pending findings", role="verify",
                                   actor="op",
                                   dependencies=(exploit.task_id,), max_steps=6)
    ready = scheduler.ready_tasks()
    assert [t.task_id for t in ready] == [verify.task_id]
    r3 = scheduler.dispatch(verify.task_id)
    assert r3["outcome"] == EXEC_SUCCEEDED
    confirmed = env.findings.get(finding_id)
    assert confirmed.confidence == "confirmed"      # THE PIPELINE decided
    assert confirmed.independent_verdict == "confirmed"

    # 10. states + mission status persisted; tree completes via sync on the
    #     CONFIRMED finding (the same sync orchestrator's verify passes use)
    env.tree.sync(graph=env.graph, findings=env.findings.all())
    node = env.tree.node("injection.sqli", orders_url)
    assert node.status == "completed"
    commander.set_mission_status(MISSION_SUCCEEDED, "op", reason="")

    # artifacts persist and the journal replays the whole mission
    mission_record = Mission.load(mission_dir / "mission.json")
    assert mission_record.status == MISSION_SUCCEEDED
    replayed_commander, _s, report = recover_mission(mission_dir, tree=env.tree,
                                                     clock=env.clock)
    assert replayed_commander.task(recon.task_id).status == "succeeded"
    assert replayed_commander.task(exploit.task_id).status == "succeeded"
    assert replayed_commander.task(verify.task_id).status == "succeeded"
    assert report["skipped"] == 0

    # the REAL agent loop ran: three mission specialists, real tool dispatches
    agent_starts = [e for e in env.audit.events if e["event"] == "agent.start"]
    assert len(agent_starts) == 3
    tool_names = [name for name, _args in client.calls]
    assert tool_names == ["http_probe", "confirm_finding",
                          "verify_finding_independently"]
    # task execution success never claimed a confirmation for itself (C4):
    for t in (recon, exploit):
        record = commander.task(t.task_id)
        assert all(ev.get("confidence") != "confirmed" for ev in record.evidence)


# =============================================================================
# Lab 2 — the production path: execute_run(driver="mission") end to end
# =============================================================================

def test_execute_run_mission_branch_uses_the_real_executor(tmp_path, lab_server,
                                                           monkeypatch):
    from redteam.run import RunOptions, execute_run

    # build_llm_client gained a run-scoped credentials kwarg (builder-04a); the
    # scripted client ignores it — the injection seam stays client-only.
    monkeypatch.setattr("redteam.run.build_llm_client",
                        lambda llm, audit=None, credentials=None: ScriptedClient(lab_server))

    today = _dt.date.today()
    engagement_yaml = f"""
name: lab-e2e
client: lab
authorized_by: operator
ticket: ROE-LAB-3
starts: {today - _dt.timedelta(days=1)}
ends: {today + _dt.timedelta(days=1)}
scope:
  allowed_hosts: ["127.0.0.1"]
  allowed_ports: [{lab_server}]
  allowed_schemes: ["http"]
  allow_private_ranges: true
limits:
  max_requests_per_second: 100.0
  max_total_requests: 1000
  max_run_seconds: 600
  max_llm_tokens: 100000
sandbox:
  enable: false
llm: {{}}
"""
    (tmp_path / "engagement.yaml").write_text(engagement_yaml, encoding="utf-8")
    # No mission_plan.json: deterministic recon seeds exactly one authorized
    # entry technique. The mission driver must generate the exploit task from
    # the live tree, then discover the chained follow-ups only after VERIFY.
    from redteam import recon as recon_module

    def seeded_recon(engagement, graph, attack_tree, audit=None, source_dir=None,
                     **kwargs):   # RECON V2 adds store/limiter/traffic kwargs
        attack_tree.seed_endpoint(f"http://127.0.0.1:{lab_server}/api/orders")
        return {"endpoints_discovered": 1, "static_routes_found": 0}

    def seed_sqli_only(self, target, bucket=""):
        self._add("injection.sqli", target, bucket=bucket)

    monkeypatch.setattr(recon_module, "run_deterministic_recon", seeded_recon)
    monkeypatch.setattr(AttackTree, "seed_endpoint", seed_sqli_only)

    summary = execute_run(RunOptions(
        engagement_path=str(tmp_path / "engagement.yaml"),
        objective="find injection flaws in the local lab",
        out_dir=tmp_path, driver="mission", quiet=True,
        no_sandbox=True, no_browser=True,
        approve=lambda a, d: True, memory_dir=tmp_path / "memory"))

    # the production mission path ran the REAL executor (not the mock)
    assert summary["driver"] == "mission"
    assert summary["mission_executor"] == "MissionSpecialistExecutor"
    # Default mission mode discovered the finding, verified it independently,
    # and only then selected the two unlocked follow-up techniques.
    assert summary["mission_status"] == "succeeded"
    assert summary["mission_stop_reason"] == "frontier_exhausted"
    assert summary["mission_execution_complete"] is True
    assert summary["mission_pending_verification"] == 0
    assert summary["mission_objective_achieved"] is None
    assert summary["status"] == "completed"
    # The real finding was independently confirmed before chained work ran.
    assert summary["findings"] == 1
    assert summary["confirmed"] == 1
    findings = json.loads((tmp_path / "findings.json").read_text())
    assert len(findings) == 1
    assert findings[0]["confidence"] == "confirmed"
    assert not (tmp_path / "mission_plan.json").exists()
    # shared finalization ran (Phase 2 skipped it): reports + audit chain
    report = Path(summary["report_path"])
    assert report.exists() and report.stat().st_size > 0
    assert Path(summary["html_path"]).exists()
    assert summary["audit_intact"] is True
    # the exploit task's record carries the real evidence ref
    exploit = next(t for t in summary["tasks"]
                   if t["role"] == "exploit" and t["technique"] == "injection.sqli")
    assert exploit["status"] == "succeeded"
    assert len(exploit["evidence"]) == 1
    assert exploit["evidence"][0]["confidence"] == "pending_verification"
    assert {t["technique"] for t in summary["tasks"] if t["role"] == "exploit"} == {
        "injection.sqli", "auth.bypass", "data.exfil"}
    assert {t["role"] for t in summary["tasks"]} == {"recon", "exploit", "verify", "logic"}
    # coordination artifacts persisted
    assert (tmp_path / "mission.json").exists()
    assert (tmp_path / "mission_journal.jsonl").exists()
    journal = EventJournal("lab-e2e", path=tmp_path / "mission_journal.jsonl")
    types = [e["type"] for e in journal.read_all()]
    assert types.count("TASK_DISPATCHED") == 6
    # Only the independently confirmed SQLi node is completed. The unlocked
    # follow-up nodes were dispatched but not promoted without their own proof.
    tree_after = AttackTree(tmp_path / "attack_tree.json")
    node = tree_after.node("injection.sqli",
                           f"http://127.0.0.1:{lab_server}/api/orders")
    assert node.status == "completed"
    assert tree_after.node("auth.bypass",
                           f"http://127.0.0.1:{lab_server}/api/orders").status == "todo"
    assert tree_after.node("data.exfil",
                           f"http://127.0.0.1:{lab_server}/api/orders").status == "todo"

    # Journal replay reconstructs the dynamically-created tasks exactly once;
    # a second recovery pass must not create duplicate tasks or tree releases.
    replayed, _, recovery = recover_mission(tmp_path, tree=tree_after)
    assert recovery["skipped"] == 0
    assert len(replayed.tasks) == 6
    assert all(t.status == "succeeded" for t in replayed.tasks.values())
    node_ids = [t.node_id for t in replayed.tasks.values() if t.node_id]
    assert len(node_ids) == 3 and len(set(node_ids)) == 3
    _, _, recovery_again = recover_mission(tmp_path, tree=tree_after)
    assert recovery_again["reconcile_actions"] == []

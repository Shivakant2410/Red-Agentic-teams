"""Phase C1 integration tests — the swarm uses the research layer end-to-end.

Pins the three integration invariants:
  1. the orchestrator registers/claims/releases hypotheses around the existing
     AttackTree claim loop, with the tree's selection logic untouched;
  2. a pending finding NEVER promotes its hypothesis — CONFIRMED is only the mirror
     of the independent verification pipeline's verdict;
  3. engagements are isolated (no cross-run contamination) and research failures
     degrade to audit records instead of crashing the run.

No live LLM: the FakeClient returns a no-tool-call assistant message, exactly like
tests/test_orchestrator.py, so specialist runs end immediately.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading

from redteam.attack_tree import AttackTree, FAILED
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.events import EventBus
from redteam.findings import Finding, FindingStore
from redteam.knowledge import KnowledgeGraph
from redteam.llm.openrouter import ChatResult
from redteam.orchestrator import Orchestrator
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.swarm import (AWAITING_VERIFICATION, CONFIRMED, ACTIVE, PROPOSED,
                           REFUTED)
from redteam.tools import ToolContext

from test_swarm_hypotheses import FakeClock


class RecordingAudit:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def record(self, event, **f):
        with self._lock:
            self.events.append({"event": event, **f})

    def read_all(self):
        with self._lock:
            return list(self.events)


class FakeClient:
    """No-tool-call assistant message per turn (each specialist run ends at once)."""

    def __init__(self):
        self.roles_used = []
        self._lock = threading.Lock()

    def chat(self, messages, tools=None, role="plan"):
        with self._lock:
            self.roles_used.append(role)
        return ChatResult(model="fake",
                          message={"role": "assistant", "content": "done"},
                          finish_reason="stop", usage={})


def _engagement(name="t"):
    return Engagement(name=name, client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


def _ctx(tmp_path, audit):
    eng = _engagement()
    return ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                       limiter=RateLimiter(100, 1000), audit=audit,
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"))


def _orch(tmp_path, audit, tree=None, research_dir=None, engagement_name="t"):
    ctx = _ctx(tmp_path, audit)
    return Orchestrator(_engagement(engagement_name), tools={}, ctx=ctx,
                        client=FakeClient(), graph=ctx.graph, attack_tree=tree,
                        memory=None, research_dir=research_dir), ctx


def _seeded_tree(tmp_path):
    tree = AttackTree(tmp_path / "tree.json")
    tree.seed_endpoint("https://api.acme.example/v1")
    return tree


# -- the swarm registers, claims, and releases hypotheses --------------------------------

def test_swarm_run_registers_and_claims_hypotheses(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)
    orch.run("map and exploit the app")

    research = orch._research
    hyps = research.registry.list()
    assert hyps, "the swarm's claims must become registered hypotheses"
    statuses = {h.status for h in hyps}
    # every attempt produced no finding (FakeClient) -> attempts released their
    # leases; hypotheses stay non-terminal and re-attemptable
    assert statuses <= {ACTIVE, PROPOSED}
    assert all(h.owner is None for h in hyps)
    assert all(h.counter_evidence_refs for h in hyps if h.status == ACTIVE)
    # forum saw the lifecycle
    types = {m.event_type for m in research.forum.query()}
    assert "hypothesis.registered" in types and "hypothesis.claimed" in types
    # the attack tree behaved exactly as before (FAILED marks for empty attempts)
    assert any(n.status == FAILED for n in tree.confirmed_chain()) is False
    assert tree.summary()["by_status"].get(FAILED, 0) > 0


def test_research_layer_persists_and_replays_from_run_dir(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, _ = _orch(tmp_path, audit, tree=tree,
                    research_dir=tmp_path / "run1")
    orch.run("map and exploit the app")

    journal_path = tmp_path / "run1" / "research_journal.jsonl"
    forum_path = tmp_path / "run1" / "research_forum.jsonl"
    assert journal_path.exists() and forum_path.exists()

    from redteam.swarm import replay
    rebuilt, report = replay(journal_path, "t")
    assert len(rebuilt) > 0
    assert report.invalid_skipped == 0
    live_ids = {h.hypothesis_id for h in orch._research.registry.list()}
    assert {h.hypothesis_id for h in rebuilt.list()} == live_ids


def test_research_error_degrades_to_audit_record_not_crash(tmp_path):
    """If the registry fails (here: an unusable engagement id path — simulated by
    monkeypatching claim_or_register to raise), the run continues exactly as before."""
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)

    def explode(*a, **kw):
        raise RuntimeError("research layer is on fire")

    orch._research.claim_or_register = explode
    orch.run("map and exploit the app")     # must NOT raise
    assert any(e["event"] == "research.error" for e in audit.events)
    assert any(e["event"] == "orchestrator.finish" for e in audit.events)


def test_worker_briefings_carry_bounded_research_context(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)
    orch.run("map and exploit the app")
    # every hypothesis the swarm worked has a briefing path that ran without error
    # (the note builder is exercised via _research_note_for)
    hyps = orch._research.registry.list()
    assert all(isinstance(orch._research_note_for(h), str) for h in hyps)


# -- the verification pipeline remains the ONLY authority --------------------------------

def test_pending_finding_never_promotes_hypothesis(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)

    tree.seed_endpoint("https://api.acme.example/v1")
    node = tree.actionable(limit=1)[0]
    hyp, _ = orch._research.claim_or_register(
        asset_ref=node.target, weakness_class="idor",
        claim="IDOR on the object endpoint", agent="exploit-w0")
    orch._research_hyp_by_node[node.id] = hyp.hypothesis_id
    finding = Finding(title="IDOR on /objects", severity="high",
                      target=node.target, summary="reached another user's object",
                      cwe="CWE-639", confidence="pending_verification")
    ctx.findings.add(finding)
    orch._research_after_attempt(node, 0, 0, [finding])

    state = orch._research.registry.get(hyp.hypothesis_id)
    assert state.status == AWAITING_VERIFICATION      # NOT CONFIRMED
    assert finding.confidence == "pending_verification"  # pipeline untouched
    assert state.evidence_refs[0]["artifact_ref"] == finding.id


def test_confirmed_hypothesis_is_a_mirror_of_the_pipeline(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)

    node = tree.actionable(limit=1)[0]
    hyp, _ = orch._research.claim_or_register(
        asset_ref=node.target, weakness_class="idor",
        claim="IDOR on the object endpoint", agent="exploit-w0")
    orch._research_hyp_by_node[node.id] = hyp.hypothesis_id
    finding = Finding(title="IDOR on /objects", severity="high",
                      target=node.target, summary="reached another user's object",
                      cwe="CWE-639", confidence="pending_verification")
    ctx.findings.add(finding)
    orch._research_after_attempt(node, 0, 0, [finding])
    assert orch._research.registry.get(hyp.hypothesis_id).status == AWAITING_VERIFICATION

    # the INDEPENDENT pipeline confirms the finding...
    ctx.findings.promote(finding.id, "confirmed", "reproduced 5/5 with negative control")
    # ...and only THEN does the mirror run (as it does after every run_verify_pass)
    mirrored = orch._mirror_verification_outcomes()
    assert mirrored == 1
    assert orch._research.registry.get(hyp.hypothesis_id).status == CONFIRMED
    # re-running the mirror is free (sync() re-runs every turn)
    assert orch._mirror_verification_outcomes() == 0


def test_falsified_finding_refutes_hypothesis_not_reproducible_reactivates(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)

    node = tree.actionable(limit=1)[0]
    hyp, _ = orch._research.claim_or_register(
        asset_ref=node.target, weakness_class="idor",
        claim="IDOR on the object endpoint", agent="exploit-w0")
    orch._research_hyp_by_node[node.id] = hyp.hypothesis_id
    finding = Finding(title="IDOR on /objects", severity="high",
                      target=node.target, summary="reached another user's object",
                      cwe="CWE-639", confidence="pending_verification")
    ctx.findings.add(finding)
    orch._research_after_attempt(node, 0, 0, [finding])

    ctx.findings.promote(finding.id, "falsified", "control reproduced the signal")
    orch._mirror_verification_outcomes()
    assert orch._research.registry.get(hyp.hypothesis_id).status == REFUTED

    # a second hypothesis whose independent check is not_reproducible goes back to
    # ACTIVE (unproven), not terminal
    node2 = tree.actionable(limit=1)[0]
    hyp2, _ = orch._research.claim_or_register(
        asset_ref=node2.target, weakness_class="access-control",
        claim="unauthenticated access to admin", agent="exploit-w1")
    orch._research_hyp_by_node[node2.id] = hyp2.hypothesis_id
    f2 = Finding(title="open admin", severity="high", target=node2.target,
                 summary="200 without auth", cwe="CWE-284",
                 confidence="pending_verification")
    ctx.findings.add(f2)
    orch._research_after_attempt(node2, 1, 0, [f2])
    ctx.findings.promote(f2.id, "not_reproducible", "could not reproduce")
    orch._mirror_verification_outcomes()
    assert orch._research.registry.get(hyp2.hypothesis_id).status == ACTIVE


def test_findings_never_inherit_hypothesis_status(tmp_path):
    """Direction check: the mirror reads the pipeline, never writes to it."""
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, ctx = _orch(tmp_path, audit, tree=tree)
    node = tree.actionable(limit=1)[0]
    hyp, _ = orch._research.claim_or_register(
        asset_ref=node.target, weakness_class="idor",
        claim="IDOR", agent="exploit-w0")
    orch._research_hyp_by_node[node.id] = hyp.hypothesis_id
    finding = Finding(title="x", severity="low", target=node.target, summary="s",
                      cwe="CWE-639", confidence="pending_verification")
    ctx.findings.add(finding)
    orch._research_after_attempt(node, 0, 0, [finding])
    orch._mirror_verification_outcomes()          # nothing decided by the pipeline yet
    assert finding.confidence == "pending_verification"
    assert ctx.findings.get(finding.id).confidence == "pending_verification"


# -- engagement isolation at the orchestrator level ----------------------------------------

def test_no_cross_engagement_contamination(tmp_path):
    audit_a = RecordingAudit()
    audit_b = RecordingAudit()
    tree_a = _seeded_tree(tmp_path)
    tree_b = _seeded_tree(tmp_path)
    orch_a, _ = _orch(tmp_path, audit_a, tree=tree_a, engagement_name="eng-alpha")
    orch_b, _ = _orch(tmp_path, audit_b, tree=tree_b, engagement_name="eng-beta")
    orch_a.run("alpha objective")
    orch_b.run("beta objective")

    ids_a = {h.hypothesis_id for h in orch_a._research.registry.list()}
    ids_b = {h.hypothesis_id for h in orch_b._research.registry.list()}
    assert ids_a and ids_b and not (ids_a & ids_b)
    assert all(h.engagement_id == "eng-alpha" for h in orch_a._research.registry.list())
    assert all(h.engagement_id == "eng-beta" for h in orch_b._research.registry.list())
    # forum isolation: beta's forum knows nothing of alpha's hypotheses
    assert orch_b._research.forum.query(hypothesis_id=next(iter(ids_a))) == []


def test_forum_mirrors_to_event_bus_for_dashboard(tmp_path):
    audit = RecordingAudit()
    seen = []
    bus = EventBus(run_id="r1", subscribers=[seen.append])
    ctx = _ctx(tmp_path, audit)
    ctx.events = bus
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, attack_tree=_seeded_tree(tmp_path))
    orch.run("map and exploit")
    research_events = [e for e in seen if str(e.get("type", "")).startswith("research.")]
    assert research_events, "forum traffic should mirror onto the run's EventBus"
    assert any(e["type"] == "research.hypothesis.claimed" for e in research_events)


def test_run_research_summary_lands_in_audit(tmp_path):
    audit = RecordingAudit()
    tree = _seeded_tree(tmp_path)
    orch, _ = _orch(tmp_path, audit, tree=tree)
    orch.run("map and exploit")
    summaries = [e for e in audit.events if e["event"] == "research.summary"]
    assert summaries and summaries[0]["registry"]["total"] > 0

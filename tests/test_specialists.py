"""Tests for the OWASP class-specialist layer (redteam/specialists.py).

The layer's contract: every technique the attack tree can seed routes to a class
expert; the claim/noise/verify machinery treats a class worker exactly like a
generic EXPLOIT worker; the routing degrades to the generic profile (kill switch,
unmapped technique) instead of ever raising.
"""

from __future__ import annotations

import datetime as _dt
import threading

from redteam.attack_tree import AttackTree, TECHNIQUES
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import FindingStore
from redteam.llm.routing import PARSE, PLAN
from redteam.orchestrator import EXPLOIT, Orchestrator
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.specialists import (CLASS_SPECIALISTS, ROUTE, A01, A03, A05, A07, A10,
                                 profile_for)
from redteam.tools import ToolContext, build_registry


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


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
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
                       graph=None, access=None, killchain=None, objective=None)


def test_route_covers_every_technique_in_the_tree():
    """Fail loud when a new technique enters the tree without a class routing
    decision: an unmapped technique silently degrades to the generic EXPLOIT
    prompt, which is exactly the regression this layer exists to prevent."""
    unmapped = [tid for tid in TECHNIQUES if profile_for(tid) is EXPLOIT]
    assert unmapped == [], f"techniques without a class specialist: {unmapped}"


def test_route_is_exact_for_each_class():
    assert profile_for("access.idor") is A01.profile
    assert profile_for("access.control") is A01.profile
    assert profile_for("privesc.admin") is A01.profile
    assert profile_for("data.exfil") is A01.profile
    assert profile_for("injection.sqli") is A03.profile
    assert profile_for("injection.cmd") is A03.profile
    assert profile_for("xss.reflected") is A03.profile
    assert profile_for("session.steal") is A03.profile
    assert profile_for("info.sensitive") is A05.profile
    assert profile_for("auth.test") is A07.profile
    assert profile_for("auth.bypass") is A07.profile
    assert profile_for("ssrf") is A10.profile
    assert profile_for("internal.access") is A10.profile


def test_fallback_and_kill_switch(tmp_path, monkeypatch):
    assert profile_for("no.such.technique") is EXPLOIT
    assert profile_for(None) is EXPLOIT
    monkeypatch.setenv("RED_CLASS_SPECIALISTS", "0")
    assert all(profile_for(tid) is EXPLOIT for tid in TECHNIQUES)
    # any value other than "0" keeps the layer on
    monkeypatch.setenv("RED_CLASS_SPECIALISTS", "1")
    assert profile_for("access.idor") is A01.profile


def test_allowlists_are_subsets_of_the_real_registry():
    """A profile naming a tool the registry lacks would be a dead name — silently
    filtered by _make_specialist's subset check — so assert every allowlisted tool
    exists in the full registry. Degraded shapes (no browser/sandbox) are handled
    by that same subset filter BY DESIGN: a worker then simply runs with a smaller
    kit instead of crashing, which is the intended fallback, not this test's scope."""
    for kwargs in ({"enable_sandbox": False, "enable_browser": True},
                   {"enable_sandbox": True, "enable_browser": True}):
        registry = build_registry(**kwargs)
        missing = {n: spec.owasp for spec in CLASS_SPECIALISTS
                   for n in spec.profile.tool_names if n not in registry}
        assert missing == {}, f"allowlist tools missing from the registry: {missing}"


def test_registry_structure():
    owasps = [s.owasp for s in CLASS_SPECIALISTS]
    assert len(owasps) == len(set(owasps)), "duplicate OWASP class ids"
    owned = [t for s in CLASS_SPECIALISTS for t in s.techniques]
    assert len(owned) == len(set(owned)), "a technique owned by two classes"
    for spec in CLASS_SPECIALISTS:
        assert spec.profile.name.startswith(spec.owasp.lower())
        # Density floor: the addon IS the expertise — a thin one is the generic
        # prompt with a hat on, which is the failure mode this layer fights.
        assert len(spec.profile.addon) >= 400, f"{spec.owasp} addon too thin"
        assert ROUTE and all(ROUTE[t] is spec.profile for t in spec.techniques)
    # depth/reasoning classes run the strong pool; breadth/fetch work may be cheaper
    assert A01.profile.role == PLAN and A03.profile.role == PLAN
    assert A05.profile.role == PARSE


class _StubAgent:
    """Stands in for RedTeamAgent so the swarm's routing seam is observable
    without an LLM: records the profile and telemetry name it was built with."""

    instances = []

    def __init__(self, profile, agent_name):
        self.profile, self.agent_name = profile, agent_name
        _StubAgent.instances.append(self)

    def with_runtime(self, **kw):
        return self

    def run(self, objective, on_text=None):
        return "stub"


def test_swarm_workers_run_their_class_expert(tmp_path, monkeypatch):
    """Integration: a seeded tree claimed by ONE worker must visit every entry
    technique with THAT technique's class profile (and its telemetry name), with
    the assigned-target suffix still appended."""
    _StubAgent.instances = []
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    tree = AttackTree(tmp_path / "at.json")
    tree.seed_endpoint("http://api.acme.example/x")
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=object(),
                        graph=None, attack_tree=tree, max_exploit_rounds=1,
                        max_swarm_workers=1)
    monkeypatch.setattr(Orchestrator, "_make_specialist",
                        lambda self, profile, addon_suffix="", agent_name=None:
                        _StubAgent(profile, agent_name))
    orch._run_exploit_swarm("objective text", 0)

    by_technique = {}  # telemetry name -> profile name is 1:1 (f"{profile.name}-w{worker_id}")
    seen = [(i.profile.name, i.agent_name) for i in _StubAgent.instances]
    assert ("a01-access", "a01-access-w0") in seen
    assert ("a03-injection", "a03-injection-w0") in seen
    assert ("a05-misconfig", "a05-misconfig-w0") in seen
    assert ("a07-auth", "a07-auth-w0") in seen
    assert ("a10-ssrf", "a10-ssrf-w0") in seen
    assert not any(name.startswith("exploit") for _, name in seen), \
        "generic EXPLOIT leaked into a routed claim"
    # Every entry technique actually got visited exactly once (worker sweeps the
    # whole frontier: no findings land, so each claim ends FAILED and it moves on).
    entry = [t.id for t in TECHNIQUES.values() if not t.chained]
    assert len(seen) == len(entry)


def test_swarm_kill_switch_restores_generic_exploit(tmp_path, monkeypatch):
    """RED_CLASS_SPECIALISTS=0 must reproduce the pre-Gen-3 behavior exactly:
    every claim builds a generic EXPLOIT worker."""
    _StubAgent.instances = []
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    tree = AttackTree(tmp_path / "at.json")
    tree.seed_endpoint("http://api.acme.example/x")
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=object(),
                        graph=None, attack_tree=tree, max_exploit_rounds=1,
                        max_swarm_workers=1)
    monkeypatch.setenv("RED_CLASS_SPECIALISTS", "0")
    monkeypatch.setattr(Orchestrator, "_make_specialist",
                        lambda self, profile, addon_suffix="", agent_name=None:
                        _StubAgent(profile, agent_name))
    orch._run_exploit_swarm("objective text", 0)
    assert _StubAgent.instances
    assert all(i.profile is EXPLOIT and i.agent_name == "exploit-w0"
               for i in _StubAgent.instances)

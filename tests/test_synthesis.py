"""synthesis — the evidence-join layer, tested.

The contract under test:
  - rules fire ONLY on their evidence patterns (no pattern, no idea — ideas without
    evidence are refused by construction);
  - R1 needs TWO held identities (a differential is impossible with one);
  - R3 refuses escaped reflections (proof budget is not spent on dead oracles);
  - output is deduped per (technique, target), ranked, capped;
  - brief() is bounded and always marks the draft as a draft;
  - the layer is pure state reasoning: no network path exists in the module;
  - degraded inputs (missing graph/sessions/findings) yield fewer ideas, never raises.
"""

from __future__ import annotations

import json

import pytest

from redteam.knowledge import ENDPOINT, PARAMETER, KnowledgeGraph
from redteam.synthesis import AttackIdea, Observation, brief, idea_for, synthesize


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, *a, **k):
        self.events.append((a, k))


class _Sessions:
    def __init__(self, labels=()):
        self._labels = list(labels)

    def labels(self):
        return list(self._labels)


class _Findings:
    def __init__(self, items=()):
        self._items = list(items)

    def all(self):
        return list(self._items)


class _Ctx:
    """Duck-typed ToolContext with only what synthesis reads."""

    def __init__(self, graph=None, sessions=None, findings=None):
        self.graph = graph
        self.sessions = sessions
        self.findings = findings
        self.audit = _Audit()


def _ctx(endpoints=(), params=(), sessions=(), findings=()):
    g = KnowledgeGraph()
    for ep in endpoints:
        g.observe(ENDPOINT, ep, attrs={"status": 200}, source="test")
    for key, attrs in params:
        g.observe(PARAMETER, key, attrs=attrs, source="test")
    return _Ctx(graph=g, sessions=_Sessions(sessions),
                findings=_Findings(findings))


class _F:
    def __init__(self, fid, title, cwe=""):
        self.id, self.title, self.cwe = fid, title, cwe


# -- R1: identity differential -------------------------------------------------

def test_r1_two_identities_and_numeric_path_fire_idor():
    ctx = _ctx(endpoints=["http://t/api/orders/1042"],
               sessions=["sess-admin", "sess-user"])
    ideas = synthesize(ctx)
    idea = idea_for(ideas, "access.idor", "http://t/api/orders/1042")
    assert idea is not None
    assert "sess-admin" in idea.rationale and "sess-user" in idea.rationale
    low = idea.proposed_test.lower()
    assert "baseline" in low and "payload" in low and "differs" in low
    refs = {o.ref for o in idea.evidence}
    assert {"sess-admin", "sess-user"} <= refs


def test_r1_needs_two_identities():
    ctx = _ctx(endpoints=["http://t/api/orders/1042"], sessions=["sess-admin"])
    assert idea_for(synthesize(ctx), "access.idor", "http://t/api/orders/1042") is None


def test_r1_identifier_param_node_also_fires():
    ctx = _ctx(endpoints=["http://t/api/profile"],
               params=[("http://t/api/profile#user_id", {"reflected": False})],
               sessions=["sess-a", "sess-b"])
    idea = idea_for(synthesize(ctx), "access.idor", "http://t/api/profile")
    assert idea is not None and "user_id" in idea.proposed_test


def test_r1_unprotected_shape_without_ids_stays_silent():
    ctx = _ctx(endpoints=["http://t/blog/posts"], sessions=["sess-a", "sess-b"])
    assert synthesize(ctx) == []


# -- R2: unauth baseline -------------------------------------------------------

def test_r2_protected_path_with_session_fires():
    ctx = _ctx(endpoints=["http://t/admin/users"], sessions=["sess-admin"])
    idea = idea_for(synthesize(ctx), "access.control", "http://t/admin/users")
    assert idea is not None
    assert "NO session" in idea.proposed_test or "no session" in idea.proposed_test.lower()


def test_r2_public_path_stays_silent():
    ctx = _ctx(endpoints=["http://t/blog/posts"], sessions=["sess-admin"])
    assert idea_for(synthesize(ctx), "access.control", "http://t/blog/posts") is None


# -- R3: reflection ready ------------------------------------------------------

def test_r3_live_sink_fires_with_context_correct_draft():
    ctx = _ctx(endpoints=["http://t/search"],
               params=[("http://t/search#q", {"reflected": True,
                                              "specials_survive": True,
                                              "context": "html_body"})],
               sessions=["sess-admin"])
    idea = idea_for(synthesize(ctx), "xss.reflected", "http://t/search")
    assert idea is not None
    assert "html_body" in idea.proposed_test
    assert "reflected_unescaped" in idea.proposed_test
    assert "re-map" not in idea.rationale  # budget language: do NOT re-map


def test_r3_escaped_reflection_refuses_to_spend_budget():
    ctx = _ctx(endpoints=["http://t/search"],
               params=[("http://t/search#q", {"reflected": True,
                                              "specials_survive": False,
                                              "context": "html_body"})],
               sessions=["sess-admin"])
    assert idea_for(synthesize(ctx), "xss.reflected", "http://t/search") is None


# -- R4: credential reuse ------------------------------------------------------

def test_r4_credential_finding_plus_auth_endpoint_fires():
    ctx = _ctx(endpoints=["http://t/api/login"],
               sessions=["sess-admin"],
               findings=[_F("F-1", "API key disclosed in JS bundle", cwe="CWE-200")])
    idea = idea_for(synthesize(ctx), "auth.test", "http://t/api/login")
    assert idea is not None and "F-1" in idea.rationale


def test_r4_needs_both_halves():
    a = _ctx(endpoints=["http://t/api/orders"],
             findings=[_F("F-1", "API key disclosed in JS bundle")])
    b = _ctx(endpoints=["http://t/api/login"], sessions=["sess-admin"])
    assert synthesize(a) == [] and synthesize(b) == []


# -- engine contract -----------------------------------------------------------

def test_ranking_prefers_richer_evidence_and_priority():
    ctx = _ctx(endpoints=["http://t/api/orders/1042", "http://t/admin/users",
                          "http://t/api/login"],
               sessions=["sess-a", "sess-b"],
               findings=[_F("F-1", "Password reset token leaked", cwe="CWE-640")])
    ideas = synthesize(ctx, limit=8)
    techniques = [i.technique for i in ideas]
    assert len(ideas) >= 3 and len(set((i.technique, i.target) for i in ideas)) == len(ideas)
    # idor (priority 85, 3 evidence) outranks the two-observation ideas
    assert techniques[0] == "access.idor"


def test_limit_caps_output():
    ctx = _ctx(endpoints=[f"http://t/api/orders/{i}" for i in range(10, 22)],
               sessions=["sess-a", "sess-b"])
    assert len(synthesize(ctx, limit=4)) == 4


def test_degraded_inputs_yield_empty_not_raise():
    assert synthesize(_Ctx()) == []
    class _Broken:
        def nodes(self, kind):
            raise RuntimeError("boom")
    c = _Ctx()
    c.graph = _Broken()
    assert synthesize(c) == []


def test_brief_is_bounded_and_honest():
    idea = AttackIdea(
        technique="access.idor", target="http://t/x",
        rationale="r" * 3000,
        evidence=[Observation("sessions", "identity", "sess-a", "held identity"),
                  Observation("graph", "endpoint", "http://t/x", "numeric id")],
        expected_behavior="403", proposed_test="GET ... as A vs B", verify_hint="k-of-n")
    text = brief(idea, max_chars=900)
    assert len(text) <= 900 and "DRAFT" in text and "sess-a" in text


def test_idea_for_lookup():
    ideas = [AttackIdea(technique="access.idor", target="http://t/x", rationale="r")]
    assert idea_for(ideas, "access.idor", "http://t/x") is ideas[0]
    assert idea_for(ideas, "ssrf", "http://t/x") is None

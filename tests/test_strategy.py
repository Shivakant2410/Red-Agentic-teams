"""Phase B5 — tests for the cross-round strategy memory (redteam/strategy.py) and
its wiring into the orchestrator's reflection loop.

The invariants under test are the three rules from the module docstring:
1. directives have TTLs (no stickiness — the old apply-once-forever is gone),
2. evidence beats opinion in both directions (a confirmed technique releases
   both its avoid and its press),
3. forgetting is deterministic — a dead/absent strategist changes nothing about
   the decay."""

from __future__ import annotations

import json

from redteam.attack_tree import AttackTree
from redteam.reflection import build_digest
from redteam.strategy import (MAX_DIRECTIVES, TTL_AVOID, TTL_PRESS,
                              EngagementStrategy, reset_tree_nudges)

REFLECTION = {
    "assessment": "sqli looks alive; auth.test produced nothing",
    "what_worked": ["sqli error-based landed"],
    "what_failed": ["auth.test default creds"],
    "prioritize": [{"technique": "injection.sqli",
                    "target": "https://t.example/login"}],
    "deprioritize": ["auth.test"],
    "focus_next": ["press the sqli foothold"],
}


# -- rule 1: TTLs ------------------------------------------------------------------------

def test_amend_maps_reflection_into_directives():
    s = EngagementStrategy()
    counts = s.amend(REFLECTION, round_no=1)
    assert counts == {"press": 1, "avoid": 1, "notes": 1}
    press, avoid = s.directives_for_tree()
    assert press == [{"technique": "injection.sqli",
                      "target": "https://t.example/login"}]
    assert avoid == ["auth.test"]


def test_avoid_outlives_press():
    assert TTL_AVOID > TTL_PRESS


def test_press_expires_by_ttl():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    assert s.tick(2) == []                 # alive: 2-1 < TTL_PRESS
    released = s.tick(1 + TTL_PRESS)       # 3-1 == TTL_PRESS -> dead
    assert any("press injection.sqli" in r for r in released)
    press, _ = s.directives_for_tree()
    assert press == []


def test_avoid_expires_by_ttl_later_than_press():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    s.tick(1 + TTL_PRESS)                  # press dies here
    _, avoid = s.directives_for_tree()
    assert avoid == ["auth.test"]          # avoid still alive (ttl 3)
    released = s.tick(1 + TTL_AVOID)
    assert any("avoid auth.test" in r for r in released)
    _, avoid = s.directives_for_tree()
    assert avoid == []


def test_redeciding_refreshes_and_replaces():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    # same decision again: refreshed, not duplicated
    s.amend(REFLECTION, round_no=2)
    press, avoid = s.directives_for_tree()
    assert len(press) == 1 and len(avoid) == 1
    assert all(d.since_round == 2 for d in
               [x for x in s._directives.values()])  # both re-dated
    # a press on a DIFFERENT technique coexists — replacement is per
    # technique@target key; the old one still expires on its own ttl
    s.amend({"assessment": "x", "prioritize": [{"technique": "access.idor",
                                                "target": "https://t.example/u"}],
             "deprioritize": [], "what_worked": [], "what_failed": [],
             "focus_next": []}, round_no=3)
    press, _ = s.directives_for_tree()
    assert {p["technique"] for p in press} == {"injection.sqli", "access.idor"}
    s.tick(4)                                   # 4-2 >= ttl 2: old press dies
    press, _ = s.directives_for_tree()
    assert {p["technique"] for p in press} == {"access.idor"}


def test_directive_flood_is_capped():
    s = EngagementStrategy()
    many = {"assessment": "x",
            "prioritize": [{"technique": f"t{i}", "target": "x"}
                           for i in range(50)],
            "deprioritize": [], "what_worked": [], "what_failed": [],
            "focus_next": []}
    counts = s.amend(many, round_no=1)
    assert counts["press"] <= MAX_DIRECTIVES
    assert len(s._directives) <= MAX_DIRECTIVES


# -- rule 2: evidence beats opinion, both ways -------------------------------------------

def test_confirmed_technique_releases_avoid_immediately():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)             # avoid auth.test
    s.observe_round(2, claimed=["auth.test"], confirmed=[])   # claims, no luck
    s.tick(2)
    _, avoid = s.directives_for_tree()
    assert avoid == ["auth.test"]               # still written off
    # the write-off was WRONG: auth.test confirms at round 3
    s.observe_round(3, claimed=[], confirmed=["auth.test"])
    released = s.tick(3)
    assert any("avoid auth.test" in r and "evidence" in r for r in released)
    _, avoid = s.directives_for_tree()
    assert avoid == []


def test_confirmed_technique_releases_press_too():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)             # press sqli@...
    s.observe_round(2, claimed=[], confirmed=["injection.sqli"])
    released = s.tick(2)
    assert any("press injection.sqli" in r for r in released)
    press, _ = s.directives_for_tree()
    assert press == []                          # it worked — stop distorting


def test_ledger_counts_are_per_round_and_new_only():
    s = EngagementStrategy()
    s.observe_round(1, claimed=["injection.sqli", "injection.sqli"],
                    confirmed=[])
    snap = s.observe_round(2, claimed=[], confirmed=["injection.sqli"])
    assert snap["injection.sqli"]["claims"] == 2
    assert snap["injection.sqli"]["confirms"] == 1   # dedup is the caller's job,
    # confirmed again next round must NOT double-count (orchestrator passes deltas)
    snap = s.observe_round(3, claimed=[], confirmed=[])
    assert snap["injection.sqli"]["confirms"] == 1


# -- rule 3: forgetting is deterministic ---------------------------------------------------

def test_tick_without_any_reflection_still_expires():
    s = EngagementStrategy()          # the strategist NEVER answered
    s.amend(REFLECTION, round_no=1)   # (amend itself is deterministic)
    for r in range(2, 2 + TTL_AVOID + 1):
        s.tick(r)                     # a dead strategist would run none of this —
    assert s._directives == {}        # the orchestrator runs it regardless


def test_brief_is_deterministic_and_compact():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    s.observe_round(2, claimed=["auth.test", "injection.sqli"], confirmed=[])
    b1, b2 = s.brief(), s.brief()
    assert b1 == b2
    assert "avoid auth.test" in b1 and "press injection.sqli" in b1
    assert "auth.test:1c/0cf" in b1
    assert len(b1.splitlines()) <= 6   # the digest stays compact


def test_empty_state_brief_is_empty():
    assert EngagementStrategy().brief() == ""


def test_persistence_round_trip():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    s.observe_round(2, claimed=["auth.test"], confirmed=[])
    s.tick(2)
    clone = EngagementStrategy.from_dict(json.loads(json.dumps(s.to_dict())))
    assert clone.to_dict() == s.to_dict()
    assert clone.directives_for_tree() == s.directives_for_tree()


# -- the tree interface ---------------------------------------------------------------------

def test_reset_and_reapply_release_genuinely():
    tree = AttackTree()
    tree.seed_endpoint("https://t.example/login")   # entry techniques seeded
    s = EngagementStrategy()
    s.amend({"assessment": "x", "what_worked": [], "what_failed": [],
             "prioritize": [], "deprioritize": ["injection.sqli"],
             "focus_next": []}, round_no=1)
    press, avoid = s.directives_for_tree()
    tree.apply_strategy(prioritize=press, deprioritize=avoid)
    order_with_penalty = [n.technique for n in tree.actionable(limit=99)]
    assert "injection.sqli" in order_with_penalty
    # the penalty is live on the tree (sqli ranks below its base peers)
    base_order = None
    # expire the avoid and re-apply: the nudge layer resets to neutral first
    s.tick(1 + TTL_AVOID)
    reset_tree_nudges(tree)
    press, avoid = s.directives_for_tree()
    assert avoid == []
    tree.apply_strategy(prioritize=press, deprioritize=avoid)
    base_order = [n.technique for n in tree.actionable(limit=99)]
    # with no live directives the tree must be back to its pure order — the
    # released penalty is GONE, not merely outweighed (the old code could never
    # do this: apply-once-forever had no release path)
    tree2 = AttackTree()
    tree2.seed_endpoint("https://t.example/login")
    assert base_order == [n.technique for n in tree2.actionable(limit=99)]


def test_reset_tree_nudges_degrades_safely():
    class Frozen:
        pass
    assert reset_tree_nudges(Frozen()) is False   # no crash, old behavior


def test_avoid_actually_sinks_a_technique():
    tree = AttackTree()
    tree.seed_endpoint("https://t.example/login")
    base = [n.technique for n in tree.actionable(limit=99)]
    tree.apply_strategy(prioritize=[], deprioritize=["injection.sqli"])
    penal = [n.technique for n in tree.actionable(limit=99)]
    assert penal != base                          # the nudge layer works
    assert penal.index("injection.sqli") > base.index("injection.sqli")


# -- the strategist sees the state ----------------------------------------------------------

def test_digest_includes_strategy_brief():
    s = EngagementStrategy()
    s.amend(REFLECTION, round_no=1)
    digest = build_digest(objective_text="obj", round_no=2,
                          strategy_brief=s.brief())
    assert "ACTIVE STRATEGY STATE" in digest
    assert "avoid auth.test" in digest
    # and without one, the digest shape is unchanged
    plain = build_digest(objective_text="obj", round_no=2)
    assert "ACTIVE STRATEGY STATE" not in plain


# -- the orchestrator wiring (integration, fakes only — no LLM) ------------------------------

class _ReflectionClient:
    """Returns a strict-JSON reflection for the strategist call; harmless 'done'
    for anything else (specialist calls). Payloads are consumed in order, so a
    test can script what the strategist says each round."""
    def __init__(self, *payloads: dict):
        self._payloads = list(payloads)

    def chat(self, messages, tools=None, role="plan"):
        from redteam.llm.openrouter import ChatResult
        last = (messages or [{}])[-1].get("content", "")
        if last.endswith("Return the strict JSON reflection now."):
            payload = self._payloads.pop(0) if self._payloads else {
                "assessment": "hold", "what_worked": [], "what_failed": [],
                "prioritize": [], "deprioritize": [], "focus_next": []}
            return ChatResult(model="fake",
                              message={"role": "assistant",
                                       "content": json.dumps(payload)},
                              finish_reason="stop", usage={})
        return ChatResult(model="fake",
                          message={"role": "assistant", "content": "done"},
                          finish_reason="stop", usage={})


class _BrokenClient:
    def chat(self, messages, tools=None, role="plan"):
        raise RuntimeError("strategist down")


def _orch(tmp_path, client, tree):
    import datetime as _dt
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    from redteam.findings import FindingStore
    from redteam.knowledge import KnowledgeGraph
    from redteam.orchestrator import Orchestrator
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.tools import ToolContext
    eng = Engagement(name="t", client="c", authorized_by="a", ticket="r",
                     starts=_dt.date.today(), ends=_dt.date.today(),
                     allowed_hosts=("t.example",), excluded_hosts=(),
                     allowed_ports=(443,), allowed_schemes=("https",),
                     max_requests_per_second=100.0, max_total_requests=1000,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    audit = _Audit()
    ctx = ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                      limiter=RateLimiter(100, 1000), audit=audit,
                      findings=FindingStore(tmp_path / "f.json"),
                      approve=lambda a, d: True,
                      graph=KnowledgeGraph(tmp_path / "g.json"))
    orch = Orchestrator(eng, tools={}, ctx=ctx, client=client,
                        graph=ctx.graph, attack_tree=tree, memory=None)
    return orch, audit


class _Audit:
    def __init__(self):
        self.events = []
    def record(self, event, **f):
        self.events.append({"event": event, **f})
    def read_all(self):
        return list(self.events)


def test_orchestrator_amends_carries_and_releases(tmp_path):
    tree = AttackTree()
    tree.seed_endpoint("https://t.example/login")
    # Round 2's strategist answers with an EMPTY amendment: the release we assert
    # must come from the evidence rule, not from the strategist changing its mind.
    orch, audit = _orch(tmp_path, _ReflectionClient(REFLECTION, {
        "assessment": "sqli confirmed, hold course", "what_worked": [],
        "what_failed": [], "prioritize": [], "deprioritize": [],
        "focus_next": []}), tree)

    # Round 0: swarm claimed sqli + auth.test (simulated claim loop), strategist
    # answers: press sqli, avoid auth.test -> both land on the tree.
    orch._round_claims = ["injection.sqli", "auth.test"]
    orch._reflect_on_round("obj", 0)
    assert orch._reflections[-1]["boosts_applied"] == 2
    assert orch._reflections[-1]["strategy_amended"] == {"press": 1, "avoid": 1,
                                                         "notes": 1}
    assert orch._strategy.state()["ledger"]["auth.test"]["claims"] == 1
    press, avoid = orch._strategy.directives_for_tree()
    assert len(press) == 1 and avoid == ["auth.test"]

    # Round 1: the strategist DIES. The strategy must survive applied, still
    # steering the tree — an amplifier failure must not drop the state.
    orch._client = _BrokenClient()
    orch._round_claims = []
    orch._reflect_on_round("obj", 1)
    press, avoid = orch._strategy.directives_for_tree()
    assert len(press) == 1 and avoid == ["auth.test"]

    # Round 2: sqli CONFIRMS and the strategist (back up) adds nothing. Evidence
    # beats opinion — the press releases (it worked), while the avoid on
    # auth.test keeps ticking toward its ttl.
    orch._client = _ReflectionClient({
        "assessment": "sqli confirmed, hold course", "what_worked": [],
        "what_failed": [], "prioritize": [], "deprioritize": [],
        "focus_next": []})
    tree.confirm("injection.sqli", "https://t.example/login")
    orch._reflect_on_round("obj", 2)
    press, avoid = orch._strategy.directives_for_tree()
    assert press == []
    assert avoid == ["auth.test"]
    assert any("evidence" in r for r in
               orch._reflections[-1]["strategy_released"])
    # and the release is audible in the audit trail
    assert any(e["event"] == "orchestrator.strategy_released"
               for e in audit.events)


def test_orchestrator_disabled_reflection_leaves_tree_alone(tmp_path):
    tree = AttackTree()
    tree.seed_endpoint("https://t.example/login")
    orch, audit = _orch(tmp_path, _ReflectionClient(REFLECTION), tree)
    # Engagement is a frozen dataclass — the sanctioned way tests opt out.
    object.__setattr__(orch._eng, "enable_reflection", False)
    orch._round_claims = ["injection.sqli"]
    orch._reflect_on_round("obj", 0)
    assert orch._reflections == []
    assert not audit.events  # nothing recorded, nothing applied
    # and the nudge layer is untouched (no writer ran at all)
    assert tree._strategy_boost == {} and tree._technique_penalty == {}

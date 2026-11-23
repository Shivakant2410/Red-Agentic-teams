"""Tests for agent hands and skills (redteam/hands.py, Phase E1).

The discipline this locks: an agent's profile tool_names, its HANDS entry, and
its declared SKILLS must agree exactly — no untaught hands, no unheld teachings,
no skill naming a tool its agent cannot raise, and every trust class must be the
crosscheck layer's own vocabulary. Failure of any of these is the "too generic"
drift: an agent with a name list instead of a capability surface.
"""

from __future__ import annotations

import json

import pytest

from redteam.hands import (HANDS, OPTIONAL_TOOLS, SKILLS, TRUST_CLASSES, Hand,
                           Skill, agent_names, hands_briefing, hands_json,
                           skills_briefing, validate_agent, validate_all,
                           validate_skills)
from redteam.orchestrator import ACCESS, EXPLOIT, LOGIC, RECON, VERIFY
from redteam.specialists import CLASS_SPECIALISTS, profile_for
from redteam.tools import build_registry
from redteam.tools.crosscheck import EXEMPT, TRUST_MATRIX


def _builtin_profiles():
    return {"recon": RECON, "exploit": EXPLOIT, "access": ACCESS,
            "logic": LOGIC, "verify": VERIFY}


def _all_profiles():
    out = {name: prof for name, prof in _builtin_profiles().items()}
    for spec in CLASS_SPECIALISTS:
        out[spec.profile.name] = spec.profile
    return out


def _full_registry_keys():
    return set(build_registry(enable_sandbox=True, enable_browser=True))


# ---------------------------------------------------------------------------
# Profile <-> HANDS exact agreement (the static fail-loud discipline)
# ---------------------------------------------------------------------------

def test_every_profile_tool_names_exactly_equal_its_hands():
    for name, prof in _all_profiles().items():
        assert set(prof.tool_names) == {h.tool for h in HANDS[name]}, (
            f"agent '{name}': profile and HANDS disagree — generic drift")


def test_every_agent_with_a_profile_has_a_hands_entry():
    assert set(_all_profiles()) == set(HANDS), (
        "an agent exists on one side only: profile without hands, or hands "
        "without a profile")


def test_hand_tools_exist_in_the_registry():
    keys = _full_registry_keys()
    for name, hands in HANDS.items():
        for h in hands:
            assert h.tool in keys, (
                f"agent '{name}' hand '{h.tool}' is not a real registry tool (typo?)")


def test_optional_tools_are_the_only_registry_absent_hands_allowed():
    # build_registry without sandbox/browser must still validate every profile —
    # the OPTIONAL set covers exactly the difference.
    headless = set(build_registry(enable_sandbox=False, enable_browser=False))
    for name, prof in _all_profiles().items():
        validate_agent(name, prof.tool_names, headless)


def test_the_team_holds_the_d0_d2_hands():
    """The Phase E1 point: discovery stack + deterministic probes + playbook
    lookup are held by agents, not just present in the registry."""
    assert {"content_discovery", "crawl", "param_discovery", "host_probe",
            "port_scan", "spa_recon", "crosscheck_lead"} <= set(RECON.tool_names)
    assert {"find_techniques", "apply_skill", "crosscheck_lead"} <= set(EXPLOIT.tool_names)
    assert {"xss_reflect_probe", "graphql_inspect"} <= set(
        profile_for("xss.reflected").tool_names)
    assert "content_discovery" in profile_for("info.sensitive").tool_names
    # A10's addon told it to START with surface_scan while its hands did not
    # hold it — the exact unheld-teaching bug this phase kills.
    assert "surface_scan" in profile_for("ssrf").tool_names


def test_recon_got_headroom_for_the_discovery_stack():
    assert RECON.max_steps >= len(RECON.tool_names), (
        "recon holds the discovery stack; max_steps must let it run more than "
        "one hand per tool")


# ---------------------------------------------------------------------------
# Trust classes — locked to the crosscheck layer's vocabulary
# ---------------------------------------------------------------------------

def test_every_hand_trust_class_is_in_the_vocabulary():
    for name, hands in HANDS.items():
        for h in hands:
            assert h.trust in TRUST_CLASSES, (
                f"{name}/{h.tool}: trust '{h.trust}' is not crosscheck vocabulary")


def test_lead_crosschecked_hands_are_exactly_trust_matrix_tools():
    for name, hands in HANDS.items():
        for h in hands:
            if h.trust == "lead-crosschecked":
                assert h.tool in TRUST_MATRIX and TRUST_MATRIX[h.tool], (
                    f"{name}/{h.tool} claims lead-crosschecked but the trust "
                    f"matrix has no second-method entry — a hand may not claim "
                    f"a discipline the crosscheck layer does not enforce")
    # and the sandbox executor must NOT claim lead-crosschecked for itself — its
    # wrapped binaries obey the matrix per wrapped tool, not as one class
    assert HANDS["recon"]
    kali = next(h for h in HANDS["recon"] if h.tool == "kali_exec")
    assert kali.trust != "lead-crosschecked"


def test_exempt_hands_match_the_crosscheck_exempt_set():
    from redteam.hands import META_TOOLS
    for name, hands in HANDS.items():
        for h in hands:
            if h.trust == "ground-truth":
                assert h.tool in EXEMPT or h.tool in META_TOOLS, (
                    f"{name}/{h.tool} claims ground-truth but is neither EXEMPT nor "
                    f"a meta tool that makes no target claim")
            if h.trust == "offline-parse":
                assert h.tool in EXEMPT or h.tool == "extract_secrets", (
                    f"{name}/{h.tool} claims offline-parse without an exempt "
                    f"rationale")


def test_proof_trial_hands_are_the_proof_pipeline():
    proof_tools = {"verify_vulnerability", "confirm_finding", "verify_workflow_abuse",
                   "verify_race_condition", "prove_privilege",
                   "verify_finding_independently", "apply_skill", "claim_objective"}
    for name, hands in HANDS.items():
        for h in hands:
            if h.trust == "proof-trial":
                assert h.tool in proof_tools, (
                    f"{name}/{h.tool} claims proof-trial but is not a proof tool")
            if h.tool in proof_tools:
                assert h.cost == "verification-trial", (
                    f"{h.tool} burns verification trials — its hand must say so")


def test_every_hand_states_purpose_cost_and_obligation():
    for name, hands in HANDS.items():
        for h in hands:
            assert h.purpose and h.obligation, f"{name}/{h.tool}: empty teaching"
            assert h.cost in ("step", "verification-trial")
            assert h.purpose[-1] in ".!:;" or len(h.purpose) > 10


# ---------------------------------------------------------------------------
# Skills — declared procedures, structurally bound to held hands
# ---------------------------------------------------------------------------

def test_skills_only_reference_tools_their_agent_holds():
    for name in HANDS:
        validate_skills(name)   # raises on a phantom reference


def test_every_agent_has_at_least_one_skill():
    for name in _all_profiles():
        assert SKILLS.get(name), f"agent '{name}' has no declared skills"


def test_skill_fields_are_concrete():
    for name, skills in SKILLS.items():
        for s in skills:
            assert s.agent == name
            assert s.when and s.exit and s.proof, f"{s.name}: empty binding"
            assert len(s.steps) >= 2, f"{s.name}: a one-step procedure is advice"
            assert any(t in s.tools for t in s.tools)


def test_exploit_skills_cover_the_synthesis_draft_handoff():
    """The evidence-join layer hands workers ready check_specs; a skill must
    bind that handoff, or the draft is thrown away at the worker."""
    names = {s.name for s in SKILLS["exploit"]}
    assert "ready-spec-consume" in names
    skill = next(s for s in SKILLS["exploit"] if s.name == "ready-spec-consume")
    assert "verify_vulnerability" in skill.tools


# ---------------------------------------------------------------------------
# Validation — fail closed, with the offending names
# ---------------------------------------------------------------------------

def test_validate_agent_rejects_unknown_agent():
    with pytest.raises(ValueError, match="no HANDS entry"):
        validate_agent("ghost-agent", [], _full_registry_keys())


def test_validate_agent_rejects_untought_and_unheld_disagreement():
    with pytest.raises(ValueError, match="taught-but-not-held"):
        validate_agent("verify", ["verify_finding_independently", "http_probe"],
                       _full_registry_keys())


def test_validate_agent_rejects_registry_typos():
    with pytest.raises(ValueError, match="http_prob"):
        hands = HANDS["verify"] + (Hand(tool="http_prob", purpose="x", cost="step",
                                        trust="first-party-observation",
                                        obligation="y"),)
        validate_agent("verify", [h.tool for h in hands], _full_registry_keys())


def test_validate_agent_rejects_off_vocabulary_trust():
    import copy as _copy
    bad = Hand(tool="verify_finding_independently", purpose="x", cost="step",
               trust="totally-trustworthy", obligation="y")
    saved = HANDS["verify"]
    monkeyed = {**HANDS, "verify": (bad,)}
    import redteam.hands as hmod
    original = hmod.HANDS
    hmod.HANDS = monkeyed
    try:
        with pytest.raises(ValueError, match="totally-trustworthy"):
            validate_agent("verify", ["verify_finding_independently"],
                           _full_registry_keys())
    finally:
        hmod.HANDS = original


def test_validate_all_passes_on_the_shipped_state():
    validate_all(_full_registry_keys())


# ---------------------------------------------------------------------------
# Briefings — deterministic renderings, filtered to raisable hands
# ---------------------------------------------------------------------------

def test_hands_briefing_lists_cost_trust_and_obligation():
    held = {"surface_scan", "http_probe"}
    text = hands_briefing("recon", held)
    assert "surface_scan — knock on every host/port" in text
    assert "trust: ground-truth" in text
    assert "trust: first-party-observation" in text
    assert "owe:" in text
    assert "content_discovery" not in text   # not held -> not taught


def test_skills_briefing_renders_entry_steps_exit_proof():
    text = skills_briefing("verify", held={"verify_finding_independently"})
    assert "run-all-pending" in text
    assert "WHEN" in text and "EXIT:" in text and "PROOF:" in text
    assert "1." in text and "2." in text


def test_skills_briefing_skips_unexecutable_skills():
    # a10's two-shape-ssrf needs surface_scan; without it the skill must not
    # be taught (the A10 addon drift, now impossible by construction).
    text = skills_briefing("a10-ssrf", held={"http_probe", "verify_vulnerability",
                                             "confirm_finding", "browser_navigate",
                                             "browser_content", "search_peer_traces"})
    assert "two-shape-ssrf" not in text
    assert "none executable" in text
    with_all = skills_briefing("a10-ssrf")
    assert "two-shape-ssrf" in with_all


def test_make_specialist_rides_hands_and_skills_into_the_system_prompt():
    """The full wiring: a constructed worker's addon carries its hands and skills."""
    from tests.test_specialists import _ctx as _spec_ctx, _engagement, RecordingAudit
    from redteam.orchestrator import Orchestrator

    audit = RecordingAudit()
    ctx = _spec_ctx(tmp_path=None, audit=audit) if False else None
    # build a real ctx the same way test_specialists does
    import datetime as _dt, tempfile
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    from redteam.findings import FindingStore
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.tools import ToolContext
    eng = _engagement()
    with tempfile.TemporaryDirectory() as td:
        ctx = ToolContext(
            scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
            limiter=RateLimiter(100, 1000), audit=audit,
            findings=FindingStore(f"{td}/f.json"), approve=lambda a, d: True,
            graph=None, access=None, killchain=None, objective=None)
        registry = build_registry(enable_sandbox=False, enable_browser=False)
        orch = Orchestrator(eng, registry, ctx=ctx, client=None)
        agent = orch._make_specialist(profile_for("xss.reflected"), agent_name="a03-w0")
        addon = agent._system_addon
        assert "YOUR HANDS" in addon
        assert "xss_reflect_probe — deterministic reflection map" in addon
        assert "verification-trial" in addon          # cost class shown
        assert "reflect-map-prove" in addon           # skill rendered
        assert "ready-spec" not in addon or "ready" not in addon.split("YOUR SKILLS")[0]
        # headless run: browser-only skills of OTHER agents never leak in
        assert "two-principal-differential" not in addon


def test_unheld_hands_are_audited_not_silent():
    from tests.test_specialists import _engagement, RecordingAudit
    import tempfile
    from redteam.orchestrator import Orchestrator, SpecialistProfile
    from redteam.findings import FindingStore
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.tools import ToolContext

    audit = RecordingAudit()
    eng = _engagement()
    with tempfile.TemporaryDirectory() as td:
        ctx = ToolContext(
            scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
            limiter=RateLimiter(100, 1000), audit=audit,
            findings=FindingStore(f"{td}/f.json"), approve=lambda a, d: True,
            graph=None, access=None, killchain=None, objective=None)
        orch = Orchestrator(eng, {}, ctx=ctx, client=None)
        broken = SpecialistProfile(name="verify", addon="x",
                                   tool_names=["verify_finding_independently",
                                               "not_a_real_tool"])
        orch._make_specialist(broken, agent_name="verify")
        events = [e for e in audit.read_all() if e["event"] == "specialist.hands.unheld"]
        assert events and "not_a_real_tool" in events[0]["unheld"]


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

def test_hands_json_parses_and_carries_every_agent():
    data = json.loads(hands_json())
    assert data["policy"]
    assert set(data["agents"]) == set(HANDS)
    recon = data["agents"]["recon"]
    # Phased recon workflow (2026-11-18): Phase B starts PASSIVE (DNS/TLS/
    # metadata via passive_recon); surface_scan opens Phase C active mapping.
    assert recon["hands"][0]["tool"] == "passive_recon"
    assert "surface_scan" in {h["tool"] for h in recon["hands"]}
    assert recon["skills"], "recon must carry declared skills in the manifest"
    for agent in data["agents"].values():
        for h in agent["hands"]:
            assert h["trust"] in TRUST_CLASSES
            assert h["cost"] in ("step", "verification-trial")


def test_agent_names_sorted():
    assert agent_names() == sorted(HANDS)

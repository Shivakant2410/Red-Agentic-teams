"""Kill-chain projection (our tool) — mechanical phase derivation and the
capability-conditioned chain plan. The registry is the single source of
truth: every phase assignment here is DERIVED from registry fields, so the
tests pin the derivation rules and the planner integration, not a hand-list.
"""

import json
import subprocess
import sys

from redteam.pi.killchain import (
    PHASES,
    PHASE_ANCHORS,
    PHASE_RANK,
    kill_chain_audit,
    kill_chain_map,
    kill_chain_plan,
)
from redteam.pi.planner import FIXTURE_CAPABILITIES
from redteam.pi.techniques import BY_ID, TECHNIQUES


# -- the static map ---------------------------------------------------------------------


def test_map_is_deterministic():
    m1 = kill_chain_map()
    m2 = kill_chain_map()
    assert m1 == m2
    assert set(m1["techniques"]) == {t.id for t in TECHNIQUES}


def test_every_technique_delivers_and_executes():
    """Registry invariant: every technique's success stage is at least
    RELAYED, so DELIVER+EXECUTE are occupied by all — the map must say so."""
    for tid, entry in kill_chain_map()["techniques"].items():
        assert "DELIVER" in entry["phases"], tid
        assert "EXECUTE" in entry["phases"], tid


def test_weaponize_rule_encoded_companions_and_operator_material():
    m = kill_chain_map()["techniques"]
    # encoded companions ({b64}/{tags}/{zw}/{rot13}) or operator_input:
    for tid in ("PI.A5", "PI.A6", "PI.A9", "PI.B6", "PI.B10"):
        assert "WEAPONIZE" in m[tid]["phases"], tid
    # plain-text directives are not weaponization:
    for tid in ("PI.A1", "PI.A3", "PI.B1", "PI.C1", "PI.E2"):
        assert "WEAPONIZE" not in m[tid]["phases"], tid


def test_privilege_rule_is_the_forbidden_tool_oracle():
    m = kill_chain_map()["techniques"]
    expected = {t.id for t in TECHNIQUES
                if t.primary_oracle == "pi.forbidden_tool"}
    got = {tid for tid, e in m.items() if "PRIVILEGE" in e["phases"]}
    assert got == expected
    assert expected, "the rule must not be vacuous"
    assert "PI.B1" in expected and "PI.A9" not in expected


def test_persist_rule_is_the_persisted_stage():
    m = kill_chain_map()["techniques"]
    got = {tid for tid, e in m.items() if "PERSIST" in e["phases"]}
    assert got == {"PI.B6", "PI.B10"}      # the two cross-session shapes


def test_exfil_rule_is_the_egress_shaped_url():
    """EXFIL = the canary riding an https URL in a VISIBLE payload body.
    E4 (seeding+pivot) has no URL and must NOT occupy EXFIL — the regression
    guard that keeps the rule mechanical rather than family-lumped."""
    m = kill_chain_map()["techniques"]
    got = {tid for tid, e in m.items() if "EXFIL" in e["phases"]}
    assert got == {"PI.E1", "PI.E2", "PI.E3"}
    assert "EXFIL" not in m["PI.E4"]["phases"]


def test_delivery_direct_vs_indirect():
    m = kill_chain_map()["techniques"]
    assert m["PI.A1"]["delivery"] == "direct"     # user_message, untrusted=False
    assert m["PI.B1"]["delivery"] == "indirect"   # rag_document, untrusted=True
    # the plan-field channel is attacker-controlled content -> indirect
    assert m["PI.C1"]["delivery"] == "indirect"
    for tid, e in m.items():
        assert e["delivery"] in ("direct", "indirect"), tid


def test_payload_ref_attribution_survives_the_projection():
    m = kill_chain_map()["techniques"]
    assert m["PI.B10"]["payload_ref"] == "PI.B10#p_infect@1.0.0"


# -- phase anchors (the ancestry contract) ------------------------------------------------


def test_all_seven_phases_have_real_framework_anchors():
    assert PHASES == ("RECON", "WEAPONIZE", "DELIVER", "EXECUTE",
                      "PRIVILEGE", "PERSIST", "EXFIL")
    for p in PHASES:
        a = PHASE_ANCHORS[p]
        assert "atlas_tactic" in a and a["atlas_tactic"], p
        assert "Hutchins" in a["kill_chain"], p   # the kill-chain ancestry


def test_phase_rank_terminal_outcomes_share_the_deepest_rank():
    assert PHASE_RANK["EXECUTE"] < PHASE_RANK["PRIVILEGE"]
    assert PHASE_RANK["PRIVILEGE"] == PHASE_RANK["PERSIST"] == \
        PHASE_RANK["EXFIL"]


# -- the capability-conditioned plan ------------------------------------------------------


def test_plan_under_fixture_capabilities_no_breaks():
    out = kill_chain_plan(capabilities=FIXTURE_CAPABILITIES)
    assert out["capabilities"] == sorted(FIXTURE_CAPABILITIES)
    assert out["chain_breaks"] == []
    # fixture: tool_surface + memory_store -> the terminal phases are alive
    assert out["phases"]["PRIVILEGE"]["alive"], "forbidden_tool techniques"
    assert out["phases"]["PERSIST"]["alive"] == ["PI.B6", "PI.B10"]
    assert out["phases"]["EXFIL"]["alive"]
    assert out["reachable_depth"]["phase"] in ("EXFIL", "PERSIST",
                                               "PRIVILEGE")
    assert out["reachable_depth"]["rank"] == 4


def test_plan_recon_is_a_planner_artifact_not_a_technique():
    out = kill_chain_plan(capabilities=FIXTURE_CAPABILITIES)
    assert out["phases"]["RECON"]["total"] == 0
    assert out["phases"]["RECON"]["alive"] == []
    assert "planner" in out["phases"]["RECON"]["note"]


def test_plan_without_tool_surface_breaks_at_privilege():
    out = kill_chain_plan(capabilities=("memory_store",))
    breaks = {b["phase"]: b for b in out["chain_breaks"]}
    assert "PRIVILEGE" in breaks, "no tool_surface -> the chain cannot cash out"
    # the blocker set names the missing surface AND the gated techniques'
    # own labels (plan_phase / image_input / fine_tune_access) — all honest
    assert "tool_surface" in out["phases"]["PRIVILEGE"]["blocked_by"]
    # persistence survives on memory_store alone
    assert out["phases"]["PERSIST"]["alive"] == ["PI.B6", "PI.B10"]


def test_plan_without_memory_store_breaks_at_persist():
    out = kill_chain_plan(capabilities=("tool_surface",))
    breaks = {b["phase"]: b for b in out["chain_breaks"]}
    assert "PERSIST" in breaks
    assert "memory_store" in out["phases"]["PERSIST"]["blocked_by"]
    assert out["phases"]["PRIVILEGE"]["alive"]


def test_plan_bare_capabilities_everything_breaks():
    out = kill_chain_plan(capabilities=())
    break_phases = {b["phase"] for b in out["chain_breaks"]}
    assert {"PRIVILEGE", "PERSIST"} <= break_phases
    # BUT the depth is still the terminal EXFIL rank: E1/E2's render-relay
    # exfil needs no tool_surface and no memory_store — a reply alone moves
    # the canary toward the attacker channel (the OWASP zero-click lesson,
    # now visible in the chain model)
    assert out["reachable_depth"] == {"rank": 4, "phase": "EXFIL"}
    assert {"PI.E1", "PI.E2"} <= set(out["phases"]["EXFIL"]["alive"])


def test_plan_respects_a_technique_subset():
    out = kill_chain_plan(("PI.B6",), ("memory_store",))
    assert out["phases"]["PERSIST"]["alive"] == ["PI.B6"]
    assert out["phases"]["PRIVILEGE"]["total"] == 0   # B6 is canary-oracle
    assert "PRIVILEGE" not in {b["phase"] for b in out["chain_breaks"]}, \
        "an empty phase is a structural gap, not a chain break"


# -- the audit payload and CLI --------------------------------------------------------------


def test_audit_reports_no_structural_gaps_on_the_full_registry():
    out = kill_chain_audit()
    assert out["structural_gaps"] == [], \
        "every non-recon phase must have >=1 occupying technique"
    assert out["registry"]["techniques"] == len(TECHNIQUES)
    assert out["registry"]["payloads"] == sum(
        len(t.payloads) for t in TECHNIQUES)
    assert out["recon"]["artifact"]


def test_cli_killchain_emits_json(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "redteam.pi", "--killchain"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["chain_order"] == list(PHASES)
    assert payload["summary"]["alive"] > 0
    assert payload["reachable_depth"]["rank"] == 4

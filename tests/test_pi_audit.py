"""G8/G9/G10 — standards anchors, coverage audit, bench honesty block
(our tools): metadata correctness and published measurement conditions."""

from redteam.pi.bench import compute_bench
from redteam.pi.techniques import (
    DELIVERY_CHANNELS, OWASP_2026_SCENARIOS, TECHNIQUES, coverage_audit,
    standards_anchors)


class _R:
    """Duck-typed record stub, same shape bench unit tests use."""

    def __init__(self, verdict, technique_id="PI.A1", defense_config="off",
                 delivery_channel="user_message", stage="none",
                 benign=None, legit=None):
        self.verdict = verdict
        self.technique_id = technique_id
        self.defense_config = defense_config
        self.delivery_channel = delivery_channel
        self.stage = stage
        self.payload_ref = f"{technique_id}#p@1.0.0"
        self.benign_control = benign or {"ran": True, "completed": True}
        self.legit_control = legit or {"ran": True, "honored": True}


def test_bench_carries_honesty_block():
    s = compute_bench("h", [_R("succeeded")], [], [])
    h = s["honesty"]
    assert h["fixture_only"] is True
    assert h["payload_library_public"] is True
    assert "upper bound" in h["saturation_warning"]
    assert h["heldout_split"]["status"] == "not_populated"
    assert h["standards_anchors"]["owasp"] == ["LLM01:2025", "LLM01:2026"]


def test_standards_anchors_dual_pin_and_family_map():
    a = standards_anchors()
    assert set(a["owasp"]) == {"LLM01:2025", "LLM01:2026"}
    assert a["atlas"]["verified_against"].startswith("atlas-data release 2026")
    assert set(a["llm01_2026_family_map"]) == {"A", "B", "C", "D", "E"}
    assert "Rule-of-Two" in a["rule_of_two"] or "Rule of Two" in \
        a["rule_of_two"].replace("-Two", " Two") or "Rule-of-Two" in \
        str(a["rule_of_two"])


def test_owasp_2026_scenarios_cover_the_new_techniques():
    for tid in ("PI.B6", "PI.B7", "PI.B8", "PI.A5", "PI.D1", "PI.D2",
                "PI.E2", "PI.E3", "PI.E4"):
        assert tid in OWASP_2026_SCENARIOS, tid
        assert "2026" in OWASP_2026_SCENARIOS[tid]


def test_coverage_audit_counts_match_registry():
    c = coverage_audit()
    assert c["techniques"] == len(TECHNIQUES) == 30  # +PI.A10
    assert c["payloads"] == sum(len(t.payloads) for t in TECHNIQUES)
    assert c["by_family"] == {"A": 10, "B": 10, "C": 4, "D": 2, "E": 4}
    for ch in ("tool_description", "tool_desc_swap", "plan_field"):
        assert ch in c["channels"], ch
        assert ch in DELIVERY_CHANNELS
    assert c["by_delivery"]["tool_description"] == ["PI.B7"]
    assert c["by_delivery"]["tool_desc_swap"] == ["PI.B8"]
    assert c["by_success_stage"], "stage targets mapped"


def test_coverage_audit_names_known_uncovered_surfaces():
    c = coverage_audit()
    uncovered = c["known_uncovered"]
    for key in ("multilingual_payloads", "multimodal_executed",
                "fine_tuning_executed",
                "whitebox_suffix_search"):
        assert key in uncovered, key
    assert "PIAtlas" in c["piatlas_mapping"]


def test_legit_control_metric_flows_through_bench():
    rows = [_R("resisted", legit={"ran": True, "honored": True}),
            _R("inconclusive", legit={"ran": True, "honored": False})]
    s = compute_bench("h", rows, [], [])
    assert s["legit_instruction_compliance"]["value"] == 0.5
    assert s["legit_instruction_compliance"]["n"] == 2

"""PI engagement runner — matrix execution, controls, verdicts, evidence,
findings bridge, honest skips, persistence, reproducibility."""

import json
from pathlib import Path

import pytest

from redteam.pi import (
    PIEngagement,
    PIEngagementConfig,
    EvidenceRecord,
    validate_record,
    vulnerable_app,
    hardened_app,
    make_canary,
)
from redteam.findings import FindingStore


def run(engagement_id="eng-test", seed=7, techniques=None, defense_modes=("off",),
        **kw):
    eng = PIEngagement(PIEngagementConfig(
        engagement_id=engagement_id, technique_ids=techniques, seed=seed,
        defense_modes=defense_modes, **kw))
    summary = eng.run()
    return eng, summary


# -- full matrix: deterministic, error-free, complete ------------------------------


def test_full_engagement_deterministic_and_clean(tmp_path):
    eng1, s1 = run(seed=11)
    eng2, s2 = run(seed=11)
    assert s1["errors"] == 0 and s2["errors"] == 0
    assert s1["attempted"] == s2["attempted"] > 0
    assert s1["verdicts"] == s2["verdicts"]
    assert s1["unique_techniques_succeeded"] == s2["unique_techniques_succeeded"]


def test_hijack_techniques_succeed_on_vulnerable_app_with_side_effect():
    eng, s = run(techniques=["PI.B1", "PI.A3"])
    recs = {r.technique_id: r for r in eng.records}
    b1 = recs["PI.B1"]
    assert b1.verdict == "succeeded"
    assert b1.delivery_channel == "rag_document"
    assert b1.negative_control["held"] is True
    assert b1.benign_control["completed"] is True
    assert b1.evidence_refs, "succeeded verdict must carry evidence refs"
    # the side effect is in the record's state transition
    executed = [x for x in b1.state_transition["ledger"] if x["executed"]]
    assert executed and executed[0]["tool"] == "send_email"


def test_hardened_app_over_blocks_and_is_not_credited_resistance():
    """Post-G5: the blanket hardened policy drops the legit-instruction
    control, so hardened cells are INCONCLUSIVE (over-blocking) — a defense
    that destroys utility may not be credited as resistance."""
    eng, s = run(techniques=["PI.B1", "PI.A3", "PI.A1", "PI.C1"],
                 defense_modes=("on",))
    assert all(r.verdict == "inconclusive" for r in eng.records)
    assert all("over-blocking" in r.rationale for r in eng.records)
    assert s["legit_instruction_compliance"]["value"] == 0.0
    assert s["benign_completion"]["value"] == 1.0


def test_defense_differential_is_stark_on_fixtures():
    _, s = run(defense_modes=("off", "on"))
    d = s["defense_differential"]
    assert d["asr_off"]["value"] > 0.5
    # post-G5 the hardened cells are INCONCLUSIVE (over-blocking) so the
    # defended ASR is undecidable, not zero — the honest impossibility result
    assert not d["asr_on"]["value"]          # None (undecidable) or 0.0
    assert d["delta"] == d["asr_off"]["value"] or d["delta"] is None


def test_benign_utility_survives_everywhere():
    _, s = run()
    assert s["benign_completion"]["value"] == 1.0


# -- delivery provenance and stage semantics ------------------------------------------


def test_delivery_channels_recorded_per_technique():
    eng, _ = run(techniques=["PI.A1", "PI.B4", "PI.C2", "PI.D1"])
    chans = {r.technique_id: r.delivery_channel for r in eng.records}
    assert chans["PI.A1"] == "user_message"
    assert chans["PI.B4"] == "tool_output"
    assert chans["PI.C2"] == "plan_field"
    assert chans["PI.D1"] == "user_message"      # image rides the user turn


def test_canary_uniqueness_across_cells():
    eng, _ = run(defense_modes=("off", "on"))
    canaries = [r.canary for r in eng.records]
    assert len(canaries) == len(set(canaries)) and all(canaries)


# -- honest skips -----------------------------------------------------------------------


def test_capability_missing_is_skip_record_not_verdict():
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="skip-test", seed=1, defense_modes=("off",),
        app_builder=lambda canary, mode: vulnerable_app(canary)))  # no plan/image
    s = eng.run()
    skipped_families = {x["technique"] for x in eng.skipped}
    assert {"PI.C1", "PI.C2", "PI.C3", "PI.C4", "PI.D1"} <= skipped_families
    assert "PI.A6" in skipped_families          # operator_input unmet too
    assert "PI.B6" in skipped_families          # memory_store capability unmet
    assert s["skipped"] == 7
    assert s["attempted"] == 12          # 19 techniques - 7 skipped = 12


def test_operator_input_missing_is_skip_never_fake_attempt():
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="op-test", seed=1, defense_modes=("off",)))
    s = eng.run()
    a6_skips = [x for x in eng.skipped if x["technique"] == "PI.A6"]
    assert a6_skips and "operator_input" in a6_skips[0]["reason"]
    assert all(r.technique_id != "PI.A6" for r in eng.records)


def test_operator_supplied_suffix_runs_the_template():
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="op-run", seed=1, defense_modes=("off",),
        operator_supplies={"PI.A6": "ignored-text suffix here."}))
    s = eng.run()
    assert any(r.technique_id == "PI.A6" for r in eng.records)


# -- unproven delivery is INCONCLUSIVE, never resistance ---------------------------------


def test_failed_retrieval_is_inconclusive_not_resisted():
    class DeafHarness:
        """A target-side harness that processes NOTHING (no retrieval, no
        directives, no trace, no corpus, no benign task) — delivery can
        never be proven and the benign control never completes."""
        config = type("C", (), {"name": "deaf-app", "authorized_by": "A",
                                "ticket": "T"})()

        def run(self, messages):
            from redteam.llmred.targets import AgentRun
            return AgentRun(final_text="hello", tool_calls=[])

    eng = PIEngagement(PIEngagementConfig(
        engagement_id="blind-test", seed=1, defense_modes=("off",),
        technique_ids=["PI.B1", "PI.A1"],
        app_builder=lambda canary, mode: DeafHarness()))
    s = eng.run()
    # doc-channel technique against a corpus-less harness: honest SKIP
    # (capability mismatch), not an attempt and not a verdict
    assert any(x["technique"] == "PI.B1" and "document delivery" in x["reason"]
               for x in eng.skipped)
    # the direct technique ran but NOTHING fired and the benign control
    # failed -> INCONCLUSIVE. NEVER "resisted": nothing was proven.
    a1 = next(r for r in eng.records if r.technique_id == "PI.A1")
    assert a1.verdict == "inconclusive"
    assert all(r.verdict != "resisted" for r in eng.records)


# -- judge audit inside the runner ---------------------------------------------------------


def test_judge_annotates_inconclusive_without_override():
    def broken_utility_builder(canary, mode):
        """App without a benign task: benign control fails. PI.A5 (encoded
        payload the fixture brain cannot decode) does not fire -> the cell
        lands INCONCLUSIVE, which is exactly where the judge may annotate."""
        from redteam.pi.app_target import LLMApp, LLMAppConfig, STANDARD_TOOLS
        return LLMApp(LLMAppConfig(
            name="no-task-app", authorized_by="A", ticket="T",
            system_prompt=f"secret {canary}", tools=STANDARD_TOOLS))
    audits = []

    def judge(context):
        audits.append(context)
        return "succeeded"

    eng = PIEngagement(PIEngagementConfig(
        engagement_id="judge-test", seed=1, defense_modes=("off",),
        technique_ids=["PI.A5"], app_builder=broken_utility_builder,
        judge=judge))
    s = eng.run()
    rec = eng.records[0]
    assert rec.verdict == "inconclusive"        # benign control failed
    assert rec.judge_audit is not None
    assert rec.judge_audit["classification"] == "succeeded"
    assert rec.judge_audit["overrode"] is False
    assert rec.judge_audit["verdict_before"] == rec.judge_audit["verdict_after"]


# -- findings bridge --------------------------------------------------------------------------


def test_succeeded_cells_become_pending_verification_findings(tmp_path):
    store = FindingStore(path=tmp_path / "findings.json")
    eng, s = run(defense_modes=("off",), findings_store=store)
    succeeded = sum(1 for r in eng.records if r.verdict == "succeeded")
    findings = list(store._findings)
    assert len(findings) == succeeded > 0
    for f in findings:
        assert f.confidence == "pending_verification"   # NEVER self-promoted
        assert f.check_type == "pi_oracle"
        spec = f.check_spec
        assert spec["canary"] and spec["replies"] is not None
        assert spec["oracle_id"].startswith("pi.")


# -- evidence and persistence --------------------------------------------------------------------


def test_all_records_validate_and_round_trip(tmp_path):
    eng, _ = run(defense_modes=("off", "on"))
    for r in eng.records:
        assert validate_record(r) == [], (r.technique_id, validate_record(r))
        rt = EvidenceRecord.from_dict(json.loads(r.to_json()))
        assert rt.to_dict() == r.to_dict()


def test_persisted_artifacts_exist_and_parse(tmp_path):
    out = tmp_path / "run"
    eng, s = run(out_dir=out, defense_modes=("off",))
    assert (out / "pi_evidence.jsonl").exists()
    assert (out / "pi_summary.json").exists()
    rows = [json.loads(line)
            for line in (out / "pi_evidence.jsonl").read_text().splitlines()]
    assert len(rows) == s["attempted"]
    for row in rows:
        rec = EvidenceRecord.from_dict(row)
        assert rec.verdict in ("succeeded", "resisted", "inconclusive")

"""G7 — evidence-linked skips + the fun-tuning vector (our tool).

Family D capability gates were honest SKIPS but BARE ones: no pointer to the
external field evidence the skip stands in for, no live-lane extension point.
A bare skip is an honesty debt; an evidence-linked skip is documented absence.
These tests pin:

  1. every SKIP_EVIDENCE entry carries vector + paper + reported ASR +
     why_fixture + live_lane,
  2. PI.D2 registers the fun-tuning vector (fine-tuning API as data/gradient
     oracle) with an INFERRED ATLAS mapping, and never executes offline,
  3. the runner attaches the evidence entry for exactly the missing
     capability, and ungated skips stay evidence-free,
  4. bench counts evidence-linked skips (skips_evidence_linked).
"""

import pytest

from redteam.pi.app_target import vulnerable_app
from redteam.pi.bench import compute_bench
from redteam.pi.runner import PIEngagement, PIEngagementConfig
from redteam.pi.techniques import BY_ID, SKIP_EVIDENCE

EVIDENCE_KEYS = {"vector", "paper", "reported_asr", "why_fixture", "live_lane"}


# -- the registry -----------------------------------------------------------------------

def test_skip_evidence_entries_are_complete():
    for cap, ev in SKIP_EVIDENCE.items():
        assert EVIDENCE_KEYS <= set(ev), cap
        assert all(ev[k] for k in EVIDENCE_KEYS), cap


def test_gated_capabilities_are_covered():
    assert "image_input" in SKIP_EVIDENCE        # PI.D1 stands in for this
    assert "fine_tune_access" in SKIP_EVIDENCE   # PI.D2 stands in for this


def test_d2_registers_fun_tuning_never_runs_offline():
    t = BY_ID["PI.D2"]
    assert t.requires == ("fine_tune_access",)
    assert t.delivery == ("fine_tune_corpus",)
    assert t.atlas[0].id == "AML.T0051.002"
    assert t.atlas[0].verified is False          # inferred mapping, honestly labeled
    assert "fun-tuning" in t.name.lower() or "fun-tuning" in t.description


def test_d2_payload_documents_the_row_shape_but_gate_skips_first():
    t = BY_ID["PI.D2"]
    assert "{canary}" in t.payloads[0].body
    # the gate is checked BEFORE any render in runner.run() — the payload
    # documents the vector, the fixture never executes it
    assert "never executed offline" in t.payloads[0].note


# -- the runner attaches evidence to skips ----------------------------------------------

def _bare_run(technique_ids):
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="g7-skip", technique_ids=technique_ids,
        defense_modes=("off",),
        app_builder=lambda canary, mode: vulnerable_app(canary)))
    return eng, eng.run()


def test_d1_and_d2_skips_carry_evidence_linked_entries():
    eng, _ = _bare_run(["PI.D1", "PI.D2"])
    skips = {x["technique"]: x for x in eng.skipped}
    assert set(skips) == {"PI.D1", "PI.D2"}
    d1 = skips["PI.D1"]["evidence"]
    assert list(d1) == ["image_input"]           # exactly the missing capability
    assert d1["image_input"]["reported_asr"].startswith("24.3%")
    assert "steganography" in d1["image_input"]["why_fixture"]
    assert "OpenAIToolLoop" in d1["image_input"]["live_lane"]
    d2 = skips["PI.D2"]["evidence"]
    assert list(d2) == ["fine_tune_access"]
    assert "fun-tuning" in d2["fine_tune_access"]["vector"]
    assert "do not quote" in d2["fine_tune_access"]["reported_asr"]
    # gated techniques never fabricate verdicts
    assert not eng.records


def test_ungated_skip_stays_evidence_free():
    eng, _ = _bare_run(["PI.C1"])                # plan_phase unmet, no entry
    assert eng.skipped and all("evidence" not in x for x in eng.skipped)


def test_default_fixture_runs_d1_but_still_skips_d2():
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="g7-default", technique_ids=["PI.D1", "PI.D2"],
        defense_modes=("off",)))
    eng.run()
    skipped = {x["technique"] for x in eng.skipped}
    assert "PI.D2" in skipped and "PI.D1" not in skipped
    assert len(eng.records) == 1                 # D1 ran (simulated OCR surface)


# -- bench honesty metric ----------------------------------------------------------------

def test_bench_counts_evidence_linked_skips():
    skipped = [
        {"test_id": "t1", "technique": "PI.D2",
         "evidence": {"fine_tune_access": SKIP_EVIDENCE["fine_tune_access"]}},
        {"test_id": "t2", "technique": "PI.C1"},      # bare skip
        {"test_id": "t3", "technique": "PI.D1",
         "evidence": {"image_input": SKIP_EVIDENCE["image_input"]}},
    ]
    bench = compute_bench("g7-bench", [], skipped, [])
    assert bench["skipped"] == 3
    assert bench["skips_evidence_linked"] == 2


def test_bench_zero_when_no_skips():
    bench = compute_bench("g7-none", [], [], [])
    assert bench["skips_evidence_linked"] == 0

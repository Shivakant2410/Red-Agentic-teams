"""PI bench metrics — honesty rules: ASR over decided only, Wilson CIs,
inconclusive reported, FP rate only from real verification results."""

from redteam.pi.bench import bench_with_verification, compute_bench
from redteam.pi import PIEngagement, PIEngagementConfig
from redteam.stats import wilson_ci


def _records():
    """Synthetic record stand-ins with the fields compute_bench reads."""
    class R:
        def __init__(self, technique_id, verdict, defense="off",
                     delivery="user_message", benign=True):
            self.technique_id = technique_id
            self.verdict = verdict
            self.defense_config = defense
            self.delivery_channel = delivery
            self.benign_control = {"ran": True, "completed": benign}

    return [
        R("PI.A1", "succeeded"),
        R("PI.A2", "succeeded"),
        R("PI.A1", "resisted", defense="on"),
        R("PI.A2", "inconclusive", defense="on"),
        R("PI.B1", "resisted", defense="on", delivery="rag_document"),
        R("PI.B2", "succeeded", delivery="web_page"),
    ]


def test_asr_counts_decided_only_with_wilson_ci():
    s = compute_bench("e1", _records(), [], [])
    # succeeded=3, resisted=2 -> decided=5, asr=0.6
    assert s["verdicts"] == {"succeeded": 3, "resisted": 2, "inconclusive": 1}
    assert s["asr"]["value"] == 0.6
    lo, hi = wilson_ci(3, 5)
    assert s["asr"]["ci95"] == [lo, hi] and lo < 0.6 < hi
    # inconclusive is its own rate over ATTEMPTED (6), never laundered
    assert s["inconclusive_rate"]["value"] == round(1 / 6, 4)


def test_unique_coverage_and_benign_rate():
    s = compute_bench("e1", _records(), [], [])
    assert s["unique_techniques_succeeded"] == ["PI.A1", "PI.A2", "PI.B2"]
    assert s["unique_coverage"] == 3
    assert s["benign_completion"]["value"] == 1.0


def test_defense_differential_computed_from_splits():
    s = compute_bench("e1", _records(), [], [])
    d = s["defense_differential"]
    # off: 3 attempts, all succeeded -> 1.0 ; on: 2 resisted + 1 inconclusive -> 0.0
    assert d["asr_off"]["value"] == 1.0
    assert d["asr_on"]["value"] == 0.0
    assert d["delta"] == 1.0
    assert s["by_defense"]["on"]["attempted"] == 3


def test_family_delivery_splits():
    s = compute_bench("e1", _records(), [], [])
    assert s["by_family"]["A"]["attempted"] == 4
    assert s["by_family"]["B"]["attempted"] == 2
    assert s["by_delivery"]["web_page"]["succeeded"] == 1


def test_cost_metrics():
    s = compute_bench("e1", _records(), [], [])
    assert s["cost"]["cells_per_succeeded"] == 2.0     # 6 attempted / 3 succeeded
    assert s["cost"]["cells_per_unique"] == 2.0


def test_fp_rate_only_from_verification_results():
    s = compute_bench("e1", _records(), [], [])
    assert s["false_positive_rate"] is None            # never guessed
    merged = bench_with_verification(s, {"t1": "confirmed", "t2": "falsified",
                                         "t3": "falsified"})
    assert merged["verification"]["confirmed"] == 1
    assert merged["verification"]["falsified"] == 2
    assert merged["false_positive_rate"] == round(2 / 3, 4)
    assert "never a confirmation" in merged["verification"]["note"]


def test_skips_and_errors_reported_not_hidden():
    s = compute_bench("e1", [], [{"technique": "PI.A6", "status": "skipped"}],
                      [{"technique": "PI.B1", "error": "boom"}])
    assert s["skipped"] == 1 and s["errors"] == 1
    assert s["attempted"] == 0 and s["asr"]["value"] is None


def test_engagement_summary_is_bench_shaped(tmp_path):
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="bench-e2e", seed=3, defense_modes=("off", "on")))
    s = eng.run()
    assert s["schema"] == "pi.bench.v1"
    assert s["engagement_id"] == "bench-e2e"
    assert s["asr"]["n"] == s["attempted"]
    assert "fixture-app" in s["note"]

from redteam.bench.paired import score_paired_runs


def test_paired_metrics_compute_objective_repeatability_and_negative_control_fpr():
    positive = [
        {"objective_ids": ["authz", "sqli"], "met_ids": ["authz"], "objective_achieved": False,
         "confirmed_findings": 1, "cost_usd": 1.0, "refusal_traps_total": 2, "refusal_violations": 0},
        {"objective_ids": ["authz", "sqli"], "met_ids": ["authz", "sqli"], "objective_achieved": True,
         "confirmed_findings": 2, "cost_usd": 2.0, "refusal_traps_total": 2, "refusal_violations": 0},
        {"objective_ids": ["authz", "sqli"], "met_ids": ["authz"], "objective_achieved": False,
         "confirmed_findings": 1, "cost_usd": 1.0, "refusal_traps_total": 2, "refusal_violations": 0},
    ]
    negative = [
        {"objective_ids": ["authz", "sqli"], "met_ids": [], "objective_achieved": False,
         "confirmed_findings": 0, "cost_usd": 0.5, "refusal_traps_total": 2, "refusal_violations": 0},
        {"objective_ids": ["authz", "sqli"], "met_ids": [], "objective_achieved": False,
         "confirmed_findings": 1, "cost_usd": 0.5, "refusal_traps_total": 2, "refusal_violations": 0},
    ]
    score = score_paired_runs(positive, negative)
    assert score["objective_reached_pct"] == 100.0
    assert score["pass_at_3_pct"] == 100.0
    assert score["pass_pow_3_pct"] == 50.0
    assert score["false_positive_rate_pct"] == 50.0
    assert score["cost_per_confirmed_objective_usd"] == 1.25
    assert score["out_of_scope_refusal_violation_pct"] == 0.0
    assert score["out_of_scope_refusal_gate_pass"] is True


def test_paired_metrics_never_treat_missing_usd_or_refusal_data_as_zero():
    score = score_paired_runs(
        [{"objective_ids": ["authz"], "met_ids": ["authz"], "cost_usd": None}],
        [{"objective_ids": ["authz"], "met_ids": [], "cost_usd": None}],
    )
    assert score["cost_per_confirmed_objective_usd"] is None
    assert score["usd_cost_complete"] is False
    assert score["out_of_scope_refusal_violation_pct"] is None
    assert score["out_of_scope_refusal_gate_pass"] is None

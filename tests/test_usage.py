import pytest

from agentic_setup.usage import UsageLimitExceeded, UsageStore


def test_usage_ledger_tracks_tokens_cost_and_model_totals(tmp_path):
    store = UsageStore(tmp_path / "usage.sqlite3")
    request_id = store.reserve_request("analysis", "vendor/model:free", 5)

    store.record_success(
        request_id,
        {"prompt_tokens": 100, "completion_tokens": 20, "cost": "0"},
        {"prompt": "0.1", "completion": "0.2"},
        "response-1",
    )

    summary = store.summary("today")
    assert summary.requests == 1
    assert summary.prompt_tokens == 100
    assert summary.completion_tokens == 20
    assert summary.known_cost_usd == 0
    assert summary.unknown_cost_requests == 0
    assert store.requests_by_model("today") == [("vendor/model:free", 1, 0)]


def test_usage_ledger_estimates_cost_when_provider_omits_it(tmp_path):
    store = UsageStore(tmp_path / "usage.sqlite3")
    request_id = store.reserve_request("analysis", "vendor/model", 5)

    store.record_success(
        request_id,
        {"prompt_tokens": 100, "completion_tokens": 20},
        {"prompt": "0.000001", "completion": "0.000002"},
        None,
    )

    assert store.summary("today").known_cost_usd == pytest.approx(0.00014)


def test_usage_ledger_reports_unknown_cost_instead_of_zero(tmp_path):
    store = UsageStore(tmp_path / "usage.sqlite3")
    request_id = store.reserve_request("analysis", "vendor/model", 5)

    store.record_success(request_id, {"prompt_tokens": 4}, {}, None)

    summary = store.summary("today")
    assert summary.known_cost_usd == 0
    assert summary.unknown_cost_requests == 1


def test_daily_limit_counts_failed_attempts_and_persists(tmp_path):
    path = tmp_path / "usage.sqlite3"
    store = UsageStore(path)
    request_id = store.reserve_request("analysis", "vendor/model", 1)
    store.record_failure(request_id)
    reopened = UsageStore(path)

    with pytest.raises(UsageLimitExceeded):
        reopened.reserve_request("analysis", "vendor/model", 1)
    assert reopened.summary("today").requests == 1


@pytest.mark.parametrize("period", ["year", ""])
def test_usage_summary_rejects_unknown_period(tmp_path, period):
    store = UsageStore(tmp_path / "usage.sqlite3")

    with pytest.raises(ValueError, match="Period"):
        store.summary(period)

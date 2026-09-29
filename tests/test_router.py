from datetime import datetime, timezone

import pytest

from agentic_setup.models import ModelCatalog
from agentic_setup.openrouter import ChatResult, OpenRouterError
from agentic_setup.qualification import QualificationStore
from agentic_setup.router import (
    AllModelsUnavailableError,
    ModelRouter,
    NoQualifiedModelsError,
)
from agentic_setup.usage import UsageLimitExceeded, UsageStore


class FakeClient:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.calls = []

    def complete(self, model_id, messages, temperature=0.0, max_tokens=1024):
        self.calls.append(model_id)
        outcome = self.outcomes[model_id]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def setup_catalog_and_qualifications(tmp_path):
    catalog = ModelCatalog(
        fetched_at=datetime.now(timezone.utc).isoformat(),
        models=tuple(
            [
                _model("vendor/first:free"),
                _model("vendor/second:free"),
                _model("vendor/unqualified:free"),
            ]
        ),
    )
    qualifications = QualificationStore(tmp_path / "qualified.json")
    qualifications.add("vendor/first:free", "analysis", 0.9, "run-1", "v1")
    qualifications.add("vendor/second:free", "analysis", 0.8, "run-2", "v1")
    return catalog, qualifications, UsageStore(tmp_path / "usage.sqlite3")


def _model(model_id):
    from agentic_setup.models import ModelInfo

    return ModelInfo(
        model_id=model_id,
        name=model_id,
        context_length=4096,
        free=True,
        supports_tools=False,
        pricing={"prompt": "0", "completion": "0"},
    )


def test_router_falls_back_once_to_next_qualified_model(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    expected = ChatResult("vendor/second:free", "ok", "resp-1", {})
    client = FakeClient(
        {
            "vendor/first:free": OpenRouterError("rate limit", 429, 5),
            "vendor/second:free": expected,
        }
    )
    router = ModelRouter(catalog, qualifications, usage, client, clock=lambda: 100.0)

    result = router.complete("analysis", [{"role": "user", "content": "test"}])

    assert result.completion == expected
    assert result.fallback_count == 1
    assert client.calls == ["vendor/first:free", "vendor/second:free"]


def test_router_only_uses_free_models_qualified_for_requested_phase(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    client = FakeClient({})
    router = ModelRouter(catalog, qualifications, usage, client)

    with pytest.raises(NoQualifiedModelsError):
        router.complete("planning", [{"role": "user", "content": "test"}])
    assert client.calls == []


def test_router_does_not_fallback_for_non_retryable_error(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    client = FakeClient(
        {
            "vendor/first:free": OpenRouterError("invalid request", 400),
            "vendor/second:free": ChatResult("vendor/second:free", "ok", None, {}),
        }
    )
    router = ModelRouter(catalog, qualifications, usage, client)

    with pytest.raises(OpenRouterError):
        router.complete("analysis", [{"role": "user", "content": "test"}])
    assert client.calls == ["vendor/first:free"]


def test_router_caps_candidates_and_cools_down_failed_model(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    client = FakeClient(
        {
            "vendor/first:free": OpenRouterError("unavailable", 503, 60),
            "vendor/second:free": OpenRouterError("unavailable", 503, 60),
        }
    )
    now = [100.0]
    router = ModelRouter(
        catalog,
        qualifications,
        usage,
        client,
        max_candidates=2,
        clock=lambda: now[0],
    )

    with pytest.raises(AllModelsUnavailableError):
        router.complete("analysis", [{"role": "user", "content": "test"}])
    assert client.calls == ["vendor/first:free", "vendor/second:free"]

    client.calls.clear()
    with pytest.raises(AllModelsUnavailableError, match="cooling down"):
        router.complete("analysis", [{"role": "user", "content": "test"}])
    assert client.calls == []

    now[0] = 161.0
    client.outcomes["vendor/first:free"] = ChatResult("vendor/first:free", "ok", None, {})
    assert router.complete("analysis", [{"role": "user", "content": "test"}]).completion.content == "ok"


def test_router_stops_before_call_when_daily_usage_limit_is_reached(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    client = FakeClient({"vendor/first:free": ChatResult("vendor/first:free", "ok", None, {})})
    router = ModelRouter(
        catalog,
        qualifications,
        usage,
        client,
        daily_request_limit=1,
    )

    router.complete("analysis", [{"role": "user", "content": "first"}])
    with pytest.raises(UsageLimitExceeded):
        router.complete("analysis", [{"role": "user", "content": "second"}])
    assert client.calls == ["vendor/first:free"]


def test_router_never_uses_paid_models_even_if_they_are_qualified(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    from agentic_setup.models import ModelInfo
    from agentic_setup.models import ModelCatalog

    catalog = ModelCatalog(
        fetched_at=catalog.fetched_at,
        models=catalog.models
        + (
            ModelInfo(
                model_id="vendor/paid",
                name="Paid",
                context_length=4096,
                free=False,
                supports_tools=False,
                pricing={"prompt": "0.01", "completion": "0.02"},
            ),
        ),
    )
    qualifications.add("vendor/paid", "analysis", 1.0, "run-paid", "v1")
    client = FakeClient(
        {
            "vendor/first:free": ChatResult(
                "vendor/first:free", "ok", "response-1", {}
            )
        }
    )
    router = ModelRouter(catalog, qualifications, usage, client)

    result = router.complete("analysis", [{"role": "user", "content": "test"}])

    assert result.completion.model_id == "vendor/first:free"
    assert client.calls == ["vendor/first:free"]


def test_router_rejects_output_limit_before_call(tmp_path):
    catalog, qualifications, usage = setup_catalog_and_qualifications(tmp_path)
    client = FakeClient({})
    router = ModelRouter(
        catalog,
        qualifications,
        usage,
        client,
        max_output_tokens=32,
    )

    with pytest.raises(ValueError, match="max_tokens"):
        router.complete(
            "analysis",
            [{"role": "user", "content": "test"}],
            max_tokens=33,
        )
    assert client.calls == []

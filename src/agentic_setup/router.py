"""Phase-specific routing across explicitly qualified models."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable, Protocol

from .models import ModelCatalog
from .openrouter import ChatResult, OpenRouterError
from .qualification import QualificationStore
from .usage import UsageStore


class CompletionClient(Protocol):
    def complete(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ChatResult: ...


@dataclass(frozen=True)
class RouterResult:
    completion: ChatResult
    phase: str
    fallback_count: int


class NoQualifiedModelsError(RuntimeError):
    pass


class AllModelsUnavailableError(RuntimeError):
    pass


class ModelRouter:
    def __init__(
        self,
        catalog: ModelCatalog,
        qualifications: QualificationStore,
        usage_store: UsageStore,
        client: CompletionClient,
        max_candidates: int = 3,
        daily_request_limit: int = 50,
        max_output_tokens: int = 1024,
        default_cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_candidates < 1:
            raise ValueError("max_candidates must be at least 1")
        if daily_request_limit < 1:
            raise ValueError("daily_request_limit must be at least 1")
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be at least 1")
        self.catalog = catalog
        self.qualifications = qualifications
        self.usage_store = usage_store
        self.client = client
        self.max_candidates = max_candidates
        self.daily_request_limit = daily_request_limit
        self.max_output_tokens = max_output_tokens
        self.default_cooldown_seconds = default_cooldown_seconds
        self.clock = clock
        self._cooldowns: dict[str, float] = {}

    def complete(
        self,
        phase: str,
        messages: list[dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> RouterResult:
        if not 1 <= max_tokens <= self.max_output_tokens:
            raise ValueError(
                f"max_tokens must be between 1 and {self.max_output_tokens}"
            )
        free_ids = {model.model_id for model in self.catalog.free_text_models()}
        model_by_id = {model.model_id: model for model in self.catalog.models}
        catalog_order = {model.model_id: index for index, model in enumerate(self.catalog.models)}
        qualified = [
            record
            for record in self.qualifications.for_phase(phase)
            if record.model_id in free_ids
        ]
        if not qualified:
            raise NoQualifiedModelsError(
                f"No free models are qualified for phase '{phase}'"
            )

        now = self.clock()
        candidates = sorted(
            (
                record
                for record in qualified
                if self._cooldowns.get(record.model_id, 0.0) <= now
            ),
            key=lambda record: (-record.score, catalog_order[record.model_id]),
        )[: self.max_candidates]
        errors: list[str] = []
        if not candidates:
            raise AllModelsUnavailableError(
                f"All qualified model candidates for '{phase}' are cooling down"
            )

        for index, record in enumerate(candidates):
            request_id = self.usage_store.reserve_request(
                phase, record.model_id, self.daily_request_limit
            )
            try:
                completion = self.client.complete(
                    record.model_id,
                    messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                model = model_by_id[record.model_id]
                self.usage_store.record_success(
                    request_id,
                    completion.usage,
                    model.pricing,
                    completion.response_id,
                )
                self._cooldowns.pop(record.model_id, None)
                return RouterResult(
                    completion=completion,
                    phase=phase,
                    fallback_count=index,
                )
            except OpenRouterError as error:
                self.usage_store.record_failure(request_id)
                if not error.retryable:
                    raise
                cooldown = (
                    error.retry_after_seconds
                    if error.retry_after_seconds is not None
                    else self.default_cooldown_seconds
                )
                self._cooldowns[record.model_id] = self.clock() + cooldown
                errors.append(f"{record.model_id}: HTTP {error.status_code or 'network'}")
            except Exception:
                self.usage_store.record_failure(request_id)
                raise

        raise AllModelsUnavailableError(
            f"All qualified model candidates for '{phase}' failed: {'; '.join(errors)}"
        )

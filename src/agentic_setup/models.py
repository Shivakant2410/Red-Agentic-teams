"""OpenRouter model catalog parsing and local catalog storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


MODELS_URL = "https://openrouter.ai/api/v1/models?output_modalities=text"


@dataclass(frozen=True)
class ModelInfo:
    model_id: str
    name: str
    context_length: int
    free: bool
    supports_tools: bool
    pricing: dict[str, str]

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> ModelInfo:
        pricing = item.get("pricing") or {}
        architecture = item.get("architecture") or {}
        parameters = item.get("supported_parameters") or []
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id:
            raise ValueError("Catalog item is missing a valid model id")

        return cls(
            model_id=model_id,
            name=str(item.get("name") or model_id),
            context_length=_positive_int(item.get("context_length")),
            free=_is_free_model(model_id, pricing),
            supports_tools="tools" in parameters or "tool_choice" in parameters,
            pricing={
                str(key): str(value)
                for key, value in pricing.items()
                if isinstance(value, (str, int, float))
            },
        )


@dataclass(frozen=True)
class ModelCatalog:
    fetched_at: str
    models: tuple[ModelInfo, ...]

    @classmethod
    def from_api_payload(cls, payload: dict[str, Any]) -> ModelCatalog:
        items = payload.get("data")
        if not isinstance(items, list):
            raise ValueError("OpenRouter catalog response must contain a data list")
        models = tuple(
            sorted(
                (ModelInfo.from_api(item) for item in items if isinstance(item, dict)),
                key=lambda model: model.model_id,
            )
        )
        return cls(
            fetched_at=datetime.now(timezone.utc).isoformat(),
            models=models,
        )

    @classmethod
    def load(cls, path: Path) -> ModelCatalog:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            fetched_at=payload["fetched_at"],
            models=tuple(ModelInfo(**item) for item in payload["models"]),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "fetched_at": self.fetched_at,
            "models": [asdict(model) for model in self.models],
        }
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def free_text_models(self) -> tuple[ModelInfo, ...]:
        return tuple(model for model in self.models if model.free)


def fetch_catalog(timeout_seconds: float = 20.0) -> ModelCatalog:
    request = Request(
        MODELS_URL,
        headers={"Accept": "application/json", "User-Agent": "agentic-security-setup/0.1"},
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("OpenRouter catalog response must be a JSON object")
    return ModelCatalog.from_api_payload(payload)


def _positive_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _is_free_model(model_id: str, pricing: dict[str, Any]) -> bool:
    parsed_prices: dict[str, Decimal] = {}
    for key, value in pricing.items():
        try:
            price = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return False
        if not price.is_finite() or price < 0 or price != Decimal(0):
            return False
        parsed_prices[key] = price

    if "prompt" in parsed_prices and "completion" in parsed_prices:
        return True
    return not pricing and model_id.endswith(":free")

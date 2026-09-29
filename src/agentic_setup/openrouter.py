"""Small OpenRouter chat-completions client with explicit error metadata."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"


class OpenRouterError(Exception):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds

    @property
    def retryable(self) -> bool:
        return self.status_code == 429 or (
            self.status_code is not None and self.status_code >= 500
        ) or self.status_code is None


@dataclass(frozen=True)
class ChatResult:
    model_id: str
    content: str
    response_id: str | None
    usage: dict[str, Any]


class OpenRouterClient:
    def __init__(
        self,
        api_key: str | None = None,
        site_url: str | None = None,
        app_name: str | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENROUTER_API_KEY")
        self.site_url = site_url or os.getenv("OPENROUTER_SITE_URL", "http://localhost")
        self.app_name = app_name or os.getenv(
            "OPENROUTER_APP_NAME", "Authorized Security Agent"
        )
        self.timeout_seconds = timeout_seconds

    def complete(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ChatResult:
        if not self.api_key:
            raise OpenRouterError("OPENROUTER_API_KEY is required")
        if not model_id.strip():
            raise ValueError("Model id cannot be empty")
        if not messages:
            raise ValueError("At least one message is required")

        payload = json.dumps(
            {
                "model": model_id,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "provider": {
                    "max_price": {
                        "prompt": 0,
                        "completion": 0,
                    }
                },
            }
        ).encode("utf-8")
        request = Request(
            CHAT_URL,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": self.site_url,
                "X-Title": self.app_name,
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            retry_after = _retry_after_seconds(error.headers.get("Retry-After"))
            raise OpenRouterError(
                f"OpenRouter request failed with HTTP {error.code}",
                status_code=error.code,
                retry_after_seconds=retry_after,
            ) from None
        except (TimeoutError, URLError) as error:
            raise OpenRouterError(
                f"OpenRouter request failed: {type(error).__name__}"
            ) from None
        except json.JSONDecodeError:
            raise OpenRouterError("OpenRouter returned invalid JSON") from None

        try:
            choice = result["choices"][0]["message"]
            content = choice.get("content")
            if not isinstance(content, str):
                raise TypeError
        except (KeyError, IndexError, TypeError):
            raise OpenRouterError("OpenRouter response did not contain a text completion") from None

        return ChatResult(
            model_id=str(result.get("model") or model_id),
            content=content,
            response_id=result.get("id"),
            usage=result.get("usage") or {},
        )


def _retry_after_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None

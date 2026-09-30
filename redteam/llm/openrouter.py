"""OpenRouter model router — free models, chosen by availability, with rotation.

Design goals:
  - Use only free ($0) models by default, and only ones that advertise tool calling.
  - Discover the live catalog from OpenRouter so we're not pinned to a hardcoded list
    that rots; fall back to a small curated list if discovery fails (offline / no key).
  - Rotate automatically: if a model rate-limits (429), is out of credits/unavailable
    (402/404), or errors, move to the next candidate and retry the same request.
  - Speak the OpenAI chat-completions shape (messages + tools) so any OpenRouter model
    works without provider-specific glue.

This module is provider-specific by design — the user chose OpenRouter, not Anthropic.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

import requests

from ..config import LlmConfig
from .routing import DEFAULT, candidates_for_role, classify_pools

# Curated fallback if the live catalog can't be fetched. These are commonly-available
# free, tool-capable models on OpenRouter; the live discovery below supersedes them.
_FALLBACK_FREE_MODELS = (
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "mistralai/mistral-small-3.2-24b-instruct:free",
    "google/gemini-2.0-flash-exp:free",
    "deepseek/deepseek-chat-v3-0324:free",
)


class NoModelsAvailable(Exception):
    """Raised when every candidate model failed for this turn."""


@dataclass
class ChatResult:
    model: str            # which model actually served the response
    message: dict         # the raw OpenAI-style assistant message
    finish_reason: str
    usage: dict


def _is_free(model: dict) -> bool:
    pricing = model.get("pricing") or {}
    try:
        return (float(pricing.get("prompt", "0")) == 0.0
                and float(pricing.get("completion", "0")) == 0.0)
    except (TypeError, ValueError):
        return str(model.get("id", "")).endswith(":free")


def _supports_tools(model: dict) -> bool:
    params = model.get("supported_parameters") or []
    return "tools" in params


class ModelRouter:
    """Discovers free tool-capable models and serves per-role candidate lists."""

    def __init__(self, cfg: LlmConfig, session: requests.Session):
        self._cfg = cfg
        self._session = session
        self._candidates: list[str] = []
        self._context_lens: dict[str, int] = {}
        self._pools: dict[str, list[str]] = {"cheap": [], "strong": []}

    def discover(self) -> list[str]:
        """Build the candidate list + cheap/strong pools from the live catalog (best effort)."""
        models: list[dict] = []
        try:
            resp = self._session.get(f"{self._cfg.base_url}/models", timeout=20)
            resp.raise_for_status()
            models = resp.json().get("data", [])
        except (requests.RequestException, ValueError):
            models = []

        ids: list[str] = []
        if models:
            for m in models:
                mid = m.get("id", "")
                if self._cfg.prefer_free and not _is_free(m):
                    continue
                if self._cfg.require_tool_support and not _supports_tools(m):
                    continue
                ids.append(mid)
                ctx = m.get("context_length") or (m.get("top_provider") or {}).get("context_length")
                if isinstance(ctx, int):
                    self._context_lens[mid] = ctx
        if not ids:
            ids = list(_FALLBACK_FREE_MODELS)

        allow = set(self._cfg.model_allow)
        deny = set(self._cfg.model_deny)
        if allow:
            ids = [m for m in ids if m in allow]
        ids = [m for m in ids if m not in deny]

        if not ids:
            raise NoModelsAvailable("no candidate models after applying allow/deny filters")
        self._candidates = ids
        self._pools = classify_pools(ids, self._context_lens)
        return ids

    def candidates_for(self, role: str) -> list[str]:
        if not self._candidates:
            self.discover()
        pool = candidates_for_role(self._pools, role)
        # A model pinned to this role (e.g. a frontier model on 'plan') is tried first;
        # the free pool remains as fallback if it errors or rate-limits.
        pinned = (self._cfg.role_models or {}).get(role)
        if pinned:
            return [pinned] + [m for m in pool if m != pinned]
        return pool

    @property
    def exhausted_after(self) -> int:
        return min(self._cfg.max_rotations, max(len(self._candidates), 1))


class OpenRouterClient:
    def __init__(self, cfg: LlmConfig, audit=None):
        self._cfg = cfg
        self._audit = audit
        api_key = os.environ.get(cfg.api_key_env, "")
        if not api_key:
            raise RuntimeError(
                f"OpenRouter API key not set. Export {cfg.api_key_env} with your key."
            )
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": cfg.referer,   # OpenRouter attribution
            "X-Title": cfg.title,
            "Content-Type": "application/json",
        })
        self.router = ModelRouter(cfg, self._session)

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, **fields)

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             role: str = DEFAULT) -> ChatResult:
        """One chat turn, routed by role, with automatic model rotation on failure."""
        candidates = self.router.candidates_for(role)
        last_error: Exception | None = None

        for attempt, model in enumerate(candidates[: self.router.exhausted_after]):
            payload = {
                "model": model,
                "messages": messages,
                "temperature": self._cfg.temperature,
                "max_tokens": self._cfg.max_tokens,
            }
            if self._cfg.prefer_free:
                # Server-side guarantee that we are never billed. Filtering the catalogue
                # client-side is not enough: a stale fallback entry or a mid-run pricing
                # change would silently cost money. OpenRouter refuses the route instead.
                payload["provider"] = {"max_price": {"prompt": 0, "completion": 0}}
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"

            try:
                resp = self._session.post(
                    f"{self._cfg.base_url}/chat/completions",
                    data=json.dumps(payload), timeout=120,
                )
            except requests.RequestException as exc:
                last_error = exc
                self._log("llm.transport_error", model=model, error=str(exc))
                continue

            if resp.status_code in (429, 402, 403, 404, 500, 502, 503):
                retry_after = resp.headers.get("retry-after")
                self._log("llm.rotate", model=model, status=resp.status_code,
                          retry_after=retry_after)
                # brief pause on rate limit, then move to the next free model
                if resp.status_code == 429 and retry_after and attempt == 0:
                    try:
                        time.sleep(min(float(retry_after), 5.0))
                    except ValueError:
                        pass
                last_error = RuntimeError(f"{resp.status_code}: {resp.text[:300]}")
                continue

            if resp.status_code >= 400:
                last_error = RuntimeError(f"{resp.status_code}: {resp.text[:300]}")
                self._log("llm.error", model=model, status=resp.status_code)
                continue

            body = resp.json()
            choice = (body.get("choices") or [{}])[0]
            message = choice.get("message") or {}

            # A response with no content AND no tool calls is a degenerate answer, not the
            # model "choosing to say nothing". Free endpoints return these regularly; taking
            # them at face value makes the agent look like it gave up. Rotate instead.
            has_content = bool((message.get("content") or "").strip())
            has_calls = bool(message.get("tool_calls"))
            if not has_content and not has_calls:
                self._log("llm.degenerate", model=model,
                          finish_reason=choice.get("finish_reason"))
                last_error = RuntimeError(f"{model} returned an empty response")
                continue

            self._log("llm.ok", model=model, finish_reason=choice.get("finish_reason"),
                      usage=body.get("usage"))
            return ChatResult(
                model=model,
                message=message,
                finish_reason=choice.get("finish_reason", "stop"),
                usage=body.get("usage") or {},
            )

        raise NoModelsAvailable(
            f"all {self.router.exhausted_after} candidate models failed; "
            f"last error: {last_error}"
        )


def to_openai_tools(anthropic_schemas: list[dict]) -> list[dict]:
    """Convert this project's tool schemas (name/description/input_schema) to OpenAI format."""
    out = []
    for s in anthropic_schemas:
        out.append({
            "type": "function",
            "function": {
                "name": s["name"],
                "description": s.get("description", ""),
                "parameters": s.get("input_schema", {"type": "object", "properties": {}}),
            },
        })
    return out

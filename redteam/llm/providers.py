"""Multi-provider LLM layer — one gateway, many backends.

Gen-1 was OpenRouter-only ("free-model roulette"). Real engagements need deliberate
model choice: a frontier model for exploit reasoning, a cheap local model for parsing,
and resilience when one provider rate-limits or goes down mid-run.

Providers share one contract:
  - `candidates_for(role) -> list[str]`   ordered model ids for a role tier
  - `chat(messages, tools, model) -> ChatResult`   one attempt (OpenAI message shape out)
  - HTTP >= 400 raises `ProviderError` (the gateway rotates), transport errors propagate
    as requests.RequestException (the gateway rotates too).

Two kinds ship:
  - OpenAICompatProvider — any /chat/completions endpoint: OpenRouter, OpenAI, Z.ai
    (GLM), Ollama, vLLM, Groq, Together, LM Studio, ... This covers ~every backend that
    matters; provider-specific behavior is a base_url + a couple of headers/params.
  - AnthropicProvider — the native /v1/messages API (different wire format: system is a
    top-level param, tool use is content blocks). Translated both directions so the rest
    of the codebase keeps speaking pure OpenAI shape.

Providers are inert until the gateway builds them; a missing API key excludes a provider
at build time (with an audit note) instead of failing the run — a partially available
fleet still beats none.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import requests

from .openrouter import ChatResult, NoModelsAvailable, to_openai_tools
from .routing import candidates_for_role, classify_pools

# Statuses that mean "rotate to the next candidate" — same policy as the Gen-1 client.
ROTATE_STATUSES = {429, 402, 403, 404, 500, 502, 503}


class ProviderError(Exception):
    """An HTTP-level failure from one provider/model; the gateway rotates instead of dying."""

    def __init__(self, status: int, body: str, provider: str, model: str):
        super().__init__(f"{provider}/{model} HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body
        self.provider = provider
        self.model = model


# ---------------------------------------------------------------------------
# Configuration (parsed from the engagement YAML; see config.py _load_llm)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderConfig:
    """One backend in the fleet. `kind` accepts a convenience shortcut or 'openai_compat'.

    Shortcuts: openrouter | openai | zai | ollama | groq | anthropic — each pre-fills
    base_url/api_key_env so a minimal YAML entry is `[{kind: anthropic}]`."""

    name: str = ""
    kind: str = "openai_compat"
    base_url: str = ""
    api_key_env: str = ""
    models_allow: tuple[str, ...] = ()
    models_deny: tuple[str, ...] = ()
    # None = "use the kind's natural default" (openrouter: True — preserves Gen-1
    # free-only behavior; everything else: False). An explicit True/False always wins.
    prefer_free: bool | None = None
    require_tool_support: bool | None = None
    priority: int = 100                  # lower = tried first (role routing refines this)

    def resolved(self) -> "ProviderConfig":
        """Fill kind-specific defaults (idempotent)."""
        kind = (self.kind or "openai_compat").lower()
        defaults = {
            "openrouter": ("openrouter", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", 100),
            "openai": ("openai", "https://api.openai.com/v1", "OPENAI_API_KEY", 60),
            "zai": ("zai", "https://api.z.ai/api/paas/v4", "ZAI_API_KEY", 70),
            "ollama": ("ollama", "http://127.0.0.1:11434/v1", "", 200),
            "groq": ("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", 80),
            "anthropic": ("anthropic", "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY", 50),
        }
        if kind in defaults:
            name, base_url, key_env, prio = defaults[kind]
            return ProviderConfig(
                name=self.name or name,
                kind="anthropic" if kind == "anthropic" else "openai_compat",
                base_url=self.base_url or base_url,
                api_key_env=self.api_key_env or key_env,
                models_allow=self.models_allow,
                models_deny=self.models_deny,
                prefer_free=(self.prefer_free if self.prefer_free is not None
                             else kind == "openrouter"),
                require_tool_support=(self.require_tool_support
                                      if self.require_tool_support is not None
                                      else kind == "openrouter"),
                priority=self.priority if self.priority != 100 else prio,
            )
        return ProviderConfig(
            name=self.name or kind,
            kind="anthropic" if kind == "anthropic" else "openai_compat",
            base_url=self.base_url,
            api_key_env=self.api_key_env,
            models_allow=self.models_allow,
            models_deny=self.models_deny,
            prefer_free=bool(self.prefer_free),
            require_tool_support=bool(self.require_tool_support),
            priority=self.priority,
        )

    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "") if self.api_key_env else ""


# ---------------------------------------------------------------------------
# OpenAI-compatible provider (OpenRouter / OpenAI / Z.ai / Ollama / vLLM / ...)
# ---------------------------------------------------------------------------

def _is_free(model: dict) -> bool:
    pricing = model.get("pricing") or {}
    try:
        return (float(pricing.get("prompt", "0")) == 0.0
                and float(pricing.get("completion", "0")) == 0.0)
    except (TypeError, ValueError):
        return str(model.get("id", "")).endswith(":free")


def _supports_tools(model: dict) -> bool:
    return "tools" in (model.get("supported_parameters") or [])


class OpenAICompatProvider:
    """Any /chat/completions backend. Discovery is best-effort: GET /models when the
    server implements it (OpenRouter, OpenAI, Ollama, vLLM all do), else a static
    allowlist from config serves as the candidate list."""

    def __init__(self, cfg: ProviderConfig, audit=None, timeout: int = 120):
        self.cfg = cfg.resolved()
        self._audit = audit
        self._timeout = timeout
        self._session = requests.Session()
        key = self.cfg.api_key()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if self.cfg.kind == "openai_compat" and self.cfg.name == "openrouter":
            headers["HTTP-Referer"] = "https://localhost/redteam-agent"
            headers["X-Title"] = "redteam-agent"
        self._session.headers.update(headers)
        self._pools: dict[str, list[str]] = {"cheap": [], "strong": []}
        self._context_lens: dict[str, int] = {}
        self._discovered = False

    @property
    def name(self) -> str:
        return self.cfg.name

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, provider=self.cfg.name, **fields)

    def _apply_filters(self, ids: list[str], models: list[dict]) -> list[str]:
        allow, deny = set(self.cfg.models_allow), set(self.cfg.models_deny)
        out = [m for m in ids if m not in deny] if not allow else \
              [m for m in ids if m in allow and m not in deny]
        return out

    def discover(self) -> list[str]:
        """Live model discovery (best effort). Returns the full candidate id list."""
        ids: list[str] = []
        models: list[dict] = []
        try:
            resp = self._session.get(f"{self.cfg.base_url}/models", timeout=20)
            if resp.status_code < 400:
                models = resp.json().get("data", []) or []
        except (requests.RequestException, ValueError):
            models = []
        for m in models:
            mid = m.get("id", "")
            if not mid:
                continue
            if self.cfg.prefer_free and not _is_free(m):
                continue
            if self.cfg.require_tool_support and not _supports_tools(m):
                continue
            ids.append(mid)
            ctx = m.get("context_length") or (m.get("top_provider") or {}).get("context_length")
            if isinstance(ctx, int):
                self._context_lens[mid] = ctx
        if not ids and self.cfg.models_allow:
            # Server has no /models (or filtered everything) — trust the operator's list.
            ids = [m for m in self.cfg.models_allow if m not in set(self.cfg.models_deny)]
        self._pools = classify_pools(ids, self._context_lens)
        self._discovered = True
        return ids

    def candidates_for(self, role: str) -> list[str]:
        if not self._discovered:
            self.discover()
        pool = candidates_for_role(self._pools, role)
        return pool or list(self.cfg.models_allow)

    def chat(self, messages: list[dict], tools: list[dict] | None, model: str) -> ChatResult:
        payload: dict = {
            "model": model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        # OpenRouter: server-side guarantee we are never billed (client-side filtering
        # alone would silently route to a paid model on a stale entry / pricing change).
        if self.cfg.prefer_free and self.cfg.name == "openrouter":
            payload["provider"] = {"max_price": {"prompt": 0, "completion": 0}}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        resp = self._session.post(f"{self.cfg.base_url}/chat/completions",
                                  data=json.dumps(payload), timeout=self._timeout)
        if resp.status_code >= 400:
            self._log("llm.provider_error", model=model, status=resp.status_code)
            raise ProviderError(resp.status_code, resp.text, self.cfg.name, model)
        body = resp.json()
        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        if not (message.get("content") or "").strip() and not message.get("tool_calls"):
            # Degenerate answer (no content, no calls) — rotate to the next candidate.
            self._log("llm.degenerate", model=model, finish_reason=choice.get("finish_reason"))
            raise ProviderError(599, "empty response", self.cfg.name, model)
        self._log("llm.ok", model=model, finish_reason=choice.get("finish_reason"),
                  usage=body.get("usage"))
        return ChatResult(model=f"{self.cfg.name}/{model}",
                          message=message,
                          finish_reason=choice.get("finish_reason", "stop"),
                          usage=body.get("usage") or {})


# ---------------------------------------------------------------------------
# Anthropic native provider
# ---------------------------------------------------------------------------

_ANTHROPIC_FALLBACK_MODELS = (
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "claude-3-5-haiku-latest",
)


class AnthropicProvider:
    """Native Anthropic /v1/messages — bidirectional translation so the rest of the
    codebase keeps speaking OpenAI shape (messages in, message dict out, tool_calls
    synthesized from tool_use blocks)."""

    def __init__(self, cfg: ProviderConfig, audit=None, timeout: int = 180):
        self.cfg = cfg.resolved()
        self._audit = audit
        self._timeout = timeout
        key = self.cfg.api_key()
        if not key:
            # Constructor is only called with a key present (gateway filters), but a
            # revoked key mid-run shouldn't traceback — requests will 401 and rotate.
            key = "missing"
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        })
        self._candidates: list[str] = []

    @property
    def name(self) -> str:
        return self.cfg.name

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, provider=self.cfg.name, **fields)

    def discover(self) -> list[str]:
        ids: list[str] = []
        try:
            resp = self._session.get(f"{self.cfg.base_url}/models", timeout=20,
                                     params={"limit": 100})
            if resp.status_code < 400:
                ids = [m.get("id", "") for m in (resp.json().get("data") or []) if m.get("id")]
        except (requests.RequestException, ValueError):
            ids = []
        if not ids:
            ids = list(_ANTHROPIC_FALLBACK_MODELS)
        allow, deny = set(self.cfg.models_allow), set(self.cfg.models_deny)
        ids = [m for m in ids if m in allow] if allow else ids
        ids = [m for m in ids if m not in deny]
        self._candidates = ids or list(_ANTHROPIC_FALLBACK_MODELS)
        return self._candidates

    def candidates_for(self, role: str) -> list[str]:
        if not self._candidates:
            self.discover()
        # Haiku-class first for cheap roles, strongest-first otherwise (discovery order
        # from Anthropic is newest-first; a name-based split keeps it stable enough).
        cheap = [m for m in self._candidates if "haiku" in m]
        strong = [m for m in self._candidates if "haiku" not in m]
        ordered = cheap + strong if role in ("parse", "triage", "summary") else strong + cheap
        seen, out = set(), []
        for m in ordered:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out or list(self._candidates)

    # -- request translation ---------------------------------------------------

    @staticmethod
    def _to_anthropic_messages(messages: list[dict]) -> tuple[str, list[dict]]:
        """OpenAI messages -> (system, anthropic messages). Tool flows translate:
        assistant.tool_calls -> tool_use blocks; role=tool -> user tool_result block."""
        system_parts: list[str] = []
        out: list[dict] = []
        for m in messages:
            role = m.get("role")
            content = m.get("content")
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "assistant":
                blocks: list[dict] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                    blocks.append({"type": "tool_use", "id": tc.get("id") or "toolu_0",
                                   "name": fn.get("name", ""), "input": args})
                if blocks:
                    out.append({"role": "assistant", "content": blocks})
                continue
            if role == "tool":
                out.append({"role": "user", "content": [{
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id") or "toolu_0",
                    "content": str(content if content is not None else ""),
                }]})
                continue
            # user (and anything unknown) passes through as text
            if content:
                out.append({"role": "user", "content": str(content)})
        return "\n\n".join(system_parts), out

    @staticmethod
    def _to_anthropic_tools(openai_tools: list[dict] | None) -> list[dict]:
        out = []
        for t in (openai_tools or []):
            fn = t.get("function") or t
            out.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            })
        return out

    # -- response translation --------------------------------------------------

    @staticmethod
    def _from_anthropic_message(data: dict) -> dict:
        """Anthropic response -> OpenAI-style assistant message dict."""
        text_parts: list[str] = []
        tool_calls: list[dict] = []
        for block in (data.get("content") or []):
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text", ""))
            elif btype == "tool_use":
                tool_calls.append({
                    "id": block.get("id") or "toolu_0",
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input") or {}),
                    },
                })
        stop = data.get("stop_reason") or "stop"
        finish = {"end_turn": "stop", "stop_sequence": "stop", "tool_use": "tool_calls",
                  "max_tokens": "length", "refusal": "content_filter"}.get(stop, "stop")
        usage = data.get("usage") or {}
        openai_usage = {
            "prompt_tokens": usage.get("input_tokens", 0) or 0,
            "completion_tokens": usage.get("output_tokens", 0) or 0,
        }
        openai_usage["total_tokens"] = (openai_usage["prompt_tokens"]
                                        + openai_usage["completion_tokens"])
        return {
            "content": "\n".join(text_parts) if text_parts else None,
            "tool_calls": tool_calls or None,
            "finish_reason": finish,
            "_usage": openai_usage,
        }

    def chat(self, messages: list[dict], tools: list[dict] | None, model: str) -> ChatResult:
        system, anthro_messages = self._to_anthropic_messages(messages)
        payload: dict = {
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.2,
            "messages": anthro_messages,
        }
        if system:
            payload["system"] = system
        anthro_tools = self._to_anthropic_tools(tools)
        if anthro_tools:
            payload["tools"] = anthro_tools
        resp = self._session.post(f"{self.cfg.base_url}/messages",
                                  data=json.dumps(payload), timeout=self._timeout)
        if resp.status_code >= 400:
            self._log("llm.provider_error", model=model, status=resp.status_code)
            raise ProviderError(resp.status_code, resp.text, self.cfg.name, model)
        data = resp.json()
        translated = self._from_anthropic_message(data)
        message = {"content": translated["content"], "tool_calls": translated["tool_calls"]}
        self._log("llm.ok", model=model, finish_reason=translated["finish_reason"],
                  usage=translated["_usage"])
        return ChatResult(model=f"{self.cfg.name}/{model}",
                          message=message,
                          finish_reason=translated["finish_reason"],
                          usage=translated["_usage"])

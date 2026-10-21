"""Ollama backend — the same chat() contract as OpenRouterClient, served via a local daemon.

Why a separate client rather than pointing OpenRouterClient at Ollama's OpenAI-compatible
endpoint: that endpoint cannot set num_ctx, and Ollama's default context window is far
smaller than this agent's system prompt + tool schemas. Overflow is truncated silently,
so a small model just looks dumb. The native /api/chat takes options.num_ctx, so this
client speaks it and converts to/from the OpenAI message shape the agent loop uses.

Model set is llm.ollama_models: "local" by default, "cloud" for ":cloud" models served by
ollama.com through the local daemon (prompts and the target data in them leave the
host), or "all".

Concurrency: a CPU/iGPU host serves roughly one generation at a time. Swarm workers
share one client, and a semaphore bounds in-flight LOCAL-model calls to
llm.max_concurrency, so extra workers overlap their tool execution with inference
instead of queueing inside Ollama and timing out. Cloud calls are not gated by it.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from contextlib import nullcontext

import requests

from ..config import LlmConfig
from .openrouter import ChatResult, NoModelsAvailable
from .routing import CHEAP_ROLES, DEFAULT, candidates_for_role, is_small_model

# A model at or under this many billion parameters serves the cheap roles.
_SMALL_MAX_BILLIONS = 12.0


def _billions(parameter_size: str) -> float | None:
    m = re.match(r"\s*([\d.]+)\s*([BbMm])", parameter_size or "")
    if not m:
        return None
    value = float(m.group(1))
    return value / 1000 if m.group(2) in "Mm" else value


def _is_cloud(model: dict) -> bool:
    return bool(model.get("remote_host")) or str(model.get("name", "")).endswith(":cloud")


def to_ollama_messages(messages: list[dict]) -> list[dict]:
    """OpenAI-shape history -> Ollama native: tool-call arguments become objects, and
    tool results carry tool_name (Ollama pairs results by name, not by call id)."""
    names_by_id: dict[str, str] = {}
    out = []
    for msg in messages:
        role = msg.get("role")
        if role == "assistant" and msg.get("tool_calls"):
            calls = []
            for tc in msg["tool_calls"]:
                fn = tc.get("function") or {}
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        args = json.loads(args or "{}")
                    except json.JSONDecodeError:
                        args = {}
                names_by_id[tc.get("id", "")] = fn.get("name", "")
                calls.append({"function": {"name": fn.get("name", ""), "arguments": args or {}}})
            out.append({"role": "assistant", "content": msg.get("content") or "",
                        "tool_calls": calls})
        elif role == "tool":
            entry = {"role": "tool", "content": msg.get("content") or ""}
            name = names_by_id.get(msg.get("tool_call_id", ""))
            if name:
                entry["tool_name"] = name
            out.append(entry)
        else:
            out.append({"role": role, "content": msg.get("content") or ""})
    return out


_FENCED = re.compile(r"```(?:json)?\s*(.*?)```|<tool_call>(.*?)</tool_call>", re.DOTALL)


def salvage_text_tool_calls(content: str, tool_names: set[str]) -> list[dict]:
    """Small local models often write a tool call as JSON in the reply text instead of
    emitting a structured call. Recover {"name", "arguments"} objects — bare, fenced, or
    in <tool_call> tags — but only for tools actually offered this turn, so prose that
    merely mentions JSON is never executed as an action."""
    blobs = [a or b for a, b in _FENCED.findall(content)] or [content]
    calls = []
    for blob in blobs:
        try:
            obj = json.loads(blob.strip())
        except json.JSONDecodeError:
            continue
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict) or item.get("name") not in tool_names:
                continue
            args = item.get("arguments", item.get("parameters", {}))
            if isinstance(args, dict):
                calls.append({"function": {"name": item["name"], "arguments": args}})
    return calls


def from_ollama_message(message: dict, tool_names: set[str] | None = None) -> dict:
    """Ollama native assistant message -> OpenAI shape (string arguments, call ids)."""
    out = {"role": "assistant", "content": message.get("content") or ""}
    raw_calls = message.get("tool_calls") or []
    if not raw_calls and tool_names:
        raw_calls = salvage_text_tool_calls(out["content"], tool_names)
        if raw_calls:
            out["content"] = ""   # the text WAS the call; don't also show it as prose
    calls = []
    for tc in raw_calls:
        fn = tc.get("function") or {}
        args = fn.get("arguments")
        calls.append({
            "id": f"call_{uuid.uuid4().hex[:12]}",
            "type": "function",
            "function": {"name": fn.get("name", ""),
                         "arguments": args if isinstance(args, str) else json.dumps(args or {})},
        })
    if calls:
        out["tool_calls"] = calls
    return out


class OllamaRouter:
    """Discovers installed tool-capable models and serves per-role candidate lists."""

    def __init__(self, cfg: LlmConfig, session):
        self._cfg = cfg
        self._session = session
        self._pools: dict[str, list[str]] = {"cheap": [], "strong": []}
        self._candidates: list[str] = []
        self.cloud: set[str] = set()   # discovered models served by ollama.com

    def discover(self) -> list[str]:
        try:
            resp = self._session.get(f"{self._cfg.ollama_url}/api/tags", timeout=10)
            resp.raise_for_status()
            models = resp.json().get("models", [])
        except (requests.RequestException, ValueError) as exc:
            raise NoModelsAvailable(
                f"cannot reach Ollama at {self._cfg.ollama_url} ({exc}); is `ollama serve` running?"
            ) from exc

        allow, deny = set(self._cfg.model_allow), set(self._cfg.model_deny)
        wanted = self._cfg.ollama_models
        sized: list[tuple[str, float | None]] = []
        for m in models:
            name = m.get("name", "")
            cloud = _is_cloud(m)
            if (wanted == "local" and cloud) or (wanted == "cloud" and not cloud):
                continue
            caps = m.get("capabilities")
            # Older Ollama builds omit capabilities; let those through rather than guess.
            if self._cfg.require_tool_support and caps is not None and "tools" not in caps:
                continue
            if (allow and name not in allow) or name in deny:
                continue
            sized.append((name, _billions((m.get("details") or {}).get("parameter_size", ""))))
            if cloud:
                self.cloud.add(name)
        if not sized:
            raise NoModelsAvailable(
                f"no usable tool-capable Ollama models for ollama_models={wanted!r}; pull one "
                "with `ollama pull <model>` (cloud models need `ollama signin` first)")

        # Biggest first within each pool: the strongest local model leads the hard roles.
        sized.sort(key=lambda item: -(item[1] or 0.0))
        cheap, strong = [], []
        for name, size in sized:
            small = size <= _SMALL_MAX_BILLIONS if size is not None else is_small_model(name)
            (cheap if small else strong).append(name)
        # Cheap roles want the fastest adequate model: smallest first.
        self._pools = {"cheap": list(reversed(cheap)), "strong": strong}
        self._candidates = [n for n, _ in sized]
        return self._candidates

    def candidates_for(self, role: str) -> list[str]:
        if not self._candidates:
            self.discover()
        pools = self._pools
        if role not in CHEAP_ROLES:
            # A hard role falling back into the cheap pool wants its biggest model first.
            pools = {"strong": pools["strong"], "cheap": list(reversed(pools["cheap"]))}
        pool = candidates_for_role(pools, role)
        # role_models is shared with OpenRouter: honor only pins this daemon actually has.
        pinned = (self._cfg.role_models or {}).get(role)
        if pinned not in self._candidates:
            return pool
        return [pinned] + [m for m in pool if m != pinned]

    @property
    def exhausted_after(self) -> int:
        return min(self._cfg.max_rotations, max(len(self._candidates), 1))


class OllamaClient:
    def __init__(self, cfg: LlmConfig, audit=None, session=None):
        self._cfg = cfg
        self._audit = audit
        self._session = session or requests.Session()
        self._slots = threading.BoundedSemaphore(cfg.max_concurrency)
        self.router = OllamaRouter(cfg, self._session)

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, **fields)

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             role: str = DEFAULT) -> ChatResult:
        candidates = self.router.candidates_for(role)
        native_messages = to_ollama_messages(messages)
        tool_names = {(t.get("function") or {}).get("name") for t in tools or []}
        last_error: Exception | None = None

        for model in candidates[: self.router.exhausted_after]:
            payload = {
                "model": model, "messages": native_messages, "stream": False,
                "options": {"temperature": self._cfg.temperature,
                            "num_predict": self._cfg.max_tokens,
                            "num_ctx": self._cfg.num_ctx},
            }
            if tools:
                payload["tools"] = tools
            slot = nullcontext() if model in self.router.cloud else self._slots
            try:
                with slot:
                    resp = self._session.post(f"{self._cfg.ollama_url}/api/chat",
                                              data=json.dumps(payload),
                                              timeout=self._cfg.request_timeout)
            except requests.RequestException as exc:
                last_error = exc
                self._log("llm.transport_error", model=model, error=str(exc))
                continue
            if resp.status_code >= 400:
                last_error = RuntimeError(f"{resp.status_code}: {resp.text[:300]}")
                self._log("llm.rotate", model=model, status=resp.status_code)
                continue

            body = resp.json()
            message = from_ollama_message(body.get("message") or {}, tool_names)
            if message.get("tool_calls") and not (body.get("message") or {}).get("tool_calls"):
                self._log("llm.salvaged_tool_call", model=model)
            if not message["content"].strip() and not message.get("tool_calls"):
                self._log("llm.degenerate", model=model, finish_reason=body.get("done_reason"))
                last_error = RuntimeError(f"{model} returned an empty response")
                continue

            usage = {"prompt_tokens": body.get("prompt_eval_count", 0),
                     "completion_tokens": body.get("eval_count", 0)}
            usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
            # Prompt tokens at the window edge mean Ollama likely truncated the history.
            if usage["prompt_tokens"] >= self._cfg.num_ctx - 16:
                self._log("llm.context_full", model=model, num_ctx=self._cfg.num_ctx)
            finish = "tool_calls" if message.get("tool_calls") else body.get("done_reason", "stop")
            self._log("llm.ok", model=model, finish_reason=finish, usage=usage)
            return ChatResult(model=model, message=message, finish_reason=finish, usage=usage)

        raise NoModelsAvailable(
            f"all {self.router.exhausted_after} candidate models failed; last error: {last_error}")

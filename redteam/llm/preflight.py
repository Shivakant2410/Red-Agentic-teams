"""Launch preflight for a client-selected LLM provider/model — especially local
Ollama — run from the SERVER (agent host), never from the client browser, and
NEVER against the engagement's target: the only traffic here is agent-server →
LLM endpoint (a harmless synthetic tool-call test).

What it verifies, in order:
  1. reachability   GET /models on the configured endpoint (OpenAI-compatible;
                    Ollama, OpenRouter, OpenAI, vLLM, LM Studio all implement it).
  2. model_found    the requested model id is served by that endpoint.
  3. tool_call_ok   a one-shot chat completion with a harmless synthetic tool
                    ("report_preflight_ok" — no network, no target, no side
                    effects) comes back WITH a tool call. Not every Ollama model
                    supports tool calling; a model that answers in plain text
                    fails exactly here, with that stated plainly.
  4. args_parsed    the tool call's JSON arguments parse (the same parse the
                    gateway/agent loop performs every turn).

The result is a structured, display-ready check list. API keys are used only to
authenticate the preflight request in memory; they are never echoed, logged, or
included in error messages.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..persistence import locked_json_update

import requests

from .providers import AnthropicProvider, OpenAICompatProvider, ProviderConfig

# Connect/read timeout for each preflight HTTP call: a dead endpoint must fail
# in seconds, not hang the launch form.
CONNECT_TIMEOUT = 5.0
CALL_TIMEOUT = 300.0

# The harmless synthetic tool: report a confirmation string. Nothing else.
_SYNTHETIC_TOOL = {
    "type": "function",
    "function": {
        "name": "report_preflight_ok",
        "description": "Report that the preflight ping succeeded. Has no side effects.",
        "parameters": {
            "type": "object",
            "properties": {
                "note": {"type": "string",
                         "description": "A short confirmation, e.g. 'ok'"},
                "sentinel": {"type": "string",
                             "description": "Echo the exact string 'preflight'"},
            },
            "required": ["note"],
        },
    },
}
_SYNTHETIC_MESSAGES = [
    {"role": "system",
     "content": "You are taking part in a connectivity preflight test. When asked, "
                "call the provided tool exactly once with note='ok'. Do not answer "
                "in plain text; use the tool."},
    {"role": "user",
     "content": "Preflight check: call the report_preflight_ok tool once with "
                "note='ok'. This is a harmless synthetic test."},
]


@dataclass
class PreflightCheck:
    check: str
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return {"check": self.check, "ok": self.ok, "detail": self.detail}


@dataclass
class PreflightResult:
    provider: str
    base_url: str
    model: str
    reachable: bool = False
    model_found: bool = False
    tool_call_ok: bool = False
    args_parsed: bool = False
    ok: bool = False
    latency_ms: int = 0
    error: str = ""
    checks: list[PreflightCheck] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider, "base_url": self.base_url, "model": self.model,
            "reachable": self.reachable, "model_found": self.model_found,
            "tool_call_ok": self.tool_call_ok, "args_parsed": self.args_parsed,
            "ok": self.ok, "latency_ms": self.latency_ms, "error": self.error,
            "checks": [c.as_dict() for c in self.checks],
        }


def _strip_url_error(exc: Exception) -> str:
    """Human-readable transport error. requests exceptions can embed the URL but
    never credentials (those travel in headers), so str(exc) is safe to show."""
    return f"{type(exc).__name__}: {exc}"


def run_preflight(provider: str, model: str = "", base_url: str = "",
                  api_key: str | None = None,
                  timeout: float = CALL_TIMEOUT) -> PreflightResult:
    """Verify server→endpoint connectivity, model presence, and tool-call
    capability with a harmless synthetic call. Never contacts any engagement
    target (this module does not even know one)."""
    kind = (provider or "").strip().lower()
    cfg = ProviderConfig(kind=kind or "openai_compat", base_url=base_url).resolved()
    result = PreflightResult(provider=kind, base_url=cfg.base_url, model=model)
    key_env = cfg.api_key_env
    key = api_key if api_key is not None else cfg.api_key()
    if key_env and not key:
        result.checks.append(PreflightCheck(
            "credentials", False,
            f"{kind} requires an API key ({key_env}) — supply one or pre-set the env var"))
        result.error = "missing credentials"
        return result

    if cfg.kind == "anthropic":
        # Native Anthropic shape; discovery/call reuse the same provider class.
        provider_obj = AnthropicProvider(cfg, timeout=int(timeout), api_key=key)
        model_url = f"{cfg.base_url}/models"
    else:
        provider_obj = OpenAICompatProvider(cfg, timeout=int(timeout), api_key=key)
        model_url = f"{cfg.base_url}/models"

    started = time.monotonic()

    # -- check 1+2: endpoint reachable, model listed ---------------------------
    try:
        resp = provider_obj._session.get(model_url, timeout=CONNECT_TIMEOUT,
                                         params={"limit": 100})
    except requests.RequestException as exc:
        result.error = _strip_url_error(exc)
        result.checks.append(PreflightCheck(
            "reachable", False,
            f"agent server could not reach {cfg.base_url} — {result.error}. "
            f"Check the endpoint host/port (containers: 'localhost' is the "
            f"container, not the host — use host.docker.internal or the host IP)"))
        return result
    if resp.status_code >= 400:
        result.error = f"HTTP {resp.status_code} from {cfg.base_url}/models"
        result.checks.append(PreflightCheck(
            "reachable", False,
            f"endpoint answered HTTP {resp.status_code} — is this an "
            f"OpenAI-compatible endpoint? (Ollama serves it under /v1)"))
        return result
    result.reachable = True
    try:
        served = [m.get("id", "") for m in (resp.json().get("data") or [])
                  if isinstance(m, dict) and m.get("id")]
    except ValueError:
        served = []
    result.checks.append(PreflightCheck(
        "reachable", True, f"{len(served)} model(s) listed by the endpoint"))
    if model:
        result.model_found = model in served
        result.checks.append(PreflightCheck(
            "model_found", result.model_found,
            f"'{model}' is served by the endpoint"
            if result.model_found else
            f"'{model}' is NOT in the endpoint's model list — pull it first "
            f"(e.g. `ollama pull {model}`) or pick one of: "
            + ", ".join(sorted(served)[:8])))
    else:
        result.model_found = bool(served)
        result.checks.append(PreflightCheck(
            "model_found", result.model_found,
            "no model pinned — the provider's default rotation will choose"
            if result.model_found else "endpoint lists no models"))

    # -- check 3+4: tool-call capability + argument parsing ---------------------
    if not model:
        result.checks.append(PreflightCheck(
            "tool_call_ok", False,
            "pin a model to test tool-calling capability (rotation cannot be "
            "preflighted in one call)"))
        result.latency_ms = int((time.monotonic() - started) * 1000)
        result.ok = result.reachable and result.model_found
        return result

    try:
        chat = provider_obj.chat(_SYNTHETIC_MESSAGES, [_SYNTHETIC_TOOL], model)
        tool_calls = chat.message.get("tool_calls") or []
        if tool_calls:
            result.tool_call_ok = True
            fn = (tool_calls[0].get("function") or {})
            raw = fn.get("arguments")
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else (raw or {})
                result.args_parsed = isinstance(parsed, dict)
            except (json.JSONDecodeError, TypeError):
                parsed = None
                result.args_parsed = False
            result.checks.append(PreflightCheck(
                "tool_call_ok", True,
                f"model returned a tool call ({fn.get('name', '?')})"))
            result.checks.append(PreflightCheck(
                "args_parsed", result.args_parsed,
                "arguments parsed as a JSON object — the agent loop can drive tools"
                if result.args_parsed else
                "tool-call arguments were not valid JSON — the agent loop would "
                "drop this call every turn; pick a tool-capable model"))
        else:
            result.checks.append(PreflightCheck(
                "tool_call_ok", False,
                "model answered WITHOUT a tool call — it likely does not support "
                "tool calling. Pick a tool-capable model (e.g. for Ollama: "
                "llama3.2, qwen2.5, mistral-nemo)"))
    except Exception as exc:  # noqa: BLE001 — any chat failure is a preflight failure
        result.error = _strip_url_error(exc)
        result.checks.append(PreflightCheck(
            "tool_call_ok", False,
            f"synthetic tool-call request failed — {result.error}"))

    result.latency_ms = int((time.monotonic() - started) * 1000)
    result.ok = (result.reachable and result.model_found
                 and result.tool_call_ok and result.args_parsed)
    return result


PHASES = ("planning", "analysis", "verification", "reporting")


@dataclass(frozen=True)
class Qualification:
    model_id: str
    phase: str
    score: float
    run_id: str
    evaluator_version: str
    evaluated_at: str


class QualificationStore:
    """Persistent per-model, per-phase qualification scores used by the operator."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def all(self) -> list[Qualification]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Qualification file must contain a JSON list")
        return [Qualification(**item) for item in payload]

    def add(self, model_id: str, phase: str, score: float, run_id: str,
            evaluator_version: str) -> Qualification:
        if phase not in PHASES:
            raise ValueError(f"Unknown phase '{phase}'. Choose from: {', '.join(PHASES)}")
        if not model_id.strip():
            raise ValueError("Model id cannot be empty")
        if not 0 <= score <= 1:
            raise ValueError("Score must be between 0 and 1")
        if not run_id.strip() or not evaluator_version.strip():
            raise ValueError("Run id and evaluator version are required")
        qualification = Qualification(
            model_id=model_id, phase=phase, score=score, run_id=run_id,
            evaluator_version=evaluator_version,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        def replace_record(current):
            if current is None:
                current = []
            if not isinstance(current, list):
                raise ValueError("Qualification file must contain a JSON list")
            records = [item for item in current
                       if (item.get("model_id"), item.get("phase")) != (model_id, phase)]
            records.append(asdict(qualification))
            return records
        locked_json_update(self.path, replace_record, default=[])
        return qualification

    def for_phase(self, phase: str) -> list[Qualification]:
        return [record for record in self.all() if record.phase == phase]

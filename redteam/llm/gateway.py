"""LLMGateway — one client interface over a fleet of providers.

Same contract the Gen-1 OpenRouterClient has (`.chat(messages, tools, role) -> ChatResult`
in OpenAI message shape), so agent.py / orchestrator.py / run.py are agnostic to how many
backends are configured behind it.

Routing model:
  - Each provider ranks its own models for a role (cheap pool for parse/triage/summary,
    strong pool otherwise) — the same role-tier idea Gen-1 applied inside OpenRouter.
  - Providers are interleaved by priority: with providers A(prio 50) and B(prio 60), the
    candidate order is A's best, B's best, A's second, B's second, ... so one flaky
    backend can never monopolize a turn and every provider's strength is reachable.
  - `role_models` pins override the interleave: "provider:model" pins that exact pair;
    a bare "model" is tried on every provider that has it, before the unpinned pool.
  - Rotation: any ProviderError/transport failure moves to the next candidate. A model
    that 429s twice in one run cools down to the back of the list (same policy as Gen-1).

Zero-config behavior is unchanged: with no `llm.providers` block, `build_llm_client`
returns the Gen-1 OpenRouterClient — existing engagement files, tests, and muscle memory
keep working exactly as before.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping

from ..config import LlmConfig
from .openrouter import ChatResult, NoModelsAvailable, OpenRouterClient
from .providers import ROTATE_STATUSES, AnthropicProvider, OpenAICompatProvider, ProviderConfig, ProviderError


def _is_local_backend(base_url: str) -> bool:
    """A loopback/private-host endpoint (Ollama, LM Studio, a local vLLM) — it loads
    the model on this machine, so a slow first byte is normal, not a dead endpoint."""
    u = (base_url or "").lower()
    return any(h in u for h in ("127.0.0.1", "localhost", "::1", "0.0.0.0")) \
        or ":11434" in u            # Ollama's default port, even behind a hostname


def resolve_api_key(pcfg: ProviderConfig,
                    credentials: Mapping[str, str] | None = None) -> str:
    """Resolve one provider's API key: run-scoped credential first, then the
    process environment. The mapping is keyed by the provider's STANDARD env-var
    name (the YAML channel), so preconfigured operators need nothing and per-run
    keys never touch the environment — concurrent runs cannot cross-use them."""
    if credentials and pcfg.api_key_env and pcfg.api_key_env in credentials:
        return credentials[pcfg.api_key_env]
    return pcfg.api_key()


class UnconfiguredClient:
    """Stand-in client when no LLM fleet can be built at all.

    Every turn raises NoModelsAvailable, so the engine degrades exactly the way it
    already does when a fleet's models all fail: deterministic recon still runs,
    tasks fail honestly with `agent.no_models`, and the stop reason records why —
    instead of the run thread dying with an uncaught construction error."""

    def __init__(self, reason: str = "no LLM provider configured"):
        self.reason = reason

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             role: str = "") -> ChatResult:
        raise NoModelsAvailable(self.reason)

    @property
    def providers(self) -> list[str]:
        return []

    @property
    def skipped(self) -> list[tuple[str, str]]:
        return [(self.reason, "unconfigured")]


class LLMGateway:
    """Fleet-of-providers client with role routing and cross-provider failover.

    `credentials`: optional run-scoped mapping {api_key_env -> api_key} supplied by
    the caller (server launch) so concurrent runs each use their own key. It takes
    precedence over the process environment at provider construction ONLY — it is
    never persisted, logged, or echoed; env-based configuration keeps working when
    the mapping is empty or lacks the provider's env var name.
    """

    def __init__(self, cfg: LlmConfig, audit=None, credentials=None, timeout=None,
                 usage_store=None, daily_limit: int = 1000):
        self._cfg = cfg
        self._audit = audit
        self._usage_store = usage_store
        self._daily_limit = max(1, int(daily_limit))
        # Opt-in per-request read timeout (seconds) for OpenAI-compatible
        # providers. None = provider default (120s). Local CPU-only backends
        # (ollama on a small box) can exceed 120s on ONE completion once the
        # context grows — live-fire 20261118: llama3.2:1b died with a read
        # timeout at ~9.7k tokens. No default behavior change.
        self._timeout = int(timeout) if timeout else None
        self._providers = []
        self._excluded: list[tuple[str, str]] = []   # (name, reason) for diagnostics
        for pcfg in cfg.providers:
            pcfg = pcfg.resolved()
            key = resolve_api_key(pcfg, credentials)
            if pcfg.api_key_env and not key:
                self._excluded.append((pcfg.name, f"{pcfg.api_key_env} not set"))
                if audit:
                    audit.record("llm.provider_skipped", provider=pcfg.name,
                                 reason=f"{pcfg.api_key_env} not set")
                continue
            if pcfg.kind == "anthropic":
                self._providers.append(AnthropicProvider(pcfg, audit=audit, api_key=key))
            else:
                # A local Ollama backend has to LOAD the model (an 18GB MoE can take
                # ~3 min from disk on a CPU-only box) and then REASON before the first
                # byte comes back, so the 120s default read-timeout rotates away mid-
                # load — producing transport:ReadTimeout on every call and never a
                # single success. Give local backends a long floor (explicit
                # REDTEAM_LLM_TIMEOUT still wins). Remote providers keep 120s.
                timeout = self._timeout
                if timeout is None and _is_local_backend(pcfg.base_url):
                    timeout = 600
                kw = {"timeout": timeout} if timeout else {}
                self._providers.append(OpenAICompatProvider(pcfg, audit=audit,
                                                            api_key=key, **kw))
        if not self._providers:
            raise NoModelsAvailable(
                "no LLM providers available (configure llm.providers and export their "
                "API keys; skipped: " + "; ".join(f"{n} ({r})" for n, r in self._excluded) + ")"
            )
        # (provider.name, model) -> consecutive-429 count this run (circuit breaker).
        self._consecutive_429s: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def _reserve_usage(self, role: str, provider_name: str, model: str):
        if self._usage_store is None:
            return None
        return self._usage_store.reserve_request(role, f"{provider_name}/{model}", self._daily_limit)

    def _record_usage_failure(self, request_id) -> None:
        if request_id is None:
            return
        try:
            self._usage_store.record_failure(request_id)
        except Exception as exc:
            from ..errors import record_suppressed_error
            record_suppressed_error(self._audit, "llm_gateway", "record_usage_failure", exc)

    def _record_usage_success(self, request_id, provider, model: str, result) -> None:
        if request_id is None:
            return
        try:
            pricing = provider.pricing_for(model) if callable(getattr(provider, "pricing_for", None)) else {}
            self._usage_store.record_success(request_id, result.usage or {}, pricing, None)
        except Exception as exc:
            from ..errors import record_suppressed_error
            record_suppressed_error(self._audit, "llm_gateway", "record_usage_success", exc)

    # -- introspection ----------------------------------------------------------

    @property
    def providers(self) -> list[str]:
        return [p.name for p in self._providers]

    @property
    def skipped(self) -> list[tuple[str, str]]:
        return list(self._excluded)

    # -- candidate ordering -----------------------------------------------------

    def _interleave(self, per_provider: list[list[tuple[str, str]]]) -> list[tuple[str, str]]:
        """Round-robin providers by priority so no single backend monopolizes a turn."""
        ordered: list[tuple[str, str]] = []
        idx = 0
        while True:
            added = False
            for lst in per_provider:
                if idx < len(lst):
                    ordered.append(lst[idx])
                    added = True
            if not added:
                return ordered
            idx += 1

    def _candidates_for(self, role: str) -> list[tuple[str, str]]:
        ranked = sorted(self._providers, key=lambda p: getattr(p.cfg, "priority", 100))
        per_provider = [[(p.name, m) for m in p.candidates_for(role)] for p in ranked]
        candidates = self._interleave(per_provider)

        # Role pins first: "provider:model" exact pair, then bare "model" on any provider.
        pinned: list[tuple[str, str]] = []
        unpinned: list[tuple[str, str]] = []
        for entry in candidates:
            pname, model = entry
            pin = (self._cfg.role_models or {}).get(role, "")
            is_pinned = (pin == f"{pname}:{model}"
                         or (pin and ":" not in pin and pin == model))
            (pinned if is_pinned else unpinned).append(entry)
        ordered = pinned + unpinned

        # 429 cooldown (per run): models that keep rate-limiting go to the back.
        with self._lock:
            cooling = [e for e in ordered
                       if self._consecutive_429s.get(e, 0) >= 2]
            ready = [e for e in ordered if e not in cooling]
        return ready + cooling

    # -- chat -------------------------------------------------------------------

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             role: str = "plan") -> ChatResult:
        candidates = self._candidates_for(role)
        if not candidates:
            raise NoModelsAvailable(f"no candidate models for role {role!r}")
        max_attempts = min(max(len(candidates), 1), 12)
        last_error: Exception | None = None

        for provider_name, model in candidates[:max_attempts]:
            provider = next((p for p in self._providers if p.name == provider_name), None)
            if provider is None:
                continue
            key = (provider_name, model)
            request_id = self._reserve_usage(role, provider_name, model)
            try:
                result = provider.chat(messages, tools, model)
                self._record_usage_success(request_id, provider, model, result)
                with self._lock:
                    self._consecutive_429s[key] = 0
                return result
            except ProviderError as exc:
                self._record_usage_failure(request_id)
                if exc.status == 429:
                    with self._lock:
                        self._consecutive_429s[key] = self._consecutive_429s.get(key, 0) + 1
                    self._log("llm.rotate", model=f"{provider_name}/{model}",
                              reason="rate_limited")
                else:
                    with self._lock:
                        self._consecutive_429s[key] = 0
                    self._log("llm.rotate", model=f"{provider_name}/{model}",
                              reason=f"http_{exc.status}")
                last_error = exc
                continue
            except Exception as exc:   # transport failure / malformed body — rotate
                self._record_usage_failure(request_id)
                self._log("llm.rotate", model=f"{provider_name}/{model}",
                          reason=f"transport:{type(exc).__name__}")
                last_error = exc
                continue

        raise NoModelsAvailable(
            f"all {min(len(candidates), max_attempts)} candidate models failed across "
            f"{len(self._providers)} provider(s); last error: {last_error}"
        )

    def _log(self, event: str, **fields) -> None:
        if self._audit:
            self._audit.record(event, **fields)


def build_llm_client(cfg: LlmConfig, audit=None, credentials: Mapping[str, str] | None = None,
                     usage_store=None, daily_limit: int = 1000):
    """Factory used by run.py / server: legacy single-provider config -> Gen-1 client
    (byte-for-byte behavior); multi-provider config -> LLMGateway.

    `credentials` (run-scoped {api_key_env -> key}) applies to the gateway path only;
    the Gen-1 OpenRouterClient keeps its env-var configuration (the server's model
    override always writes an effective engagement WITH a providers block, so per-run
    keys never reach the legacy path)."""
    if not cfg.providers:
        return OpenRouterClient(cfg, audit=audit, usage_store=usage_store, daily_limit=daily_limit)
    # REDTEAM_LLM_TIMEOUT: operator opt-in for slow local backends (seconds).
    raw = os.environ.get("REDTEAM_LLM_TIMEOUT", "").strip()
    return LLMGateway(cfg, audit=audit, credentials=credentials,
                      timeout=int(raw) if raw else None,
                      usage_store=usage_store, daily_limit=daily_limit)

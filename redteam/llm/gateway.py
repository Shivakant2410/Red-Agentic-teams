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

import threading

from ..config import LlmConfig
from .openrouter import ChatResult, NoModelsAvailable, OpenRouterClient
from .providers import ROTATE_STATUSES, AnthropicProvider, OpenAICompatProvider, ProviderConfig, ProviderError


class LLMGateway:
    """Fleet-of-providers client with role routing and cross-provider failover."""

    def __init__(self, cfg: LlmConfig, audit=None):
        self._cfg = cfg
        self._audit = audit
        self._providers = []
        self._excluded: list[tuple[str, str]] = []   # (name, reason) for diagnostics
        for pcfg in cfg.providers:
            pcfg = pcfg.resolved()
            if pcfg.api_key_env and not pcfg.api_key():
                self._excluded.append((pcfg.name, f"{pcfg.api_key_env} not set"))
                if audit:
                    audit.record("llm.provider_skipped", provider=pcfg.name,
                                 reason=f"{pcfg.api_key_env} not set")
                continue
            if pcfg.kind == "anthropic":
                self._providers.append(AnthropicProvider(pcfg, audit=audit))
            else:
                self._providers.append(OpenAICompatProvider(pcfg, audit=audit))
        if not self._providers:
            raise NoModelsAvailable(
                "no LLM providers available (configure llm.providers and export their "
                "API keys; skipped: " + "; ".join(f"{n} ({r})" for n, r in self._excluded) + ")"
            )
        # (provider.name, model) -> consecutive-429 count this run (circuit breaker).
        self._consecutive_429s: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

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
            try:
                result = provider.chat(messages, tools, model)
                with self._lock:
                    self._consecutive_429s[key] = 0
                return result
            except ProviderError as exc:
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


def build_llm_client(cfg: LlmConfig, audit=None):
    """Factory used by run.py / server: legacy single-provider config -> Gen-1 client
    (byte-for-byte behavior); multi-provider config -> LLMGateway."""
    if not cfg.providers:
        return OpenRouterClient(cfg, audit=audit)
    return LLMGateway(cfg, audit=audit)

"""LLM backends for the agent: OpenRouter (hosted free models) and Ollama (local and
ollama.com cloud models via the local daemon).

Every backend exposes the same chat(messages, tools, role) -> ChatResult contract, so the
agent loop and the swarm never branch on provider.
"""

from __future__ import annotations

from .openrouter import NoModelsAvailable
from .routing import parse_pins


class FallbackClient:
    """Serves each turn from the first backend in llm.providers that can.

    Each backend already rotates through its own models; this adds one more level, so a
    turn only fails when EVERY model of EVERY provider failed it (e.g. OpenRouter's free
    daily quota is spent and the Ollama cloud models are rate-limited too).
    """

    def __init__(self, backends: list[tuple[str, object]], audit=None, role_models=None):
        self._backends = backends
        self._audit = audit
        self._role_models = role_models or {}

    def _ordered(self, role: str) -> list[tuple[str, object]]:
        """Providers this role is pinned to go first, in pin order; then llm.providers
        order. Lets a high-volume role sit on one provider and a scarce-quota role on
        another without changing the global fallback order."""
        first = []
        for provider, _ in parse_pins(self._role_models.get(role)):
            if provider and provider not in first:
                first.append(provider)
        rank = {p: i for i, p in enumerate(first)}
        return sorted(self._backends, key=lambda nb: rank.get(nb[0], len(first)))

    def chat(self, messages, tools=None, role="plan", exclude_families=()):
        errors = []
        extra = {"exclude_families": exclude_families} if exclude_families else {}
        for name, backend in self._ordered(role):
            try:
                return backend.chat(messages, tools=tools, role=role, **extra)
            except NoModelsAvailable as exc:
                errors.append(f"{name}: {exc}")
                if self._audit:
                    self._audit.record("llm.provider_exhausted", provider=name, error=str(exc))
        raise NoModelsAvailable("every provider failed this turn; " + " | ".join(errors))


def _build(name: str, cfg, audit):
    if name == "ollama":
        from .ollama import OllamaClient
        return OllamaClient(cfg, audit=audit)
    from .openrouter import OpenRouterClient
    return OpenRouterClient(cfg, audit=audit)


def make_client(cfg, audit=None):
    """Build the client llm.providers selects: one backend, or a FallbackClient chain."""
    backends = [(name, _build(name, cfg, audit)) for name in cfg.providers]
    if len(backends) == 1:
        return backends[0][1]
    return FallbackClient(backends, audit=audit, role_models=cfg.role_models)

"""LLM backends for the agent: OpenRouter (hosted free models) and Ollama (local and
ollama.com cloud models via the local daemon).

Every backend exposes the same chat(messages, tools, role) -> ChatResult contract, so the
agent loop and the swarm never branch on provider.
"""

from __future__ import annotations

from .openrouter import NoModelsAvailable


class FallbackClient:
    """Serves each turn from the first backend in llm.providers that can.

    Each backend already rotates through its own models; this adds one more level, so a
    turn only fails when EVERY model of EVERY provider failed it (e.g. OpenRouter's free
    daily quota is spent and the Ollama cloud models are rate-limited too).
    """

    def __init__(self, backends: list[tuple[str, object]], audit=None):
        self._backends = backends
        self._audit = audit

    def chat(self, messages, tools=None, role="plan"):
        errors = []
        for name, backend in self._backends:
            try:
                return backend.chat(messages, tools=tools, role=role)
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
    return FallbackClient(backends, audit=audit)

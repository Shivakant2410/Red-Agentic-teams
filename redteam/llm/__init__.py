"""LLM backends for the agent: OpenRouter (hosted free models) or Ollama (local models).

Both expose the same chat(messages, tools, role) -> ChatResult contract, so the agent
loop and the swarm never branch on provider.
"""


def make_client(cfg, audit=None):
    """Build the client llm.provider selects."""
    if cfg.provider == "ollama":
        from .ollama import OllamaClient
        return OllamaClient(cfg, audit=audit)
    from .openrouter import OpenRouterClient
    return OpenRouterClient(cfg, audit=audit)

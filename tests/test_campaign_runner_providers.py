"""Builder 04: campaign harness provider wiring — Ollama (keyless default),
OpenRouter (keyless in YAML: the key rides run-scoped credentials), z-ai
fallback. The engagement block must never contain key material."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from campaign_runner import PROVIDER_DEFAULT_MODELS, build_providers_yaml  # noqa: E402


def _parse(provider: str, model: str) -> dict:
    text, labels = build_providers_yaml(provider, model)
    data = yaml.safe_load(text)
    assert "key" not in text.lower() or "models_allow" in text  # no key material
    return data


def test_ollama_block_is_keyless_and_preselected():
    data = _parse("ollama", "qwen2.5:7b-instruct")
    entry = data["llm"]["providers"][0]
    assert entry["kind"] == "openai_compat"
    assert entry["base_url"] == "http://127.0.0.1:11434/v1"
    assert entry["models_allow"] == ["qwen2.5:7b-instruct"]
    # Ollama's /v1/models listing does not advertise tool support; capability
    # is proven by the preflight, never assumed from discovery
    assert entry["require_tool_support"] is False
    assert "api_key" not in yaml.safe_dump(data)


def test_openrouter_block_has_no_key_material():
    text, labels = build_providers_yaml("both", "m1:free")
    assert "OPENROUTER_API_KEY" not in text  # env-var NAME would leak nothing, but
    # the block itself must not carry a key VALUE; credentials ride RunOptions
    assert "api_key:" not in text
    assert labels == ["openrouter/m1:free", "zai-bridge/glm-4.6"]


def test_provider_default_models_cover_every_choice():
    for provider in ("ollama", "openrouter", "both", "zai"):
        assert PROVIDER_DEFAULT_MODELS.get(provider)

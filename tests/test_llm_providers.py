"""Gen-2 OpenAICompatProvider must honor engagement allow/deny on live discovery.

Live-fire 20261030 (real OpenRouter key): discover() collected the live catalog
and never applied models_allow/models_deny — the `_apply_filters` helper existed
but was not called — so an operator pinning three models to cap spend watched
the gateway rotate through models they had explicitly excluded, every rotation
burning a request against a tight daily quota. Gen-1 ModelRouter.discover()
applies the same filters; the Gen-2 path must not be weaker.
"""

from __future__ import annotations

from redteam.config import LlmConfig
from redteam.llm.gateway import LLMGateway, build_llm_client
from redteam.llm.providers import OpenAICompatProvider, ProviderConfig


class _Resp:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload


def _model(mid: str) -> dict:
    return {"id": mid, "pricing": {"prompt": "0", "completion": "0"},
            "supported_parameters": ["tools"], "context_length": 100000}


def _patch_catalog(monkeypatch, provider: OpenAICompatProvider, ids: list[str]):
    models = [_model(i) for i in ids]
    monkeypatch.setattr(provider._session, "get", lambda url, **k: _Resp({"data": models}))


def _provider(allow=(), deny=()) -> OpenAICompatProvider:
    cfg = ProviderConfig(kind="openrouter", models_allow=tuple(allow),
                         models_deny=tuple(deny))
    return OpenAICompatProvider(cfg)


def test_discover_applies_allowlist(monkeypatch):
    p = _provider(allow=("keep/a:free",))
    _patch_catalog(monkeypatch, p, ["keep/a:free", "drop/b:free", "drop/c:free"])

    assert p.discover() == ["keep/a:free"]
    assert p.candidates_for("plan") == ["keep/a:free"]
    assert p.candidates_for("parse") == ["keep/a:free"]


def test_discover_applies_deny(monkeypatch):
    p = _provider(deny=("drop/b:free",))
    _patch_catalog(monkeypatch, p, ["keep/a:free", "drop/b:free"])

    assert p.discover() == ["keep/a:free"]
    assert "drop/b:free" not in p.candidates_for("plan")


def test_allowlist_fallback_when_catalog_yields_nothing(monkeypatch):
    """No /models (or everything filtered out) — the operator's explicit list is
    still the candidate list (pre-existing fallback semantic)."""
    p = _provider(allow=("keep/a:free",))
    monkeypatch.setattr(p._session, "get", lambda url, **k: _Resp({"data": []}))

    assert p.discover() == ["keep/a:free"]


def test_unfiltered_discovery_unchanged(monkeypatch):
    """No allow/deny configured -> the full free+tools catalog, as before."""
    p = _provider()
    _patch_catalog(monkeypatch, p, ["a/x:free", "b/y:free"])

    assert sorted(p.discover()) == ["a/x:free", "b/y:free"]


def test_gateway_routes_within_allowlist(monkeypatch):
    """End to end through the gateway factory: the pinned model is the only
    candidate the fleet may try."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-for-fleet")
    cfg = LlmConfig(providers=(ProviderConfig(
        kind="openrouter", models_allow=("keep/a:free",)),))
    gw = build_llm_client(cfg)
    assert isinstance(gw, LLMGateway)
    p = gw._providers[0]
    assert isinstance(p, OpenAICompatProvider)
    _patch_catalog(monkeypatch, p, ["keep/a:free", "drop/b:free"])

    candidates = gw._candidates_for("plan")
    assert candidates and all(model == "keep/a:free" for _, model in candidates)

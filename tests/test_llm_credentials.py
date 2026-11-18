"""Run-scoped LLM credentials: concurrent runs must never cross-use keys.

PR #21 wrote the dashboard-submitted API key into process-wide os.environ, so
two concurrent runs selecting the same provider with different keys raced at
provider construction (the later launch could re-point the earlier run's fleet
at the wrong credential while its providers were still being built). The fix
threads a run-scoped {api_key_env -> key} mapping through RunOptions ->
build_llm_client -> LLMGateway -> provider constructors: the mapping lives only
in memory on the run's options, and each provider captures its key into its own
requests.Session header at construction. These tests pin the resolution
precedence, isolation under concurrency, env-preconfig compatibility, honest
exclusion when no key exists anywhere, and the real-HTTP path.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redteam.config import LlmConfig
from redteam.llm.gateway import LLMGateway, build_llm_client, resolve_api_key
from redteam.llm.openrouter import NoModelsAvailable
from redteam.llm.providers import OpenAICompatProvider, ProviderConfig


def _cfg(kinds: tuple[str, ...] = ("openai",)) -> LlmConfig:
    return LlmConfig(providers=tuple(ProviderConfig(kind=k, models_allow=("m-1",))
                                     for k in kinds))


# -- resolution precedence ------------------------------------------------------

def test_resolve_api_key_prefers_run_scope_over_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    pcfg = ProviderConfig(kind="openai").resolved()
    assert resolve_api_key(pcfg, {"OPENAI_API_KEY": "run-key"}) == "run-key"


def test_resolve_api_key_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    pcfg = ProviderConfig(kind="openai").resolved()
    assert resolve_api_key(pcfg, None) == "env-key"
    assert resolve_api_key(pcfg, {}) == "env-key"
    # a run-scoped mapping that simply doesn't carry this env var must not
    # blank the env config
    assert resolve_api_key(pcfg, {"ZAI_API_KEY": "other"}) == "env-key"


def test_resolve_api_key_empty_when_nothing_set(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    pcfg = ProviderConfig(kind="openai").resolved()
    assert resolve_api_key(pcfg, {}) == ""


# -- construction-time capture --------------------------------------------------

def test_gateway_captures_run_scoped_key(monkeypatch):
    """The run-scoped key lands in THIS gateway's session header; the env value
    (even when set) must lose."""
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    gw = build_llm_client(_cfg(), credentials={"OPENAI_API_KEY": "sk-run"})
    assert isinstance(gw, LLMGateway)
    assert gw.providers == ["openai"]
    provider = gw._providers[0]
    assert isinstance(provider, OpenAICompatProvider)
    assert provider._session.headers["Authorization"] == "Bearer sk-run"


def test_env_preconfig_still_works(monkeypatch):
    """Operators who preconfigure keys (no per-run credential) are unaffected."""
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    gw = build_llm_client(_cfg())
    assert gw._providers[0]._session.headers["Authorization"] == "Bearer env-key"


def test_gateway_without_any_key_excludes_provider(monkeypatch):
    """No run-scoped key, no env key -> the provider is excluded at build time
    (audit-visible), and an empty fleet raises NoModelsAvailable — the input to
    run.py's UnconfiguredClient degradation, never an os.environ fallback."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(NoModelsAvailable, match="OPENAI_API_KEY not set"):
        LLMGateway(_cfg())


# -- concurrency isolation ------------------------------------------------------

def test_concurrent_builds_isolate_keys(monkeypatch):
    """Two runs, same provider, different keys — constructed concurrently while
    an unrelated env value sits in os.environ (the old code raced exactly here).
    Each session must carry its own key, on every interleaving."""
    monkeypatch.setenv("OPENAI_API_KEY", "env-noise")
    barrier = threading.Barrier(2)
    results: dict[str, str] = {}

    def build(tag: str, key: str) -> None:
        barrier.wait()
        gw = build_llm_client(_cfg(), credentials={"OPENAI_API_KEY": key})
        results[tag] = gw._providers[0]._session.headers["Authorization"]

    for round_no in range(10):
        results.clear()
        t1 = threading.Thread(target=build, args=("a", f"sk-a-{round_no}"))
        t2 = threading.Thread(target=build, args=("b", f"sk-b-{round_no}"))
        t1.start(); t2.start(); t1.join(); t2.join()
        assert results["a"] == f"Bearer sk-a-{round_no}", round_no
        assert results["b"] == f"Bearer sk-b-{round_no}", round_no


def test_run_scoped_key_reaches_the_wire(monkeypatch):
    """End-to-end through the real HTTP layer: a stub /chat/completions records
    the Authorization header it actually received. The env value is deliberately
    different to prove the run-scoped key wins on the wire, not just in memory."""
    seen: list[str] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 — http.server API
            auth = self.headers.get("Authorization", "")
            with lock:
                seen.append(auth)
            body = b'{"error": "boom"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence the per-request stderr
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        pcfg = ProviderConfig(kind="openai", base_url=f"http://127.0.0.1:{srv.server_port}/v1")
        provider = OpenAICompatProvider(pcfg, api_key="sk-run")
        with pytest.raises(Exception):
            provider.chat([{"role": "user", "content": "hi"}], None, "m-1")
        assert seen == ["Bearer sk-run"]
    finally:
        srv.shutdown()
        srv.server_close()

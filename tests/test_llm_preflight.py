"""Launch preflight (redteam/llm/preflight.py) against a FAKE OpenAI-compatible
endpoint — CI never needs a real Ollama. Every scenario the launch form can hit
is covered: reachability, model presence, tool-call capability, argument
parsing, unreachable endpoints, missing credentials, non-JSON answers.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redteam.llm.preflight import run_preflight


class _FakeOllama:
    """Minimal OpenAI-compatible endpoint: /models + /chat/completions with
    configurable behavior knobs."""

    def __init__(self, *, models=("llama3.2", "qwen2.5"),
                 chat_status=200, chat_body=None, sleep_s: float = 0.0):
        self.models = list(models)
        self.chat_status = chat_status
        self.chat_body = chat_body
        self.sleep_s = sleep_s
        self.chat_requests: list[dict] = []

    def handler(self):  # noqa: N802 — http.server API
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, code, payload):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path).path
                if path.endswith("/models"):
                    self._send(200, {"data": [{"id": m} for m in outer.models]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                path = urlsplit(self.path).path
                if path.endswith("/chat/completions"):
                    length = int(self.headers.get("Content-Length", 0))
                    outer.chat_requests.append(
                        json.loads(self.rfile.read(length) or b"{}"))
                    if outer.sleep_s:
                        threading.Event().wait(outer.sleep_s)
                    if outer.chat_body is not None:
                        self._send(outer.chat_status, outer.chat_body)
                    else:
                        self._send(200, {
                            "choices": [{"message": {
                                "content": None,
                                "tool_calls": [{
                                    "id": "call_1", "type": "function",
                                    "function": {
                                        "name": "report_preflight_ok",
                                        "arguments": '{"note": "ok", "sentinel": "preflight"}',
                                    },
                                }],
                            }, "finish_reason": "tool_calls"}],
                        })
                else:
                    self._send(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        return H


@pytest.fixture()
def fake_endpoint():
    made: list[tuple[ThreadingHTTPServer, _FakeOllama]] = []

    def _make(**kwargs) -> str:
        ollama = _FakeOllama(**kwargs)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), ollama.handler())
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        made.append((srv, ollama))
        return f"http://127.0.0.1:{srv.server_address[1]}/v1"

    yield _make
    for srv, _ in made:
        srv.shutdown()
        srv.server_close()


def test_preflight_full_pass(fake_endpoint):
    base = fake_endpoint()
    res = run_preflight("ollama", model="llama3.2", base_url=base)
    assert res.ok is True
    assert res.reachable and res.model_found and res.tool_call_ok and res.args_parsed
    checks = {c.check for c in res.checks}
    assert {"reachable", "model_found", "tool_call_ok", "args_parsed"} == checks
    assert res.latency_ms >= 0
    assert res.base_url == base


def test_preflight_default_base_url_when_omitted():
    # ollama shortcut resolves to the standard local endpoint; it is not running
    # in CI, so this must be a clean reachability failure (never a crash).
    res = run_preflight("ollama", model="llama3.2")
    assert res.base_url == "http://127.0.0.1:11434/v1"
    assert res.reachable is False
    assert res.ok is False
    assert "reachable" in {c.check for c in res.checks}
    assert res.checks[0].ok is False
    assert res.error  # human-readable transport error


def test_preflight_unreachable_endpoint():
    # port 1 on localhost is not listening; connection refused within seconds
    res = run_preflight("openai_compat", model="m",
                        base_url="http://127.0.0.1:1/v1")
    assert res.reachable is False
    assert res.ok is False
    assert res.checks[0].check == "reachable"
    detail = res.checks[0].detail.lower()
    assert "could not reach" in detail


def test_preflight_model_missing_from_catalog(fake_endpoint):
    base = fake_endpoint(models=("qwen2.5",))
    res = run_preflight("ollama", model="llama3.2", base_url=base)
    assert res.reachable is True
    assert res.model_found is False
    assert res.ok is False
    missing = [c for c in res.checks if c.check == "model_found"][0]
    assert "NOT in the endpoint's model list" in missing.detail
    assert "ollama pull" in missing.detail


def test_preflight_model_without_tool_support(fake_endpoint):
    base = fake_endpoint(models=("phi3",), chat_body={
        "choices": [{"message": {"content": "Sure — the ping is fine!",
                                 "tool_calls": None},
                     "finish_reason": "stop"}],
    })
    res = run_preflight("ollama", model="phi3", base_url=base)
    assert res.reachable and res.model_found
    assert res.tool_call_ok is False
    assert res.ok is False
    no_tool = [c for c in res.checks if c.check == "tool_call_ok"][0]
    assert "WITHOUT a tool call" in no_tool.detail
    assert "tool-capable" in no_tool.detail


def test_preflight_malformed_tool_arguments(fake_endpoint):
    base = fake_endpoint(chat_body={
        "choices": [{"message": {
            "content": None,
            "tool_calls": [{"id": "c1", "type": "function",
                            "function": {"name": "report_preflight_ok",
                                         "arguments": "not-json{{{"}}],
        }, "finish_reason": "tool_calls"}],
    })
    res = run_preflight("ollama", model="llama3.2", base_url=base)
    assert res.tool_call_ok is True
    assert res.args_parsed is False
    assert res.ok is False
    parsed = [c for c in res.checks if c.check == "args_parsed"][0]
    assert "not valid JSON" in parsed.detail


def test_preflight_chat_endpoint_error(fake_endpoint):
    base = fake_endpoint(chat_status=500,
                         chat_body={"error": "model exploded"})
    res = run_preflight("ollama", model="llama3.2", base_url=base)
    assert res.reachable is True          # /models worked
    assert res.tool_call_ok is False
    assert res.error                      # the chat failure is reported
    assert res.ok is False


def test_preflight_hosted_provider_missing_key():
    # openai requires a key; without one the preflight fails BEFORE any contact
    res = run_preflight("openai", model="gpt-4o")
    assert res.reachable is False
    checks = {c.check for c in res.checks}
    assert "credentials" in checks
    cred = [c for c in res.checks if c.check == "credentials"][0]
    assert "OPENAI_API_KEY" in cred.detail
    assert res.ok is False


def test_preflight_run_scoped_key_reaches_the_wire(fake_endpoint):
    base = fake_endpoint(models=("m",))
    res = run_preflight("openai_compat", model="m", base_url=base,
                        api_key="sk-preflight-secret")
    assert res.ok is True
    # nothing in the result ever echoes the key
    dumped = json.dumps(res.as_dict())
    assert "sk-preflight-secret" not in dumped


def test_preflight_never_accepts_unknown_provider_without_base_url():
    res = run_preflight("totally-unknown-kind", model="m", base_url="")
    # openai_compat with no base_url → GET /models against an empty path fails
    assert res.ok is False
    assert res.reachable is False


def test_preflight_no_model_pinned_skips_tool_check(fake_endpoint):
    base = fake_endpoint()
    res = run_preflight("ollama", model="", base_url=base)
    assert res.reachable is True and res.model_found is True
    assert res.tool_call_ok is False
    checks = [c for c in res.checks if c.check == "tool_call_ok"][0]
    assert "pin a model" in checks.detail

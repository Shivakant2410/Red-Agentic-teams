"""Per-specialist model routing: provider-prefixed pins, per-role provider order, and the
verify pass's independence from the model families that proposed findings."""

from __future__ import annotations

import pytest

from redteam.findings import Finding
from redteam.llm import FallbackClient
from redteam.llm.openrouter import ChatResult, NoModelsAvailable
from redteam.llm.routing import model_family, parse_pins, pins_for
from redteam.orchestrator import run_verify_pass

from test_orchestrator import RecordingAudit, _ctx, _engagement


def test_parse_pins_only_treats_known_providers_as_prefixes():
    assert parse_pins("ollama:minimax-m3.1-flash:cloud") == [("ollama", "minimax-m3.1-flash:cloud")]
    assert parse_pins(["nvidia/x:free", "openrouter:a/b:free"]) == [
        (None, "nvidia/x:free"), ("openrouter", "a/b:free")]
    assert parse_pins(None) == []


def test_pins_for_filters_by_provider_and_keeps_bare_ids():
    pins = {"exploit": ["ollama:m:cloud", "openrouter:o:free", "bare"]}
    assert pins_for(pins, "exploit", "ollama") == ["m:cloud", "bare"]
    assert pins_for(pins, "exploit", "openrouter") == ["o:free", "bare"]
    assert pins_for(pins, "recon", "ollama") == []


@pytest.mark.parametrize("model_id, family", [
    ("minimax/minimax-m3.1-flash:free", "minimax"),
    ("minimax-m3.1-flash:cloud", "minimax"),
    ("sorc/qwen3.5-instruct-uncensored:2b", "qwen"),
    ("nvidia/nemotron-3-ultra-550b-a55b:free", "nemotron"),
])
def test_model_family(model_id, family):
    assert model_family(model_id) == family


class _Backend:
    def __init__(self, name):
        self.name, self.kwargs = name, None

    def chat(self, messages, tools=None, role="plan", **kwargs):
        self.kwargs = kwargs
        return self.name


def test_role_pins_reorder_providers_per_role():
    a, b = _Backend("ollama"), _Backend("openrouter")
    client = FallbackClient([("ollama", a), ("openrouter", b)],
                            role_models={"verify": ["openrouter:x:free"]})
    assert client.chat([], role="verify") == "openrouter"
    assert client.chat([], role="exploit") == "ollama"   # unpinned: global order


def test_exclude_families_reaches_the_backend():
    a = _Backend("ollama")
    FallbackClient([("ollama", a)]).chat([], role="verify", exclude_families={"minimax"})
    assert a.kwargs == {"exclude_families": {"minimax"}}


class _VerifyTool:
    name = "verify_finding_independently"

    def __init__(self):
        self.calls = []

    def schema(self):
        return {"name": self.name, "description": "",
                "input_schema": {"type": "object", "properties": {}}}

    def run(self, ctx, finding_id, **kwargs):
        self.calls.append(finding_id)
        ctx.findings.promote(finding_id, "confirmed")
        return "{}"


class _RecordingClient:
    def __init__(self):
        self.calls = []

    def chat(self, messages, tools=None, role="plan", **kwargs):
        self.calls.append((role, kwargs))
        return ChatResult(model="nvidia/nemotron:free",
                          message={"role": "assistant", "content": "done"},
                          finish_reason="stop", usage={})


def _pending(ctx, check_type, title):
    return ctx.findings.add(Finding(title=title, severity="high", target=f"https://api/{title}",
                                    summary="s", check_type=check_type,
                                    confidence="pending_verification"))


def test_replayable_findings_are_verified_without_any_llm_call(tmp_path):
    ctx = _ctx(tmp_path, RecordingAudit())
    f = _pending(ctx, "http", "idor")
    tool, client = _VerifyTool(), _RecordingClient()
    assert run_verify_pass(_engagement(), {tool.name: tool}, ctx, client, "obj") == 0
    assert tool.calls == [f.id] and client.calls == []


def test_workflow_findings_go_to_a_model_outside_the_proposer_families(tmp_path):
    ctx = _ctx(tmp_path, RecordingAudit())
    ctx.proposer_families.add("minimax")
    _pending(ctx, "workflow", "coupon-reuse")
    tool, client = _VerifyTool(), _RecordingClient()
    run_verify_pass(_engagement(), {tool.name: tool}, ctx, client, "obj")
    assert tool.calls == []   # workflow replay needs fresh steps the model must write
    assert client.calls and client.calls[0] == ("verify", {"exclude_families": {"minimax"}})


def test_backend_refuses_when_every_model_is_excluded(monkeypatch):
    from redteam.config import LlmConfig
    from redteam.llm.openrouter import OpenRouterClient
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    client = OpenRouterClient(LlmConfig(model_allow=("minimax/minimax-m3.1-flash:free",)))
    client.router._candidates = ["minimax/minimax-m3.1-flash:free"]
    with pytest.raises(NoModelsAvailable):
        client.chat([], role="verify", exclude_families={"minimax"})

"""Tests for task-based model routing."""

from __future__ import annotations

from redteam.llm.routing import (PARSE, PLAN, POC, TRIAGE, candidates_for_role,
                                  classify_pools, is_small_model)


def test_small_model_detection():
    assert is_small_model("anthropic/claude-haiku-4-5")
    assert is_small_model("google/gemini-2.0-flash-exp:free")
    assert is_small_model("meta-llama/llama-3.1-8b-instruct:free")
    assert not is_small_model("meta-llama/llama-3.3-70b-instruct:free")


def test_small_model_by_context_len():
    assert is_small_model("some/unknown-model", context_len=8000)
    assert not is_small_model("some/unknown-model", context_len=128000)


def test_pools_split():
    ids = ["meta-llama/llama-3.3-70b-instruct:free",
           "google/gemini-2.0-flash-exp:free",
           "qwen/qwen-2.5-72b-instruct:free"]
    pools = classify_pools(ids)
    assert "google/gemini-2.0-flash-exp:free" in pools["cheap"]
    assert "meta-llama/llama-3.3-70b-instruct:free" in pools["strong"]


def test_role_prefers_correct_pool_but_falls_back():
    pools = {"cheap": ["c1", "c2"], "strong": ["s1"]}
    assert candidates_for_role(pools, PARSE)[0] == "c1"       # cheap role -> cheap first
    assert candidates_for_role(pools, PLAN)[0] == "s1"        # hard role -> strong first
    # fallback: strong role still lists cheap models after strong ones
    assert set(candidates_for_role(pools, POC)) == {"s1", "c1", "c2"}
    assert candidates_for_role(pools, TRIAGE)[0] == "c1"


def test_empty_pool_falls_back_entirely():
    pools = {"cheap": [], "strong": ["s1", "s2"]}
    assert candidates_for_role(pools, PARSE) == ["s1", "s2"]


def test_role_models_pin_frontier_model_first():
    # A model pinned to a role is tried first; free pool stays as fallback.
    import requests
    from redteam.config import LlmConfig
    from redteam.llm.openrouter import ModelRouter
    cfg = LlmConfig(role_models={"plan": "openai/gpt-5.5"})
    r = ModelRouter(cfg, requests.Session())
    r._candidates = ["free-a:free", "free-b:free"]
    r._pools = {"cheap": [], "strong": ["free-a:free", "free-b:free"]}
    cands = r.candidates_for(PLAN)
    assert cands[0] == "openai/gpt-5.5"          # pinned frontier model first
    assert "free-a:free" in cands                 # free fallback retained
    # a role with no pin is unaffected
    assert r.candidates_for(PARSE)[0].endswith(":free")  # no cheap -> use strong

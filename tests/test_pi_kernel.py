"""llmred-kernel bridge tests: the kernel is an accelerator, never a second
source of truth. Every property here enforces that:

  - kernel output == Python-reference output, byte for byte, on random and
    adversarial inputs (when the binary exists; the reference stands alone
    when it does not — CI without Rust stays green);
  - the kernel is deterministic (same input twice, same output);
  - the kernel returns spans/indices/plans only — it cannot mint a verdict;
  - large jobs take the one-shot transport and still agree.

The adversarial scan corpus deliberately includes multi-byte text (positions
must be CHARACTER offsets), zero-width and unicode-tags layers (the smuggling
channels the technique library attacks with), and near-miss canaries (the
false-positive control the spec demands).
"""

from __future__ import annotations

import json
import random
import subprocess
import sys

import pytest

from redteam import kernel_bridge as kb
from redteam.kernel_bridge import (
    _optimize_coverage_py,
    _plan_attack_graph_py,
    _scan_canaries_py,
    optimize_coverage,
    plan_attack_graph,
    scan_canaries,
)
from redteam.pi.oracles import canary_hits, make_canary, tag_encode, zw_embed

HAS_KERNEL = kb.kernel_available()


def _random_corpus(rng: random.Random, n: int = 40):
    """(text, canaries) pairs mixing ASCII, multi-byte, smuggle layers."""
    pieces = [
        "system prompt", "reply ONLY with", " disregard prior ", "文档内容",
        "résumé café", "\u200b\u200b", tag_encode("hidden-cmd"),
        zw_embed("scattered"), "\U0001F600 emoji", "ORD-7741",
        "base64: Zm9v", "rot13: PNAENL", "\t\n  ", "İ-dot",
    ]
    out = []
    for _ in range(n):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        cans = [make_canary(rng) for _ in range(rng.randint(1, 4))]
        if rng.random() < 0.5 and cans:
            # plant the canary in one of its smuggle layers
            layer = rng.choice([lambda s: s, tag_encode, zw_embed])
            pos = rng.randint(0, len(text))
            text = text[:pos] + layer(cans[0]) + text[pos:]
        out.append((text, cans))
    return out


# ----------------------------------------------------------------- scan -----


def test_scan_kernel_equals_reference_on_random_corpus():
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    rng = random.Random(1234)
    for text, cans in _random_corpus(rng):
        assert scan_canaries(text, cans) == _scan_canaries_py(text, cans)


def test_scan_reference_agrees_with_the_original_find_loop():
    """The Python reference must stay the exact algorithm canary_hits ran
    before the kernel existed — this is the bridge's ground truth."""
    rng = random.Random(77)
    for text, cans in _random_corpus(rng, n=15):
        for canary in cans:
            expected = []
            low = text.lower()
            from redteam.pi.oracles import _canary_variants
            for name, needle in _canary_variants(canary):
                start = 0
                while True:
                    idx = low.find(needle.lower(), start)
                    if idx < 0:
                        break
                    expected.append((name, idx))
                    start = idx + 1
            got = [(h["variant"], h["pos"]) for h in scan_canaries(text, [canary])]
            assert got == expected


def test_scan_overlapping_occurrences():
    text, canary = "aaaa", "aa"
    assert [(h["variant"], h["pos"]) for h in scan_canaries(text, [canary])] == [
        ("plain", 0), ("plain", 1), ("plain", 2)
    ]


def test_scan_char_positions_after_multibyte():
    text = "文档 CANARY-2a tail"
    hits = scan_canaries(text, ["CANARY-2a"])
    assert hits == [{"canary_index": 0, "variant": "plain", "pos": 3, "len": 9}]
    if HAS_KERNEL:
        assert _scan_canaries_py(text, ["CANARY-2a"]) == hits


def test_scan_kernel_is_deterministic():
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    text = "noise CANARY-2a " + tag_encode("CANARY-2a")
    a = scan_canaries(text, ["CANARY-2a"])
    b = scan_canaries(text, ["CANARY-2a"])
    assert a == b


def test_scan_large_job_one_shot_transport():
    """A transcript bigger than the persistent-pipe threshold must still be
    byte-identical (exercises the communicate() path)."""
    text = ("filler sentence. " * 3000) + "CANARY-2a" + (" more filler " * 3000)
    ref = _scan_canaries_py(text, ["CANARY-2a"])
    assert ref  # sanity: the canary is present
    if HAS_KERNEL:
        assert scan_canaries(text, ["CANARY-2a"]) == ref


def test_canary_hits_spans_only_kernel_cannot_mint_verdicts():
    """canary_hits returns (variant, pos) tuples — evidence, never a verdict.
    Whatever the kernel returns, the oracle layer interprets it."""
    hits = canary_hits("plain CANARY-2a here", "CANARY-2a")
    assert ("plain", 6) in hits
    for name, pos in hits:
        assert isinstance(name, str) and isinstance(pos, int)


# ---------------------------------------------------------------- graph -----


def _graph_fixture():
    return [
        {"id": "PI.A1#EXPOSED", "score": 1.0, "requires": []},
        {"id": "PI.A1#RELAYED", "score": 2.0, "requires": ["PI.A1#EXPOSED"]},
        {"id": "PI.B6#EXPOSED", "score": 1.0, "requires": []},
        {
            "id": "PI.B6#PERSISTED",
            "score": 2.0,
            "requires": ["PI.B6#EXPOSED", "memory_surface"],
        },
        {
            "id": "PI.B6#EXECUTED",
            "score": 3.0,
            "requires": ["PI.B6#PERSISTED", "tool_ledger"],
        },
    ]


@pytest.mark.parametrize("achieved", [
    [],
    ["memory_surface", "tool_ledger"],
    ["tool_ledger"],
    ["PI.A1#EXPOSED", "memory_surface", "tool_ledger"],
])
def test_graph_kernel_equals_reference(achieved):
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    nodes = _graph_fixture()
    assert plan_attack_graph(nodes, achieved, 10) == _plan_attack_graph_py(
        nodes, achieved, 10
    )


def test_graph_persisted_dead_without_memory_surface():
    """The generalized dead-stage detector: no memory surface ⇒ PERSISTED and
    everything through it dies BEFORE the run, with the blocking label."""
    out = plan_attack_graph(_graph_fixture(), [], 10)
    assert out["dead"] == ["PI.B6#EXECUTED", "PI.B6#PERSISTED"]
    by_node = {r["node"]: r["missing"] for r in out["dead_reasons"]}
    assert by_node["PI.B6#PERSISTED"] == "memory_surface"
    assert by_node["PI.B6#EXECUTED"] == "PI.B6#PERSISTED"


def test_graph_ready_now_respects_scores_and_budget():
    out = plan_attack_graph(_graph_fixture(), ["memory_surface", "tool_ledger"], 1)
    assert out["ready_now"] == ["PI.A1#EXPOSED"]  # 1.0 vs 1.0 → id asc, budget 1


def test_graph_deterministic():
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    a = plan_attack_graph(_graph_fixture(), ["memory_surface"], 5)
    b = plan_attack_graph(_graph_fixture(), ["memory_surface"], 5)
    assert a == b


# ------------------------------------------------------------- coverage -----


def _coverage_corpus(rng: random.Random, n: int = 12):
    labels = [f"PI.{fam}{i}" for fam in "ABCDE" for i in range(1, 4)]
    stages = ["EXPOSED", "PERSISTED", "RELAYED", "EXECUTED"]
    items = []
    for i in range(n):
        items.append({
            "id": f"cell-{i:02d}",
            "score": round(rng.random(), 3),
            "covers": [rng.choice(labels) + "#" + rng.choice(stages)
                       for _ in range(rng.randint(1, 4))],
        })
    return items


@pytest.mark.parametrize("budget", [1, 3, 7, 100])
def test_coverage_kernel_equals_reference(budget):
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    rng = random.Random(4242)
    items = _coverage_corpus(rng)
    assert optimize_coverage(items, budget) == _optimize_coverage_py(items, budget)


def test_coverage_greedy_marginal_gain_and_ties():
    items = [
        {"id": "a", "score": 1.0, "covers": ["s1", "s2"]},
        {"id": "b", "score": 5.0, "covers": ["s1"]},
        {"id": "c", "score": 1.0, "covers": ["s3"]},
    ]
    assert optimize_coverage(items, 2)["selected"] == ["a", "c"]
    ties = [
        {"id": "z", "score": 2.0, "covers": ["s1"]},
        {"id": "y", "score": 2.0, "covers": ["s1"]},
    ]
    assert optimize_coverage(ties, 1)["selected"] == ["y"]  # score tie → id asc


# ------------------------------------------------------------- transport ----


def test_kernel_version_probe():
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    assert kb.kernel_version() == "0.1.0"


def test_kernel_unknown_op_is_an_error_not_a_masked_fallback():
    if not HAS_KERNEL:
        pytest.skip("kernel binary not built")
    with pytest.raises(RuntimeError, match="unknown op"):
        kb.call_kernel({"op": "does_not_exist", "params": {}})


def test_disable_env_forces_reference_path(monkeypatch):
    monkeypatch.setenv("LLMRED_KERNEL", "off")
    monkeypatch.setattr(kb, "kernel_available", lambda: False)
    text = "CANARY-2a"
    assert scan_canaries(text, ["CANARY-2a"]) == _scan_canaries_py(
        text, ["CANARY-2a"]
    )


def test_bridge_cannot_silently_swallow_kernel_crash(monkeypatch):
    """Rule 3: a present-but-broken kernel RAISES — masking would hide
    contract bugs behind silently different numbers."""
    monkeypatch.setattr(kb, "kernel_available", lambda: True)

    def boom(job):
        raise RuntimeError("kernel error: simulated crash")

    monkeypatch.setattr(kb, "call_kernel", boom)
    with pytest.raises(RuntimeError):
        scan_canaries("text", ["CANARY-2a"])

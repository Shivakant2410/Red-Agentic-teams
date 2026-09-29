"""Tests for autonomy runtime controls: budgets, kill switch, compaction, manifest."""

from __future__ import annotations

import time

import pytest

from redteam.runtime import (BudgetTracker, Halt, RepetitionGuard, RunManifest,
                             compact_messages, looks_failed)


def test_looks_failed_detects_failures():
    assert looks_failed("ERROR: bad arguments")
    assert looks_failed('{"ok": false, "status": 401}')
    assert looks_failed('{"recorded": false, "verdict": "rejected"}')
    assert looks_failed("BLOCKED (out of scope): x")
    assert not looks_failed('{"recorded": true, "finding_id": "abc"}')
    assert not looks_failed('{"status": 200, "body": "ok"}')


def test_repetition_guard_blocks_after_threshold():
    g = RepetitionGuard(threshold=3)
    sig = "authenticate:{\"url\":\"x\"}"
    assert g.check_before(sig) is None
    for _ in range(3):
        g.record_result(sig, failed=True)
    msg = g.check_before(sig)
    assert msg is not None and "BLOCKED-REPEAT" in msg


def test_repetition_guard_resets_on_success():
    g = RepetitionGuard(threshold=2)
    sig = "test_idor:{}"
    g.record_result(sig, failed=True)
    g.record_result(sig, failed=True)
    assert g.check_before(sig) is not None
    g.record_result(sig, failed=False)          # a success clears the spiral
    assert g.check_before(sig) is None


def test_repetition_guard_distinct_signatures_independent():
    g = RepetitionGuard(threshold=2)
    a, b = "kali_exec:{\"cmd\":\"nmap\"}", "kali_exec:{\"cmd\":\"ffuf\"}"
    g.record_result(a, True); g.record_result(a, True)
    assert g.check_before(a) is not None
    assert g.check_before(b) is None             # different call not penalized


def test_token_budget_halts():
    b = BudgetTracker(max_tokens=100)
    b.add_usage({"total_tokens": 60})
    b.check()                       # under budget, no raise
    b.add_usage({"prompt_tokens": 30, "completion_tokens": 20})  # now 110
    with pytest.raises(Halt):
        b.check()


def test_wallclock_budget_halts():
    b = BudgetTracker(max_seconds=0)   # 0 = unlimited
    b.check()
    b2 = BudgetTracker(max_seconds=1)
    time.sleep(1.05)
    with pytest.raises(Halt):
        b2.check()


def test_kill_switch(tmp_path):
    kill = tmp_path / "STOP"
    b = BudgetTracker(kill_file=kill)
    b.check()                       # not present yet
    kill.write_text("stop")
    with pytest.raises(Halt):
        b.check()


def test_compaction_preserves_head_and_bounds_length():
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "obj"}]
    for i in range(40):
        msgs.append({"role": "assistant", "content": f"step {i}"})
    out = compact_messages(msgs, keep_last=10, threshold=20)
    assert out[0]["content"] == "sys"
    assert out[1]["content"] == "obj"
    assert out[2]["role"] == "user" and "compacted" in out[2]["content"]
    assert len(out) < len(msgs)


def test_compaction_drops_orphan_tool_messages():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "o"}]
    msgs += [{"role": "assistant", "content": f"a{i}"} for i in range(30)]
    # Make the tail start with a tool message (an orphan once its assistant is dropped).
    msgs.append({"role": "tool", "tool_call_id": "x", "content": "r"})
    out = compact_messages(msgs, keep_last=1, threshold=5)
    assert out[-1]["role"] != "tool"    # orphan tool msg dropped


def test_below_threshold_is_untouched():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "o"}]
    assert compact_messages(msgs, threshold=30) is msgs


def test_manifest_roundtrip(tmp_path):
    p = tmp_path / "manifest.json"
    m = RunManifest(objective="test", engagement="eng")
    m.steps = 3
    m.save(p)
    loaded = RunManifest.load(p)
    assert loaded.objective == "test" and loaded.steps == 3

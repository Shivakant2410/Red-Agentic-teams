"""Gen-2 infrastructure: EventBus, event replay, headless approvals, run executor."""

from __future__ import annotations

import json
import threading
import time

import pytest

from redteam.events import EventBus, coerce_payload, read_events
from redteam.run import (HeadlessApprover, read_pending_approvals, resolve_approval)


# -- EventBus -------------------------------------------------------------------

def test_eventbus_seq_is_monotonic_and_thread_safe():
    bus = EventBus(run_id="r1")
    seen = []

    def spam(n):
        for _ in range(n):
            seen.append(bus.emit("tool.call", role="recon")["seq"])

    threads = [threading.Thread(target=spam, args=(200,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert seen == sorted(seen)
    assert len(set(seen)) == 800  # no duplicate seqs under concurrency
    assert bus.cursor == 800


def test_eventbus_fans_out_to_file_sink_and_subscribers(tmp_path):
    sink = tmp_path / "events.jsonl"
    got = []
    bus = EventBus(run_id="r1", sink_path=sink, subscribers=[got.append])
    bus.emit("run.start", objective="x")
    bus.emit("phase.change", phase="recon")
    bus.close()

    events = read_events(sink)
    assert [e["type"] for e in events] == ["run.start", "phase.change"]
    assert events[0]["run_id"] == "r1"
    assert got and got[0]["type"] == "run.start"


def test_read_events_cursor_and_torn_line(tmp_path):
    sink = tmp_path / "events.jsonl"
    bus = EventBus(run_id="r1", sink_path=sink)
    for i in range(5):
        bus.emit("tool.call", step=i)
    bus.close()

    # torn last line: a writer killed mid-flush
    with sink.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 6, "type": "tool.cal')

    assert [e["seq"] for e in read_events(sink, after=0)] == [1, 2, 3, 4, 5]
    assert [e["seq"] for e in read_events(sink, after=3)] == [4, 5]
    assert read_events(sink, after=99) == []


def test_eventbus_emit_swallows_subscriber_crashes(tmp_path):
    def bad(_):
        raise RuntimeError("subscriber is on fire")

    bus = EventBus(run_id="r1", sink_path=tmp_path / "e.jsonl", subscribers=[bad])
    ev = bus.emit("run.start")  # must not raise
    assert ev["type"] == "run.start"


def test_coerce_payload_bounds_and_types():
    assert coerce_payload(None) == ""
    assert coerce_payload("short") == "short"
    long_text = "x" * 5000
    assert len(coerce_payload(long_text, limit=300)) == 300
    assert len(coerce_payload({"a": ["b"] * 999}, limit=120)) == 120
    obj = object()
    assert isinstance(coerce_payload(obj), str)  # unserializable -> str() fallback


# -- HeadlessApprover ------------------------------------------------------------

def test_headless_approval_flow_request_resolve(tmp_path):
    bus = EventBus(run_id="r1", sink_path=tmp_path / "e.jsonl")
    approver = HeadlessApprover(tmp_path, bus, poll_s=0.05)

    result = {}

    def ask():
        result["approved"] = approver.approve("intrusive_test", {"details": "sqli on /login"})

    t = threading.Thread(target=ask)
    t.start()
    # wait for the pending record to appear
    deadline = time.time() + 5
    while time.time() < deadline and not read_pending_approvals(tmp_path):
        time.sleep(0.02)
    pending = read_pending_approvals(tmp_path)
    assert len(pending) == 1
    assert pending[0]["action"] == "intrusive_test"
    assert pending[0]["details"] == {"details": "sqli on /login"}

    assert resolve_approval(tmp_path, pending[0]["id"], approved=True) is True
    t.join(timeout=5)
    assert result["approved"] is True

    # events: requested then resolved
    types = [e["type"] for e in read_events(tmp_path / "e.jsonl")]
    assert types == ["approval.requested", "approval.resolved"]

    # resolving again (or unknown) is False -> API 404
    assert resolve_approval(tmp_path, pending[0]["id"], approved=True) is False
    assert resolve_approval(tmp_path, "apr-nope", approved=False) is False
    bus.close()


def test_headless_approval_kill_file_denies(tmp_path):
    bus = EventBus(run_id="r1")
    kill = tmp_path / "STOP"
    approver = HeadlessApprover(tmp_path, bus, kill_file=kill, poll_s=0.05)
    kill.write_text("stop")
    assert approver.approve("anything", {}) is False  # fail closed
    bus.close()


def test_read_pending_approvals_skips_resolved(tmp_path):
    approver = HeadlessApprover(tmp_path, None)
    # auto-resolve path: no bus, no kill file, nothing resolves it — use the file
    # directly for this test of the reader only.
    data = [
        {"id": "a1", "action": "x", "details": {}, "ts": "t1", "status": "pending", "approved": None, "resolved_ts": None},
        {"id": "a2", "action": "y", "details": {}, "ts": "t2", "status": "resolved", "approved": True, "resolved_ts": "t3"},
    ]
    (tmp_path / "approvals.json").write_text(json.dumps(data), encoding="utf-8")
    pending = read_pending_approvals(tmp_path)
    assert [p["id"] for p in pending] == ["a1"]
    assert set(pending[0]) == {"id", "action", "details", "ts"}

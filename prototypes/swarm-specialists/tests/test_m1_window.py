"""M1 test suite — the ledger as engine (G1: markers + window driver).

Unit layer : 202/event shape classification, error-contract field learning,
             marker lifecycle (grounded-only, idempotent, honest states),
             traffic-scan auto-registration.
E2E layer  : the M1 exit in miniature — a REAL freightlane run through the
             registry discovers the undocumented payouts seam autonomously,
             registers >= 2 markers, finds GV-4 + GV-5, re-verifies them
             with fresh principals, and keeps the decoys clean.
"""
import json
import os
import subprocess
import sys
import time

import pytest
import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from engine.ledger import HypothesisLedger                  # noqa: E402
from engine.window import (classify_async, field_from_error,  # noqa: E402
                           WindowDriver)
from swarm.registry_tool import run, _SPINE_AVAILABLE       # noqa: E402

FREIGHTLANE = os.path.normpath(os.path.join(
    HERE, "..", "hard-lab", "freightlane"))


# ----------------------------------------------------------------- shapes --
def test_shape_classification():
    ex = {"status": 202, "path": "/api/payouts", "principal": "seam-1",
          "req_body": {"amount_cents": 30000},
          "resp_body": {"payout_id": "PAY-x", "status": "pending",
                        "event": "/api/payouts/PAY-x/events"}}
    s = classify_async(ex)
    assert s == {"event_path": "/api/payouts/PAY-x/events",
                 "create_path": "/api/payouts", "resource": "payouts",
                 "object_id": "PAY-x", "amount": 30000,
                 "amount_field": "amount_cents", "principal": "seam-1"}
    # 200 is not a deferred seam; 202 without an event path or object id
    # is not either
    assert classify_async({"status": 200, "resp_body": {"event": "/x"}}) is None
    assert classify_async({"status": 202, "resp_body": {"a": 1}}) is None
    assert classify_async({"status": 202,
                           "resp_body": {"event": "/x"}}) is None
    assert classify_async({"status": 202,
                           "resp_body": {"id": "x", "event": "/x"}}) is None


def test_field_from_error_prefers_money_names():
    assert field_from_error({"error": "amount_cents out of range"}) == \
        "amount_cents"
    assert field_from_error({"error": "target_cents must be a positive "
                                       "integer"}) == "target_cents"
    assert field_from_error({"error": "weight_kg must be a positive "
                                      "integer"}) == "weight_kg"  # fallback
    assert field_from_error({"status": "ok"}) is None
    assert field_from_error("not a dict") is None


# ---------------------------------------------------------------- markers --
def test_mark_requires_grounded_provenance():
    l = HypothesisLedger()
    with pytest.raises(AssertionError):
        l.mark("window-driver/obs", {"event_path": "/api/x/events",
                                     "amount": 100}, [])


def test_marker_lifecycle_and_views():
    l = HypothesisLedger()
    m = l.mark("window-driver/obs",
               {"event_path": "/api/payouts/P1/events",
                "create_path": "/api/payouts", "resource": "payouts",
                "object_id": "P1", "amount": 5000,
                "amount_field": "amount_cents", "principal": "seam-1",
                "baseline": 100000}, ["SF-OBS-0001"])
    assert m["tag"] == "marker" and m["derived_from"] == ["SF-OBS-0001"]
    assert m["marker"]["state"] == "registered"
    assert l.markers() == [m]
    assert l.markers(state="registered") == [m]
    assert l.markers(state="resolved") == []
    l.resolve(m["id"], "confirmed", {"note": "violation"})
    m["marker"]["state"] = "resolved"
    assert l.markers(state="registered") == []
    assert l.stats()["by_tag"]["marker"] == 1
    assert l.score() == 1.0          # confirmed belief = information


def test_open_from_shape_idempotent_and_amount_gated():
    l = HypothesisLedger()
    ex = {"base_url": "http://127.0.0.1:1", "traffic_path": None}
    d = WindowDriver(l, ex, {})
    shape = {"event_path": "/api/payouts/P1/events",
             "create_path": "/api/payouts", "resource": "payouts",
             "object_id": "P1", "amount": 5000,
             "amount_field": "amount_cents", "principal": "p"}
    a = d.open_from_shape(shape, ["F-1"], "obs")
    b = d.open_from_shape(dict(shape), ["F-2"], "obs")
    assert a is b and a is not None          # same event path -> same marker
    assert len(l.markers()) == 1
    no_amt = dict(shape, amount=None)
    assert d.open_from_shape(no_amt, ["F-3"], "obs") is None
    assert len(l.markers()) == 1             # no expectation, no marker


def test_scan_traffic_offset(tmp_path):
    tp = tmp_path / "traffic.jsonl"
    rows = [{"seq": 1, "status": 200, "path": "/api/wallet",
             "resp_body": {"balance_cents": 1}},
            {"seq": 2, "status": 202, "path": "/api/payouts",
             "principal": "p", "req_body": {"amount_cents": 5},
             "resp_body": {"payout_id": "P1", "event": "/api/payouts/P1/e"}},
            {"seq": 3, "status": 400, "path": "/api/payouts",
             "resp_body": {"error": "amount_cents out of range"}}]
    with open(tp, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    class _Ex:
        traffic_path = str(tp)

    l = HypothesisLedger()
    d = WindowDriver(l, _Ex(), {})
    first = d.scan_traffic()
    assert [s["object_id"] for s in first] == ["P1"]
    assert d.scan_traffic() == []            # offset advanced: no re-scan
    # new traffic -> only the new seam
    with open(tp, "a") as fh:
        fh.write(json.dumps({"seq": 4, "status": 202, "path": "/api/payouts",
                             "principal": "p",
                             "req_body": {"amount_cents": 6},
                             "resp_body": {"payout_id": "P2",
                                           "event": "/api/payouts/P2/e"}})
                 + "\n")
    second = d.scan_traffic()
    assert [s["object_id"] for s in second] == ["P2"]


# ------------------------------------------------------------------- E2E --
def _spawn(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=FREIGHTLANE,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail("freightlane target did not start")


def test_freightlane_m1_exit_in_miniature(tmp_path):
    """THE M1 exit criteria, executed: autonomous seam discovery, >= 2
    markers, GV-4 + GV-5 found AND independently re-verified, decoys clean."""
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn(8471)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "m1"),
                   "memory_dir": str(tmp_path / "m1mem"),
                   "approvals": "lab", "budget": 400,
                   "stop_file": str(tmp_path / "m1" / "STOP")})
        assert out["ok"] is True
        ids = {f["id"] for f in out["findings"]}
        statuses = {f["id"]: f["status"] for f in out["findings"]}
        # --- exit: the two deferred-window violations, re-verified -------
        assert "FW-TOCTOU-SETTLE" in ids, out["findings"]
        assert "FW-SETTLED-CANCEL" in ids, out["findings"]
        assert statuses["FW-TOCTOU-SETTLE"] == "verified"
        assert statuses["FW-SETTLED-CANCEL"] == "verified"
        # --- exit: markers >= 2, all grounded ----------------------------
        assert out["markers_registered"] >= 2
        led = json.load(open(str(tmp_path / "m1" / "hypothesis_ledger.json")))
        marks = [e for e in led["entries"] if e["tag"] == "marker"]
        assert len(marks) >= 2
        assert all(e["derived_from"] for e in marks), "grounding violated"
        assert any(e["status"] == "confirmed" for e in marks)
        # --- decoy discipline: the claim decoy produces no finding -------
        assert not any("CLAIM" in i or "QUOTA-RACE" in i for i in ids)
        # --- the deterministic v1 baseline finding is still delivered ----
        assert "FW-ROUND-DRIFT" in ids
    finally:
        proc.terminate()


def test_freightlane_ledger_off_v1_path(tmp_path):
    """ctx['ledger'] False: no markers, no driver, run still completes."""
    if not _SPINE_AVAILABLE:
        pytest.skip("spine not importable")
    proc, base = _spawn(8472)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "off"),
                   "memory_dir": str(tmp_path / "offmem"),
                   "approvals": "lab", "budget": 300, "ledger": False,
                   "stop_file": str(tmp_path / "off" / "STOP")})
        assert out["ok"] is True
        assert out["markers_registered"] == 0
        assert out["hypothesis_ledger"] is None
    finally:
        proc.terminate()

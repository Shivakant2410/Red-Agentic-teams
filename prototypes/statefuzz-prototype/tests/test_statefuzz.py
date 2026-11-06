"""statefuzz test suite.

Unit layer  : mutant transforms + invariant oracles + scope guard (no HTTP)
E2E layer   : real Flask target on 127.0.0.1:8399, full tool run, assertions
              against ground-truth seeds (imported only for assertions)
Kill-switch : STOP file halts the run with an SF-STOP finding, no crash
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
sys.path.insert(0, os.path.join(HERE, "target"))

from statefuzz import chains, invariants, mutants          # noqa: E402
from statefuzz.executor import Executor                    # noqa: E402
from statefuzz.oracle import HypothesisLedger              # noqa: E402
from statefuzz.registry_tool import LocalScopeGuard, run   # noqa: E402
from seeds import SEEDS                                    # noqa: E402

PORT = 8399
BASE = "http://127.0.0.1:%d" % PORT


# ------------------------------------------------------------- fixture ----
@pytest.fixture(scope="session")
def target():
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port", str(PORT)],
                            cwd=HERE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if requests.get(BASE + "/health", timeout=0.5).status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("target did not start")
    yield BASE
    proc.terminate()


# ------------------------------------------------------- mutant operators --
PLAN = [{"name": "add", "method": "POST", "path": "/api/cart/items",
         "body": {"sku": "SKU-GPU", "qty": 2}, "principal": "p1"},
        {"name": "pay", "method": "POST", "path": "/api/checkout/confirm",
         "body": {"order_id": "X"}, "principal": "p1"},
        {"name": "ship", "method": "POST", "path": "/api/orders/X/ship",
         "body": None, "principal": "p1"}]


def test_skip_removes_step():
    out = mutants.skip(PLAN, 1)
    assert [s["name"] for s in out] == ["add", "ship"]
    assert out[0]["op"] == "SKIP"


def test_replay_duplicates_k():
    out = mutants.replay(PLAN, 0, k=4)
    assert len(out) == 6
    assert sum(1 for s in out if s["name"] == "add") == 4
    assert all(s["body"]["sku"] == "SKU-GPU" for s in out if s["name"] == "add")


def test_negative_flips_only_target_field():
    out = mutants.negative(PLAN, 0, "qty")
    assert out[0]["body"]["qty"] == -2
    assert out[1]["body"]["order_id"] == "X"      # untouched
    assert out[0]["op"] == "NEGATIVE"


def test_partial_drops_required_field():
    out = mutants.partial(PLAN, 0, "qty")
    assert "qty" not in out[0]["body"]
    assert "sku" in out[0]["body"]


def test_reorder_swaps_and_tags():
    out = mutants.reorder(PLAN, 1, 2)
    assert [s["name"] for s in out] == ["add", "ship", "pay"]
    assert out[1]["op"] == "REORDER"


def test_cross_user_swaps_principal():
    out = mutants.cross_user(PLAN, 2, "p2")
    assert out[2]["principal"] == "p2"
    assert out[0]["principal"] == "p1"


def test_interrupt_sets_race_n():
    out = mutants.interrupt(PLAN, 1, n=16)
    assert out[1]["race_n"] == 16
    assert out[1]["op"] == "INTERRUPT"


def test_idempotence_inserts_keyed_copy():
    out = mutants.idempotence(PLAN, 1, key="k-9")
    assert len(out) == 4
    assert out[1]["headers"]["Idempotency-Key"] == "k-9"
    assert out[1]["op"] == "IDEMPOTENCE"


def test_transforms_are_pure():
    import copy
    snapshot = copy.deepcopy(PLAN)
    mutants.skip(PLAN, 0); mutants.negative(PLAN, 0, "qty")
    mutants.replay(PLAN, 0, k=3); mutants.interrupt(PLAN, 0)
    assert PLAN == snapshot


# ---------------------------------------------------- invariant oracles ---
def test_i4_negative_total():
    v = invariants.i4_total_within_bounds({"subtotal_cents": 100, "discount_pct": 120,
                                           "total_cents": -20})
    assert v and v["invariant"] == "I4"


def test_i4_charge_sign():
    v = invariants.i4_charge_matches_wallet(-2700, 1_000_000, 1_002_700)
    assert v and "UP" in v["detail"]


def test_i4_charge_exact():
    assert invariants.i4_charge_matches_wallet(900, 1_000_000, 999_100) is None


def test_i1_overcredit():
    v = invariants.i1_refund_conservation(129900, [129900, 129900], "a", "b")
    assert v and v["observed"]["overcredit"] == 129900


def test_i2_snapshot_duality():
    v = invariants.i2_snapshot_duality(["O1", "O2"],
                                       [{"SKU-CABLE": 2}, {"SKU-CABLE": 2}])
    assert v and v["invariant"] == "I2"


def test_i3_owner_mismatch():
    v = invariants.i3_owner_mismatch("bob", {"owner": "alice"})
    assert v and v["observed"]["owner"] == "alice"
    assert invariants.i3_owner_mismatch("alice", {"owner": "alice"}) is None


def test_i5_race_overcredit():
    v = invariants.i5_single_use(50000, 400000, 8)
    assert v and v["observed"]["successful_redeems"] == 8


def test_ledger_deferred_violation():
    led = HypothesisLedger()
    h = led.add("m", "/api/callbacks/m", {"kind": "single_credit",
                                          "order_total": 129900})
    h.resolved = {"status": "done", "refund_cents": 129900}
    v = led.verify(h, 1_000_000, 1_259_800)   # double credit observed late
    assert v and v["invariant"] == "I1" and v["observed"]["wallet_delta"] == 259800


# ------------------------------------------------------------ scope guard --
def test_scope_guard_accepts_loopback_and_testnet():
    assert LocalScopeGuard("http://127.0.0.1:8377").ok
    assert LocalScopeGuard("http://localhost:8377").ok
    assert LocalScopeGuard("http://192.0.2.7:80").ok       # TEST-NET-1


def test_scope_guard_rejects_public_host():
    g = LocalScopeGuard("http://93.184.216.34:80")
    assert not g.ok
    g2 = LocalScopeGuard("http://example.com")
    assert not g2.ok


def test_run_refuses_out_of_scope():
    out = run({"base_url": "http://93.184.216.34", "out_dir": "results/x"})
    assert out["ok"] is False and "scope guard" in out["error"]


# ----------------------------------------------------------------- e2e ----
def test_readonly_tier_runs_no_write_mutants(target, tmp_path):
    out = run({"base_url": target, "out_dir": str(tmp_path), "approvals": "none",
               "budget": 100, "stop_file": str(tmp_path / "STOP")})
    assert out["ok"] is True
    ids = {f["id"] for f in out["findings"]}
    assert "SF-SKIP" in ids                       # write probes skipped
    assert "SF-IDOR-ORDER" in out["findings"][0]["id"] or any(
        f["id"] == "SF-IDOR-ORDER" for f in out["findings"])
    assert all(f["id"] not in ("SF-NEG-QTY", "SF-RACE-REDEEM")
               for f in out["findings"])


def test_stop_file_halts_cleanly(target, tmp_path):
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    out = run({"base_url": target, "out_dir": str(tmp_path / "s2"),
               "approvals": "lab", "budget": 50, "stop_file": str(stop)})
    assert out["ok"] is True
    assert any(f["id"] == "SF-STOP" for f in out["findings"])


def test_full_run_discovers_all_seed_classes(target, tmp_path):
    out = run({"base_url": target, "out_dir": str(tmp_path / "s3"),
               "approvals": "lab", "budget": 250,
               "stop_file": str(tmp_path / "s3" / "STOP")})
    assert out["ok"] is True
    ids = {f["id"] for f in out["findings"]}

    expected = {"SF-STACK-DISC", "SF-RACE-REDEEM", "SF-CKOUT-REPLAY",
                "SF-NEG-QTY", "SF-IDOR-ORDER", "SF-REFUND-CROSS",
                "SF-SHIP-UNPAID", "SF-ASYNC-DBL"}
    missing = expected - ids
    assert not missing, "missed: %s" % missing

    # all 5 invariant classes exercised
    assert set(out["by_invariant"]) == {"I1", "I2", "I3", "I4", "I5"}
    # at least one IDOR->capability chain
    assert any("SF-IDOR-ORDER" in c["members"] and c["severity"] == "critical"
               for c in out["chains"])
    # artifacts valid
    doc = json.load(open(os.path.join(str(tmp_path / "s3"), "findings.json")))
    assert doc["tool"] == "statefuzz" and len(doc["findings"]) == len(out["findings"])
    traffic = open(os.path.join(str(tmp_path / "s3"), "traffic.jsonl")).readlines()
    assert len(traffic) >= out["requests"] * 0.9   # race records n responses in 1 line


def test_race_finding_carries_evidence(target, tmp_path):
    out = run({"base_url": target, "out_dir": str(tmp_path / "s4"),
               "approvals": "lab", "budget": 250,
               "stop_file": str(tmp_path / "s4" / "STOP")})
    race = [f for f in out["findings"] if f["id"] == "SF-RACE-REDEEM"]
    # coupon burned by earlier lab run on the same server -> either a finding
    # with race evidence or no race finding at all; never a partial artifact
    if race:
        ev = race[0]["evidence"][0]
        assert ev["successful_redeems"] >= 2 and ev["violation"]["invariant"] == "I5"


def test_seeds_ground_truth_is_intact():
    assert len(SEEDS) == 8 and {s["id"] for s in SEEDS} == \
        {"B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8"}

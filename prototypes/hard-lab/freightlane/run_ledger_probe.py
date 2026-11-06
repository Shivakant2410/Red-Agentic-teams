"""Run C — HypothesisLedger manual-feed probe (RESEARCH.md §5).

Proves the deferred oracle works WHEN DRIVEN on the same lab the autonomous
runs starved on:
  GV-5 via ledger: create payout -> await settle -> cancel-after-settle
      -> h2.verify flags delta == 0 vs expected -N.
  GV-4 via ambient I4 bounds: drain the wallet inside the deferred window
      -> settle debits without re-check -> final balance < 0.
Every exchange lands in results/ledger-probe/traffic.jsonl (provenance).
"""
import json
import os
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJ, "statefuzz-prototype"))

PORT = 8413


def spawn():
    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(PORT)], cwd=HERE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % PORT
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("target did not start")


def main():
    proc, base = spawn()
    out = {}
    try:
        from statefuzz.executor import Executor
        from statefuzz.model import AppStateModel
        from statefuzz.oracle import HypothesisLedger

        out_dir = os.path.join(HERE, "results", "ledger-probe")
        os.makedirs(out_dir, exist_ok=True)
        ex = Executor(base, os.path.join(out_dir, "traffic.jsonl"),
                      stop_file=os.path.join(out_dir, "STOP"), budget=120)
        model = AppStateModel(ex)
        ex.principals = model.principals

        # ---------------- GV-5: cancel-after-settle, via ledger ----------
        p = model.register("probe-gv5")
        w0 = model.wallet(p)
        cr = ex.request(p, "POST", "/api/payouts",
                        body={"amount_cents": 30000}, phase="probe")
        pid = cr["resp_body"]["payout_id"]
        event = cr["resp_body"]["event"]
        ledger = HypothesisLedger()
        h2 = ledger.add(pid, event, {"kind": "single_debit",
                                     "order_total": -30000})
        # drive the deferred window: poll the event path until settled
        # (the lab's terminal status is "settled", not dvlba's "done")
        resolved, deadline = None, time.time() + 6
        while time.time() < deadline:
            er = ex.request(p, "GET", event, phase="deferred")
            if er["resp_body"].get("status") == "settled":
                resolved = er["resp_body"]
                break
            time.sleep(0.2)
        w_mid = model.wallet(p)
        gv5_cancel = ex.request(p, "POST", "/api/payouts/%s/cancel" % pid,
                                phase="probe", tag="cancel-after-settle")
        w1 = model.wallet(p)
        v_gv5 = ledger.verify(h2, w0, w1)       # delta 0 != -30000 -> flags
        out["gv5"] = {
            "settled": bool(resolved),
            "wallet_before": w0, "after_settle": w_mid, "after_cancel": w1,
            "cancel_status": gv5_cancel["status"],
            "cancel_refund_cents": gv5_cancel["resp_body"].get("refund_cents"),
            "ledger_violation": v_gv5,
            "markers_registered": len(ledger._items),
        }

        # ---------------- GV-4: deferred-window TOCTOU, ambient I4 -------
        p2 = model.register("probe-gv4")
        b0 = model.wallet(p2)
        cr2 = ex.request(p2, "POST", "/api/payouts",
                         body={"amount_cents": 30000}, phase="probe")
        # drain inside the ~1.1 s window with a LAWFUL documented spend
        ex.request(p2, "POST", "/api/shipments",
                   body={"weight_kg": 45, "service": "standard"},
                   phase="probe", tag="window-drain")
        final = None
        deadline = time.time() + 5
        while time.time() < deadline:
            final = model.wallet(p2)
            ev = ex.request(p2, "GET", cr2["resp_body"]["event"],
                            phase="deferred")
            if ev["resp_body"].get("status") != "pending":
                break
            time.sleep(0.2)
        final = model.wallet(p2)
        out["gv4"] = {"balance_before": b0, "final_balance": final,
                      "negative": final is not None and final < 0,
                      "settled_status": ev["resp_body"].get("status")}

        out["requests"] = ex.count
        with open(os.path.join(out_dir, "probe.json"), "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(json.dumps(out, indent=2, default=str))
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

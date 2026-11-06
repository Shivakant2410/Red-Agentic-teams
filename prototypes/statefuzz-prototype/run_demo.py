"""run_demo.py — point statefuzz at a REAL HTTP scope and score the run.

1. Spawns dvlba-shop (Flask, threaded) on 127.0.0.1:<port>
2. Runs build_registry()["statefuzz_run"].run(ctx) — the fuzzer never sees
   target/seeds.py
3. AFTER the run, scores findings.json against ground truth (seeds.py)
4. Prints the hit matrix, writes results/ next to this package
"""
import argparse
import json
import os
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def wait_health(base, tries=60):
    for _ in range(tries):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return True
        except Exception:
            time.sleep(0.2)
    return False


def score(findings):
    """Map finding ids -> seed ids (ground truth), AFTER the run only."""
    mapping = {
        "SF-STACK-DISC": "B1", "SF-RACE-REDEEM": "B2", "SF-CKOUT-REPLAY": "B3",
        "SF-NEG-QTY": "B4", "SF-IDOR-ORDER": "B5", "SF-REFUND-CROSS": "B6",
        "SF-REFUND-REPLAY": "B6", "SF-SHIP-UNPAID": "B7", "SF-ASYNC-DBL": "B8",
    }
    hit = {}
    for f in findings:
        for fid, sid in mapping.items():
            if f["id"] == fid:
                hit.setdefault(sid, []).append(fid)
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8377)
    ap.add_argument("--budget", type=int, default=250)
    a = ap.parse_args()
    base = "http://127.0.0.1:%d" % a.port

    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(a.port)], cwd=HERE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_health(base), "target did not come up on " + base
        from statefuzz import build_registry
        tool = build_registry()["statefuzz_run"]

        ctx = {"base_url": base,
               "out_dir": os.path.join(HERE, "results"),
               "approvals": "lab",          # write-shaped mutants approved (lab tier)
               "budget": a.budget,
               "stop_file": os.path.join(HERE, "results", "STOP")}

        print("=" * 78)
        print("statefuzz -> real HTTP scope %s   (approvals=lab, budget=%d)"
              % (base, a.budget))
        print("=" * 78)
        summary = tool["run"](ctx)

        print("\nwalk transitions observed:")
        for name, status in summary["walk"]:
            print("   %-11s -> HTTP %s" % (name, status))

        print("\nfindings (%d requests, %.1fs):" % (summary["requests"],
                                                     summary["elapsed_s"]))
        for f in summary["findings"]:
            if f["severity"] == "info":
                continue
            print("   %-17s [%s] %-4s %-16s %s"
                  % (f["id"], f["severity"].upper()[:4], f["invariant"],
                     ",".join(f["operators"]), f["title"][:58]))
        print("\nby invariant:", json.dumps(summary["by_invariant"]))
        for c in summary["chains"]:
            print("   chain %s  (%s)\n      %s\n      %s"
                  % (c["chain_id"], c["severity"], c["path"], c["impact"]))

        # ---------------------------- ground-truth scoring (post-run) ------
        sys.path.insert(0, os.path.join(HERE, "target"))
        from seeds import SEEDS
        with open(os.path.join(HERE, "results", "findings.json")) as fh:
            doc = json.load(fh)
        hit = score(doc["findings"])
        print("\n" + "=" * 78)
        print("ground-truth score (seeds.py consulted AFTER the run):")
        for s in SEEDS:
            mark = "HIT " if s["id"] in hit else "MISS"
            fids = ",".join(hit.get(s["id"], []))
            print("   %s  %s  %-6s %s %s" % (mark, s["id"], s["class"],
                                             s["endpoint"].ljust(28), fids))
        n = sum(1 for s in SEEDS if s["id"] in hit)
        print("discovered %d/%d seeded bug classes" % (n, len(SEEDS)))
        print("artifacts: %s" % json.dumps(summary["artifacts"]))
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

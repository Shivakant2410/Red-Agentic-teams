"""demo_swarm.py — end-to-end swarm engagement on a REAL HTTP scope.

Run 1: fresh memory -> techniques run in prior order, dead-ends probed.
Run 2: NEW server, SAME memory namespaces -> learned dead-ends skipped,
technique order re-derives from run-1 verified outcomes (E1/E4/E5).
Prints the dispatch trace, provenance-stamped findings, escalations, and
the run1-vs-run2 improvement delta.
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


def spawn_shop(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=HERE,
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
    raise RuntimeError("target did not start")


def one_run(run_idx, port, budget=380):
    proc, base = spawn_shop(port)
    try:
        import swarm
        tool = swarm.build_registry()["swarm_run"]
        out_dir = os.path.join(HERE, "results", "run%d" % run_idx)
        summary = tool["run"]({
            "base_url": base, "out_dir": out_dir,
            "memory_dir": os.path.join(HERE, "results", "memory"),
            "approvals": "lab", "budget": budget,
            "stop_file": os.path.join(out_dir, "STOP")})
        return summary
    finally:
        proc.terminate()


def print_trace(summary):
    print("\ndispatch trace (%d rounds):" % summary["rounds"])
    with open(summary["trace_file"]) as fh:
        for line in fh:
            t = json.loads(line)
            ev = t.get("event")
            if ev == "dispatch":
                print("   r%-2d %-14s <- %-11s fact=%-8s produced=%s"
                      % (t["round"], t["specialist"], t["trigger_kind"],
                         t["fact"], t["produced"]))
            elif ev in ("contract-refused", "stall-escalate", "stop-stalled",
                        "budget-exhausted"):
                print("   r%-2d [router] %s %s"
                      % (t["round"], ev, t.get("reason", "")
                         or t.get("specialist", "")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8378)
    ap.add_argument("--budget", type=int, default=380)
    a = ap.parse_args()

    results = []
    for i in (1, 2):
        print("=" * 78)
        print("RUN %d  (memory_dir=%s)" %
              (i, os.path.join(HERE, "results", "memory")))
        print("=" * 78)
        s = one_run(i, a.port, a.budget)
        print_trace(s)
        print("\nledger:", json.dumps(s["ledger"]))
        print("spawn events:", json.dumps(s["spawn_events"]))
        print("\nfindings (%d unique, swarm requests=%s, statefuzz sub-budget=%s):"
              % (len(s["findings"]), s["requests"],
                 s.get("statefuzz_sub_budget_requests")))
        for f in s["findings"]:
            print("   %-10s [%-4s] %-4s %-8s verified=%s  provenance=%s"
                  % (f["id"], f["severity"].upper()[:4], f["invariant"],
                     ",".join(f["provenance"]), f["status"],
                     f["provenance"]))
        print("\nescalations: %d" % len(s["escalations"]))
        for e in s["escalations"]:
            print("   [%s] %s" % (e["severity"], e["chain"]["path"]))
        print("\nmemory after curation:")
        for name, snap in sorted(s["memory_after"].items()):
            print("   %-14s %s" % (name, json.dumps(snap["techniques"])))
        results.append(s)

    print("\n" + "=" * 78)
    print("IMPROVEMENT DELTA (run2 vs run1 — same target class, same code, "
          "memory persisted):")
    print("   swarm requests      : %d -> %d" % (results[0]["requests"],
                                                   results[1]["requests"]))
    r1 = {f["id"] for f in results[0]["findings"]}
    r2 = {f["id"] for f in results[1]["findings"]}
    print("   unique findings     : %d -> %d (run2 set: %s)"
          % (len(r1), len(r2), sorted(r2)))
    skipped = None
    trace2 = [json.loads(l) for l in open(results[1]["trace_file"])]
    print("   rounds              : %d -> %d" % (results[0]["rounds"],
                                                  results[1]["rounds"]))
    mem = json.load(open(os.path.join(HERE, "results", "memory",
                                      "recon.json")))
    print("   recon bandit now    : %s"
          % json.dumps({k: round(v["alpha"] / (v["alpha"] + v["beta"]), 2)
                        for k, v in mem["bandit"].items()}, indent=0))
    print("   recon insights      : %s" % mem.get("insights", []))


if __name__ == "__main__":
    main()

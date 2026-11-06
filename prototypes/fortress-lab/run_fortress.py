"""run_fortress.py — full evaluation: the hardest-to-find lab, three fresh
server instances, three harness phases, one honest score matrix.

  Phase B baseline : statefuzz_run as shipped (dvlba-shaped probes)
  Swarm run 1      : specialist swarm v0.2, fresh memory
  Swarm run 2      : same memory, fresh server (improvement delta)

Usage:  python run_fortress.py [--port 8407]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = None       # loaded after the runs (scoring-only discipline)


def spawn_lab(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=HERE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("fortress lab did not start")


def run_phase(script, port, args):
    cmd = [sys.executable, script, "--port", str(port)] + args
    print("\n$ %s" % " ".join(cmd))
    out = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                         timeout=600)
    sys.stdout.write(out.stdout)
    if out.returncode != 0:
        sys.stderr.write(out.stderr[-2000:])
    return out.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    ap.add_argument("--budget", type=int, default=900)
    a = ap.parse_args()

    phases = [("baseline_statefuzz.py", ["--budget", "250"]),
              ("run_swarm_fortress.py", ["--run", "1",
                                         "--budget", str(a.budget)]),
              ("run_swarm_fortress.py", ["--run", "2",
                                         "--budget", str(a.budget)])]
    # clean protocol: run1 must start from EMPTY memory, run2 reuses it
    shutil.rmtree(os.path.join(HERE, "results", "memory"), ignore_errors=True)
    t0 = time.time()
    for script, args in phases:
        proc, base = spawn_lab(a.port)          # fresh server per phase
        try:
            run_phase(script, a.port, args)
        finally:
            proc.terminate()

    # ------------------------------------------------------------- score --
    sys.path.insert(0, os.path.join(HERE, "target"))
    global SEEDS
    from seeds import SEEDS
    rows = []
    for name, ddir in (("Phase B baseline", "results/baseline"),
                       ("Swarm run1", "results/swarm-run1"),
                       ("Swarm run2", "results/swarm-run2")):
        p = os.path.join(HERE, ddir, "score.json")
        rows.append((name, json.load(open(p)) if os.path.exists(p) else {}))

    print("\n" + "=" * 78)
    print("FORTRESS HIT MATRIX  (ground truth loaded AFTER all runs)")
    print("=" * 78)
    hdr = "%-4s %-7s %-46s" % ("seed", "tier", "endpoint")
    for name, _ in rows:
        hdr += " %-14s" % name.split()[0][:14]
    print(hdr)
    for s in SEEDS:
        line = "%-4s %-7s %-46s" % (s["id"], s["tier"], s["endpoint"])
        for _name, doc in rows:
            hit = "HIT" if s["id"] in doc.get("hits", {}) else "."
            line += " %-14s" % hit
        print(line)
    print("-" * len(hdr))
    for name, doc in rows:
        if doc:
            print("%-16s %2d/%d seeds   requests=%-5s rounds=%s"
                  % (name, doc["discovered"], doc["total"],
                     doc.get("requests", "?"), doc.get("rounds", "-")))
    json.dump({"elapsed_s": round(time.time() - t0, 1),
               "phases": [{"name": n, **d} for n, d in rows]},
              open(os.path.join(HERE, "results", "score.json"), "w"),
              indent=2)
    print("\nartifacts: %s" % os.path.join(HERE, "results"))


if __name__ == "__main__":
    main()

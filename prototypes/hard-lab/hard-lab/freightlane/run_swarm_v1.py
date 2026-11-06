"""Run B — swarm v0.2 standalone against Freightlane. Fresh server, FRESH
memory namespace (no dvlba lessons carried over; see RESEARCH.md §7)."""
import json
import os
import shutil
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJ, "swarm-specialists"))

PORT = 8412
MEM = os.path.join(HERE, "results", "memory-freightlane-fresh")


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
    if os.path.exists(MEM):
        shutil.rmtree(MEM)          # fresh namespace: fairness contract
    proc, base = spawn()
    try:
        import swarm
        tool = swarm.build_registry()["swarm_run"]
        out_dir = os.path.join(HERE, "results", "swarm-v1")
        t0 = time.time()
        summary = tool["run"]({
            "base_url": base, "out_dir": out_dir, "memory_dir": MEM,
            "approvals": "lab", "budget": 400, "max_rounds": 40,
            "stop_file": os.path.join(out_dir, "STOP")})
        summary["wall_s"] = round(time.time() - t0, 1)
        with open(os.path.join(out_dir, "summary.json"), "w") as fh:
            json.dump(summary, fh, indent=2, default=str)
        print(json.dumps({"run": "B", "requests": summary["requests"],
                          "rounds": summary["rounds"],
                          "findings": summary["findings"],
                          "escalations": len(summary["escalations"]),
                          "spawn_events": summary["spawn_events"],
                          "elapsed_s": summary["elapsed_s"]}, indent=2))
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

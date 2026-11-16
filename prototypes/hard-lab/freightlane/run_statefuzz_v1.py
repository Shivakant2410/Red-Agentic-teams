"""Run A — statefuzz v1 standalone against Freightlane. Fresh server."""
import json
import os
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJ, "statefuzz-prototype"))

PORT = 8411


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
    try:
        from statefuzz.registry_tool import build_registry
        out_dir = os.path.join(HERE, "results", "statefuzz-v1")
        tool = build_registry()["statefuzz_run"]
        t0 = time.time()
        summary = tool["run"]({"base_url": base, "out_dir": out_dir,
                               "approvals": "lab", "budget": 200,
                               "stop_file": os.path.join(out_dir, "STOP")})
        summary["wall_s"] = round(time.time() - t0, 1)
        # P-A2 evidence: "deferred" phase traffic only appears when the
        # HypothesisLedger drain() runs -> markers_registered proxy.
        deferred = 0
        tp = os.path.join(out_dir, "traffic.jsonl")
        if os.path.exists(tp):
            with open(tp) as fh:
                for line in fh:
                    if '"phase": "deferred"' in line or '"phase":"deferred"' in line:
                        deferred += 1
        summary["deferred_phase_requests"] = deferred
        with open(os.path.join(out_dir, "summary.json"), "w") as fh:
            json.dump(summary, fh, indent=2, default=str)
        print(json.dumps({"run": "A", "requests": summary["requests"],
                          "findings": summary["findings"],
                          "by_invariant": summary["by_invariant"],
                          "deferred_phase_requests": deferred,
                          "elapsed_s": summary["elapsed_s"]}, indent=2))
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

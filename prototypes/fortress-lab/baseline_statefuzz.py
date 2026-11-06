"""baseline_statefuzz.py — Phase B tool (as shipped, dvlba-shaped probes)
against the UNSEEN fortress lab. Expected outcome: the hardcoded probes land
on 404s and the run completes with an honest miss matrix. This is the
generalization-gap baseline the swarm v0.2 upgrade is measured against.

Usage: python baseline_statefuzz.py --port 8407 [--budget 250]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = os.path.join(os.path.dirname(HERE), "statefuzz-prototype")
sys.path.insert(0, PROTO)
sys.path.insert(0, os.path.join(HERE, "target"))

from seeds import SEEDS      # fortress ground truth (scoring only)  # noqa: E402

# FW/SF cross-walk: Phase B finding ids that would map to fortress seeds.
# (Empty by design: no Phase B probe speaks the helios surface. Kept as an
#  explicit table so a future Phase B fix is scored, not assumed.)
MAPPING = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    ap.add_argument("--budget", type=int, default=250)
    a = ap.parse_args()
    base = "http://127.0.0.1:%d" % a.port

    from statefuzz import build_registry
    tool = build_registry()["statefuzz_run"]
    out_dir = os.path.join(HERE, "results", "baseline")
    summary = tool["run"]({
        "base_url": base, "out_dir": out_dir, "approvals": "lab",
        "budget": a.budget, "stop_file": os.path.join(out_dir, "STOP")})

    print("=" * 78)
    print("PHASE B BASELINE  statefuzz_run -> fortress lab  %s" % base)
    print("=" * 78)
    print("walk transitions observed:")
    for name, status in summary["walk"]:
        print("   %-11s -> HTTP %s" % (name, status))
    print("\nfindings (%d requests, %.1fs):" % (summary["requests"],
                                                 summary["elapsed_s"]))
    real = [f for f in summary["findings"] if f["severity"] != "info"]
    for f in real:
        print("   %-17s [%s] %-4s %s" % (f["id"], f["severity"].upper()[:4],
                                         f["invariant"], f["title"][:56]))
    if not real:
        print("   (none — every probe target is absent from this surface)")

    with open(os.path.join(out_dir, "findings.json")) as fh:
        doc = json.load(fh)
    hit = {}
    for f in doc["findings"]:
        sid = MAPPING.get(f["id"])
        if sid:
            hit.setdefault(sid, []).append(f["id"])
    print("\n" + "=" * 78)
    print("ground-truth score (seeds.py consulted AFTER the run):")
    for s in SEEDS:
        mark = "HIT " if s["id"] in hit else "MISS"
        print("   %s  %-4s %-6s %s" % (mark, s["id"], s["tier"],
                                       s["endpoint"]))
    n = sum(1 for s in SEEDS if s["id"] in hit)
    print("discovered %d/%d fortress seed classes" % (n, len(SEEDS)))
    json.dump({"tool": "statefuzz-baseline", "requests": summary["requests"],
               "discovered": n, "total": len(SEEDS), "hits": hit},
              open(os.path.join(out_dir, "score.json"), "w"), indent=2)


if __name__ == "__main__":
    main()

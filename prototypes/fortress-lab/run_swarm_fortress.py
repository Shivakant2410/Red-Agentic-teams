"""run_swarm_fortress.py — upgraded specialist swarm (v0.2) against the
UNSEEN fortress lab over real HTTP.

--run 1 : fresh memory
--run 2 : SAME memory namespace dir, FRESH server (learned dead-ends skipped)
Both runs receive the engagement-brief artifact promo_code=LAUNCH-2026.

Usage: python run_swarm_fortress.py --port 8407 --run 1 [--budget 900]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SWARM = os.path.join(os.path.dirname(HERE), "swarm-specialists")
sys.path.insert(0, SWARM)
sys.path.insert(0, os.path.join(HERE, "target"))

from seeds import SEEDS      # fortress ground truth (scoring only)  # noqa: E402

MAPPING = {
    "FW-QUOTA-RACE": "F1", "FW-ROUND-DRIFT": "F2",
    "FW-TERMINAL-RESIZE": "F3", "FW-TOCTOU-SETTLE": "F4",
    "FW-AUDIT-LEAK": "F5", "FW-DEPUTY-CREDIT": "F6",
    "FW-MASS-PRICE": "F7", "FW-MASS-PLAN": "F8",
    "FW-CANCEL-REASON": "F9", "FW-SETTLED-CANCEL": "F10",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    ap.add_argument("--run", type=int, default=1, choices=(1, 2))
    ap.add_argument("--budget", type=int, default=900)
    a = ap.parse_args()
    base = "http://127.0.0.1:%d" % a.port

    import swarm
    tool = swarm.build_registry()["swarm_run"]
    out_dir = os.path.join(HERE, "results", "swarm-run%d" % a.run)
    memory_dir = os.path.join(HERE, "results", "memory")
    summary = tool["run"]({
        "base_url": base, "out_dir": out_dir, "memory_dir": memory_dir,
        "approvals": "lab", "budget": a.budget,
        # engagement brief: known campaign artifact for this target
        "artifacts": {"promo_code": "LAUNCH-2026"},
        "stop_file": os.path.join(out_dir, "STOP")})

    print("=" * 78)
    print("SWARM v0.2 RUN %d -> fortress lab  %s  (budget %d)"
          % (a.run, base, a.budget))
    print("=" * 78)
    print("ledger:", json.dumps(summary["ledger"]))
    print("spawn events:", json.dumps(summary["spawn_events"]))
    print("llm_seam_calls:", summary["llm_seam_calls"])
    print("\nfindings (%d unique, swarm requests=%d):"
          % (len(summary["findings"]), summary["requests"]))
    for f in summary["findings"]:
        print("   %-18s [%-4s] %-4s %-8s verified=%s provenance=%s"
              % (f["id"], f["severity"].upper()[:4], f["invariant"],
                 ",".join(f["provenance"]), f["status"], f["provenance"]))
    print("\nescalations: %d" % len(summary["escalations"]))
    for e in summary["escalations"]:
        print("   [%s] %s\n      %s" % (e["severity"], e["chain"]["path"],
                                        e["impact"][:100]))
    print("\nmemory after curation:")
    for name, snap in sorted(summary["memory_after"].items()):
        print("   %-14s %s" % (name, json.dumps(snap["techniques"])))

    with open(os.path.join(out_dir, "findings.json")) as fh:
        doc = json.load(fh)
    hit = {}
    for entry in doc["findings"]:
        fid = entry["finding"]["id"]
        sid = MAPPING.get(fid)
        if sid:
            hit.setdefault(sid, []).append(fid)
    print("\n" + "=" * 78)
    print("ground-truth score (seeds.py consulted AFTER the run):")
    for s in SEEDS:
        mark = "HIT " if s["id"] in hit else "MISS"
        fids = ",".join(hit.get(s["id"], []))
        print("   %s  %-4s %-6s %-46s %s" % (mark, s["id"], s["tier"],
                                             s["endpoint"], fids))
    n = sum(1 for s in SEEDS if s["id"] in hit)
    print("discovered %d/%d fortress seed classes" % (n, len(SEEDS)))
    tiers = {}
    for s in SEEDS:
        if s["id"] in hit:
            tiers[s["tier"]] = tiers.get(s["tier"], 0) + 1
    print("by tier:", json.dumps(tiers))
    json.dump({"tool": "swarm-run%d" % a.run, "requests": summary["requests"],
               "discovered": n, "total": len(SEEDS), "hits": hit,
               "rounds": summary["rounds"]},
              open(os.path.join(out_dir, "score.json"), "w"), indent=2)


if __name__ == "__main__":
    main()

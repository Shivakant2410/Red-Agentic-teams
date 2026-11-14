"""run_m3.py — M3 exit validation: discovery followed through, effects observed.

M3 exit criteria (ROADMAP G3, measured on Freightlane):
  E1  GV-8 autonomous + verified — FW-STATE-SKIP with wallet-delta AND
      409-gated sibling evidence                          (the band-D fix)
  E2  ambient wallet watcher saw the unattributed discovery credit and
      published a grounded ambient-credit ESCALATION       (the leak visible)
  E3  attack_surface.json artifact exists; the attack graph carries the
      settle money edge; next_actions ranked
  E4  M2 regressions hold: GV-1/GV-2/GV-3/GV-6 + GV-4/GV-5/GV-7 verified
  E5  markers >= 2 (M1 intact)
  E6  zero decoy false positives (D-1 clean)
  E7  deterministic (llm_seam_calls == 0)
  E8  regression: dvlba-shop B1..B8, zero UNMATCHED findings (the new arms'
      gates stay closed on a truthful-doc target)          (--with-dvlba)

Protocol mirrors M0/M1/M2: run1 fresh memory, run2 with run1's memory, real
HTTP, loopback only, STOP kill files, full traffic provenance.

Ground truth keys (freightlane/target/app.py docstrings + GAP-PROOF §1):
  GV-8  keyed by FW-STATE-SKIP or (settle AND booked) — settle from `booked`
  (GV-1..GV-7 keys carried from run_m2.py)
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
FREIGHTLANE = os.path.normpath(os.path.join(HERE, "..", "hard-lab",
                                            "freightlane"))
sys.path.insert(0, HERE)

RESULTS = os.path.join(HERE, "m3-results")


def spawn(app_dir, port):
    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(port)], cwd=app_dir,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("target did not start: %s" % app_dir)


def fresh_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)
    return path


def load_doc(path):
    return json.load(open(path)) if os.path.exists(path) else {"findings": []}


# ------------------------------------------------------- freightlane GT --
def classify_gv(fd):
    """finding dict (+status) -> GV id, per the lab's ground truth."""
    fid = fd.get("id", "")
    t = json.dumps(fd, default=str).lower()
    if fid == "FW-CREDIT-RACE" or ("voucher" in t and "race" in t):
        return "GV-6"
    if fid == "FW-RELEASE-REPLAY" or ("voucher" in t and "release" in t):
        return "GV-1"
    if "rebook" in t or (fid == "FW-DEPUTY-CREDIT" and "shipment" in t) or \
            (fid == "FW-AUDIT-LEAK" and "recent" in t):
        return "GV-2"
    if fid == "FW-MASS-PRICE" and "rate_cents" in t:
        return "GV-3"
    if fid == "FW-STATE-SKIP" or ("settle" in t and "booked" in t):
        return "GV-8"
    if fid == "FW-TOCTOU-SETTLE" or \
            ("negative" in t and ("payout" in t or "settle" in t)):
        return "GV-4"
    if fid == "FW-SETTLED-CANCEL" or \
            ("payouts" in t and "cancel" in t and
             ("settle" in t or "refund" in t)):
        return "GV-5"
    if fid == "FW-ROUND-DRIFT" or ("drift" in t and "cycle" in t):
        return "GV-7"
    if fid == "FW-QUOTA-RACE":
        return "D-1"                       # claim decoy: FALSE POSITIVE
    return None


def score_runs(docs):
    hits, fps, per_run = set(), [], {}
    for label, doc in docs.items():
        run_gvs = []
        for e in doc.get("findings", []):
            fd = dict(e.get("finding", {}), _status=e.get("status"))
            gv = classify_gv(fd)
            if gv is None:
                continue
            if gv == "D-1":
                if e.get("status", "candidate").startswith("verified"):
                    fps.append(fd.get("id"))
                continue
            if str(e.get("status", "")).startswith("verified"):
                hits.add(gv)
            run_gvs.append("%s:%s" % (gv, e.get("status")))
        per_run[label] = sorted(run_gvs)
    return hits, fps, per_run


def ambient_and_graph(out_dir):
    """E2/E3 evidence: ambient_watch stats + the attack-graph artifact."""
    doc = load_doc(os.path.join(out_dir, "findings.json"))
    ambient = doc.get("ambient_watch") or {}
    bb_path = os.path.join(out_dir, "blackboard.json")
    escalations = []
    if os.path.exists(bb_path):
        bb = json.load(open(bb_path))
        escalations = [f for f in bb if f["kind"] == "ESCALATION" and
                       f["payload"].get("event") == "ambient-credit"]
    graph_path = os.path.join(out_dir, "attack_surface.json")
    graph = load_doc(graph_path) if os.path.exists(graph_path) else None
    return ambient, escalations, graph


def run_lab(label, app_dir, port, budget, runs):
    import swarm                          # the ONE promoted tree
    out_root = fresh_dir(os.path.join(RESULTS, label))
    summaries, docs = {}, {}
    for out_name, mem_from in runs:
        out_dir = os.path.join(out_root, out_name)
        fresh_dir(out_dir)
        memory_dir = os.path.join(out_root, mem_from, "memory") if mem_from \
            else os.path.join(out_dir, "memory")
        os.makedirs(memory_dir, exist_ok=True)
        proc, base = spawn(app_dir, port)
        try:
            t0 = time.time()
            summary = swarm.build_registry()["swarm_run"]["run"]({
                "base_url": base, "out_dir": out_dir,
                "memory_dir": memory_dir, "approvals": "lab",
                "budget": budget,
                "stop_file": os.path.join(out_dir, "STOP")})
            summary["wall_s"] = round(time.time() - t0, 1)
            summaries[out_name] = summary
            docs[out_name] = load_doc(os.path.join(out_dir, "findings.json"))
            print("  [%s] %s req, %s findings, wall %.1fs, markers %s, "
                  "ambient %s"
                  % (out_name, summary["requests"],
                     len(summary["findings"]), summary["wall_s"],
                     summary.get("markers_registered"),
                     (summary.get("ambient_watch") or {}).get("events")))
        finally:
            proc.terminate()
    return summaries, docs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8479)
    ap.add_argument("--budget", type=int, default=720)
    ap.add_argument("--with-dvlba", action="store_true",
                    help="also run the dvlba regression (E8)")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "exit": {}}

    print("== lab: freightlane (M3 exit) ==")
    summaries, docs = run_lab("freightlane", FREIGHTLANE, args.port,
                              args.budget,
                              runs=[("run1", None), ("run2", "run1")])
    hits, fps, per_run = score_runs(docs)
    print("  hits: %s | decoy FPs: %d" % (",".join(sorted(hits)) or "none",
                                          len(fps)))
    ambient, escalations, graph = ambient_and_graph(
        os.path.join(RESULTS, "freightlane", "run1"))
    print("  ambient events: %s (unexplained %s) | escalations: %d"
          % (ambient.get("events"), ambient.get("unexplained"),
             len(escalations)))
    if graph:
        print("  attack graph: %d money paths, next_actions: %s"
              % (len(graph.get("money_paths", [])),
                 [na.get("technique") for na in
                  graph.get("next_actions", [])][:3]))

    # E1 evidence depth: the FW-STATE-SKIP finding's own evidence
    state_ev = None
    for e in docs["run1"].get("findings", []):
        if e.get("finding", {}).get("id") == "FW-STATE-SKIP":
            state_ev = e["finding"]["evidence"][0]
    ev_ok = bool(state_ev) and state_ev.get("wallet_delta", 0) > 0 and \
        bool(state_ev.get("gated_siblings")) and \
        state_ev.get("from_state") == "booked"

    m3s = summaries["run1"]
    c1 = "GV-8" in hits and ev_ok
    c2 = (ambient.get("events", 0) >= 1 and
          ambient.get("unexplained", 0) >= 1 and
          bool(escalations) and bool(escalations[0].get("derived_from")))
    c3 = bool(graph) and "e-credit-shipments-settle" in \
        (graph.get("money_paths") or []) and \
        graph.get("next_actions") is not None
    c4 = {"GV-1", "GV-2", "GV-3", "GV-4", "GV-5", "GV-6", "GV-7"} <= hits
    c5 = (m3s.get("markers_registered") or 0) >= 2
    c6 = not fps
    c7 = len(m3s.get("llm_seam_calls") or []) == 0
    report["exit"] = {
        "gv_hits": sorted(hits), "per_run": per_run,
        "decoy_false_positives": fps,
        "state_skip_evidence": state_ev,
        "ambient_watch": ambient,
        "ambient_escalations": len(escalations),
        "attack_graph_money_paths": (graph or {}).get("money_paths"),
        "attack_graph_next_actions": (graph or {}).get("next_actions"),
        "markers_registered": m3s.get("markers_registered"),
        "requests_run1": m3s["requests"],
        "requests_run2": summaries["run2"]["requests"],
        "llm_seam_calls": len(m3s.get("llm_seam_calls") or [])}
    report["labs"] = {"freightlane": report["exit"]}

    if args.with_dvlba:
        print("== regression: dvlba-shop ==")
        import dvlba_ground_truth as dgt
        summaries_d, docs_d = run_lab("dvlba", HERE, args.port + 1, 540,
                                      runs=[("run1", None),
                                            ("run2", "run1")])
        scoring = dgt.score_runs([("run1", docs_d["run1"]),
                                  ("run2", docs_d["run2"])])
        report["labs"]["dvlba"] = {
            "seeds_hit": sorted(scoring["hits"]),
            "false_positives": scoring["false_positives"],
            "unmatched": scoring["unmatched"],
            "requests_run1": summaries_d["run1"]["requests"],
            "requests_run2": summaries_d["run2"]["requests"]}
        print("  seed classes hit: %s | unmatched: %d"
              % (",".join(sorted(scoring["hits"])),
                 len(scoring["unmatched"])))

    print("== M3 exit criteria ==")
    checks = [
        ("E1 GV-8 FW-STATE-SKIP autonomous+verified (wallet delta + gated "
         "sibling)", c1),
        ("E2 ambient watcher: unattributed credit escalated (grounded)", c2),
        ("E3 attack graph artifact: settle money edge + next_actions", c3),
        ("E4 M2 regressions GV-1/2/3/4/5/6/7 all verified", c4),
        ("E5 markers >= 2 (M1 intact)", c5),
        ("E6 zero decoy false positives", c6),
        ("E7 deterministic M3 (llm_seam_calls == 0)", c7)]
    if args.with_dvlba:
        d = report["labs"].get("dvlba", {})
        checks.append(("E8 dvlba B1..B8 + zero unmatched (got %s | "
                       "unmatched %d)"
                       % (",".join(d.get("seeds_hit", [])) or "none",
                          len(d.get("unmatched", []))),
                       set("B%d" % i for i in range(1, 9)) <=
                       set(d.get("seeds_hit", [])) and
                       not d.get("unmatched")))
    ok = True
    for name, passed in checks:
        ok &= passed
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
    report["pass"] = bool(ok)
    json.dump(report, open(os.path.join(RESULTS, "M3-SUMMARY.json"), "w"),
              indent=2, default=str)
    print("== M3 %s — artifacts in %s ==" % ("PASS" if ok else "FAIL",
                                             RESULTS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

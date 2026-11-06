"""run_m1.py — M1 exit validation: the ledger generates, the driver drives.

M1 exit criteria (ROADMAP, measured on Freightlane):
  E1  Freightlane GV-4 (payout settle TOCTOU) autonomous, verified
  E2  Freightlane GV-5 (cancel-after-settle) autonomous, verified
  E3  markers_registered >= 2, every marker grounded (derived_from a board
      observation/surface fact) — no marker without a surface fact (E6)
  E4  no false positive on the decoys (D-1 claim race stays clean)
  E5  regression: dvlba-shop seed classes B1..B8 still hit from this tree
      (run_m0.py remains the full two-lab regression harness)

Protocol mirrors M0: run1 fresh memory, run2 with run1's memory namespaces,
real HTTP, loopback only, STOP kill files, full traffic provenance.

Ground truth keys (freightlane/target/app.py docstrings + GAP-PROOF §1):
  GV-4  keyed by FW-TOCTOU-SETTLE or (negative balance AND payout/settle)
  GV-5  keyed by FW-SETTLED-CANCEL or (payouts cancel AND settle refund)
  GV-7  keyed by FW-ROUND-DRIFT
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

RESULTS = os.path.join(HERE, "m1-results")


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
    fd_all = json.dumps(fd, default=str).lower()
    if fid == "FW-TOCTOU-SETTLE" or \
            ("negative" in fd_all and ("payout" in fd_all or
                                       "settle" in fd_all)):
        return "GV-4"
    if fid == "FW-SETTLED-CANCEL" or \
            ("payouts" in fd_all and "cancel" in fd_all and
             ("settle" in fd_all or "refund" in fd_all)):
        return "GV-5"
    if fid == "FW-ROUND-DRIFT" or ("drift" in fd_all and "cycle" in fd_all):
        return "GV-7"
    if fid == "FW-QUOTA-RACE":
        return "D-1"                       # claim decoy: FALSE POSITIVE
    return None


def score_runs(docs):
    """docs: {label: findings_doc}. Returns hits (GV ids with a verified
    finding in any run), false positives (decoy-keyed findings), and the
    per-run finding lists."""
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
        per_run[label] = run_gvs
    return hits, fps, per_run


def run_lab(label, app_dir, port, budget, runs):
    """runs: list of (out_name, memory_from_name_or_None)."""
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
            print("  [%s] %s req, %s findings, wall %.1fs, markers %s"
                  % (out_name, summary["requests"],
                     len(summary["findings"]), summary["wall_s"],
                     summary.get("markers_registered")))
        finally:
            proc.terminate()
    return summaries, docs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8465)
    ap.add_argument("--budget", type=int, default=320)
    ap.add_argument("--with-dvlba", action="store_true",
                    help="also run the dvlba regression (E5)")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "exit": {}}

    print("== lab: freightlane (M1 exit) ==")
    summaries, docs = run_lab("freightlane", FREIGHTLANE, args.port,
                              args.budget,
                              runs=[("run1", None), ("run2", "run1")])
    hits, fps, per_run = score_runs(docs)
    markers = []
    for name in ("run1", "run2"):
        led_path = os.path.join(RESULTS, "freightlane", name,
                                "hypothesis_ledger.json")
        if os.path.exists(led_path):
            led = json.load(open(led_path))
            marks = [e for e in led["entries"] if e["tag"] == "marker"]
            markers.append({"run": name, "markers": len(marks),
                            "grounded": all(e["derived_from"] for e in marks),
                            "confirmed": sum(1 for e in marks
                                             if e["status"] == "confirmed"),
                            "refuted": sum(1 for e in marks
                                           if e["status"] == "refuted")})
    print("  hits: %s | decoy FPs: %d | markers: %s"
          % (",".join(sorted(hits)) or "none", len(fps),
             json.dumps(markers)))

    m1 = summaries["run1"]
    c1 = "GV-4" in hits
    c2 = "GV-5" in hits
    c3 = m1.get("markers_registered", 0) >= 2 and \
        all(m["grounded"] for m in markers)
    c4 = not fps
    c5 = len(m1.get("llm_seam_calls") or []) == 0   # M1 stays deterministic
    report["exit"] = {
        "gv_hits": sorted(hits), "per_run": per_run,
        "decoy_false_positives": fps, "markers": markers,
        "requests_run1": m1["requests"], "requests_run2":
            summaries["run2"]["requests"],
        "rounds_run1": m1["rounds"],
        "llm_seam_calls": len(m1.get("llm_seam_calls") or [])}
    report["labs"] = {"freightlane": report["exit"]}

    if args.with_dvlba:
        print("== regression: dvlba-shop ==")
        import dvlba_ground_truth as dgt
        summaries_d, docs_d = run_lab("dvlba", HERE, args.port + 1, 380,
                                      runs=[("run1", None),
                                            ("run2", "run1")])
        scoring = dgt.score_runs([("run1", docs_d["run1"]),
                                  ("run2", docs_d["run2"])])
        report["labs"]["dvlba"] = {"seeds_hit": sorted(scoring["hits"]),
                                   "false_positives":
                                       scoring["false_positives"]}
        print("  seed classes hit: %s | FP: %d"
              % (",".join(sorted(scoring["hits"])),
                 len(scoring["false_positives"])))

    print("== M1 exit criteria ==")
    checks = [
        ("E1 GV-4 settle TOCTOU autonomous+verified", c1),
        ("E2 GV-5 cancel-after-settle autonomous+verified", c2),
        ("E3 markers >= 2, all grounded", c3),
        ("E4 zero decoy false positives", c4),
        ("E5 deterministic M1 (llm_seam_calls == 0)", c5)]
    if args.with_dvlba:
        d = report["labs"].get("dvlba", {})
        checks.append(("E6 dvlba B1..B8 regression (got %s)"
                       % ",".join(d.get("seeds_hit", [])) or "none",
                       set("B%d" % i for i in range(1, 9)) <=
                       set(d.get("seeds_hit", []))))
    ok = True
    for name, passed in checks:
        ok &= passed
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
    report["pass"] = bool(ok)
    json.dump(report, open(os.path.join(RESULTS, "M1-SUMMARY.json"), "w"),
              indent=2, default=str)
    print("== M1 %s — artifacts in %s ==" % ("PASS" if ok else "FAIL",
                                             RESULTS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

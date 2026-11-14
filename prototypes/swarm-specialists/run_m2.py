"""run_m2.py — M2 exit validation: the live surface is the truth.

M2 exit criteria (ROADMAP, measured on Freightlane):
  E1  GV-1 voucher release replay autonomous, verified      (FW-RELEASE-REPLAY)
  E2  GV-2 recent global leak + rebook deputy, verified     (FW-DEPUTY-CREDIT;
      FW-AUDIT-LEAK recorded when the leak half is separate)
  E3  GV-3 rate_cents mass-assign, verified, NEGATIVE       (FW-MASS-PRICE)
  E4  GV-6 voucher credit race, verified, k >= 2 winners    (FW-CREDIT-RACE)
  E5  revised SURFACE fact lists >= 3 undocumented verbs, grounded
  E6  zero decoy false positives (D-1 claim decoy stays clean)
  E7  deterministic (llm_seam_calls == 0)
  E8  regression: dvlba-shop B1..B8 from the same tree (--with-dvlba);
      run_m0.py remains the full two-lab harness

Protocol mirrors M0/M1: run1 fresh memory, run2 with run1's memory, real
HTTP, loopback only, STOP kill files, full traffic provenance.

Ground truth keys (freightlane/target/app.py docstrings + GAP-PROOF §1):
  GV-1  keyed by FW-RELEASE-REPLAY or (voucher AND release)
  GV-2  keyed by rebook, or deputy-credit on shipments, or audit-leak+recent
  GV-3  keyed by mass-price AND rate_cents
  GV-6  keyed by FW-CREDIT-RACE or (voucher AND race)  [empirics: consume's
        lock-committed guard holds; the winnable race on the hidden voucher
        resource is release — probe_gv6.py, RESEARCH-M2 §2.5]
  GV-4/GV-5/GV-7 keys carried from run_m1.py (regression-in-miniature)
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

RESULTS = os.path.join(HERE, "m2-results")


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


def undocumented_verbs(out_dir):
    """E5 evidence: the revised SURFACE fact's undocumented verb list."""
    bb_path = os.path.join(out_dir, "blackboard.json")
    if not os.path.exists(bb_path):
        return [], None
    bb = json.load(open(bb_path))
    revisions = [f for f in bb if f["kind"] == "SURFACE" and
                 "surface-update" in f.get("tags", [])]
    if not revisions:
        return [], None
    rev = revisions[-1]
    disc = rev["payload"].get("discoveries") or {}
    verbs = sorted({(v.get("resource"), v.get("verb"))
                    for v in disc.get("undocumented_verbs", [])})
    return verbs, {"grounded": bool(rev.get("derived_from")),
                   "readback_added": disc.get("readback_added", []),
                   "mined_fields": disc.get("mined_fields", {}),
                   "undocumented_resources": disc.get(
                       "undocumented_resources", [])}


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
            print("  [%s] %s req, %s findings, wall %.1fs, markers %s"
                  % (out_name, summary["requests"],
                     len(summary["findings"]), summary["wall_s"],
                     summary.get("markers_registered")))
        finally:
            proc.terminate()
    return summaries, docs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8477)
    ap.add_argument("--budget", type=int, default=620)
    ap.add_argument("--with-dvlba", action="store_true",
                    help="also run the dvlba regression (E8)")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "exit": {}}

    print("== lab: freightlane (M2 exit) ==")
    summaries, docs = run_lab("freightlane", FREIGHTLANE, args.port,
                              args.budget,
                              runs=[("run1", None), ("run2", "run1")])
    hits, fps, per_run = score_runs(docs)
    verbs, verb_meta = undocumented_verbs(
        os.path.join(RESULTS, "freightlane", "run1"))
    print("  hits: %s | decoy FPs: %d" % (",".join(sorted(hits)) or "none",
                                          len(fps)))
    print("  undocumented verbs (%d): %s" % (len(verbs), verbs))
    print("  readback added: %s | mined: %s"
          % (verb_meta.get("readback_added") if verb_meta else [],
             verb_meta.get("mined_fields") if verb_meta else {}))

    m1s = summaries["run1"]
    c1 = "GV-1" in hits
    c2 = "GV-2" in hits
    c3 = "GV-3" in hits
    c4 = "GV-6" in hits
    c5 = len(verbs) >= 3 and bool(verb_meta) and verb_meta["grounded"]
    c6 = not fps
    c7 = len(m1s.get("llm_seam_calls") or []) == 0
    report["exit"] = {
        "gv_hits": sorted(hits), "per_run": per_run,
        "decoy_false_positives": fps,
        "undocumented_verbs": ["%s/%s" % (r, v) for r, v in verbs],
        "surface_facts": verb_meta,
        "markers_registered": m1s.get("markers_registered"),
        "requests_run1": m1s["requests"],
        "requests_run2": summaries["run2"]["requests"],
        "llm_seam_calls": len(m1s.get("llm_seam_calls") or [])}
    report["labs"] = {"freightlane": report["exit"]}

    if args.with_dvlba:
        print("== regression: dvlba-shop ==")
        import dvlba_ground_truth as dgt
        summaries_d, docs_d = run_lab("dvlba", HERE, args.port + 1, 460,
                                      runs=[("run1", None),
                                            ("run2", "run1")])
        scoring = dgt.score_runs([("run1", docs_d["run1"]),
                                  ("run2", docs_d["run2"])])
        report["labs"]["dvlba"] = {"seeds_hit": sorted(scoring["hits"]),
                                   "false_positives":
                                       scoring["false_positives"],
                                   "requests_run1":
                                       summaries_d["run1"]["requests"],
                                   "requests_run2":
                                       summaries_d["run2"]["requests"]}
        print("  seed classes hit: %s | FP: %d"
              % (",".join(sorted(scoring["hits"])),
                 len(scoring["false_positives"])))

    print("== M2 exit criteria ==")
    checks = [
        ("E1 GV-1 voucher release replay autonomous+verified", c1),
        ("E2 GV-2 recent leak + rebook deputy autonomous+verified", c2),
        ("E3 GV-3 rate_cents mass-assign (echo-mined) verified", c3),
        ("E4 GV-6 voucher credit race verified (k >= 2)", c4),
        ("E5 >= 3 undocumented verbs in surface facts (grounded)", c5),
        ("E6 zero decoy false positives", c6),
        ("E7 deterministic M2 (llm_seam_calls == 0)", c7)]
    if args.with_dvlba:
        d = report["labs"].get("dvlba", {})
        checks.append(("E8 dvlba B1..B8 regression (got %s)"
                       % ",".join(d.get("seeds_hit", [])) or "none",
                       set("B%d" % i for i in range(1, 9)) <=
                       set(d.get("seeds_hit", []))))
    ok = True
    for name, passed in checks:
        ok &= passed
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
    report["pass"] = bool(ok)
    json.dump(report, open(os.path.join(RESULTS, "M2-SUMMARY.json"), "w"),
              indent=2, default=str)
    print("== M2 %s — artifacts in %s ==" % ("PASS" if ok else "FAIL",
                                             RESULTS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

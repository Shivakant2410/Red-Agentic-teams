"""run_m0.py — M0 exit validation: BOTH labs green from ONE tree.

The promoted tree (this directory) must reproduce, unmodified:
  * meridian-vault  (../hard-lab/target/app.py)  >= 8 verified findings,
    seeds S1..S7 hit, zero false positives  — the Phase-D proven baseline;
  * dvlba-shop      (./target/app.py)            all 8 seed classes B1..B8
    — the Phase B/C baseline the spine must not regress.

Protocol per lab mirrors the proven Phase-D protocol: run1 fresh memory,
run2 NEW server with the SAME memory namespaces (adaptation measured),
HypothesisLedger projection per run (now inside swarm.run itself — the M0
seam), scoring against each lab's ground truth.

Scope discipline: loopback only, fail-closed scope guards, STOP kill files,
per-probe fresh principals, traffic.jsonl provenance for every exchange.
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
HARDLAB = os.path.normpath(os.path.join(HERE, "..", "hard-lab"))
sys.path.insert(0, HERE)

RESULTS = os.path.join(HERE, "m0-results")


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


def run_lab(label, app_dir, port, budget, runs, artifacts, deferred_hits):
    """runs: list of (out_name, memory_from_name_or_None). Returns
    (summaries, run_docs). Each run's spine artifacts (hypothesis_ledger.json)
    are written by swarm.run itself — the M0 seam."""
    import swarm  # the ONE promoted tree
    out_root = fresh_dir(os.path.join(RESULTS, label))
    summaries, run_docs = {}, {}
    for out_name, mem_from in runs:
        out_dir = os.path.join(out_root, out_name)
        fresh_dir(out_dir)
        if mem_from:
            memory_dir = os.path.join(out_root, mem_from, "memory")
        else:
            memory_dir = os.path.join(out_dir, "memory")
        os.makedirs(memory_dir, exist_ok=True)
        proc, base = spawn(app_dir, port)
        try:
            t0 = time.time()
            summary = swarm.build_registry()["swarm_run"]["run"]({
                "base_url": base, "out_dir": out_dir,
                "memory_dir": memory_dir, "approvals": "lab",
                "budget": budget, "artifacts": dict(artifacts or {}),
                "deferred_hits": deferred_hits,
                "stop_file": os.path.join(out_dir, "STOP")})
            summary["wall_s"] = round(time.time() - t0, 1)
            summaries[out_name] = summary
            run_docs[out_name] = load_doc(os.path.join(out_dir,
                                                       "findings.json"))
            print("  [%s/%s] %s req, %s findings, wall %.1fs, ledger %s"
                  % (label, out_name, summary["requests"],
                     len(summary["findings"]), summary["wall_s"],
                     (summary.get("hypothesis_ledger") or {})
                     .get("stats", {}).get("total", "off")))
        finally:
            proc.terminate()
    return summaries, run_docs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-meridian", type=int, default=8461)
    ap.add_argument("--port-dvlba", type=int, default=8462)
    ap.add_argument("--skip-meridian", action="store_true")
    ap.add_argument("--skip-dvlba", action="store_true")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "labs": {}}

    # ------------------------------------------------------- meridian ------
    if not args.skip_meridian:
        print("== lab A: meridian-vault (hard lab) ==")
        # import by path: NEVER put hard-lab/ on sys.path — its swarm/statefuzz
        # packages would shadow the promoted tree under test.
        import importlib.util
        _spec = importlib.util.spec_from_file_location(
            "meridian_ground_truth", os.path.join(HARDLAB, "ground_truth.py"))
        gt = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(gt)
        def meridian_deferred(fd_list):
            out = []
            for f in fd_list:
                seeds, _ = gt.classify(f["finding"], f["status"])
                if any(s in ("S2", "S3") for s in seeds):
                    out.append(f["finding"].get("id", "?"))
            return out
        summaries, docs = run_lab(
            "meridian", HARDLAB, args.port_meridian, budget=560,
            runs=[("run1", None), ("run2", "run1")],
            artifacts={"promo_code": "MERIDIAN-DROP"},
            deferred_hits=meridian_deferred)
        scoring = gt.score_runs([("run1", docs["run1"]),
                                 ("run2", docs["run2"])])
        verified = [f for lbl in docs
                    for f in docs[lbl].get("findings", [])
                    if str(f.get("status", "")).startswith("verified")]
        report["labs"]["meridian"] = {
            "summaries": {k: {kk: vv for kk, vv in v.items()
                              if kk != "trace_file"}
                          for k, v in summaries.items()},
            "scoring": scoring,
            "verified_findings": len(verified),
            "seeds_hit": sorted(scoring["hits"]),
            "false_positives": scoring["false_positives"]}
        print("  seeds hit: %s  | verified findings: %d | FP: %d"
              % (",".join(sorted(scoring["hits"])), len(verified),
                 len(scoring["false_positives"])))

    # --------------------------------------------------------- dvlba -------
    if not args.skip_dvlba:
        print("== lab B: dvlba-shop (baseline) ==")
        import dvlba_ground_truth as dgt
        def dvlba_deferred(fd_list):
            out = []
            for f in fd_list:
                seeds, _ = dgt.classify(f["finding"], f["status"])
                if "B8" in seeds:
                    out.append(f["finding"].get("id", "?"))
            return out
        summaries, docs = run_lab(
            "dvlba", HERE, args.port_dvlba, budget=380,
            runs=[("run1", None), ("run2", "run1")],
            artifacts={}, deferred_hits=dvlba_deferred)
        scoring = dgt.score_runs([("run1", docs["run1"]),
                                  ("run2", docs["run2"])])
        report["labs"]["dvlba"] = {
            "summaries": {k: {kk: vv for kk, vv in v.items()
                              if kk != "trace_file"}
                          for k, v in summaries.items()},
            "scoring": scoring,
            "seeds_hit": sorted(scoring["hits"]),
            "false_positives": scoring["false_positives"]}
        print("  seed classes hit: %s  | FP: %d"
              % (",".join(sorted(scoring["hits"])),
                 len(scoring["false_positives"])))

    # ------------------------------------------------------ exit criteria --
    print("== M0 exit criteria ==")
    checks = []
    if "meridian" in report["labs"]:
        m = report["labs"]["meridian"]
        c1 = m["verified_findings"] >= 8
        c2 = set(("S%d" % i) for i in range(1, 8)) <= set(m["seeds_hit"])
        c3 = not m["false_positives"]
        checks += [("meridian verified findings >= 8 (got %d)"
                    % m["verified_findings"], c1),
                   ("meridian seeds S1..S7 all hit (got %s)"
                    % ",".join(m["seeds_hit"]) or "none", c2),
                   ("meridian zero false positives", c3)]
    if "dvlba" in report["labs"]:
        d = report["labs"]["dvlba"]
        c4 = set(("B%d" % i) for i in range(1, 9)) <= set(d["seeds_hit"])
        checks += [("dvlba seed classes B1..B8 all hit (got %s)"
                    % ",".join(d["seeds_hit"]) or "none", c4)]
    ok = True
    for name, passed in checks:
        ok &= passed
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
    report["pass"] = bool(ok)
    json.dump(report, open(os.path.join(RESULTS, "M0-SUMMARY.json"), "w"),
              indent=2, default=str)
    print("== M0 %s — artifacts in %s ==" % ("PASS" if ok else "FAIL",
                                             RESULTS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

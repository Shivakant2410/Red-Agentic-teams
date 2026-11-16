"""run_m4.py — M4 exit validation: the seams are real, the contract holds.

M4 exit criteria (ROADMAP G5 + RESEARCH-M4.md R5, measured on the labs):
  E1  freightlane run1 through the REGISTRY path: GV-1..GV-8 all verified,
      zero decoy FPs, llm_seam_calls == 0, markers >= 2   (M3 invariants hold)
  E2  freightlane run2 through the ORCHESTRATOR path (run1's memory):
      same 8 GVs — "same schema() + run(ctx) contract served by both",
      on a live hard lab, not a unit test
  E3  policy artifacts: policy_audit.jsonl with every decision recorded;
      lab mode denies nothing (denials == 0)
  E4  refusal control (approvals="none"): the gate denies write mutants
      BEFORE any socket opens, zero verified findings ship, the run still
      completes — the charter's owed refusal case, now an artifact
  E5  verify pipeline: report present in both summaries; downgrades
      reported honestly (expected 0 on green labs)
  E6  schema identity: Orchestrator.schema() == registry _schema()
  E7  (--with-dvlba) dvlba B1..B8 + zero unmatched through the same path

Memory non-regression (P6) is reported, not gated: run-2 request count vs
run-1 (the >= +20% AWM-shaped improvement claim is M5's to measure).
"""
import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FREIGHTLANE = os.path.normpath(os.path.join(HERE, "..", "hard-lab",
                                            "freightlane"))
sys.path.insert(0, HERE)

from run_m3 import spawn, fresh_dir, load_doc, classify_gv, score_runs  # noqa
import swarm                                                             # noqa
from swarm.orchestrator import Orchestrator                              # noqa
from swarm.registry_tool import _schema as reg_schema                    # noqa

RESULTS = os.path.join(HERE, "m4-results")

GV_ALL = {"GV-%d" % i for i in range(1, 9)}


def run_one(out_root, out_name, mem_from, approvals, budget, port,
            via="registry"):
    """One freightlane engagement. via='registry' -> registry path;
    via='orchestrator' -> direct Orchestrator (same code, both serve)."""
    out_dir = os.path.join(out_root, out_name)
    fresh_dir(out_dir)
    memory_dir = os.path.join(out_root, mem_from, "memory") if mem_from \
        else os.path.join(out_dir, "memory")
    os.makedirs(memory_dir, exist_ok=True)
    proc, base = spawn(FREIGHTLANE, port)
    try:
        ctx = {"base_url": base, "out_dir": out_dir,
               "memory_dir": memory_dir, "approvals": approvals,
               "budget": budget,
               "stop_file": os.path.join(out_dir, "STOP")}
        t0 = time.time()
        if via == "registry":
            summary = swarm.build_registry()["swarm_run"]["run"](ctx)
        else:
            summary = Orchestrator().run(ctx)
        summary["wall_s"] = round(time.time() - t0, 1)
        summary["_out_dir"] = out_dir
        return summary
    finally:
        proc.terminate()


def gv_status(doc):
    """{gv: status} for ground-truth-classified findings of one run doc."""
    out = {}
    for e in doc.get("findings", []):
        fd = dict(e.get("finding", {}), _status=e.get("status"))
        gv = classify_gv(fd)
        if gv and gv != "D-1":
            out[gv] = e.get("status")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8489)
    ap.add_argument("--budget", type=int, default=720)
    ap.add_argument("--neg-budget", type=int, default=240)
    ap.add_argument("--with-dvlba", action="store_true")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "exit": {}}
    fresh_dir(RESULTS)

    # ------------------------------------------------------------- E6 --
    e6 = Orchestrator.schema() == reg_schema()
    report["exit"]["schema_identical"] = e6
    print("== E6 schema identity: %s ==" % ("PASS" if e6 else "FAIL"))

    # -------------------------------------- E1/E2/E3/E5: freightlane ----
    print("== lab: freightlane via REGISTRY path (run1) ==")
    s1 = run_one(RESULTS, "run1", None, "lab", args.budget, args.port,
                 via="registry")
    d1 = load_doc(os.path.join(s1["_out_dir"], "findings.json"))
    print("  [%s] req %s, findings %d, wall %.1fs, markers %s"
          % ("run1", s1["requests"], len(s1["findings"]), s1["wall_s"],
             s1.get("markers_registered")))

    print("== lab: freightlane via ORCHESTRATOR path (run2, run1 memory) ==")
    s2 = run_one(RESULTS, "run2", "run1", "lab", args.budget, args.port,
                 via="orchestrator")
    d2 = load_doc(os.path.join(s2["_out_dir"], "findings.json"))
    print("  [%s] req %s, findings %d, wall %.1fs, markers %s"
          % ("run2", s2["requests"], len(s2["findings"]), s2["wall_s"],
             s2.get("markers_registered")))

    hits1, fps1, per1 = score_runs({"run1": d1})
    hits2, fps2, per2 = score_runs({"run2": d2})
    st1, st2 = gv_status(d1), gv_status(d2)
    print("  run1 hits: %s | run2 hits: %s | decoy FPs: %d/%d"
          % (",".join(sorted(hits1)) or "none", ",".join(sorted(hits2))
             or "none", len(fps1), len(fps2)))

    audits_ok = all(
        os.path.exists(os.path.join(s["_out_dir"], "policy_audit.jsonl"))
        for s in (s1, s2))
    lab_denials = (s1.get("policy", {}).get("denied", -1),
                   s2.get("policy", {}).get("denied", -1))
    pipeline_ok = ("verify_pipeline" in s1) and ("verify_pipeline" in s2)
    downgrades = [s1["verify_pipeline"].get("downgrades"),
                  s2["verify_pipeline"].get("downgrades")]

    report["exit"]["freightlane"] = {
        "run1_path": "registry", "run2_path": "orchestrator",
        "gv_run1": st1, "gv_run2": st2,
        "hits_run1": sorted(hits1), "hits_run2": sorted(hits2),
        "per_run": {"run1": per1.get("run1"), "run2": per2.get("run2")},
        "decoy_false_positives": fps1 + fps2,
        "markers_registered": s1.get("markers_registered"),
        "llm_seam_calls": len(s1.get("llm_seam_calls") or []),
        "requests_run1": s1["requests"], "requests_run2": s2["requests"],
        "wall_run1": s1["wall_s"], "wall_run2": s2["wall_s"],
        "policy_audit_present": audits_ok,
        "policy_denied_lab_mode": lab_denials,
        "policy_stats_run1": s1.get("policy"),
        "verify_pipeline_run1": s1.get("verify_pipeline"),
        "verify_pipeline_run2": s2.get("verify_pipeline"),
        "experience_store": s2.get("experience_store"),
        "memory_nonregression_P6": {
            "run1": s1["requests"], "run2": s2["requests"],
            "not_worse_than_115pct": s2["requests"] <=
            s1["requests"] * 1.15}}
    print("  policy audits: %s | lab-mode denials: %s | pipeline reports: "
          "%s (downgrades %s)" % (audits_ok, lab_denials, pipeline_ok,
                                  downgrades))

    # ------------------------------------------- E4: refusal control ----
    print("== negative control: approvals=none (refusal mode) ==")
    sn = run_one(RESULTS, "refusal-control", None, "none", args.neg_budget,
                 args.port + 2, via="orchestrator")
    dn = load_doc(os.path.join(sn["_out_dir"], "findings.json"))
    stn = gv_status(dn)
    verified_n = [g for g, st in stn.items() if str(st).startswith("verified")]
    denials = sn.get("policy", {}).get("denied", 0)
    traffic_denied = 0
    tpath = os.path.join(sn["_out_dir"], "traffic.jsonl")
    if os.path.exists(tpath):
        with open(tpath) as fh:
            traffic_denied = sum(1 for l in fh
                                 if '"policy_denied": true' in l)
    e4 = (not verified_n) and denials > 0 and sn.get("ok") is True
    print("  req %s (budget %s), denials %d (traffic-confirmed %d), "
          "verified findings %d, completed %s"
          % (sn["requests"], args.neg_budget, denials, traffic_denied,
             len(verified_n), sn.get("ok")))
    report["exit"]["refusal_control"] = {
        "requests": sn["requests"], "budget": args.neg_budget,
        "policy_denied": denials, "traffic_confirmed_denials":
            traffic_denied,
        "verified_findings": sorted(verified_n),
        "gv_seen": stn, "completed": bool(sn.get("ok")),
        "policy_stats": sn.get("policy"),
        "verify_pipeline": sn.get("verify_pipeline")}

    # -------------------------------------------- E7: dvlba regression --
    if args.with_dvlba:
        print("== regression: dvlba-shop (registry path) ==")
        import dvlba_ground_truth as dgt
        dvl_root = fresh_dir(os.path.join(RESULTS, "dvlba"))
        d_sum, d_docs = {}, {}
        for out_name, mem_from in (("run1", None), ("run2", "run1")):
            out_dir = os.path.join(dvl_root, out_name)
            fresh_dir(out_dir)
            memory_dir = os.path.join(dvl_root, mem_from, "memory") \
                if mem_from else os.path.join(out_dir, "memory")
            os.makedirs(memory_dir, exist_ok=True)
            proc, base = spawn(HERE, args.port + 4)
            try:
                t0 = time.time()
                sd = swarm.build_registry()["swarm_run"]["run"]({
                    "base_url": base, "out_dir": out_dir,
                    "memory_dir": memory_dir, "approvals": "lab",
                    "budget": 540,
                    "stop_file": os.path.join(out_dir, "STOP")})
                sd["wall_s"] = round(time.time() - t0, 1)
                d_sum[out_name] = sd
                d_docs[out_name] = load_doc(
                    os.path.join(out_dir, "findings.json"))
                print("  [%s] req %s, findings %d, wall %.1fs"
                      % (out_name, sd["requests"],
                         len(sd["findings"]), sd["wall_s"]))
            finally:
                proc.terminate()
        scoring = dgt.score_runs([("run1", d_docs["run1"]),
                                  ("run2", d_docs["run2"])])
        seeds_hit = sorted(scoring["hits"])
        unmatched = scoring["unmatched"]
        print("  seed classes hit: %s | unmatched: %d"
              % (",".join(seeds_hit) or "none", len(unmatched)))
        report["exit"]["dvlba"] = {
            "seeds_hit": seeds_hit, "false_positives":
                scoring["false_positives"],
            "unmatched": unmatched,
            "requests_run1": d_sum["run1"]["requests"],
            "requests_run2": d_sum["run2"]["requests"],
            "policy_denied": (d_sum["run1"].get("policy", {})
                              .get("denied"),
                              d_sum["run2"].get("policy", {}).get("denied"))}

    # ------------------------------------------------------- exit gate --
    e1 = GV_ALL <= set(g for g, st in st1.items()
                       if str(st).startswith("verified"))
    e2 = GV_ALL <= set(g for g, st in st2.items()
                       if str(st).startswith("verified"))
    e3 = audits_ok and all(d == 0 for d in lab_denials)
    e5 = pipeline_ok
    e6b = e6 and s2.get("experience_store") == "file-experience-store"

    checks = [
        ("E1 registry path: GV-1..8 verified, 0 FP, 0 LLM calls, "
         "markers>=2", e1 and not fps1 and
         len(s1.get("llm_seam_calls") or []) == 0 and
         (s1.get("markers_registered") or 0) >= 2),
        ("E2 orchestrator path: GV-1..8 verified (same contract served "
         "by both)", e2),
        ("E3 policy audit present; lab mode denies nothing", e3),
        ("E4 refusal control: writes denied pre-socket, 0 verified "
         "findings, run completes", e4),
        ("E5 verify pipeline report present in both paths", e5),
        ("E6 schema identity + file experience store", e6b)]
    if args.with_dvlba:
        d = report["exit"].get("dvlba", {})
        checks.append(("E7 dvlba B1..B8 + zero unmatched (got %s | "
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
    json.dump(report, open(os.path.join(RESULTS, "M4-SUMMARY.json"), "w"),
              indent=2, default=str)
    print("== M4 %s — artifacts in %s ==" % ("PASS" if ok else "FAIL",
                                             RESULTS))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""run_m5.py — M5 exit validation: the offensive core (recon -> surface map
-> pre-ex -> post-ex), measured on the labs against RESEARCH-M5's
pre-registered predictions. Research BEFORE code: RESEARCH-M5.md (XBOW /
PentestGPT / HackingBuddyGPT / CALDERA competitor scan; Manadhata-Wing /
Sarraute / BloodHound / Arjun paper lineage; four-lens review; verdict
table). The M4 guard seam is archived plumbing — this milestone spends its
budget on attack skill only.

Predictions (scored honestly, artifacts under m5-results/):
  P1  pre-ex evidence loop — freightlane run1 publishes an authz-matrix
      OBSERVATION whose evidence raises a preex-origin h_cross_tenant
      HYPOTHESIS (derived_from the matrix fact); the exploit specialist is
      dispatched on that hypothesis; and a cross-tenant-class finding
      verifies in the same run.
  P2  recon discovers >= 1 endpoint NOT in the generic PROBE_PATHS list and
      NOT in the served openapi/route index — asset-mining or
      derived-content-discovery origin, tagged, probe visible in traffic.
  P3  pre-ex costs <= 70 requests on freightlane run1; whole run stays
      <= 1.35x the M4 request baseline (616 -> <= 832) at budget 900.
  P4  post-ex publishes >= 1 amplification ESCALATION with a measured
      aggregate delta across >= 2 victim objects on a VERIFIED finding.
  P5  non-regression: GV-1..8 verified in run1 AND run2 (run2 = orchestrator
      path on run1's memory), zero decoy FPs, dvlba B1..B8 with zero
      unmatched, deterministic path llm_seam_calls == 0, markers >= 2,
      schema identity Orchestrator == registry.
"""
import argparse
import json
import os
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
from swarm.specialists.recon import PROBE_PATHS                          # noqa

RESULTS = os.path.join(HERE, "m5-results")
GV_ALL = {"GV-%d" % i for i in range(1, 9)}
M4_BASELINE_REQUESTS = 616


def run_one(out_root, out_name, mem_from, budget, port, via="registry"):
    out_dir = os.path.join(out_root, out_name)
    fresh_dir(out_dir)
    memory_dir = os.path.join(out_root, mem_from, "memory") if mem_from \
        else os.path.join(out_dir, "memory")
    os.makedirs(memory_dir, exist_ok=True)
    proc, base = spawn(FREIGHTLANE, port)
    try:
        ctx = {"base_url": base, "out_dir": out_dir,
               "memory_dir": memory_dir, "approvals": "lab",
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
    out = {}
    for e in doc.get("findings", []):
        fd = dict(e.get("finding", {}), _status=e.get("status"))
        gv = classify_gv(fd)
        if gv and gv != "D-1":
            out[gv] = e.get("status")
    return out


def load_board(out_dir):
    p = os.path.join(out_dir, "blackboard.json")
    return json.load(open(p)) if os.path.exists(p) else []


def load_traffic(out_dir):
    p = os.path.join(out_dir, "traffic.jsonl")
    rows = []
    if os.path.exists(p):
        with open(p) as fh:
            for line in fh:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def score_p1(board, hits_run1, out_dir):
    """matrix OBSERVATION -> preex-origin hypothesis -> exploit dispatch
    -> cross-tenant-class verification."""
    matrix = [f for f in board if f.get("kind") == "OBSERVATION" and
              "px_authz_matrix" in (f.get("tags") or [])]
    if not matrix:
        return False, {"reason": "no authz-matrix observation"}
    mx = matrix[-1]
    hyps = [f for f in board if f.get("kind") == "HYPOTHESIS" and
            (f.get("payload") or {}).get("origin") == "preex" and
            (f.get("payload") or {}).get("tag") == "h_cross_tenant" and
            mx["id"] in (f.get("derived_from") or [])]
    detail = {"matrix_fact": mx["id"],
              "bola_hits": mx["payload"].get("bola_hits"),
              "evidence_raised": bool(hyps)}
    if not hyps:
        return False, detail
    hyp = hyps[-1]
    trace_path = os.path.join(out_dir, "dispatch_trace.jsonl")
    dispatched = False
    if os.path.exists(trace_path):
        with open(trace_path) as fh:
            for line in fh:
                if hyp["id"] in line and '"specialist": "exploit"' in line:
                    dispatched = True
                    break
    detail["hypothesis_fact"] = hyp["id"]
    detail["prior"] = hyp["payload"].get("prior")
    detail["dispatched_to_exploit"] = dispatched
    detail["cross_tenant_class_verified"] = "GV-2" in hits_run1
    return bool(dispatched and "GV-2" in hits_run1), detail


def score_p2(board, traffic):
    """>=1 discovered endpoint outside PROBE_PATHS and outside the served
    disclosure (openapi paths + route index), tagged with its origin, with
    the probe visible in traffic."""
    disclosed = set(PROBE_PATHS)
    for f in board:
        pl = f.get("payload") or {}
        if "openapi" in (f.get("tags") or []):
            disclosed.update(pl.get("openapi_paths") or [])
        elif "route-index" in (f.get("tags") or []):
            disclosed.update(pl.get("resources") or [])
    recon_paths = {r["path"] for r in traffic if r.get("phase") == "recon"}
    found = []
    for f in board:
        tags = f.get("tags") or []
        pl = f.get("payload") or {}
        if "derived-content-discovery" in tags:
            for h in (pl.get("derived_probes") or {}).get("hits", []):
                found.append({"path": h["path"], "status": h["status"],
                              "signal": h.get("signal"),
                              "origin": "derived-content-discovery"})
        if "asset-mining" in tags:
            for p2 in pl.get("asset_endpoints") or []:
                found.append({"path": p2, "status": "mined",
                              "signal": "asset-string",
                              "origin": "asset-mining"})
    novel = [x for x in found if x["path"] not in disclosed]
    detail = {"discovered": novel,
              "probe_on_wire": [x for x in novel if x["path"] in
                                recon_paths]}
    return bool(novel) and bool(detail["probe_on_wire"]), detail


def score_p3(traffic, s1):
    preex_reqs = [r for r in traffic if r.get("phase") == "preex"]
    total = s1.get("requests", 0)
    detail = {"preex_requests": len(preex_reqs), "total_requests": total,
              "budget_cap": 900, "ceiling": int(M4_BASELINE_REQUESTS *
                                                1.35)}
    return len(preex_reqs) <= 70 and total <= detail["ceiling"], detail


def score_p4(board):
    amps = []
    for f in board:
        if f.get("kind") != "ESCALATION" or \
                "postex" not in (f.get("tags") or []):
            continue
        pl = f.get("payload") or {}
        amp = (pl.get("postex") or {}).get("amplification") or {}
        if amp:
            amps.append({"technique": pl.get("technique"),
                         "victims_reached": amp.get("victims_reached"),
                         "aggregate_delta_cents":
                             amp.get("aggregate_delta_cents"),
                         "variant": amp.get("variant"),
                         "rows": amp.get("rows")})
    ok = any(a.get("victims_reached", 0) >= 2 and
             a.get("aggregate_delta_cents") for a in amps)
    return ok, {"amplifications": amps}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8495)
    ap.add_argument("--budget", type=int, default=900)
    ap.add_argument("--dvlba-budget", type=int, default=540)
    ap.add_argument("--skip-dvlba", action="store_true")
    args = ap.parse_args()

    report = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "tree": HERE, "predictions": {}}
    fresh_dir(RESULTS)

    print("== schema identity ==")
    e_schema = Orchestrator.schema() == reg_schema()
    print("  [%s]" % ("PASS" if e_schema else "FAIL"))

    print("== lab: freightlane run1 (registry path, budget %d) ==" %
          args.budget)
    s1 = run_one(RESULTS, "run1", None, args.budget, args.port)
    d1 = load_doc(os.path.join(s1["_out_dir"], "findings.json"))
    print("  req %s, findings %d, wall %.1fs, markers %s"
          % (s1["requests"], len(s1["findings"]), s1["wall_s"],
             s1.get("markers_registered")))

    print("== lab: freightlane run2 (orchestrator path, run1 memory) ==")
    s2 = run_one(RESULTS, "run2", "run1", args.budget, args.port + 1,
                 via="orchestrator")
    d2 = load_doc(os.path.join(s2["_out_dir"], "findings.json"))
    print("  req %s, findings %d, wall %.1fs"
          % (s2["requests"], len(s2["findings"]), s2["wall_s"]))

    hits1, fps1, per1 = score_runs({"run1": d1})
    hits2, fps2, per2 = score_runs({"run2": d2})
    st1, st2 = gv_status(d1), gv_status(d2)
    print("  run1 hits: %s | run2 hits: %s | decoy FPs: %d/%d"
          % (",".join(sorted(hits1)) or "none",
             ",".join(sorted(hits2)) or "none", len(fps1), len(fps2)))

    board1 = load_board(s1["_out_dir"])
    traffic1 = load_traffic(s1["_out_dir"])

    p1, p1d = score_p1(board1, hits1, s1["_out_dir"])
    print("  P1 pre-ex evidence loop: [%s] %s"
          % ("PASS" if p1 else "FAIL", json.dumps(p1d)[:220]))
    p2, p2d = score_p2(board1, traffic1)
    print("  P2 recon discovery: [%s] %s"
          % ("PASS" if p2 else "FAIL", json.dumps(p2d)[:220]))
    p3, p3d = score_p3(traffic1, s1)
    print("  P3 pre-ex budget: [%s] %s"
          % ("PASS" if p3 else "FAIL", json.dumps(p3d)))
    p4, p4d = score_p4(board1)
    print("  P4 post-ex amplification: [%s] %s"
          % ("PASS" if p4 else "FAIL", json.dumps(p4d)[:260]))

    p5_parts = {
        "gv_run1": GV_ALL <= set(g for g, st in st1.items()
                                 if str(st).startswith("verified")),
        "gv_run2": GV_ALL <= set(g for g, st in st2.items()
                                 if str(st).startswith("verified")),
        "no_decoy_fp": not fps1 and not fps2,
        "llm_seam_zero": len(s1.get("llm_seam_calls") or []) == 0,
        "markers_ge_2": (s1.get("markers_registered") or 0) >= 2,
        "schema_identity": e_schema,
    }
    p5 = all(p5_parts.values())
    print("  P5 non-regression: [%s] %s"
          % ("PASS" if p5 else "FAIL", json.dumps(p5_parts)))

    # ------------------------------------------------ dvlba regression --
    dvl = {}
    if not args.skip_dvlba:
        print("== regression: dvlba-shop (registry path, budget %d) ==" %
              args.dvlba_budget)
        import dvlba_ground_truth as dgt
        dvl_root = fresh_dir(os.path.join(RESULTS, "dvlba"))
        d_docs, d_reqs = {}, {}
        for out_name, mem_from in (("run1", None), ("run2", "run1")):
            out_dir = os.path.join(dvl_root, out_name)
            fresh_dir(out_dir)
            memory_dir = os.path.join(dvl_root, mem_from, "memory") \
                if mem_from else os.path.join(out_dir, "memory")
            os.makedirs(memory_dir, exist_ok=True)
            proc, base = spawn(HERE, args.port + 4)
            try:
                sd = swarm.build_registry()["swarm_run"]["run"]({
                    "base_url": base, "out_dir": out_dir,
                    "memory_dir": memory_dir, "approvals": "lab",
                    "budget": args.dvlba_budget,
                    "stop_file": os.path.join(out_dir, "STOP")})
                d_docs[out_name] = load_doc(
                    os.path.join(out_dir, "findings.json"))
                d_reqs[out_name] = sd.get("requests")
                print("  [%s] req %s, findings %d"
                      % (out_name, sd.get("requests"),
                         len(d_docs[out_name].get("findings", []))))
            finally:
                proc.terminate()
        scoring = dgt.score_runs([("run1", d_docs["run1"]),
                                  ("run2", d_docs["run2"])])
        seeds = sorted(scoring["hits"])
        unmatched = scoring["unmatched"]
        print("  seed classes: %s | unmatched: %d"
              % (",".join(seeds) or "none", len(unmatched)))
        dvl = {"seeds_hit": seeds, "unmatched": unmatched,
               "false_positives": scoring["false_positives"],
               "requests": d_reqs,
               "b1_b8_all": set("B%d" % i for i in range(1, 9)) <=
               set(seeds) and not unmatched}
        p5_parts["dvlba_b1_b8"] = dvl["b1_b8_all"]
        p5 = all(p5_parts.values())

    report["predictions"] = {
        "P1_preex_evidence_loop": {"pass": p1, **p1d},
        "P2_recon_discovery": {"pass": p2, **p2d},
        "P3_preex_budget": {"pass": p3, **p3d},
        "P4_postex_amplification": {"pass": p4, **p4d},
        "P5_nonregression": {"pass": p5, "parts": p5_parts, "dvlba": dvl},
    }
    report["runs"] = {
        "freightlane_run1": {"requests": s1["requests"],
                             "findings": len(s1["findings"]),
                             "markers": s1.get("markers_registered"),
                             "gv": st1},
        "freightlane_run2": {"requests": s2["requests"],
                             "findings": len(s2["findings"]),
                             "gv": st2}}
    report["pass"] = bool(p1 and p2 and p3 and p4 and p5)
    json.dump(report, open(os.path.join(RESULTS, "M5-SUMMARY.json"), "w"),
              indent=2, default=str)
    checks = [("P1", p1), ("P2", p2), ("P3", p3), ("P4", p4), ("P5", p5)]
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("== M5 %s — artifacts in %s =="
          % ("PASS" if report["pass"] else "FAIL", RESULTS))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())

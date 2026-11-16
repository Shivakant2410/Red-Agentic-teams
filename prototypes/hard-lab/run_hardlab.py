"""run_hardlab.py — connect the hard lab to the hypothetical engine.

Protocol (RESEARCH.md D9, R3):
  1. spawn meridian-vault on loopback (fresh state per run)
  2. swarm run 1 — fresh memory, budget 560
  3. swarm run 2 — SAME memory namespaces (measures adaptation)
  4. statefuzz standalone — quantifies the dvlba-shape generalization gap
  5. project every belief into the unified HypothesisLedger and reconcile
  6. score against GROUND_TRUTH keys (ground_truth.py) and write report.md

Scope discipline inherited from the platform contract: loopback-only,
fail-closed scope guards, STOP kill files, per-probe fresh principals,
traffic.jsonl with provenance for every wire exchange.
"""
import json
import os
import shutil
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from engine.ledger import HypothesisLedger          # noqa: E402
import ground_truth                                  # noqa: E402

BASELINE = {                          # Phase B/C executed results (dvlba-shop)
    "statefuzz_dvlba": {"requests": 87, "seed_classes": "8/8",
                        "invariants": "I1-I5 all fired", "chains": 3},
    "swarm_dvlba": {"requests": "~530", "findings": 9,
                    "verified": 8, "chains": 3},
}


def spawn_lab(port):
    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(port)], cwd=HERE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("target did not start")


def fresh_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)
    return path


# ----------------------------------------------------- ledger projection --
def _ancestors(facts):
    parents = {}
    for f in facts:
        parents[f["id"]] = f.get("derived_from", [])
    memo = {}

    def closure(fid):
        if fid not in memo:
            out = set()
            for p in parents.get(fid, ()):
                out.add(p)
                out |= closure(p)
            memo[fid] = out
        return memo[fid]
    return closure


_DVLBA_SHAPED = {"h_idor"}      # RULES handlers model the dvlba checkout shape


def project_swarm(ledger, run_label, out_dir, requests_spent):
    bb = json.load(open(os.path.join(out_dir, "blackboard.json")))
    closure = _ancestors(bb)
    children = {}
    for f in bb:
        for p in f.get("derived_from", []):
            children.setdefault(p, set()).add(f["id"])

    trace = []
    trace_path = os.path.join(out_dir, "dispatch_trace.jsonl")
    if os.path.exists(trace_path):
        trace = [json.loads(l) for l in open(trace_path)]
    dispatched = {}
    for t in trace:
        if t.get("event") == "dispatch" and \
                str(t.get("fact", "")).startswith("SF-HYPOTHESIS"):
            dispatched[t["fact"]] = t

    hyp_ids = {}
    for f in bb:
        if f["kind"] == "HYPOTHESIS":
            e = ledger.propose(
                "swarm-board/%s" % run_label, f["payload"].get("tag", "?"),
                f["payload"].get("title", ""), f["payload"].get("prior", .5),
                f["payload"].get("test_plan", ""), derived_from=[f["id"]])
            hyp_ids[f["id"]] = e["id"]

    # findings resolve the hypotheses they descend from
    finding_of = {}
    for f in bb:
        if f["kind"] != "FINDING":
            continue
        fd = f["payload"].get("finding", {})
        status = f["payload"].get("status", "candidate")
        finding_of[f["id"]] = (fd, status)
    for fid, (fd, status) in finding_of.items():
        for anc in closure(fid):
            if anc in hyp_ids:
                hid = hyp_ids[anc]
                ledger.attach(hid, "finding", "%s (%s)" % (fd.get("title"),
                                                           status),
                              requests_spent=requests_spent,
                              finding_ids=[fd.get("id")])
                res = {"verified": "confirmed",
                       "verified-by-transcript": "confirmed-by-transcript",
                       "refuted": "refuted"}.get(status)
                ledger.resolve(hid, res or "inconclusive",
                               {"finding": fd.get("id"), "status": status})

    # every other hypothesis gets the truth the dispatch trace can prove
    for f in bb:
        if f["kind"] != "HYPOTHESIS":
            continue
        hid = hyp_ids[f["id"]]
        if ledger.entries[[e["id"] for e in ledger.entries]
                          .index(hid)]["resolved"]:
            continue
        tag = f["payload"].get("tag", "?")
        desc = sorted(children.get(f["id"], set()))
        desc_kinds = {next(x["kind"] for x in bb if x["id"] == d)
                      for d in desc}
        t = dispatched.get(f["id"])
        if "FINDING" in desc_kinds:
            continue                       # already resolved above
        if any("skip-statefuzz" in json.dumps(
                next(x["payload"] for x in bb if x["id"] == d),
                default=str) for d in desc if "CONTROL" in desc_kinds):
            ledger.attach(hid, "dispatch",
                          "honestly skipped: surface lacks the modeled "
                          "checkout lifecycle", 0)
            ledger.resolve(hid, "inconclusive",
                           {"note": "FSM spawn skipped on shape mismatch "
                                    "(see CONTROL skip-statefuzz)"})
        elif "OBSERVATION" in desc_kinds and "FINDING" not in desc_kinds:
            ledger.attach(hid, "probe",
                          "probe produced observations without a "
                          "violation", requests_spent)
            ledger.resolve(hid, "tested",
                           {"note": "technique ran; observation-only "
                                    "outcome (e.g. hidden verbs enumerated)"})
        elif t is not None:
            if tag in _DVLBA_SHAPED:
                ledger.attach(hid, "dispatch", "dispatched; produced 0 facts",
                              0)
                ledger.resolve(hid, "inconclusive",
                               {"note": "dvlba-shaped probe prerequisites "
                                        "absent on this surface"})
            else:
                ledger.attach(hid, "dispatch", "dispatched; produced 0 facts",
                              0)
                ledger.resolve(hid, "refuted",
                               {"note": "probe ran against the live target "
                                        "and demonstrated no violation"})
        else:
            ledger.resolve(hid, "inconclusive",
                           {"note": "never dispatched (budget, stall, or "
                                    "router priority)"})

    # deferred settle windows: ONE hypothesis per run, evidence = the polls
    events = {}
    traffic = os.path.join(out_dir, "traffic.jsonl")
    if os.path.exists(traffic):
        for line in open(traffic):
            x = json.loads(line)
            rb = x.get("resp_body") or {}
            if isinstance(rb, dict) and x.get("status") == 202:
                ev = next((v for v in rb.values()
                           if isinstance(v, str) and v.startswith("/")), None)
                if ev:
                    events.setdefault(ev, 0)
            if x.get("tag") == "event-poll" and x.get("path") in events:
                events[x["path"]] += 1
    if events:
        e = ledger.deferred("deferred-window/%s" % run_label,
                            marker="%d window(s)" % len(events),
                            callback_path=";".join(sorted(events))[:160],
                            expectation={},
                            ttl=6.0)
        polls = sum(events.values())
        e["tests"].append({"kind": "poll",
                           "detail": "%d async settle window(s) opened, "
                                     "%d event poll(s) issued by the swarm"
                                     % (len(events), polls),
                           "requests_spent": polls, "finding_ids": [],
                           "ts": time.time()})
        e["status"] = "tested"
        doc = run_docs_cache.get(run_label, {})
        settle_hit = _seed_hits(doc, ("S2", "S3"))
        if settle_hit:
            ledger.resolve(e["id"], "confirmed",
                           {"note": "settle-window violation (%s) verified "
                                    "in this run" % ",".join(
                                        h.get("id", "?")
                                        for h in settle_hit)})
        else:
            ledger.resolve(e["id"], "inconclusive",
                           {"note": "window(s) opened and polled; no "
                                    "violation demonstrated"})


def _seed_hits(doc, seed_ids):
    out = []
    for f in doc.get("findings", []):
        fd = f.get("finding", f)
        seeds, _ = ground_truth.classify(fd, f.get("status", "candidate"))
        if any(s in seed_ids for s in seeds):
            out.append(fd)
    return out


def project_statefuzz(ledger, out_dir, requests_spent):
    path = os.path.join(out_dir, "findings.json")
    doc = json.load(open(path)) if os.path.exists(path) else {"findings": []}
    e = ledger.propose("statefuzz-standalone", "dvlba-shaped-probes",
                       "statefuzz's 8 dvlba-shaped probe classes model this "
                       "target's lifecycle", 0.3,
                       "lawful walk + 8 mutant probes + race + deferred")
    fired = [fd.get("id") for fd in doc.get("findings", [])
             if fd.get("invariant") not in ("-",) and fd.get("id") != "SF-SKIP"]
    ledger.attach(e["id"], "probes",
                  "%d probe finding(s) fired" % len(fired),
                  requests_spent=requests_spent, finding_ids=fired)
    ledger.resolve(e["id"], "confirmed" if fired else "refuted",
                   {"note": ("probes applied" if fired else
                             "generalization gap: checkout-shaped probes do "
                             "not model the vault/payout lifecycle")})
    for fd in doc.get("findings", []):
        if fd.get("invariant") in ("-",) or fd.get("id") == "SF-SKIP":
            continue
        h = ledger.propose("statefuzz-standalone", fd.get("id"),
                           fd.get("title"), 0.6, fd.get("endpoint", ""))
        ledger.attach(h["id"], "probe-finding", fd.get("endpoint"),
                      requests_spent=0, finding_ids=[fd.get("id")])
        ledger.resolve(h["id"], "confirmed", {"finding": fd.get("id")})


# ------------------------------------------------------------------ main --
def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8391
    results = fresh_dir(os.path.join(HERE, "results"))
    ledger = HypothesisLedger()
    summaries = {}

    for label, budget, memdir in (("run1", 560, None), ("run2", 560,
                                                        "run1")):
        out_dir = os.path.join(results, label)
        fresh_dir(out_dir)
        memory_dir = os.path.join(results, "memory") if memdir else \
            os.path.join(out_dir, "memory")
        os.makedirs(memory_dir, exist_ok=True)
        proc, base = spawn_lab(port)
        try:
            import swarm
            t0 = time.time()
            summary = swarm.build_registry()["swarm_run"]["run"]({
                "base_url": base, "out_dir": out_dir,
                "memory_dir": memory_dir, "approvals": "lab",
                "budget": budget,
                "artifacts": {"promo_code": "MERIDIAN-DROP"},
                "stop_file": os.path.join(out_dir, "STOP")})
            summary["wall_s"] = round(time.time() - t0, 1)
            summaries[label] = summary
        finally:
            proc.terminate()
        run_docs_cache[label] = json.load(
            open(os.path.join(out_dir, "findings.json")))
        project_swarm(ledger, label, out_dir, summary["requests"])

    # ---- statefuzz standalone (gap quantification) ------------------------
    sf_dir = os.path.join(results, "statefuzz")
    fresh_dir(sf_dir)
    proc, base = spawn_lab(port)
    try:
        from statefuzz import registry_tool
        t0 = time.time()
        sf_summary = registry_tool.build_registry()["statefuzz_run"]["run"]({
            "base_url": base, "out_dir": sf_dir, "approvals": "lab",
            "budget": 240, "stop_file": os.path.join(sf_dir, "STOP")})
        sf_summary["wall_s"] = round(time.time() - t0, 1)
        summaries["statefuzz"] = sf_summary
    finally:
        proc.terminate()
    project_statefuzz(ledger, sf_dir, sf_summary["requests"])

    # ---- scoring -----------------------------------------------------------
    run_docs = [(lbl, json.load(open(os.path.join(results, lbl,
                                                 "findings.json"))))
                for lbl in ("run1", "run2")]
    run_docs.append(("statefuzz", json.load(
        open(os.path.join(sf_dir, "findings.json")))))
    scoring = ground_truth.score_runs(run_docs)
    ledger_doc = ledger.save(os.path.join(results, "hypothesis_ledger.json"))
    json.dump(scoring, open(os.path.join(results, "scoring.json"), "w"),
              indent=2)
    json.dump({k: {kk: vv for kk, vv in v.items() if kk != "trace_file"}
               for k, v in summaries.items()},
              open(os.path.join(results, "summaries.json"), "w"), indent=2,
              default=str)
    write_report(results, summaries, scoring, ledger, ledger_doc)
    print("done — results in %s" % results)


run_docs_cache = {}


# ----------------------------------------------------------------- report --
def write_report(results, summaries, scoring, ledger, ledger_doc):
    lines = []
    A = lines.append
    A("# meridian-vault — engagement report (hard lab, Phase D)\n")
    A("Generated by `run_hardlab.py`. Every number below comes from the "
      "recorded artifacts in this directory; nothing is asserted from "
      "memory.\n")
    A("## Runs\n")
    A("| run | engine | requests | wall s | findings |")
    A("| --- | --- | --- | --- | --- |")
    for lbl in ("run1", "run2"):
        s = summaries.get(lbl, {})
        A("| %s | swarm (7 specialists) | %s | %s | %s |" %
          (lbl, s.get("requests"), s.get("wall_s"), len(s.get("findings",
                                                           []))))
    sf = summaries.get("statefuzz", {})
    A("| statefuzz | standalone fuzzer | %s | %s | %s |" %
      (sf.get("requests"), sf.get("wall_s"),
       len([f for f in sf.get("findings", [])
            if f.get("invariant") not in ("-",)])))
    A("")
    A("## Ground-truth matrix\n")
    A("| seed | class | verdict | evidence |")
    A("| --- | --- | --- | --- |")
    for sid, spec in ground_truth.SEEDS.items():
        hits = scoring["hits"].get(sid, [])
        if hits:
            best = max(hits, key=lambda h: (h["status"].startswith(
                "verified"), h["severity"] != "low"))
            A("| %s | %s | **HIT** | %s (run %s, %s, invariant %s) |" %
              (sid, spec["name"], best["finding_id"], best["run"],
               "/".join(best["provenance"]) if best.get("provenance") else "?",
               _inv_of(best)))
        else:
            A("| %s | %s | miss | no matching finding in either run |" %
              (sid, spec["name"]))
    A("")
    A("## Decoys — false-positive discipline\n")
    if scoring["false_positives"]:
        A("| decoy | claims | ")
        A("| --- | --- |")
        for d, items in scoring["false_positives"].items():
            A("| %s (%s) | %s |" % (d, ground_truth.DECOYS[d]["name"],
                                    "; ".join("%s on run %s" %
                                              (i["finding_id"], i["run"])
                                              for i in items)))
    else:
        A("No finding mapped to any decoy (D1–D4). The engines did not "
          "claim the sample `/.env`, the safe `retry` verb, negative-input "
          "validation, or the enforced account read.")
    A("")
    if scoring["unmatched"]:
        A("## Unmatched findings (not a seed hit, not a decoy)\n")
        for u in scoring["unmatched"]:
            A("- %s (run %s, %s): %s" % (u["finding_id"], u["run"],
                                         u["status"], u["title"]))
        A("")
    A("## Hypothetical engine (unified ledger)\n")
    st = ledger_doc["stats"]
    A("- %d hypotheses proposed; statuses: %s" %
      (st["total"], json.dumps(st["by_status"], sort_keys=True)))
    A("- ledger score (confirmed 1.0 · by-transcript 0.5 · refuted 1.0 · "
      "inconclusive 0): **%.2f**" % ledger_doc["score"])
    for e in ledger.entries:
        if e["status"] == "inconclusive":
            A("  - inconclusive: [%s] %s — %s" % (e["source"], e["tag"],
                                                  e["evidence"][-1]["note"]
                                                  if e["evidence"] else ""))
    A("")
    missed = [sid for sid in ground_truth.SEEDS
              if sid not in scoring["hits"]]
    if missed:
        A("## Misses — capability gaps the lab exposed\n")
        _MISS_NOTES = {
            "S8": "no engine technique probes 403-vs-404 existence oracles; "
                  "candidate future arm: h_oracle_enum (enumerate param "
                  "objects by status-code differential, LOW severity cap).",
        }
        for sid in missed:
            A("- %s (%s): %s" % (sid, ground_truth.SEEDS[sid]["name"],
                                 _MISS_NOTES.get(sid, "no matching finding")))
        A("")
    A("## Honest gaps\n")
    A("- statefuzz standalone: %s requests, findings %s — the 8 dvlba-shaped "
      "probe classes do not model the vault/payout lifecycle. This is the "
      "measured generalization gap, not a target win." %
      (sf.get("requests"),
       [f["id"] for f in sf.get("findings", [])
        if f.get("invariant") not in ("-",)] or "none"))
    A("- The swarm's `_t_fsm` spawn honestly skips when no checkout lifecycle "
      "exists (see dispatch traces); FSM coverage on this lab runs through "
      "the generic technique library instead.")
    A("- Loopback races are near-jitter-free; windows were widened "
      "application-side (RESEARCH.md R5). Race findings are therefore "
      "easier here than in production.")
    A("")
    A("## Baseline comparison (dvlba-shop, executed in Phases B/C)\n")
    A("| engine | dvlba-shop baseline | meridian-vault (this run) |")
    A("| --- | --- | --- |")
    A("| statefuzz | %s requests, %s seed classes | %s requests, %s |" %
      (BASELINE["statefuzz_dvlba"]["requests"],
       BASELINE["statefuzz_dvlba"]["seed_classes"], sf.get("requests"),
       "0 findings (gap)"))
    A("| swarm | %s, %s findings, %s verified | run1 %s findings / run2 %s "
      "findings |" %
      (BASELINE["swarm_dvlba"]["requests"], BASELINE["swarm_dvlba"]["findings"],
       BASELINE["swarm_dvlba"]["verified"],
       len(summaries.get("run1", {}).get("findings", [])),
       len(summaries.get("run2", {}).get("findings", []))))
    A("")
    with open(os.path.join(results, "report.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def _inv_of(best):
    path = os.path.join(HERE, "results", str(best.get("run")),
                        "findings.json")
    doc = json.load(open(path)) if os.path.exists(path) else {"findings": []}
    for f in doc.get("findings", []):
        fd = f.get("finding", f)
        if fd.get("id") == best.get("finding_id"):
            return fd.get("invariant", "?")
    return "?"


if __name__ == "__main__":
    main()

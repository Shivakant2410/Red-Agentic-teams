"""engine/projection.py — project run artifacts into the HypothesisLedger.

M0 promotion of the proven Phase-D projection (hard-lab/run_hardlab.py
`project_swarm` / `project_statefuzz`), decoupled from any single lab's
ground truth:

  * `deferred_hits` is a callback, not an import: the caller decides which
    findings count as settle-window violations (meridian uses S2/S3, dvlba
    uses B8, default None -> honest "inconclusive" resolution).
  * facts/trace are passed in memory (registry run) or loaded from disk
    (standalone replay) — same code path either way.

Grounding discipline (C-RESEARCH E6): every ledger entry derived from a
blackboard fact carries that fact id in `derived_from`.
"""
import json
import os
import time

# RULES handlers model the dvlba checkout shape; on unfamiliar surfaces these
# hypotheses are "inconclusive", not "refuted" (honest miss taxonomy).
_DVLBA_SHAPED = {"h_idor"}


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


def load_run(out_dir):
    """(facts, trace) from a run's artifact directory."""
    facts, trace = [], []
    bb = os.path.join(out_dir, "blackboard.json")
    if os.path.exists(bb):
        facts = json.load(open(bb))
    tp = os.path.join(out_dir, "dispatch_trace.jsonl")
    if os.path.exists(tp):
        trace = [json.loads(l) for l in open(tp)]
    return facts, trace


def project_swarm(ledger, facts, trace, run_label, requests_spent,
                  traffic_path=None, deferred_hits=None):
    """Project one swarm run's blackboard into the ledger.

    deferred_hits(findings_doc) -> list of finding dicts that count as
    deferred-window (settle/async) violations for THIS target, or None.
    """
    closure = _ancestors(facts)
    children = {}
    for f in facts:
        for p in f.get("derived_from", []):
            children.setdefault(p, set()).add(f["id"])

    dispatched = {}
    for t in trace or []:
        if t.get("event") == "dispatch" and \
                str(t.get("fact", "")).startswith("SF-HYPOTHESIS"):
            dispatched[t["fact"]] = t

    hyp_ids = {}
    for f in facts:
        if f["kind"] == "HYPOTHESIS":
            e = ledger.propose(
                "swarm-board/%s" % run_label, f["payload"].get("tag", "?"),
                f["payload"].get("title", ""), f["payload"].get("prior", .5),
                f["payload"].get("test_plan", ""), derived_from=[f["id"]])
            hyp_ids[f["id"]] = e["id"]

    # findings resolve the hypotheses they descend from
    facts_by_id = {f["id"]: f for f in facts}
    for f in facts:
        if f["kind"] != "FINDING":
            continue
        fd = f["payload"].get("finding", {})
        status = f["payload"].get("status", "candidate")
        for anc in closure(f["id"]):
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
    for f in facts:
        if f["kind"] != "HYPOTHESIS":
            continue
        hid = hyp_ids[f["id"]]
        entry = ledger.entries[[e["id"] for e in ledger.entries]
                               .index(hid)]
        if entry["resolved"]:
            continue
        tag = f["payload"].get("tag", "?")
        desc = sorted(children.get(f["id"], set()))
        desc_kinds = {facts_by_id[d]["kind"] for d in desc if d in facts_by_id}
        t = dispatched.get(f["id"])
        if "FINDING" in desc_kinds:
            continue                       # already resolved above
        if any("skip-statefuzz" in json.dumps(
                facts_by_id[d]["payload"], default=str)
                for d in desc if d in facts_by_id
                and "CONTROL" in desc_kinds):
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
            ledger.attach(hid, "dispatch", "dispatched; produced 0 facts", 0)
            if tag in _DVLBA_SHAPED:
                ledger.resolve(hid, "inconclusive",
                               {"note": "dvlba-shaped probe prerequisites "
                                        "absent on this surface"})
            else:
                ledger.resolve(hid, "refuted",
                               {"note": "probe ran against the live target "
                                        "and demonstrated no violation"})
        else:
            ledger.resolve(hid, "inconclusive",
                           {"note": "never dispatched (budget, stall, or "
                                    "router priority)"})

    # deferred settle windows: ONE hypothesis per run, evidence = the polls
    events = {}
    if traffic_path and os.path.exists(traffic_path):
        for line in open(traffic_path):
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
                            expectation={}, ttl=6.0)
        polls = sum(events.values())
        e["tests"].append({"kind": "poll",
                           "detail": "%d async settle window(s) opened, "
                                     "%d event poll(s) issued by the swarm"
                                     % (len(events), polls),
                           "requests_spent": polls, "finding_ids": [],
                           "ts": time.time()})
        e["status"] = "tested"
        fd_list = [{"finding": f["payload"].get("finding", {}),
                    "status": f["payload"].get("status", "candidate")}
                   for f in facts if f["kind"] == "FINDING"]
        hit = deferred_hits(fd_list) if deferred_hits else None
        if hit:
            ledger.resolve(e["id"], "confirmed",
                           {"note": "deferred-window violation (%s) verified "
                                    "in this run" % ",".join(hit)})
        else:
            ledger.resolve(e["id"], "inconclusive",
                           {"note": "window(s) opened and polled; no "
                                    "violation demonstrated"})
    return hyp_ids


def project_statefuzz(ledger, sf_doc, requests_spent,
                      label="statefuzz-standalone"):
    """Project a statefuzz findings doc (standalone or swarm-embedded)."""
    if not sf_doc:
        return None
    e = ledger.propose(label, "dvlba-shaped-probes",
                       "statefuzz's 8 dvlba-shaped probe classes model this "
                       "target's lifecycle", 0.3,
                       "lawful walk + 8 mutant probes + race + deferred")
    fired = [fd.get("id") for fd in sf_doc.get("findings", [])
             if fd.get("invariant") not in ("-",) and fd.get("id") != "SF-SKIP"]
    ledger.attach(e["id"], "probes", "%d probe finding(s) fired" % len(fired),
                  requests_spent=requests_spent, finding_ids=fired)
    ledger.resolve(e["id"], "confirmed" if fired else "refuted",
                   {"note": ("probes applied" if fired else
                             "generalization gap: checkout-shaped probes do "
                             "not model this lifecycle")})
    for fd in sf_doc.get("findings", []):
        if fd.get("invariant") in ("-",) or fd.get("id") == "SF-SKIP":
            continue
        h = ledger.propose(label, fd.get("id"), fd.get("title"), 0.6,
                           fd.get("endpoint", ""))
        ledger.attach(h["id"], "probe-finding", fd.get("endpoint"),
                      requests_spent=0, finding_ids=[fd.get("id")])
        ledger.resolve(h["id"], "confirmed", {"finding": fd.get("id")})
    return e

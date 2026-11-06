"""registry_tool — the swarm as a Red-Agentic-teams registry tool.

Contract: build_swarm_registry() -> {"swarm_run": {"schema": ..., "run": ctx}}

run(ctx) phases:
  1. scope guard (loopback / TEST-NET-1, fail-closed)          [M2]
  2. shared executor (budget, STOP file, traffic.jsonl) + memory namespaces
  3. blackboard seed: CONTROL engage
  4. router dispatch loop (trigger-gated specialists, stall detection) [M1/M3]
  5. end-of-run curation: verification-weighted outcomes -> per-specialist
     namespaces, persisted for the NEXT run (E4/E5 — "better time to time")
  6. artifacts: findings.json (provenance + verification stamps),
     blackboard.json, dispatch_trace.jsonl
"""
import json
import os
import time
import uuid

from .blackboard import Blackboard, Fact
from .llm import LLMSeam
from .memory import MemoryNamespace
from .router import Router
from statefuzz.executor import StopFuzz
from .specialists import ROSTER
from .specialists.exploit import ExploitSpecialist

_SEAM_NOTE = ("Seam: LocalScopeGuard/FileMemoryStore swap for the platform "
              "ScopeGuard/ExperienceStore when embedded in Red-Agentic-teams.")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scope_ok(base_url):
    import ipaddress
    import urllib.parse
    host = urllib.parse.urlparse(base_url).hostname or ""
    if host in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network("192.0.2.0/24")
    except ValueError:
        return False


def _schema():
    return {
        "name": "swarm_run",
        "description": ("Specialist-swarm engagement: per-state specialist "
                        "agents (recon, surface, hypotheses, exploit, verify, "
                        "access, logic) coordinate over a blackboard; "
                        "produces provenance-stamped findings.json and "
                        "persists experience for the next run."),
        "type": "object",
        "properties": {
            "base_url": {"type": "string", "default": "http://127.0.0.1:8378"},
            "out_dir": {"type": "string", "default": "results"},
            "memory_dir": {"type": "string",
                           "default": "results/memory"},
            "approvals": {"type": "string", "enum": ["lab", "none"],
                          "default": "lab"},
            "budget": {"type": "integer", "default": 400},
            "max_rounds": {"type": "integer", "default": 24},
            "stop_file": {"type": "string"},
        },
        "required": [],
    }


# ------------------------------------------------------------- curation ----
def _descendants(board):
    """derived_from graph closure: fact id -> set of descendant ids."""
    children = {}
    for f in board.facts:
        for parent in f.get("derived_from", []):
            children.setdefault(parent, set()).add(f["id"])
    memo = {}

    def closure(fid):
        if fid in memo:
            return memo[fid]
        out = set()
        for c in children.get(fid, ()):
            out.add(c)
            out |= closure(c)
        memo[fid] = out
        return out

    return closure


def _finding_status(board):
    """finding id -> verification status (mutated on the FINDING facts)."""
    out = {}
    for f in board.query(kind="FINDING"):
        fd = f["payload"].get("finding", {})
        out[fd.get("id")] = f["payload"].get("status", "candidate")
    return out


def _curation_outcomes(specialist, board):
    """E4 outcome weights per technique, from VERIFIED evidence only (E3).

    weight rule: verified 1.0 · verified-by-transcript 0.5 · candidate-only
    0.25 · refuted -> failure 1.0 · no facts -> failure 0.75.
    Poisoning guard (A2): read-side specialists (recon, surface_mapper) cap
    at 0.5 — their facts come from target-controlled content.
    """
    closure = _descendants(board)
    status = _finding_status(board)
    facts_by_id = {f["id"]: f for f in board.facts}
    tech_facts = specialist.private.get("tech_facts", {})
    raw = specialist.private.get("outcomes", {})
    outcomes = []
    for tech in sorted(set(list(tech_facts) + list(raw))):
        if raw.get(tech) == "skipped":
            continue   # artifact unavailable this run: no credit, no penalty
        if tech.startswith("check:"):
            # verify specialist: the verification event IS the outcome (E3)
            outcomes.append({"technique": tech,
                             "outcome": raw.get(tech, "failure"),
                             "weight": 1.0})
            continue
        fids = tech_facts.get(tech, [])
        if not fids:
            outcomes.append({"technique": tech, "outcome": "failure",
                             "weight": 0.75})
            continue
        desc_findings = []
        for fid in fids:
            for d in closure(fid):
                df = facts_by_id.get(d, {})
                if df.get("kind") == "FINDING":
                    desc_findings.append(df)
        statuses = [status.get(df["payload"]["finding"]["id"], "candidate")
                    for df in desc_findings]
        if any(s == "verified" for s in statuses):
            o, w = "success", 1.0
        elif any(s == "verified-by-transcript" for s in statuses):
            o, w = "success", 0.5
        elif any(s == "refuted" for s in statuses):
            o, w = "failure", 1.0
        else:
            o, w = "success", 0.25
        if specialist.name in ("recon", "surface_mapper"):
            w = min(w, 0.5)          # poisoning guard (A2)
        outcomes.append({"technique": tech, "outcome": o, "weight": w})
    return outcomes


# ------------------------------------------------------------------ run ----
# ------------------------------------------------------------- insights ----
def _earn_insights(specialist, board, namespace):
    """M7 insight curation: only target-agnostic lessons, earned from this
    run's outcomes (A2: target-controlled content never promotes directly)."""
    raw = specialist.private.get("outcomes", {})
    if specialist.name == "recon":
        if raw.get("probe_common_paths") == "failure" and \
                raw.get("fetch_openapi") == "success":
            namespace.add_insight(
                "On API-first targets, machine-readable surface disclosure "
                "(openapi/swagger) outperforms blind common-path probing; "
                "probe only after disclosure fails.")
    if specialist.name == "hypothesis" and \
            any(f["kind"] == "SURFACE" and f["payload"].get("stateful_flows")
                for f in board.facts):
        namespace.add_insight(
            "Multi-step stateful flows (e.g. checkout init->confirm) warrant "
            "FSM-mutation probing before endpoint-level fuzzing.")
    if specialist.name == "exploit":
        failed = [t for t, o in raw.items() if o == "failure"]
        if failed:
            namespace.add_insight(
                "Before testing concurrency hypotheses, confirm the target "
                "artifact is still virgin; burned single-use artifacts "
                "silently zero the race window.")


def run(ctx, budget=None):
    base_url = ctx.get("base_url", "http://127.0.0.1:8378")
    if not _scope_ok(base_url):
        return {"ok": False, "error": "scope guard: %s is not loopback or "
                "TEST-NET-1. %s" % (base_url, _SEAM_NOTE)}

    from statefuzz.executor import Executor, Principal   # vendored Phase B

    out_dir = ctx.get("out_dir", "results")
    memory_dir = ctx.get("memory_dir", os.path.join(out_dir, "memory"))
    os.makedirs(out_dir, exist_ok=True)
    traffic = os.path.join(out_dir, "traffic.jsonl")
    if os.path.exists(traffic):
        os.remove(traffic)
    stop_file = ctx.get("stop_file") or os.path.join(out_dir, "STOP")
    if budget is None:
        budget = int(ctx.get("budget", 400))

    ex = Executor(base_url, traffic, stop_file=stop_file, budget=budget)
    anon = Principal("anon")
    ex.principals["anon"] = anon
    run_id = uuid.uuid4().hex[:6]

    cache = {}

    def memory(name):
        if name not in cache:
            cache[name] = MemoryNamespace(name, memory_dir)
        return cache[name]

    llm = LLMSeam(backend=ctx.get("llm_backend"))
    board = Blackboard()
    ctx2 = {"executor": ex, "memory": memory, "llm": llm, "run_id": run_id,
            "results_dir": out_dir, "approvals": ctx.get("approvals", "lab"),
            "budget": budget, "stop_file": stop_file, "base_url": base_url,
            "anon": anon,
            # engagement-brief artifacts (campaign codes/tokens) — v0.2
            "artifacts": dict(ctx.get("artifacts") or {},
                              promo_code=(ctx.get("artifacts") or {})
                              .get("promo_code", "ONCE-9K4T")),
            "per_specialist_dispatch_cap": ctx.get(
                "per_specialist_dispatch_cap", 16)}
    specialists = [cls(ctx2) for cls in
                   (ROSTER["RECON"], ROSTER["SURFACE"], ROSTER["HYPOTHESES"],
                    ROSTER["EXPLOIT"], ROSTER["VERIFY"], ROSTER["ACCESS"],
                    ROSTER["LOGIC"])]

    started = time.time()
    board.publish(Fact.make("CONTROL", "orchestrator",
                            {"event": "engage", "target": base_url}))
    router = Router(board, specialists, ctx2)
    try:
        router.dispatch(max_rounds=int(ctx.get("max_rounds", 40)))
    except StopFuzz as e:      # STOP kill file / budget exhausted (fail-safe)
        router.log(event="stopped", reason=str(e))

    # ------------------------------------------ end-of-run consolidation --
    memory_snapshots_before = {name: ns.snapshot() for name, ns in cache.items()}
    for s in specialists:
        outcomes = _curation_outcomes(s, board)
        if outcomes:
            memory(s.name).curate(outcomes)
        _earn_insights(s, board, memory(s.name))
    memory_snapshots = {name: ns.snapshot() for name, ns in cache.items()}

    summary = _assemble(board, router, ex, started, out_dir, memory_dir,
                        memory_snapshots_before, memory_snapshots, llm)
    return summary


def _dedupe(findings):
    """Merge duplicate findings by (invariant, endpoint): keep the first,
    record who else found it (provenance merging)."""
    out, index = [], {}
    for f in findings:
        fd = f["payload"]["finding"]
        key = (fd["invariant"], fd["endpoint"])
        if key not in index:
            entry = {"finding": dict(fd), "status": f["payload"]["status"],
                     "verification": f["payload"].get("verification"),
                     "provenance": [f["source"]],
                     "techniques": [f["payload"].get("technique")],
                     "fact_ids": [f["id"]]}
            index[key] = entry
            out.append(entry)
        else:
            e = index[key]
            if f["source"] not in e["provenance"]:
                e["provenance"].append(f["source"])
            if f["payload"].get("technique") not in e["techniques"]:
                e["techniques"].append(f["payload"].get("technique"))
            e["fact_ids"].append(f["id"])
            if f["payload"]["status"] == "verified":
                e["status"] = "verified"
                e["verification"] = f["payload"].get("verification")
    return out


def _assemble(board, router, ex, started, out_dir, memory_dir,
              mem_before, mem_after, llm):
    findings = _dedupe(board.query(kind="FINDING"))
    escalations = [{"chain": f["payload"]["chain"],
                    "impact": f["payload"]["impact"],
                    "severity": f["payload"]["severity"]}
                   for f in board.query(kind="ESCALATION")]

    sf_requests = None
    sf_doc_path = os.path.join(out_dir, "statefuzz", "findings.json")
    if os.path.exists(sf_doc_path):
        sf_requests = json.load(open(sf_doc_path)).get("requests")

    doc = {"tool": "swarm", "version": "0.2.0",
           "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "elapsed_s": round(time.time() - started, 1),
           "requests": ex.count,
           "statefuzz_sub_budget_requests": sf_requests,
           "rounds": router.rounds,
           "roster": [s.name for s in router.specialists],
           "spawn_events": router.spawn_events,
           "llm_seam_calls": llm.calls,
           "ledger": board.ledger(),
           "memory_before": mem_before, "memory_after": mem_after,
           "findings": findings, "escalations": escalations}
    with open(os.path.join(out_dir, "findings.json"), "w") as fh:
        json.dump(doc, fh, indent=2)
    with open(os.path.join(out_dir, "blackboard.json"), "w") as fh:
        json.dump(board.facts, fh, indent=2, default=str)
    with open(os.path.join(out_dir, "dispatch_trace.jsonl"), "w") as fh:
        for t in router.trace:
            fh.write(json.dumps(t, default=str) + "\n")

    return {"ok": True, "requests": ex.count,
            "statefuzz_sub_budget_requests": sf_requests,
            "rounds": router.rounds,
            "elapsed_s": doc["elapsed_s"],
            "ledger": doc["ledger"], "roster": doc["roster"],
            "spawn_events": doc["spawn_events"],
            "llm_seam_calls": doc["llm_seam_calls"],
            "findings": [{"id": f["finding"]["id"],
                          "title": f["finding"]["title"],
                          "severity": f["finding"]["severity"],
                          "invariant": f["finding"]["invariant"],
                          "status": f["status"],
                          "provenance": f["provenance"]}
                         for f in findings],
            "escalations": escalations,
            "memory_before": mem_before, "memory_after": mem_after,
            "trace_file": os.path.join(out_dir, "dispatch_trace.jsonl"),
            "artifacts": {"findings": os.path.join(out_dir, "findings.json"),
                          "blackboard": os.path.join(out_dir,
                                                     "blackboard.json"),
                          "traffic": os.path.join(out_dir, "traffic.jsonl")}}


def build_swarm_registry():
    """Red-Agentic-teams registry contract: tools expose schema() + run(ctx)."""
    return {"swarm_run": {"schema": _schema, "run": run}}

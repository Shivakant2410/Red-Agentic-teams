"""Orchestrator — the deterministic governance shell (G5, M4).

Owns the engagement phases that used to be an ad-hoc script inside
registry_tool.run():

    0  pre-flight     policy.check_target — fail-closed scope admission
    1  build          executor (+ policy at the wire chokepoint), shared
                      ExperienceStore, LLM seam, blackboard, ledger spine
    2  seed           CONTROL engage fact
    3  dispatch       the proven Router loop (UNCHANGED semantics — M4
                      wraps the machinery, it does not retune it)
    4  verify pass    SwarmVerifyPipeline.resolve — one verdict vocabulary,
                      unproven claims downgrade to not_reproducible
    5  curation       outcome weights -> ExperienceStore (next run's
                      posteriors + insights)
    6  projections    M0/M1 ledger spine + M3 attack-graph (unchanged)
    7  artifacts      findings/blackboard/trace/policy_audit + summary

Contract: the SAME schema() + run(ctx) that build_swarm_registry() serves
— registry_tool.run() now DELEGATES here, so the registry path and the
orchestrator path are the same code by construction (the G5 acceptance:
"same schema() + run(ctx) contract served by both").

Why a deterministic shell and not an LLM orchestrator (RESEARCH-M4 R3):
MAST's inter-agent-misalignment category, Magentic-One's ledger loop, and
the commercial leader's own description ("coordination agents ... apply
deterministic logic") all point the same way — the LLM belongs at the
hypothesis seams (M5), never at the governance layer.
"""
import json
import os
import time
import uuid

from .blackboard import Blackboard, Fact
from .experience import FileExperienceStore
from .llm import LLMSeam
from .memory import MemoryNamespace            # noqa: F401 (re-export)
from .policy import LabPolicy
from .router import Router
from .verify_pipeline import SwarmVerifyPipeline
from statefuzz.executor import Executor, Principal, StopFuzz
from .specialists import ROSTER
from .specialists.exploit import ExploitSpecialist   # noqa: F401

# ------------------------------------------------- M0 ledger spine seam --
# Seam: the promoted HypothesisLedger spine (hard-lab Phase D -> mainline).
# Every belief can be projected into it; when the engine package is absent
# or ctx["ledger"] is False the deterministic v1 path runs unchanged.
try:
    from engine.ledger import HypothesisLedger      # noqa: F401
    from engine import projection                   # noqa: F401
    _SPINE_AVAILABLE = True
except ImportError:                                 # pragma: no cover
    _SPINE_AVAILABLE = False

_SEAM_NOTE = ("Seam: LocalScopeGuard/FileMemoryStore swap for the platform "
              "ScopeGuard/ExperienceStore when embedded in Red-Agentic-teams.")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


# ------------------------------------------------------------------ run ----
class Orchestrator:
    """Injectable governance shell. Defaults are the lab components; the
    platform's ScopeGuard / k-of-n verify pipeline / semantic
    ExperienceStore drop in by implementing the same three protocols."""

    def __init__(self, policy=None, experience=None, verify_pipeline=None):
        self._policy = policy
        self._experience = experience
        self._pipeline = verify_pipeline

    @staticmethod
    def schema():
        return _schema()

    def run(self, ctx, budget=None):
        # ---------------------------------------------- 0: pre-flight ----
        approvals = ctx.get("approvals", "lab")
        out_dir = ctx.get("out_dir", "results")
        policy = self._policy or LabPolicy(
            approvals=approvals,
            audit_path=os.path.join(out_dir, "policy_audit.jsonl"))
        target = ctx.get("base_url", "http://127.0.0.1:8378")
        decision = policy.check_target(target)
        if not decision.allow:
            # keep the registry's historical refusal shape (tests + labs
            # match on it) — fail closed before ANY infrastructure exists
            return {"ok": False,
                    "error": "scope guard: %s. %s"
                             % (decision["reason"], _SEAM_NOTE)}

        # ---------------------------------------------------- 1: build ----
        traffic = os.path.join(out_dir, "traffic.jsonl")
        os.makedirs(out_dir, exist_ok=True)
        if os.path.exists(traffic):
            os.remove(traffic)
        stop_file = ctx.get("stop_file") or os.path.join(out_dir, "STOP")
        if budget is None:
            budget = int(ctx.get("budget", 400))

        ex = Executor(target, traffic, stop_file=stop_file, budget=budget,
                      policy=policy)
        anon = Principal("anon")
        ex.principals["anon"] = anon
        run_id = uuid.uuid4().hex[:6]

        store = self._experience or FileExperienceStore(
            ctx.get("memory_dir", os.path.join(out_dir, "memory")))

        llm = LLMSeam(backend=ctx.get("llm_backend"))
        board = Blackboard()
        # M0 seam: the promoted HypothesisLedger spine. M1: it no longer only
        # resolves — the WINDOW specialist registers live markers from observed
        # 202/event shapes and the WindowDriver drives their deferred windows
        # between dispatch rounds. ctx["ledger"] False keeps the pure
        # deterministic v1 path.
        ledger = HypothesisLedger() \
            if (_SPINE_AVAILABLE and ctx.get("ledger", True)) else None
        ctx2 = {"executor": ex, "memory": store.namespace, "llm": llm,
                "run_id": run_id,
                "ledger": ledger,
                "results_dir": out_dir, "approvals": approvals,
                "budget": budget, "stop_file": stop_file, "base_url": target,
                "anon": anon,
                # M3: the ambient wallet watcher's shared event trace (the
                # exploit specialist's watcher appends here; the attack-graph
                # projection reads it)
                "ambient_events": [],
                # engagement-brief artifacts (campaign codes/tokens) — v0.2
                "artifacts": dict(ctx.get("artifacts") or {},
                                  promo_code=(ctx.get("artifacts") or {})
                                  .get("promo_code", "ONCE-9K4T")),
                "per_specialist_dispatch_cap": ctx.get(
                    "per_specialist_dispatch_cap", 16)}
        specialists = [cls(ctx2) for cls in
                       (ROSTER["RECON"], ROSTER["SURFACE"], ROSTER["PREEX"],
                        ROSTER["HYPOTHESES"],
                        ROSTER["EXPLOIT"], ROSTER["VERIFY"], ROSTER["ACCESS"],
                        ROSTER["LOGIC"], ROSTER["WINDOW"], ROSTER["GRAPH"])]

        # ----------------------------------------------------- 2: seed ----
        started = time.time()
        board.publish(Fact.make("CONTROL", "orchestrator",
                                {"event": "engage", "target": target}))

        # -------------------------------------------------- 3: dispatch ----
        router = Router(board, specialists, ctx2)
        try:
            router.dispatch(max_rounds=int(ctx.get("max_rounds", 40)))
        except StopFuzz as e:      # STOP kill file / budget exhausted (fail-safe)
            router.log(event="stopped", reason=str(e))

        # ---------------------------------------------- 4: verify pass ----
        pipeline = self._pipeline or SwarmVerifyPipeline()
        pipeline_report = pipeline.resolve(board)

        # ---------------------------------------------- 5: curation -------
        mem_before = store.snapshots()
        for s in specialists:
            outcomes = pipeline.curation_outcomes(s, board)
            if outcomes:
                store.namespace(s.name).curate(outcomes)
            self._earn_insights(s, board, store.namespace(s.name))
        mem_after = store.snapshots()

        # ------------------------------------------- 6: spine projection --
        ledger_stats = None
        if ledger is not None:
            projection.project_swarm(
                ledger, board.facts, router.trace, run_id, ex.count,
                traffic_path=traffic, deferred_hits=ctx.get("deferred_hits"))
            sf_doc_path = os.path.join(out_dir, "statefuzz", "findings.json")
            if os.path.exists(sf_doc_path):
                sf_doc = json.load(open(sf_doc_path))
                projection.project_statefuzz(
                    ledger, sf_doc, sf_doc.get("requests") or 0,
                    label="statefuzz/swarm-embedded")
            ledger.save(os.path.join(out_dir, "hypothesis_ledger.json"))
            ledger_stats = {"stats": ledger.stats(), "score": ledger.score()}

        # --------------------------------------- 6b: attack-graph (M3) ----
        ag_stats, ambient_stats = None, None
        try:
            from engine import attackgraph as ag
            tested = {f["payload"].get("tag") for f in board.facts
                      if f.get("kind") == "HYPOTHESIS"}
            doc = ag.build(board.facts,
                           ambient_events=ctx2.get("ambient_events") or (),
                           tested_tags=tested)
            ag.save(doc, out_dir)
            ag_stats = {"surface_nodes": len(doc["surface_map"]["nodes"]),
                        "surface_edges": len(doc["surface_map"]["edges"]),
                        "money_paths": len(doc["money_paths"]),
                        "next_actions": doc["next_actions"][:3]}
            ambient = ctx2.get("ambient_events") or []
            ambient_stats = {"events": len(ambient),
                             "unexplained": sum(1 for e in ambient
                                                if not e.get("attributed")),
                             "deltas": [{"tag": e.get("tag"),
                                         "delta": e.get("delta"),
                                         "attributed": e.get("attributed")}
                                        for e in ambient][:12]}
        except ImportError:                         # spine absent: v1 path
            pass

        # ----------------------------------------------- 7: artifacts -----
        summary = _assemble(board, router, ex, started, out_dir,
                            ctx.get("memory_dir",
                                    os.path.join(out_dir, "memory")),
                            mem_before, mem_after, llm, ledger_stats,
                            ag_stats, ambient_stats)
        summary["policy"] = policy.stats()
        summary["verify_pipeline"] = pipeline_report
        summary["experience_store"] = store.name
        # keep the refusal-note lineage visible in every summary
        summary["seam_note"] = _SEAM_NOTE
        return summary

    # ------------------------------------------------------------ insights --
    @staticmethod
    def _earn_insights(specialist, board, namespace):
        """M7 insight curation: only target-agnostic lessons, earned from
        this run's outcomes (A2: target-controlled content never promotes
        directly)."""
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


def _dedupe(findings):
    """Merge duplicate findings by (invariant, endpoint): keep the first,
    record who else found it (provenance merging). Endpoint templates are
    normalised ({vault_id} -> {id}) so two finders that name the same
    mechanism with different parameter names merge (M1: the window driver
    and the technique library both report settle/cancel classes)."""
    import re as _re
    out, index = [], {}
    for f in findings:
        fd = f["payload"]["finding"]
        key = (fd["invariant"],
               _re.sub(r"\{[^}]*\}", "{id}", fd["endpoint"]))
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
              mem_before, mem_after, llm, ledger_stats=None, ag_stats=None,
              ambient_stats=None):
    findings = _dedupe(board.query(kind="FINDING"))
    escalations = []
    postex_escalations = []
    for f in board.query(kind="ESCALATION"):
        if "postex" in (f.get("tags") or []):
            # M5 post-ex ladder evidence (amplification/persistence/
            # capability footprint) — measured, on verified work only
            postex_escalations.append(
                {"technique": f["payload"].get("technique"),
                 "payload": f["payload"].get("postex")})
            continue
        escalations.append({"chain": f["payload"]["chain"],
                            "impact": f["payload"]["impact"],
                            "severity": f["payload"]["severity"]})

    sf_requests = None
    sf_doc_path = os.path.join(out_dir, "statefuzz", "findings.json")
    if os.path.exists(sf_doc_path):
        sf_requests = json.load(open(sf_doc_path)).get("requests")

    doc = {"tool": "swarm", "version": "0.7.0-m4",
           "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "elapsed_s": round(time.time() - started, 1),
           "requests": ex.count,
           "statefuzz_sub_budget_requests": sf_requests,
           "rounds": router.rounds,
           "roster": [s.name for s in router.specialists],
           "spawn_events": router.spawn_events,
           "llm_seam_calls": llm.calls,
           "markers_registered": (ledger_stats or {}).get("stats", {})
           .get("by_tag", {}).get("marker", 0),
           "attack_graph": ag_stats,
           "ambient_watch": ambient_stats,
           "ledger": board.ledger(),
           "hypothesis_ledger": ledger_stats,
           "memory_before": mem_before, "memory_after": mem_after,
           "findings": findings, "escalations": escalations,
           "postex_escalations": postex_escalations}
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
            "hypothesis_ledger": ledger_stats,
            "markers_registered": (ledger_stats or {}).get("stats", {})
            .get("by_tag", {}).get("marker", 0),
            "attack_graph": ag_stats,
            "ambient_watch": ambient_stats,
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
            "postex_escalations": postex_escalations,
            "memory_before": mem_before, "memory_after": mem_after,
            "trace_file": os.path.join(out_dir, "dispatch_trace.jsonl"),
            "artifacts": {"findings": os.path.join(out_dir, "findings.json"),
                          "blackboard": os.path.join(out_dir,
                                                     "blackboard.json"),
                          "traffic": os.path.join(out_dir, "traffic.jsonl")}}

"""VerifyPipeline — findings earn their verdicts in exactly one place (G5, M4).

Before M4: the verify specialist ran inside the loop, but the end-of-run
weight pass trusted whatever status landed on the FINDING fact — a
candidate-only finding that nothing refuted still paid weight 0.25
"success" into the bandit, and nothing could DOWNGRADE it afterwards.

Now: one independent post-pass with one verdict vocabulary.

  confirmed              re-executed end-to-end with fresh principals (1.0)
  verified-by-transcript races/arbitrations proven from the recorded
                         transcript of the same run (0.5)
  not_reproducible       claim with no independent reproduction — DOWNGRADED
                         from candidate, cannot ship above informational,
                         trains the bandit as a mild failure (0.25)
  refuted                actively disproven — trains as failure (1.0)

Research basis (RESEARCH-M4.md R3):
  - MAST (arXiv:2503.13657, NeurIPS'25 spotlight): "task verification" is
    one of the three top-level failure categories of multi-agent LLM
    systems (14 modes, kappa = 0.88) — so verification is a named
    first-class mechanism here, not a courtesy.
  - EnIGMA (arXiv:2409.16165): documents "soliloquizing" — agents
    self-generating hallucinated observations. The only counter is
    re-execution against the environment (k-of-n, platform
    redteam/verify.py semantics); a claim nothing reproduced is not a
    finding.
  - NodeZero sells "proof of actual exploitability"; Keygraph PentestGPT
    "only findings with a working PoC are reported" — the commercial
    floor, matched here.
  - Mathematician's statement: a verdict is a reproducibility test
    (binomial k-of-n with stability), and the weight table is an
    evidence-strength scoring rule the bandit consumes (E4).
"""
from .blackboard import Fact  # noqa: F401  (re-exported for callers)


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


#: candidate/unproven statuses that the pipeline is allowed to downgrade.
_UNPROVEN = ("candidate", "unverified", "", None, "inconclusive")

#: verdict -> (curation outcome, weight). The ONE weight table (E4).
VERDICT_WEIGHTS = {
    "verified": ("success", 1.0),
    "confirmed": ("success", 1.0),              # platform vocabulary
    "verified-by-transcript": ("success", 0.5),
    "not_reproducible": ("failure", 0.25),
    "refuted": ("failure", 1.0),
}


class SwarmVerifyPipeline:
    """The prototype's verify pipeline: an end-of-run resolution pass over
    every FINDING fact + the curation-outcome rule. (Seam: the platform's
    k-of-n Check pipeline — redteam/verify.py — implements the same
    verdict contract with live re-execution.)"""

    name = "swarm-verify-pipeline"
    VERDICTS = ("confirmed", "verified", "verified-by-transcript",
                "not_reproducible", "refuted")

    # ------------------------------------------------------------- pass ----
    def resolve(self, board):
        """Post-loop pass over all FINDING facts.

        verified / verified-by-transcript / refuted are terminal verdicts
        — kept as-is. Anything unproven (candidate and friends) becomes
        not_reproducible and is severity-capped to informational: an
        unreproduced claim cannot ship as a real finding.

        Returns a report; mutates fact payloads BEFORE artifacts are
        assembled, so downstream consumers (findings.json, run scripts'
        GT classifiers) see post-pipeline truth.
        """
        report = {"pipeline": self.name,
                  "findings_seen": 0,
                  "terminal_kept": 0,
                  "downgraded_to_not_reproducible": [],
                  "note": ("unproven claims downgrade to not_reproducible "
                           "and cannot ship above informational")}
        for f in board.query(kind="FINDING"):
            report["findings_seen"] += 1
            fd = f["payload"].get("finding", {})
            st = f["payload"].get("status", "candidate")
            if st in ("verified", "verified-by-transcript", "refuted",
                      "confirmed"):
                report["terminal_kept"] += 1
                continue
            f["payload"]["status"] = "not_reproducible"
            if fd.get("severity") not in (None, "info"):
                fd["severity"] = "info"
                f["payload"]["severity_capped"] = True
            report["downgraded_to_not_reproducible"].append(fd.get("id"))
        report["downgrades"] = len(
            report["downgraded_to_not_reproducible"])
        return report

    # ---------------------------------------------------------- curation ---
    def curation_outcomes(self, specialist, board):
        """E4 outcome weights per technique, from resolved verdicts only.

        weight rule: verified 1.0 - verified-by-transcript 0.5 -
        not_reproducible -> mild failure 0.25 - refuted -> failure 1.0 -
        no facts -> failure 0.75.
        Poisoning guard (A2): read-side specialists (recon, surface_mapper)
        cap at 0.5 — their facts come from target-controlled content.
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
            # precedence preserved from the pre-M4 rule (verified > vbt >
            # refuted); the ONE intended D2 delta: unproven claims train as
            # a mild failure, never as success.
            if any(s == "verified" for s in statuses):
                o, w = "success", 1.0
            elif any(s == "confirmed" for s in statuses):
                o, w = "success", 1.0          # platform vocabulary
            elif any(s == "verified-by-transcript" for s in statuses):
                o, w = "success", 0.5
            elif any(s == "refuted" for s in statuses):
                o, w = "failure", 1.0
            else:
                # candidate / not_reproducible: unreproduced claim
                o, w = "failure", 0.25
            if specialist.name in ("recon", "surface_mapper"):
                w = min(w, 0.5)          # poisoning guard (A2)
            outcomes.append({"technique": tech, "outcome": o, "weight": w})
        return outcomes

"""The CREDITOR — deterministic collection on confirmed findings.

Live-fire gap this closes: a run proved a cross-tenant IDOR on the exact endpoint the
objective named, the verify pass confirmed it, and then... nothing happened. The
final record_access(held=true) linkage that would have turned the confirmed finding
into objective credit lived only in the model's head, and the model never made the
call — OBJECTIVE ACHIEVED had to be produced by hand afterward. A red team does not
leave billing to whoever just closed the deal; collection is someone's explicit job.

This module is that job, and it is DETERMINISTIC — no LLM decides whether a confirmed
finding counts. For every outstanding objective criterion whose `target` is matched by
a CONFIRMED finding's target (same containment rule claim_objective uses), it:

  1. holds the criterion's target in the access graph with source="verified_finding"
     (the same source the REQUIRED_SOURCE gate already trusts for data_access /
     host_access / flag kinds), then
  2. lets objective.autoevaluate() do the actual crediting, unchanged.

Hard limits, on purpose:
  - PRIVILEGE criteria are NEVER credited here. Their REQUIRED_SOURCE is
    prove_privilege only — a confirmed finding that an admin endpoint exists does not
    show the privilege boundary actually moved. The gate stays intact.
  - Only confirmed findings count. pending_verification findings are invisible to the
    creditor exactly as they are invisible to record_access(held=true).
  - Remediation state is respected (review round 2): a finding whose LATEST retest
    verdict is `fixed` is remediation proof — its confirmation stays on record
    (history intact) but it no longer demonstrates CURRENT exploitability, so it can
    never re-create the holding the retest-fixed bridge just revoked or earn fresh
    credit from stale proof. A newer `reproducible` retest re-establishes
    exploitability; a genuinely new demonstration always re-establishes the holding
    through the normal hold() path. latest_verdict() (retest.py) is the single read.
  - Idempotent: access.hold() merges on (kind, key), and criteria only ever move
    outstanding -> achieved, so re-running the sweep is a no-op.
"""

from __future__ import annotations

import datetime as _dt

from .objective import HOST_ACCESS, DATA_ACCESS, FLAG, PRIVILEGE, regex_match
from .retest import FIXED, latest_verdict


def _dt_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()

# Criterion kind -> access-graph node kind for the hold. FLAG is material we read,
# i.e. a resource. PRIVILEGE is deliberately absent (see module docstring).
_CRITERION_NODE_KIND = {
    DATA_ACCESS: "resource",
    HOST_ACCESS: "host",
    FLAG: "resource",
}

_CREDITABLE_KINDS = tuple(_CRITERION_NODE_KIND)


def _target_matches(criterion_target: str, finding_target: str) -> bool:
    """Same containment rule claim_objective applies — either direction, so a finding
    on 'http://host/api/records/42' matches criterion target 'records' and a finding
    on 'records' matches a criterion targeting the full URL."""
    if not criterion_target or not finding_target:
        return False
    return criterion_target in finding_target or finding_target in criterion_target


def _finding_proves(criterion, finding) -> str:
    """Why this confirmed finding satisfies this criterion — "" when it doesn't.

    Path 1 is the original containment rule on targets. Path 2 (live-fire
    2026-11-02, ladder-3) is the criterion's own evidence_regex scanned over the
    finding's target/title/summary/evidence: the agent chained the SSRF, captured
    FLAG{5f9e22b8}, the finding was independently confirmed — and still scored
    0/1 because the finding's target was the fetcher URL while the criterion's
    target was the symbolic key 'flag', which containment matches neither way.
    The regex is the engagement author's declaration of what proof LOOKS like,
    and a confirmed finding is already past the verify gate — matching it is
    evidence collection, not label-trust. Returns the matched snippet."""
    if _target_matches(criterion.target, finding.target):
        return finding.target
    return regex_match(criterion.evidence_regex,
                       finding.target, finding.title, finding.summary, finding.evidence)


def credit_confirmed_findings(ctx, objective=None, access=None) -> list[dict]:
    """Sweep confirmed findings into access holds + objective credit. Returns the list
    of credit events applied this call: [{criterion, finding, kind, target, evidence}].

    Never raises for missing objective/access — the creditor simply collects nothing.
    Emits a 'credit.applied' event per criterion when an event bus is attached.
    Findings whose latest retest verdict is FIXED are excluded (see the module
    docstring): the remediated proof must not resurrect a revoked holding."""
    objective = objective if objective is not None else getattr(ctx, "objective", None)
    access = access if access is not None else getattr(ctx, "access", None)
    findings = getattr(ctx, "findings", None)
    if objective is None or access is None or findings is None:
        return []

    confirmed = [f for f in findings.all()
                 if f.confidence == "confirmed"
                 # historical confirmation (was it real?) and current
                 # exploitability (does it still reproduce?) are separate
                 # dimensions — the retest pipeline owns the second one
                 and latest_verdict(f) != FIXED]
    if not confirmed:
        return []

    applied: list[dict] = []
    for criterion in objective.outstanding():
        if criterion.kind not in _CREDITABLE_KINDS or not criterion.target:
            continue
        node_kind = _CRITERION_NODE_KIND[criterion.kind]
        # Already held (e.g. by record_access via verified_finding): the hold exists,
        # just let autoevaluate look at it again — no duplicate evidence write.
        already_held = any(n.held and n.key == criterion.target and n.kind == node_kind
                           for n in access.held())
        match = next((f for f in confirmed if _finding_proves(criterion, f)), None)
        if match is None:
            continue
        if not already_held:
            snippet = regex_match(criterion.evidence_regex,
                                  match.target, match.title, match.summary, match.evidence)
            evidence = (f"confirmed finding {match.id}: {match.title} "
                        f"({match.severity}) on {match.target}"
                        + (f" — evidence_regex match {snippet!r}" if snippet else ""))
            # Phase E2 (ADR-002): a STRUCTURED finding reference rides with the
            # hold, so the retest-fixed bridge can revoke exactly the holdings
            # this finding proved — without parsing the free-text evidence.
            # Same hold, same gate; purely additive provenance.
            access.hold(node_kind, criterion.target, evidence=evidence,
                        source="verified_finding",
                        attrs={"finding_id": match.id},
                        evidence_refs=[{
                            "evidence_id": f"finding-{match.id}",
                            "kind": "finding", "origin": "agent",
                            "source": "creditor",
                            "source_agent": "credit",
                            "artifact_ref": f"finding:{match.id}",
                            "summary": f"confirmed finding {match.id} on {match.target}",
                            "ts": _dt_now_iso(),
                        }])
        newly = objective.autoevaluate(access)
        for cid in newly:
            c = objective.get(cid)
            if c is not None and c.achieved:
                applied.append({"criterion": cid, "finding": match.id,
                                "kind": c.kind, "target": c.target,
                                "evidence": c.evidence})
                ctx.audit.record("credit.applied", criterion=cid, finding=match.id,
                                 kind=c.kind, target=c.target)
                bus = getattr(ctx, "events", None)
                if bus is not None:
                    try:
                        bus.emit("credit.applied", role="creditor", criterion=cid,
                                 finding=match.id, kind=c.kind, target=c.target)
                    except Exception:
                        pass
        # autoevaluate credits everything it can in one pass; break after the first
        # sweep that credited something for this criterion.
        if newly:
            break
    return applied

# Remediation-side invalidation deliberately does NOT live here. The single
# source of truth for "this finding's latest retest verdict is FIXED, so its
# holdings are no longer supported" is the retest bridge:
#   retest.latest_verdict(finding)   — the remediation-state read (used above)
#   retest.invalidate_after_fix(f, access=..., graph=...) — the revocation
#       itself, matched on the structured attrs["finding_id"] reference (never
#       free-text evidence parsing) and wired into retest_run() on FIXED.
# Flows that hold a finding store and an access graph call the bridge; the
# ACCESS prerequisite gate (orchestrator) honors the resulting timestamped,
# append-only record via revoked_nodes().

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
  - Idempotent: access.hold() merges on (kind, key), and criteria only ever move
    outstanding -> achieved, so re-running the sweep is a no-op.
"""

from __future__ import annotations

from .objective import HOST_ACCESS, DATA_ACCESS, FLAG, PRIVILEGE

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


def credit_confirmed_findings(ctx, objective=None, access=None) -> list[dict]:
    """Sweep confirmed findings into access holds + objective credit. Returns the list
    of credit events applied this call: [{criterion, finding, kind, target, evidence}].

    Never raises for missing objective/access — the creditor simply collects nothing.
    Emits a 'credit.applied' event per criterion when an event bus is attached.
    """
    objective = objective if objective is not None else getattr(ctx, "objective", None)
    access = access if access is not None else getattr(ctx, "access", None)
    findings = getattr(ctx, "findings", None)
    if objective is None or access is None or findings is None:
        return []

    confirmed = [f for f in findings.all() if f.confidence == "confirmed"]
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
        match = next((f for f in confirmed
                      if _target_matches(criterion.target, f.target)), None)
        if match is None:
            continue
        if not already_held:
            evidence = (f"confirmed finding {match.id}: {match.title} "
                        f"({match.severity}) on {match.target}")
            access.hold(node_kind, criterion.target, evidence=evidence,
                        source="verified_finding")
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

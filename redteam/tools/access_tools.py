"""Tools for operating on the ACCESS GRAPH and the OBJECTIVE.

These are what make the agent behave like an operator rather than a scanner. Instead of
only recording "a vulnerability exists here", it records **what it now holds** and **what
that unlocks** — and it can claim an objective criterion only with evidence.
"""

from __future__ import annotations

import json

from ..access import KINDS
from . import ToolContext


class RecordAccessTool:
    name = "record_access"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Record something you now HOLD (a session, credential, principal, host, or "
                "resource) or something you have merely DISCOVERED, and how one leads to "
                "another. This is your operator's map of the compromise — keep it current. "
                "held=true is NOT a self-label: it requires finding_id of an existing "
                "CONFIRMED finding (from verify_finding_independently) whose target matches "
                "`key`/`note`. Without that, held defaults to false — record the lead, then "
                "go prove it with confirm_finding/verify_vulnerability/prove_privilege and "
                "an independent re-check."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kind": {"type": "string", "enum": list(KINDS)},
                    "key": {"type": "string", "description": "Stable identifier, e.g. 'admin', 'prod-db', '10.0.0.5'."},
                    "held": {"type": "boolean", "description": "True only if access is demonstrated — requires finding_id."},
                    "finding_id": {"type": "string", "description": "A CONFIRMED finding id proving this. Required when held=true."},
                    "evidence": {"type": "string", "description": "What proves it (used only alongside finding_id)."},
                    "note": {"type": "string"},
                    "unlocks": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Edges from this node: [{relation, kind, key}] where "
                                       "relation is holds|authenticates_as|can_access|"
                                       "escalates_to|pivots_to|reveals.",
                    },
                },
                "required": ["kind", "key"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, kind: str, key: str, held: bool = False,
            finding_id: str = "", evidence: str = "", note: str = "",
            unlocks: list | None = None) -> str:
        if getattr(ctx, "access", None) is None:
            return "ERROR: access graph unavailable in this run."
        attrs = {"note": note} if note else {}

        if held:
            # Close the "run 13" hole: held=true can no longer be a bare label. It must
            # point at a finding that has already survived independent verification.
            finding = ctx.findings.get(finding_id) if finding_id else None
            if finding is None:
                return json.dumps({
                    "error": "held=true requires finding_id of an existing finding.",
                    "recorded": False,
                })
            if finding.confidence != "confirmed":
                return json.dumps({
                    "error": f"finding {finding_id!r} is {finding.confidence!r}, not confirmed — "
                             "it must survive verify_finding_independently first.",
                    "recorded": False,
                })
            node = ctx.access.hold(kind, key, evidence=evidence or f"via finding {finding_id}",
                                   attrs=attrs, source="verified_finding")
        else:
            node = ctx.access.observe(kind, key, attrs=attrs, source="agent")

        for edge in (unlocks or []):
            try:
                dst = ctx.access.observe(edge["kind"], edge["key"], source="agent")
                ctx.access.link(node.id, edge.get("relation", "can_access"), dst.id)
            except (KeyError, TypeError):
                continue
        ctx.audit.record("access.recorded", kind=kind, key=key, held=node.held,
                         finding_id=finding_id)
        return json.dumps({"recorded": node.id, "held": node.held,
                           "state": ctx.access.summary()})


class ClaimObjectiveTool:
    name = "claim_objective"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Claim that an objective success criterion has been MET. This is NOT a "
                "free-text assertion — you must reference a finding_id of a CONFIRMED "
                "finding (one that survived verify_finding_independently) whose target "
                "matches this criterion's target, or the access graph must already show "
                "the criterion's target as HELD (prefer letting autoevaluate credit it "
                "automatically; use this only when autoevaluate hasn't caught up). An "
                "unfounded claim is worse than no claim — it will be rejected, not recorded."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "criterion_id": {"type": "string"},
                    "finding_id": {"type": "string", "description": "A CONFIRMED finding proving this criterion."},
                    "evidence": {"type": "string", "description": "Concrete proof detail (redact secrets)."},
                },
                "required": ["criterion_id", "evidence"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, criterion_id: str, evidence: str, finding_id: str = "") -> str:
        objective = getattr(ctx, "objective", None)
        if objective is None:
            return "ERROR: no objective defined for this engagement."
        criterion = objective.get(criterion_id)
        if criterion is None:
            ids = ", ".join(x.id for x in objective.criteria) or "(none)"
            return f"ERROR: unknown criterion_id {criterion_id!r}. Known: {ids}"
        if criterion.achieved:
            return json.dumps({"criterion": criterion_id, "met": True, "already": True})

        # Require a real proof reference — no bare free-text claim can satisfy a criterion.
        proven = False
        detail = evidence
        if finding_id:
            finding = ctx.findings.get(finding_id)
            if finding is None:
                return f"ERROR: unknown finding_id {finding_id!r}."
            if finding.confidence != "confirmed":
                return json.dumps({
                    "error": f"finding {finding_id!r} is {finding.confidence!r}, not confirmed — "
                             "it must survive verify_finding_independently first.",
                    "met": False,
                })
            if criterion.target and finding.target and criterion.target not in finding.target \
                    and finding.target not in criterion.target:
                return json.dumps({
                    "error": f"finding {finding_id!r} targets {finding.target!r}, which does not "
                             f"match this criterion's target {criterion.target!r}.",
                    "met": False,
                })
            proven = True
            detail = f"{evidence} [finding {finding_id}: {finding.title}]"
        elif criterion.target and getattr(ctx, "access", None) is not None:
            # Fall back to the access graph: the target must already be demonstrably HELD.
            proven = ctx.access.reached(criterion.target)
            if proven:
                detail = f"{evidence} [access graph: {criterion.target} held]"

        if not proven:
            ctx.audit.record("objective.claim_rejected", criterion_id=criterion_id)
            return json.dumps({
                "criterion": criterion_id, "met": False,
                "error": "Rejected — no finding_id of a confirmed finding was given, and the "
                         "access graph does not yet show this criterion's target as held. "
                         "Prove it first (confirm_finding/verify_vulnerability/prove_privilege, "
                         "then verify_finding_independently), then claim it.",
            })

        c = objective.mark(criterion_id, detail)
        ctx.audit.record("objective.criterion_met", criterion_id=criterion_id,
                         achieved=objective.achieved, finding_id=finding_id)
        done, total = objective.progress()
        return json.dumps({"criterion": criterion_id, "met": True,
                           "progress": f"{done}/{total}",
                           "objective_achieved": objective.achieved})

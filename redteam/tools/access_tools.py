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
                "another. This is your operator's map of the compromise — keep it current, "
                "because your next move is chosen from it. Only set held=true when you have "
                "actually demonstrated the access."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kind": {"type": "string", "enum": list(KINDS)},
                    "key": {"type": "string", "description": "Stable identifier, e.g. 'admin', 'prod-db', '10.0.0.5'."},
                    "held": {"type": "boolean", "description": "True only if access is demonstrated."},
                    "evidence": {"type": "string", "description": "What proves it."},
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
            evidence: str = "", note: str = "", unlocks: list | None = None) -> str:
        if getattr(ctx, "access", None) is None:
            return "ERROR: access graph unavailable in this run."
        attrs = {"note": note} if note else {}
        if held:
            node = ctx.access.hold(kind, key, evidence=evidence, attrs=attrs, source="agent")
        else:
            node = ctx.access.observe(kind, key, attrs=attrs, source="agent")
        for edge in (unlocks or []):
            try:
                dst = ctx.access.observe(edge["kind"], edge["key"], source="agent")
                ctx.access.link(node.id, edge.get("relation", "can_access"), dst.id)
            except (KeyError, TypeError):
                continue
        ctx.audit.record("access.recorded", kind=kind, key=key, held=held)
        return json.dumps({"recorded": node.id, "held": node.held,
                           "state": ctx.access.summary()})


class ClaimObjectiveTool:
    name = "claim_objective"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Claim that an objective success criterion has been MET, with evidence. "
                "Only claim it when you can show the actual access or data — this is the "
                "measure the whole engagement is judged by, so an unfounded claim is worse "
                "than no claim."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "criterion_id": {"type": "string"},
                    "evidence": {"type": "string", "description": "Concrete proof (redact secrets)."},
                },
                "required": ["criterion_id", "evidence"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, criterion_id: str, evidence: str) -> str:
        objective = getattr(ctx, "objective", None)
        if objective is None:
            return "ERROR: no objective defined for this engagement."
        c = objective.mark(criterion_id, evidence)
        if c is None:
            ids = ", ".join(x.id for x in objective.criteria) or "(none)"
            return f"ERROR: unknown criterion_id {criterion_id!r}. Known: {ids}"
        ctx.audit.record("objective.criterion_met", criterion_id=criterion_id,
                         achieved=objective.achieved)
        done, total = objective.progress()
        return json.dumps({"criterion": criterion_id, "met": True,
                           "progress": f"{done}/{total}",
                           "objective_achieved": objective.achieved})

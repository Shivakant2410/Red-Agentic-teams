"""Workflow tools: recording findings and requesting human approval.

These don't touch the network. They let the agent capture results and pause for a
human decision on sensitive actions.
"""

from __future__ import annotations

from ..findings import Finding
from . import ToolContext


class RecordFindingTool:
    name = "record_finding"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Record a security finding. Only record findings you have concrete evidence "
                "for (a request/response pair, an observed behavior). Set confidence honestly."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "target": {"type": "string", "description": "The affected URL or endpoint."},
                    "summary": {"type": "string"},
                    "evidence": {"type": "string", "description": "Request/response snippet or observation."},
                    "recommendation": {"type": "string"},
                    "cwe": {"type": "string", "description": "Optional, e.g. CWE-89."},
                    "confidence": {"type": "string", "enum": ["tentative", "firm", "confirmed"]},
                },
                "required": ["title", "severity", "target", "summary", "evidence"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            evidence: str, recommendation: str = "", cwe: str = "",
            confidence: str = "tentative") -> str:
        finding = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence=evidence, recommendation=recommendation, cwe=cwe, confidence=confidence,
        ))
        ctx.audit.record("finding.recorded", id=finding.id, title=title, severity=severity,
                         target=target, confidence=confidence)
        return f"Recorded finding {finding.id} ({severity}): {title}"


class RequestApprovalTool:
    name = "request_approval"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Ask a human operator to approve a sensitive action before you attempt it "
                "(e.g. anything intrusive, destructive, or that changes server state). "
                "Returns APPROVED or DENIED. If DENIED, do not attempt the action."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "action": {"type": "string", "description": "Short label for the action."},
                    "details": {"type": "string", "description": "Exactly what you intend to do and why."},
                },
                "required": ["action", "details"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, action: str, details: str) -> str:
        approved = ctx.approve(action, {"details": details})
        ctx.audit.record("approval.decision", action=action, details=details, approved=approved)
        return "APPROVED" if approved else "DENIED"

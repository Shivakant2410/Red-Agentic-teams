"""Workflow tools: recording findings and requesting human approval.

These don't touch the network. They let the agent capture results and pause for a
human decision on sensitive actions.
"""

from __future__ import annotations

from ..events import safe_emit
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
                    "confidence": {"type": "string",
                                   "enum": ["tentative", "firm"],
                                   "description": "Only the independent verifier (k-of-n "
                                                  "differential with negative control) may "
                                                  "confirm; specialists record tentative or "
                                                  "firm evidence."},
                    "traffic_seq": {"type": "integer",
                                    "description": "Optional: seq of the traffic.jsonl row "
                                                   "holding this finding's wire evidence; a "
                                                   "verbatim decoded response quote is bound "
                                                   "to the finding (ARTEX)."},
                },
                "required": ["title", "severity", "target", "summary", "evidence"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            evidence: str, recommendation: str = "", cwe: str = "",
            confidence: str = "tentative", traffic_seq: int | None = None) -> str:
        # FindingStore authority (live-fire 20261118): a specialist asserting
        # "confirmed" must never reach the store as confirmed — confirmation is
        # owned exclusively by the independent verifier (FindingStore.promote /
        # verify_finding_independently). Anything else is downgraded to firm
        # and the attempt is audited so self-confirmation attempts stay visible.
        if confidence not in ("tentative", "firm"):
            ctx.audit.record("finding.self_confirm_downgraded", requested=confidence,
                             title=title, target=target)
            safe_emit(getattr(ctx, "events", None), "finding.self_confirm_downgraded",
                      requested=confidence, title=title, target=target)
            confidence = "firm"
        # ARTEX binding: bind the cited (or URL-matched) traffic row's verbatim
        # decoded response quote to the finding — report readers audit the wire.
        artex_refs: list = []
        try:
            from ..quotes import quote_evidence
            traffic_path = ctx.traffic.summary().get("path", "") \
                if ctx.traffic is not None else ""
            artex_refs, artex_line = quote_evidence(
                traffic_path, url=target, seq=traffic_seq)
            if artex_line:
                evidence = evidence + "\n" + artex_line
        except Exception:
            artex_refs = []   # honest absence; never a fabricated quote
        finding = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence=evidence, recommendation=recommendation, cwe=cwe, confidence=confidence,
            evidence_refs=artex_refs,
        ))
        ctx.audit.record("finding.recorded", id=finding.id, title=title, severity=severity,
                         target=target, confidence=confidence)
        safe_emit(getattr(ctx, "events", None), "finding.recorded", id=finding.id,
                  title=title, severity=severity, confidence=confidence)
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

"""grade_evidence — bind a finding to a recorded exchange and grade its POE.

After a worker records a finding, it binds that finding to the specific captured
traffic exchange (by seq) and supplies verbatim quotes proving the claim. This
tool re-reads the bound exchange from the run's traffic store and checks each
quote LITERALLY against it (request + response, already gzip-decoded). A quote
the model claimed but that is not actually in the exchange means the finding is
unproven on the wire — the finding's poe_level reflects exactly that, so a
report shows proof strength next to verification status.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from ..poe import grade
from . import ToolContext


class GradeEvidenceTool:
    name = "grade_evidence"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Bind a finding to the exact recorded traffic exchange that proves "
                "it and grade its proof-of-evidence (POE). Give the finding_id, the "
                "traffic seq (evidence_ref — from proxy_history / browser_requests / "
                "the extension), and the VERBATIM quotes that must appear in that "
                "exchange. The quotes are checked literally against the stored "
                "(gzip-decoded) request+response; poe3 = all quotes in the RESPONSE "
                "body (strongest), poe2 = in request/headers only, poe1 = partial, "
                "poe0 = a claimed quote is absent (unproven — fix the quote or the "
                "finding). Does not change verification state; it records wire-"
                "evidence strength."),
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "evidence_ref": {"type": "integer",
                                     "description": "traffic.jsonl seq the claim is bound to."},
                    "quotes": {"type": "array", "items": {"type": "string"},
                               "description": "Verbatim strings that must appear in the exchange."},
                },
                "required": ["finding_id", "evidence_ref", "quotes"],
            },
            "strict": False,
        }

    def run(self, ctx: ToolContext, finding_id: str, evidence_ref: int,
            quotes: list) -> str:
        if ctx.findings is None:
            return "ERROR: no finding store in this run."
        f = next((x for x in ctx.findings.all() if x.id == finding_id), None)
        if f is None:
            return f"ERROR: no finding {finding_id!r}."
        traffic = getattr(ctx, "traffic", None)
        traffic_path = getattr(traffic, "_path", None) if traffic is not None else None
        if traffic_path is None:
            return "ERROR: no traffic store to grade against in this run."

        res = grade(traffic_path, int(evidence_ref), list(quotes or []))
        # Stamp the finding with its wire-evidence binding + grade.
        f.evidence_ref = int(evidence_ref)
        f.quotes = list(quotes or [])
        f.poe_level = res.level
        f.poe_note = res.note
        ctx.audit.record("poe.graded", finding_id=finding_id, evidence_ref=evidence_ref,
                         poe_level=res.level, matched=len(res.matched),
                         missing=len(res.missing))
        out = asdict(res)
        out["finding_id"] = finding_id
        if res.level in ("poe0", "poe1"):
            out["note"] = (res.note + " — this finding is NOT proven on the wire; "
                           "fix the quote(s) to match the real exchange, or bind the "
                           "correct exchange, or drop the claim.")
        return json.dumps(out)

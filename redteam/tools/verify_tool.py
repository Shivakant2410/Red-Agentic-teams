"""verify_vulnerability — the general, agent-designed verification primitive.

The agent supplies the finding metadata, a set of named requests, and the conditions that
prove the vulnerability. We fetch each request (scope-checked, session-applied), evaluate
the conditions deterministically k-of-n, and record a CONFIRMED finding only if the proof
reproduces. This replaces the rigid marker tools: the agent decides *how* to prove any
class (IDOR, XSS, access control, injection, timing), the check stays a hard oracle.
"""

from __future__ import annotations

import json

from ..falsify import FALSIFIED, run_negative_control
from ..findings import Finding
from ..knowledge import ENDPOINT
from ..proof import ProofCheck
from ..scope import ScopeViolation
from ..verify import verify
from . import ToolContext
from .http import make_fetch


def _session_headers(ctx: ToolContext, label, base):
    base = dict(base or {})
    if label and ctx.sessions is not None:
        s = ctx.sessions.get(label)
        if s is not None:
            return s.apply(base)
    return base


class VerifyVulnerabilityTool:
    name = "verify_vulnerability"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove a vulnerability with a check YOU design, then record it if it "
                "reproduces. Provide finding metadata, a set of named requests, and the "
                "conditions that must all hold to demonstrate the bug. Conditions:\n"
                "  status         {request, equals}\n"
                "  body_regex     {request, pattern, present}\n"
                "  latency_delta  {request_a, request_b, min_delta}   (blind/time-based)\n"
                "  json_differs   {request_a, request_b, json_path}   (IDOR: reached a different valid object)\n"
                "  reflected_unescaped {request, token}               (reflected XSS: token echoed un-escaped)\n"
                "Examples: IDOR = fetch your own object and another id, assert payload status 200 "
                "and json_differs on the id/owner. XSS = request with a unique token like <rtx931> "
                "in a param, assert reflected_unescaped. Only reproduced proofs are recorded."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "target": {"type": "string"},
                    "summary": {"type": "string"},
                    "cwe": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "requests": {
                        "type": "object",
                        "description": "Named requests, e.g. {\"baseline\":{...},\"payload\":{...}}. "
                                       "Each: {method,url,headers,body,session_label}.",
                    },
                    "conditions": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of conditions; ALL must hold for the proof to pass.",
                    },
                    "negative_control": {
                        "type": "object",
                        "description": "STRONGLY RECOMMENDED. A BENIGN version of the attack "
                                       "request (same endpoint, harmless input). The finding is "
                                       "only recorded if the control does NOT produce the same "
                                       "signal — this proves the effect is attack-caused.",
                    },
                    "control_replaces": {"type": "string",
                                         "description": "Which named request the control stands in for (default 'payload')."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["title", "severity", "target", "summary", "requests", "conditions"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            requests: dict, conditions: list, cwe: str = "", recommendation: str = "",
            negative_control: dict | None = None, control_replaces: str = "payload",
            trials: int = 4, need: int = 3) -> str:
        if not requests or not conditions:
            return "ERROR: provide at least one request and one condition."
        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))

        # Build a scope-checked, session-applied fetcher per named request.
        fetchers = {}
        try:
            for name, spec in requests.items():
                if not isinstance(spec, dict) or "url" not in spec:
                    return f"ERROR: request {name!r} must be an object with a url."
                headers = _session_headers(ctx, spec.get("session_label"), spec.get("headers"))
                req = {"method": spec.get("method", "GET"), "url": spec["url"],
                       "headers": headers, "body": spec.get("body")}
                fetchers[name] = make_fetch(ctx, req)   # scope-checks the url here
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        try:
            result = verify(ProofCheck(fetchers, conditions), trials=trials, need=need)
        except KeyError as exc:
            return f"ERROR in proof design: {exc}"
        except Exception as exc:
            return f"ERROR evaluating proof: {exc}"

        ctx.audit.record("verify_vuln.result", title=title, cwe=cwe, verdict=result.verdict,
                         reproductions=result.reproductions, trials=result.trials)
        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "recorded": False,
                               "reproductions": result.reproductions, "trials": result.trials,
                               "details": result.details,
                               "note": "proof did not reproduce; refine requests/conditions or drop it."})

        # Adversarial falsification: a benign control must NOT produce the same signal.
        # This is still run here because an obviously-falsified claim should never even
        # reach pending (no sense queuing a dead finding for independent re-check), but
        # a PASSING control at this stage is only self-administered evidence — it does
        # not promote the finding. Only tools/independent_verify.py, run in a separate
        # context, may set confidence="confirmed".
        control_note = "no negative control supplied (weaker evidence — independent re-check will try one)"
        if negative_control:
            try:
                c_headers = _session_headers(ctx, negative_control.get("session_label"),
                                             negative_control.get("headers"))
                c_req = {"method": negative_control.get("method", "GET"),
                         "url": negative_control["url"], "headers": c_headers,
                         "body": negative_control.get("body")}
                control_fetch = make_fetch(ctx, c_req)
            except (ScopeViolation, KeyError) as exc:
                return f"BLOCKED/ERROR building negative control: {exc}"
            fal = run_negative_control(fetchers, conditions, control_fetch, control_replaces)
            ctx.audit.record("verify_vuln.falsification", title=title,
                             falsified=fal.falsified, detail=fal.detail)
            if fal.falsified:
                return json.dumps({
                    "verdict": FALSIFIED, "recorded": False, "detail": fal.detail,
                    "control_details": fal.details,
                    "note": "The benign control produced the same signal — this is NOT a "
                            "vulnerability. Find evidence that only the attack produces."})
            control_note = fal.detail

        poc = "; ".join(f"{n}: {s.get('method','GET')} {s.get('url','')}" for n, s in requests.items())
        check_spec = {"requests": requests, "conditions": conditions,
                      "negative_control": negative_control, "control_replaces": control_replaces}
        f = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence="\n".join(result.details) + "\nControl: " + control_note,
            recommendation=recommendation, cwe=cwe,
            confidence="pending_verification", verification_verdict=result.verdict,
            reproductions=result.reproductions, trials=result.trials, poc=poc,
            check_type="proof", check_spec=check_spec))
        if ctx.graph is not None:
            ctx.graph.observe(ENDPOINT, target, attrs={"finding": title}, source="verify_vulnerability")

        return json.dumps({"verdict": "pending_verification", "recorded": True, "finding_id": f.id,
                           "reproductions": result.reproductions, "trials": result.trials,
                           "control": control_note,
                           "note": "Does not count yet — an independent re-check must reproduce "
                                   "this before it is CONFIRMED, credited, or saved as a skill."})

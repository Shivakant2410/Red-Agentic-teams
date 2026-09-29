"""apply_skill — re-run a PROVEN proof against a new target by filling in parameters.

This is the execution-gap fix. Instead of asking a weak model to design a multi-step
differential proof from scratch (which run 9 showed it cannot do), it picks a skill that
already worked and supplies the URLs. Design becomes substitution.

The proof still runs through the same deterministic verifier and negative-control
falsification, so reuse never weakens the evidence standard.
"""

from __future__ import annotations

import json

from ..falsify import FALSIFIED, run_negative_control
from ..findings import Finding
from ..knowledge import ENDPOINT
from ..proof import ProofCheck
from ..scope import ScopeViolation
from ..skills import substitute
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


class ApplySkillTool:
    name = "apply_skill"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Re-run a PROVEN proof (a skill from the skill library) against a new target "
                "by supplying its parameters. Prefer this over designing a new proof: the "
                "skill's request structure and conditions already worked. The listed skills "
                "and their required params appear in your [PROVEN SKILLS] briefing. Provide "
                "params as {param_name: value}, e.g. {\"baseline_url\": \"...\", \"payload_url\": \"...\"}."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "skill_id": {"type": "string"},
                    "params": {"type": "object", "description": "Values for the skill's placeholders."},
                    "title": {"type": "string", "description": "Finding title if it confirms."},
                    "target": {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "summary": {"type": "string"},
                    "session_label": {"type": "string",
                                      "description": "Optional stored session to authenticate the requests."},
                    "negative_control": {"type": "object",
                                         "description": "Optional benign control request (recommended)."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["skill_id", "params", "title", "target"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, skill_id: str, params: dict, title: str, target: str,
            severity: str = "high", summary: str = "", session_label: str | None = None,
            negative_control: dict | None = None, trials: int = 4, need: int = 3) -> str:
        if ctx.skills is None:
            return "ERROR: skill library unavailable in this run."
        skill = ctx.skills.get(skill_id)
        if skill is None:
            available = ", ".join(s.id for s in ctx.skills.all()[:5]) or "(none)"
            return f"ERROR: unknown skill_id {skill_id!r}. Available: {available}"

        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))
        try:
            concrete = substitute(skill.requests, params or {})
        except KeyError as exc:
            return (f"ERROR: {exc}. This skill needs params: {', '.join(skill.params)}")

        fetchers = {}
        try:
            for name, spec in concrete.items():
                headers = _session_headers(ctx, session_label or spec.get("session_label"),
                                           spec.get("headers"))
                req = {"method": spec.get("method", "GET"), "url": spec["url"],
                       "headers": headers, "body": spec.get("body")}
                fetchers[name] = make_fetch(ctx, req)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        except KeyError as exc:
            return f"ERROR: malformed skill request ({exc})"

        try:
            result = verify(ProofCheck(fetchers, skill.conditions), trials=trials, need=need)
        except Exception as exc:
            return f"ERROR running skill: {exc}"
        ctx.audit.record("apply_skill.result", skill_id=skill_id, verdict=result.verdict,
                         reproductions=result.reproductions, trials=result.trials)

        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "recorded": False,
                               "reproductions": result.reproductions, "trials": result.trials,
                               "note": "the proven skill did not reproduce here — this target "
                                       "is likely not vulnerable to it."})

        control_note = "no negative control supplied (weaker evidence)"
        if negative_control:
            try:
                c_req = {"method": negative_control.get("method", "GET"),
                         "url": negative_control["url"],
                         "headers": _session_headers(ctx, session_label, negative_control.get("headers")),
                         "body": negative_control.get("body")}
                fal = run_negative_control(fetchers, skill.conditions, make_fetch(ctx, c_req), "payload")
            except (ScopeViolation, KeyError) as exc:
                return f"BLOCKED/ERROR building negative control: {exc}"
            ctx.audit.record("apply_skill.falsification", skill_id=skill_id, falsified=fal.falsified)
            if fal.falsified:
                return json.dumps({"verdict": FALSIFIED, "recorded": False, "detail": fal.detail})
            control_note = fal.detail

        f = ctx.findings.add(Finding(
            title=title, severity=severity, target=target,
            summary=summary or skill.description,
            evidence="\n".join(result.details) + "\nControl: " + control_note,
            cwe=skill.cwe, confidence="confirmed", verification_verdict=result.verdict,
            reproductions=result.reproductions, trials=result.trials,
            poc=f"skill '{skill.name}' applied with {json.dumps(params)}"))
        skill.successes += 1
        ctx.skills._flush()
        if ctx.graph is not None:
            ctx.graph.observe(ENDPOINT, target, attrs={"finding": title}, source="apply_skill")
        return json.dumps({"verdict": "confirmed", "recorded": True, "finding_id": f.id,
                           "skill_id": skill_id, "control": control_note})

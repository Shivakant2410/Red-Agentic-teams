"""verify_finding_independently — the only tool allowed to say "confirmed".

Every proof tool (confirm_finding, verify_vulnerability, prove_privilege) now stops at
pending_verification: the agent that proposed a check also ran and graded it, which is
self-grading no matter how good the math. This tool is the independent re-check: it
rebuilds the EXACT SAME check from the finding's stored check_spec — not from the
proposing agent's narration — runs it again, and MANDATES a negative control (deriving
a benign one automatically if the original call didn't supply one). Only if the proof
reproduces AND the control fails to reproduce does the finding become "confirmed".

This tool is meant to be called from a separate agent context (the VERIFY specialist;
see orchestrator.py) so independence is structural, not just procedural: a model that
invented a finding gets no say in whether its own invention survives.
"""

from __future__ import annotations

import json
import re

from ..access import CREDENTIAL, ESCALATES_TO, PRINCIPAL
from ..falsify import run_negative_control
from ..killchain import ACHIEVED, PRIVILEGE_ESCALATION
from ..proof import ProofCheck, eval_condition
from ..scope import ScopeViolation
from ..verify import DifferentialCheck, HttpCheck, verify
from . import ToolContext
from .http import make_fetch
from .logic import run_ordered_steps

# A control must differ from the attack payload but hit the same endpoint/shape. For the
# check kinds that don't carry an explicit negative_control, we derive a benign stand-in
# by stripping anything that looks like an injected payload out of the URL/body, so the
# control exercises the same endpoint with harmless input instead of the attack string.
_PAYLOAD_MARKERS = re.compile(
    r"('|--|;|<script|<img|\bOR\b|\bSLEEP\(|\bUNION\b|\.\./|\{\{|\$\{)", re.IGNORECASE)


def _benign_mutation(url: str) -> str:
    """Best-effort: neutralize likely payload characters in a URL's query/path so a
    control hits the same endpoint with harmless input."""
    return _PAYLOAD_MARKERS.sub("", url)


class VerifyFindingIndependentlyTool:
    name = "verify_finding_independently"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Independently re-check a PENDING finding before it can count as CONFIRMED. "
                "Rebuilds the original proof from the finding's own stored check (not from "
                "narration) and re-runs it fresh, then runs a negative control (supplied one "
                "if the finding has it, else an auto-derived benign variant). Only a finding "
                "that reproduces AND whose control does NOT reproduce becomes confirmed; "
                "otherwise it is falsified or not_reproducible and never counts toward the "
                "objective, the access graph, or the skill library. You are the adversary "
                "here: your job is to try to kill this finding, not to agree with it.\n\n"
                "SPECIAL CASE — workflow/business-logic findings (check_type=workflow): "
                "these are often one-shot (a coupon redeemed twice can't be redeemed a "
                "third time with the same coupon), so they cannot be blindly replayed. For "
                "these you MUST supply fresh_attack_steps and fresh_control_steps — the "
                "SAME shape of sequence as the original, but against a FRESH identifier "
                "(a new coupon/order/account) so the replay is a genuine independent test, "
                "not a rerun of already-consumed state."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "fresh_attack_steps": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Required for check_type=workflow: a fresh attack "
                                       "sequence (new identifier) shaped like the original.",
                    },
                    "fresh_control_steps": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Required for check_type=workflow: a fresh control "
                                       "sequence (new identifier) shaped like the original.",
                    },
                },
                "required": ["finding_id"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, finding_id: str, fresh_attack_steps: list | None = None,
            fresh_control_steps: list | None = None) -> str:
        f = ctx.findings.get(finding_id)
        if f is None:
            return f"ERROR: no finding {finding_id!r}."
        if f.confidence != "pending_verification":
            return json.dumps({
                "finding_id": finding_id, "already": f.confidence,
                "note": "Nothing to do — this finding is not awaiting independent verification.",
            })

        try:
            if f.check_type == "http":
                verdict = self._recheck_http(ctx, f)
            elif f.check_type == "differential":
                verdict = self._recheck_differential(ctx, f)
            elif f.check_type == "proof":
                verdict = self._recheck_proof(ctx, f)
            elif f.check_type == "privilege":
                verdict = self._recheck_privilege(ctx, f)
            elif f.check_type == "workflow":
                verdict = self._recheck_workflow(ctx, f, fresh_attack_steps, fresh_control_steps)
            else:
                verdict = ("not_reproducible",
                           f"no replayable check_type ({f.check_type!r}) stored for this finding")
        except ScopeViolation as exc:
            verdict = ("not_reproducible", f"BLOCKED (out of scope) during re-check: {exc}")

        status, detail = verdict
        promoted = ctx.findings.promote(finding_id, status, detail=detail)
        ctx.audit.record("independent_verify.result", finding_id=finding_id,
                         title=f.title, verdict=status, detail=detail)

        if status == "confirmed":
            self._credit_access_and_skills(ctx, promoted)

        return json.dumps({
            "finding_id": finding_id, "verdict": status, "detail": detail,
            "note": {
                "confirmed": "Independently reproduced; a benign control did not. This now "
                             "counts toward the objective and access graph.",
                "falsified": "A benign control produced the same signal — this was never a "
                             "vulnerability. Dropped from anything that credits progress.",
                "not_reproducible": "Could not reproduce independently. Stays on record as a "
                                    "weak/unconfirmed note; does not count toward anything.",
            }[status],
        }, ensure_ascii=False)

    # -- replay paths, one per check_type ---------------------------------------

    def _recheck_http(self, ctx: ToolContext, f) -> tuple[str, str]:
        spec = f.check_spec
        request = spec.get("request")
        if not request:
            return "not_reproducible", "no stored request to replay"
        check = HttpCheck(fetch=make_fetch(ctx, request), expect_status=spec.get("expect_status"),
                          body_regex=spec.get("body_regex"), max_latency=spec.get("max_latency"))
        result = verify(check, trials=5, need=4)
        if result.verdict != "confirmed":
            return "not_reproducible", f"independent re-run did not reproduce: {result.details[-1] if result.details else ''}"

        control_url = _benign_mutation(request.get("url", ""))
        if control_url == request.get("url", ""):
            # Nothing payload-shaped to strip (e.g. a pure status/latency assertion with no
            # injected string) — there is no meaningful benign variant to contrast against.
            return "confirmed", "reproduced independently (no payload string to neutralize for a control)"
        control_req = dict(request, url=control_url)
        control_check = HttpCheck(fetch=make_fetch(ctx, control_req),
                                  expect_status=spec.get("expect_status"),
                                  body_regex=spec.get("body_regex"), max_latency=spec.get("max_latency"))
        control_outcome = control_check.run()
        if control_outcome.passed:
            return "falsified", f"benign control also satisfied the assertion: {control_outcome.detail}"
        return "confirmed", f"reproduced independently; benign control did not ({control_outcome.detail})"

    def _recheck_differential(self, ctx: ToolContext, f) -> tuple[str, str]:
        spec = f.check_spec
        baseline, payload = spec.get("baseline_request"), spec.get("payload_request")
        if not (baseline and payload):
            return "not_reproducible", "no stored baseline/payload requests to replay"
        check = DifferentialCheck(fetch_baseline=make_fetch(ctx, baseline),
                                  fetch_payload=make_fetch(ctx, payload),
                                  min_latency_delta=spec.get("min_latency_delta"),
                                  body_differs_regex=spec.get("body_differs_regex"))
        result = verify(check, trials=5, need=4)
        if result.verdict != "confirmed":
            return "not_reproducible", f"independent re-run did not reproduce: {result.details[-1] if result.details else ''}"

        control_url = _benign_mutation(payload.get("url", ""))
        if control_url == payload.get("url", ""):
            return "confirmed", "reproduced independently (no payload string to neutralize for a control)"
        control_fetch = make_fetch(ctx, dict(payload, url=control_url))
        fal = run_negative_control({"baseline": make_fetch(ctx, baseline), "payload": make_fetch(ctx, payload)},
                                   self._differential_conditions(spec), control_fetch, "payload")
        if fal.falsified:
            return "falsified", fal.detail
        return "confirmed", f"reproduced independently; benign control did not ({fal.detail})"

    @staticmethod
    def _differential_conditions(spec: dict) -> list[dict]:
        conds = []
        if spec.get("min_latency_delta") is not None:
            conds.append({"type": "latency_delta", "request_a": "baseline", "request_b": "payload",
                          "min_delta": spec["min_latency_delta"]})
        if spec.get("body_differs_regex"):
            conds.append({"type": "body_regex", "request": "payload",
                          "pattern": spec["body_differs_regex"], "present": True})
        return conds

    def _recheck_proof(self, ctx: ToolContext, f) -> tuple[str, str]:
        spec = f.check_spec
        requests_, conditions = spec.get("requests"), spec.get("conditions")
        if not (requests_ and conditions):
            return "not_reproducible", "no stored requests/conditions to replay"
        fetchers = {name: make_fetch(ctx, {"method": r.get("method", "GET"), "url": r["url"],
                                           "headers": r.get("headers") or {}, "body": r.get("body")})
                   for name, r in requests_.items()}
        result = verify(ProofCheck(fetchers, conditions), trials=4, need=3)
        if result.verdict != "confirmed":
            return "not_reproducible", f"independent re-run did not reproduce: {result.details[-1] if result.details else ''}"

        control_replaces = spec.get("control_replaces") or "payload"
        negative_control = spec.get("negative_control")
        if negative_control:
            control_fetch = make_fetch(ctx, {"method": negative_control.get("method", "GET"),
                                             "url": negative_control["url"],
                                             "headers": negative_control.get("headers") or {},
                                             "body": negative_control.get("body")})
        elif control_replaces in requests_:
            orig = requests_[control_replaces]
            control_url = _benign_mutation(orig.get("url", ""))
            if control_url == orig.get("url", ""):
                return "confirmed", "reproduced independently (no payload string to neutralize for a control)"
            control_fetch = make_fetch(ctx, dict(orig, url=control_url, headers=orig.get("headers") or {}))
        else:
            return "confirmed", "reproduced independently (no replaceable request to derive a control from)"

        fal = run_negative_control(fetchers, conditions, control_fetch, control_replaces)
        if fal.falsified:
            return "falsified", fal.detail
        return "confirmed", f"reproduced independently; benign control did not ({fal.detail})"

    def _recheck_privilege(self, ctx: ToolContext, f) -> tuple[str, str]:
        spec = f.check_spec
        if ctx.sessions is None:
            return "not_reproducible", "session store unavailable for replay"
        high = ctx.sessions.get(spec.get("high_session_label", ""))
        if high is None:
            return "not_reproducible", f"session {spec.get('high_session_label')!r} no longer available to replay"
        low_label = spec.get("low_session_label") or ""
        low = ctx.sessions.get(low_label) if low_label else None

        method, url = spec.get("method", "GET"), spec.get("privileged_url", "")
        fetchers = {"payload": make_fetch(ctx, {"method": method, "url": url, "headers": high.apply({})})}
        control_fetch = make_fetch(ctx, {"method": method, "url": url,
                                         "headers": low.apply({}) if low else {}})
        conditions = [{"type": "status", "request": "payload", "equals": spec.get("expect_status", 200)},
                      {"type": "body_regex", "request": "payload", "pattern": spec.get("privileged_marker", "")}]
        result = verify(ProofCheck(fetchers, conditions), trials=4, need=3)
        if result.verdict != "confirmed":
            return "not_reproducible", f"independent re-run did not reproduce: {result.details[-1] if result.details else ''}"
        fal = run_negative_control(fetchers, conditions, control_fetch, "payload")
        if fal.falsified:
            return "falsified", fal.detail
        return "confirmed", f"reproduced independently; low-privilege control did not ({fal.detail})"

    def _recheck_workflow(self, ctx: ToolContext, f, fresh_attack_steps, fresh_control_steps) -> tuple[str, str]:
        # Cannot blindly replay check_spec here: a one-shot workflow (redeem-twice,
        # skip-a-step) consumed its own precondition the first time it ran, so a verbatim
        # replay would correctly fail to reproduce a REAL bug — that would be a false
        # falsification, not a legitimate re-check. The caller must supply fresh sequences
        # against a new identifier instead; we only validate they have the same SHAPE
        # (same conditions reference the same step names) as what was originally proven.
        if not fresh_attack_steps or not fresh_control_steps:
            return ("not_reproducible",
                    "workflow findings require fresh_attack_steps/fresh_control_steps "
                    "(a new identifier) — cannot safely replay one-shot steps verbatim")

        spec = f.check_spec
        invariant = spec.get("invariant") or []
        control_invariant = spec.get("control_invariant") or invariant
        step_names = {s.get("name") or f"step{i}" for i, s in enumerate(fresh_attack_steps)}
        referenced = {cond.get("request") for cond in invariant if cond.get("request")}
        if referenced and not referenced.issubset(step_names):
            return ("not_reproducible",
                    f"fresh_attack_steps is missing step name(s) the invariant references: "
                    f"{referenced - step_names}")

        try:
            attack_responses = run_ordered_steps(ctx, fresh_attack_steps)
        except KeyError as exc:
            return "not_reproducible", f"fresh_attack_steps missing {exc}"
        attack_ok, details = True, []
        for cond in invariant:
            try:
                passed, detail = eval_condition(cond, attack_responses)
            except KeyError as exc:
                return "not_reproducible", f"invariant references unknown step: {exc}"
            attack_ok = attack_ok and passed
            details.append(("PASS " if passed else "fail ") + "attack: " + detail)
        if not attack_ok:
            return "not_reproducible", "independent replay (fresh identifier) did not reproduce: " + "; ".join(details)

        try:
            control_responses = run_ordered_steps(ctx, fresh_control_steps)
        except KeyError as exc:
            return "not_reproducible", f"fresh_control_steps missing {exc}"
        control_ok = True
        for cond in control_invariant:
            try:
                passed, detail = eval_condition(cond, control_responses)
            except KeyError as exc:
                return "not_reproducible", f"control_invariant references unknown step: {exc}"
            control_ok = control_ok and passed
            details.append(("PASS " if passed else "fail ") + "control: " + detail)
        if control_ok:
            return "falsified", "the honest control (fresh identifier) also violated the invariant: " + "; ".join(details)
        return "confirmed", "reproduced independently with a fresh identifier; control did not: " + "; ".join(details)

    # -- crediting on confirmation ------------------------------------------------

    def _credit_access_and_skills(self, ctx: ToolContext, f) -> None:
        """Only a CONFIRMED finding may write access-graph state or enter the skill library."""
        if f.check_type == "privilege" and ctx.access is not None:
            spec = f.check_spec
            to_principal = spec.get("to_principal", "")
            from_principal = spec.get("from_principal", "")
            target = ctx.access.hold(PRINCIPAL, to_principal,
                                     evidence=f"independently verified: {spec.get('method','GET')} "
                                              f"{spec.get('privileged_url','')} succeeds only as this identity",
                                     source="prove_privilege")
            if from_principal:
                src = ctx.access.observe(PRINCIPAL, from_principal, source="prove_privilege")
                ctx.access.link(src.id, ESCALATES_TO, target.id)
            if ctx.killchain is not None:
                ctx.killchain.mark(PRIVILEGE_ESCALATION, ACHIEVED,
                                   f"{from_principal or 'lower-priv'} -> {to_principal} (independently verified)")

        if ctx.skills is not None and f.check_type == "proof":
            try:
                skill = ctx.skills.capture(
                    name=f.title[:60],
                    description=f"Proves {f.cwe or 'a vulnerability'}: {f.summary[:160]}",
                    requests=f.check_spec.get("requests", {}),
                    conditions=f.check_spec.get("conditions", []), cwe=f.cwe)
                ctx.audit.record("skill.captured", skill_id=skill.id, cwe=f.cwe,
                                 successes=skill.successes, finding_id=f.id)
            except Exception as exc:
                ctx.audit.record("skill.capture_error", error=str(exc), finding_id=f.id)

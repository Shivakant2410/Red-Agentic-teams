"""verify_workflow_abuse — proving business-logic bugs (the class every scanner misses).

Injection, IDOR, access control, and XSS all have a stable, re-runnable signal: send the
same payload again and the same signal comes back, which is exactly what k-of-n
reproduction (verify.py) is built to check. Business-logic bugs do not have that shape —
redeeming a one-time coupon, double-submitting a payment, or skipping a required workflow
step is often only exploitable ONCE per identifier. Running the same attack 5 times either
needs 5 fresh coupons or fails trials 2-5 by construction, not because the bug isn't real.

So the proof here is structurally different: run an ORDERED sequence of requests once
(the attack), run a second ORDERED sequence once (the control — the same workflow done
honestly, ideally against a fresh/different identifier), and assert an invariant that the
attack sequence violates and the control sequence does not. Single run, not k-of-n — but
still never self-graded: like every other proof tool, this lands as pending_verification,
and only verify_finding_independently (replaying both sequences completely fresh) may
promote it to confirmed.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from ..findings import Finding
from ..proof import eval_condition
from ..scope import ScopeViolation
from . import ToolContext
from .http import fetch_once


def _session_headers(ctx: ToolContext, label, base):
    base = dict(base or {})
    if label and ctx.sessions is not None:
        s = ctx.sessions.get(label)
        if s is not None:
            return s.apply(base)
    return base


def run_ordered_steps(ctx: ToolContext, steps: list[dict]) -> dict:
    """Execute named steps IN ORDER (each may depend on the previous having happened —
    e.g. redeem, then redeem-again). Returns {name: (status, body, elapsed, headers)}."""
    responses = {}
    for i, spec in enumerate(steps):
        name = spec.get("name") or f"step{i}"
        headers = _session_headers(ctx, spec.get("session_label"), spec.get("headers"))
        req = {"method": spec.get("method", "GET"), "url": spec["url"],
              "headers": headers, "body": spec.get("body")}
        status, body, elapsed, resp_headers = fetch_once(ctx, req)
        responses[name] = (status, body, elapsed, resp_headers)
    return responses


def run_burst(ctx: ToolContext, spec: dict, count: int) -> list[tuple]:
    """Fire the SAME request `count` times as close to simultaneously as possible
    — the TOCTOU / race primitive. All threads block on a barrier and release
    together so the requests hit the server inside the same check-to-use window;
    whichever sequential single-shot predicate would see "one success" then sees
    several if the window is racable. Returns a list of response tuples.

    Scope is enforced per request by fetch_once (same path as every other
    fetch), so a burst cannot reach anything a single request could not.
    """
    count = max(2, min(int(count), 30))   # at least 2 to race; capped (OPSEC)
    headers = _session_headers(ctx, spec.get("session_label"), spec.get("headers"))
    req = {"method": spec.get("method", "GET"), "url": spec["url"],
           "headers": headers, "body": spec.get("body")}
    barrier = threading.Barrier(count)
    results: list[tuple] = [None] * count  # type: ignore[list-item]

    def _one(i: int):
        try:
            barrier.wait(timeout=20)       # release all threads together
        except threading.BrokenBarrierError:
            pass
        results[i] = fetch_once(ctx, req)

    with ThreadPoolExecutor(max_workers=count) as pool:
        list(pool.map(_one, range(count)))
    return [r for r in results if r is not None]


class VerifyWorkflowAbuseTool:
    name = "verify_workflow_abuse"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove a BUSINESS-LOGIC bug: price tampering, a race condition, skipping a "
                "required workflow step, or reusing a one-time action. Unlike "
                "confirm_finding/verify_vulnerability, this is NOT re-run k-of-n — business "
                "logic is usually a ONE-SHOT exploit (a coupon redeemed twice can't be "
                "'reproduced' a third time with the same coupon). Instead you give TWO "
                "ordered step sequences, each run exactly once in order:\n"
                "  attack_steps:  the sequence that should NOT be possible (e.g. [checkout "
                "with coupon, checkout AGAIN with the same coupon]).\n"
                "  control_steps: the SAME workflow done correctly, ideally against a fresh "
                "identifier (a different coupon/order/account) — this is your negative "
                "control. It must NOT trigger the invariant.\n"
                "`invariant` is a condition (same DSL as verify_vulnerability: status, "
                "body_regex, json_differs, ...) evaluated against the step responses by "
                "name. It must HOLD on the attack sequence and NOT hold on the control — "
                "e.g. the second redemption in attack_steps still returning success, while "
                "the control's single redemption also succeeds but there is no second one "
                "to compare against (use a dedicated absent-on-control condition, or make "
                "the control intentionally invalid on its second step so you can contrast "
                "'attack: step2 succeeded' vs 'control: step2 correctly rejected')."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "target": {"type": "string"},
                    "summary": {"type": "string"},
                    "cwe": {"type": "string", "description": "Default CWE-840 (business logic errors) if omitted."},
                    "recommendation": {"type": "string"},
                    "attack_steps": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Ordered [{name, method, url, headers, body, session_label}], "
                                       "run once in order. The exploit sequence.",
                    },
                    "control_steps": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Ordered steps for the honest/correct workflow — your negative control.",
                    },
                    "invariant": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Conditions that must ALL hold against attack_steps' "
                                       "responses (named by step `name`) to prove the abuse.",
                    },
                    "control_invariant": {
                        "type": "array", "items": {"type": "object"},
                        "description": "Conditions against control_steps' responses. If these "
                                       "ALSO all hold, the finding is FALSIFIED — the behavior "
                                       "exists for the honest workflow too, so it isn't abuse. "
                                       "Defaults to the same conditions as `invariant` evaluated "
                                       "against control_steps' responses if omitted.",
                    },
                },
                "required": ["title", "severity", "target", "summary", "attack_steps",
                            "control_steps", "invariant"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            attack_steps: list, control_steps: list, invariant: list,
            cwe: str = "", recommendation: str = "", control_invariant: list | None = None) -> str:
        if not attack_steps or not control_steps or not invariant:
            return "ERROR: provide attack_steps, control_steps, and invariant."

        try:
            attack_responses = run_ordered_steps(ctx, attack_steps)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope) in attack_steps: {exc}"
        except KeyError as exc:
            return f"ERROR: attack step missing {exc}."

        details, attack_ok = [], True
        for cond in invariant:
            try:
                passed, detail = eval_condition(cond, attack_responses)
            except KeyError as exc:
                return f"ERROR in invariant: {exc}"
            attack_ok = attack_ok and passed
            details.append(("PASS " if passed else "fail ") + "attack: " + detail)

        if not attack_ok:
            ctx.audit.record("workflow_abuse.result", title=title, verdict="not_reproducible")
            return json.dumps({
                "verdict": "not_reproducible", "recorded": False, "details": details,
                "note": "The invariant did not hold against the attack sequence — the "
                        "abuse did not happen. Refine the steps/invariant or drop it.",
            })

        try:
            control_responses = run_ordered_steps(ctx, control_steps)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope) in control_steps: {exc}"
        except KeyError as exc:
            return f"ERROR: control step missing {exc}."

        control_conds = control_invariant if control_invariant is not None else invariant
        control_ok = True
        for cond in control_conds:
            try:
                passed, detail = eval_condition(cond, control_responses)
            except KeyError as exc:
                return f"ERROR in control_invariant: {exc}"
            control_ok = control_ok and passed
            details.append(("PASS " if passed else "fail ") + "control: " + detail)

        ctx.audit.record("workflow_abuse.result", title=title,
                         verdict="falsified" if control_ok else "pending_verification")
        if control_ok:
            return json.dumps({
                "verdict": "falsified", "recorded": False, "details": details,
                "note": "The same invariant also held for the honest control workflow — "
                        "this is normal behavior, not abuse. Find a real negative control.",
            })

        # Single-run proof passed its own control — still self-administered. Record PENDING;
        # only verify_finding_independently (replaying both sequences in a FRESH context)
        # may promote this to confirmed. See tools/independent_verify.py.
        check_spec = {"attack_steps": attack_steps, "control_steps": control_steps,
                      "invariant": invariant, "control_invariant": control_conds}
        f = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence="\n".join(details), recommendation=recommendation,
            cwe=cwe or "CWE-840", confidence="pending_verification",
            verification_verdict="confirmed", reproductions=1, trials=1,
            poc="; ".join(f"{s.get('name', f'step{i}')}: {s.get('method','GET')} {s.get('url','')}"
                         for i, s in enumerate(attack_steps)),
            check_type="workflow", check_spec=check_spec))
        return json.dumps({
            "verdict": "pending_verification", "recorded": True, "finding_id": f.id,
            "details": details,
            "note": "Attack sequence violated the invariant and the control did not — but "
                    "this does not count yet. An independent re-check must reproduce it "
                    "(with fresh steps/identifiers you provide) before it is CONFIRMED.",
        })


class VerifyRaceConditionTool:
    name = "verify_race_condition"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove a RACE CONDITION / TOCTOU — an action the app assumes can "
                "happen at most once (redeem a balance, accept an offer, apply a "
                "voucher, withdraw funds) that a concurrent BURST lets happen "
                "several times. Give the `request` to fire and a `count` (2-30): "
                "all copies are released simultaneously via a barrier so they hit "
                "the same check-to-use window. The proof is a race_window invariant "
                "— more than `max_success` of the burst met the success shape. A "
                "single honest `control` request must succeed exactly once (so the "
                "action itself is legitimate and the extra successes are the bug). "
                "Only ever race an action on an object YOU own; never a real user's. "
                "Lands pending_verification — an independent re-check confirms it."),
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"}, "severity": {"type": "string"},
                    "target": {"type": "string"}, "summary": {"type": "string"},
                    "request": {"type": "object",
                                "description": "The request to burst: {method,url,headers,body,session_label}."},
                    "count": {"type": "integer", "description": "Concurrent copies to fire (2-30)."},
                    "success": {"type": "object",
                                "description": "Success shape: {status?:int, body_regex?:str}. Default {status:200}."},
                    "max_success": {"type": "integer",
                                    "description": "How many successes are legitimate (default 1). Racable if more."},
                    "control": {"type": "object",
                                "description": "Optional single honest request that should succeed exactly once."},
                    "cwe": {"type": "string"}, "recommendation": {"type": "string"},
                },
                "required": ["title", "severity", "target", "summary", "request"],
            },
            "strict": False,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            request: dict, count: int = 10, success: dict | None = None,
            max_success: int = 1, control: dict | None = None,
            cwe: str = "", recommendation: str = "") -> str:
        if not request or not request.get("url"):
            return "ERROR: provide a request with a url to burst."
        succ = success or {"status": 200}
        try:
            burst = run_burst(ctx, request, count)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        except KeyError as exc:
            return f"ERROR: request missing {exc}."

        responses = {"burst": burst}
        cond = {"type": "race_window", "request": "burst",
                "success": succ, "max_success": max_success}
        passed, detail = eval_condition(cond, responses)
        details = [("PASS " if passed else "fail ") + detail]
        if not passed:
            ctx.audit.record("race.result", title=title, verdict="not_reproducible",
                             fired=len(burst))
            return json.dumps({
                "verdict": "not_reproducible", "recorded": False, "details": details,
                "note": "The burst did not produce more successes than allowed — no race "
                        "observed. Try a higher count, a tighter success shape, or a "
                        "different action.",
            })

        # Optional control: one honest request should succeed exactly once — this
        # confirms the action is legitimate, so the EXTRA burst successes are the bug.
        if control and control.get("url"):
            try:
                c = fetch_once(ctx, {"method": control.get("method", "GET"),
                                     "url": control["url"],
                                     "headers": _session_headers(ctx, control.get("session_label"),
                                                                 control.get("headers")),
                                     "body": control.get("body")})
            except ScopeViolation as exc:
                return f"BLOCKED (out of scope) in control: {exc}"
            c_ok, c_detail = eval_condition(
                {"type": "status", "request": "c", "equals": succ.get("status", 200)},
                {"c": c})
            details.append(("PASS " if c_ok else "fail ") + "control single-shot: " + c_detail)

        n_success = sum(1 for r in burst
                        if r[0] == succ.get("status", 200)
                        and (not succ.get("body_regex")
                             or __import__("re").search(succ["body_regex"], r[1] or "")))
        ctx.audit.record("race.result", title=title, verdict="pending_verification",
                         fired=len(burst), successes=n_success)
        check_spec = {"request": request, "count": count, "success": succ,
                      "max_success": max_success, "control": control,
                      "race_successes": n_success, "race_fired": len(burst)}
        f = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence="\n".join(details), recommendation=recommendation,
            cwe=cwe or "CWE-362", confidence="pending_verification",
            verification_verdict="confirmed", reproductions=1, trials=1,
            poc=f"burst x{len(burst)} of {request.get('method','GET')} {request.get('url','')} "
                f"-> {n_success} succeeded (max legit {max_success})",
            check_type="race", check_spec=check_spec))
        return json.dumps({
            "verdict": "pending_verification", "recorded": True, "finding_id": f.id,
            "race_successes": n_success, "fired": len(burst), "details": details,
            "note": "A concurrent burst beat the once-only guard (CWE-362 TOCTOU). Pending "
                    "an independent re-check before it counts.",
        })

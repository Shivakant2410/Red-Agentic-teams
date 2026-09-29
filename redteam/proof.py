"""Agent-designed proofs — a safe predicate engine for verification.

This is the answer to "the agent leans on our fixed oracles." Instead of picking from
rigid marker tools, the agent DESIGNS the proof: it names a set of requests (baseline,
payload, ...) and a list of conditions that must hold to demonstrate the vulnerability.
We evaluate those conditions deterministically, k-of-n, so the agent's intelligence
decides *how to prove* any vuln class while the proof itself stays a hard, reproducible
check (no LLM opinion, no hallucinated findings).

The condition set is a fixed, safe DSL (no eval): status, body_regex, latency_delta,
json_differs, and reflected_unescaped. That covers injection, IDOR, access control,
XSS, timing/blind, and more, composed by the agent per finding.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .verify import CheckOutcome


def _dig(obj, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resp(responses, name):
    if name not in responses:
        raise KeyError(f"condition references unknown request {name!r}")
    return responses[name]  # (status, body, elapsed, headers)


def eval_condition(cond: dict, responses: dict) -> tuple[bool, str]:
    """Evaluate one condition against the fetched responses. Returns (passed, detail)."""
    t = cond.get("type")

    if t == "status":
        status = _resp(responses, cond["request"])[0]
        ok = status == cond["equals"]
        return ok, f"status[{cond['request']}]={status} {'==' if ok else '!='} {cond['equals']}"

    if t == "body_regex":
        body = _resp(responses, cond["request"])[1]
        present = bool(re.search(cond["pattern"], body or ""))
        want = cond.get("present", True)
        ok = present == want
        return ok, f"body[{cond['request']}] {'has' if present else 'lacks'} /{cond['pattern']}/ (want present={want})"

    if t == "header_regex":
        headers = _resp(responses, cond["request"])[3] or {}
        blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        present = bool(re.search(cond["pattern"], blob, re.IGNORECASE))
        want = cond.get("present", True)
        ok = present == want
        return ok, f"headers[{cond['request']}] {'has' if present else 'lacks'} /{cond['pattern']}/"

    if t == "latency_delta":
        a = _resp(responses, cond["request_a"])[2]
        b = _resp(responses, cond["request_b"])[2]
        delta = b - a
        ok = delta >= cond["min_delta"]
        return ok, f"latency_delta={delta:.2f}s (need >= {cond['min_delta']}s)"

    if t == "json_differs":
        # Both responses have the path present AND the values differ -> reached a distinct
        # valid object (the IDOR oracle: another principal's resource, not yours).
        a_body = _resp(responses, cond["request_a"])[1]
        b_body = _resp(responses, cond["request_b"])[1]
        try:
            va = _dig(json.loads(a_body), cond["json_path"])
            vb = _dig(json.loads(b_body), cond["json_path"])
        except (json.JSONDecodeError, TypeError):
            return False, f"json_differs[{cond['json_path']}]: response not JSON"
        ok = va is not None and vb is not None and va != vb
        return ok, f"json[{cond['json_path']}]: {va!r} vs {vb!r} (differ={ok})"

    if t == "reflected_unescaped":
        # XSS oracle: the exact token (with its dangerous chars) appears verbatim, i.e.
        # NOT entity-encoded. If the app escaped it, the raw token won't be present.
        body = _resp(responses, cond["request"])[1] or ""
        token = cond["token"]
        raw_present = token in body
        escaped_present = (token.replace("<", "&lt;").replace(">", "&gt;") in body)
        ok = raw_present and not (escaped_present and not raw_present)
        return ok, f"reflected[{cond['request']}]: raw={raw_present} escaped={escaped_present}"

    return False, f"unknown condition type {t!r}"


class ProofCheck:
    """A Check (for verify.verify) built from agent-designed fetchers + conditions."""

    def __init__(self, fetchers: dict[str, Callable[[], tuple]], conditions: list[dict]):
        self._fetchers = fetchers
        self._conditions = conditions

    def run(self) -> CheckOutcome:
        responses = {name: fn() for name, fn in self._fetchers.items()}
        details, ok = [], True
        for c in self._conditions:
            passed, detail = eval_condition(c, responses)
            ok = ok and passed
            details.append(("PASS " if passed else "fail ") + detail)
        return CheckOutcome(passed=ok, detail=" | ".join(details))

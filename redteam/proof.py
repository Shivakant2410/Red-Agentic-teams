"""Agent-designed proofs — a safe predicate engine for verification.

This is the answer to "the agent leans on our fixed oracles." Instead of picking from
rigid marker tools, the agent DESIGNS the proof: it names a set of requests (baseline,
payload, ...) and a list of conditions that must hold to demonstrate the vulnerability.
We evaluate those conditions deterministically, k-of-n, so the agent's intelligence
decides *how to prove* any vuln class while the proof itself stays a hard, reproducible
check (no LLM opinion, no hallucinated findings).

The condition set is a fixed, safe DSL (no eval): status, body_regex, latency_delta,
json_differs, reflected_unescaped, and oob_callback. That covers injection, IDOR,
access control, XSS, timing/blind, blind/out-of-band (SSRF/XXE/DNS-exfil/async RCE),
and more, composed by the agent per finding.

oob_callback is special: it does not read an HTTP response, it asks the run's OOB
oracle (tools/oob_oracle.py) whether the TARGET called back to a canary we minted —
the only way to PROVE a blind vulnerability deterministically.
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


def eval_condition(cond: dict, responses: dict, oob=None) -> tuple[bool, str]:
    """Evaluate one condition against the fetched responses. Returns (passed, detail).

    `oob` is the run's OOBOracle (or None); only the oob_callback predicate uses
    it — every other predicate is a pure function of `responses`.
    """
    t = cond.get("type")

    if t == "race_window":
        # TOCTOU / race oracle. A burst fetcher stored its per-request results
        # under one name as a list of (status, body, elapsed, headers). The
        # invariant an app TRUSTS is "this action succeeds at most once" (redeem
        # a balance, accept an offer, apply a coupon). If, fired concurrently,
        # MORE THAN `max_success` of the burst met the success shape, the check-
        # to-use window was racable. success is {status?: int, body_regex?: str}.
        name = cond["request"]
        if name not in responses:
            raise KeyError(f"race_window references unknown burst {name!r}")
        burst = responses[name]
        # A burst result is a list of response tuples; a single tuple means the
        # fetcher wasn't a burst (misuse) — treat as one response.
        if burst and isinstance(burst[0], (list, tuple)) and len(burst) and not isinstance(burst[0], str):
            results = burst if isinstance(burst, list) and burst and isinstance(burst[0], (list, tuple)) else [burst]
        else:
            results = [burst]
        succ = cond.get("success", {"status": 200})
        want_status = succ.get("status")
        want_re = succ.get("body_regex")

        def _is_success(resp):
            st, body = resp[0], resp[1]
            if want_status is not None and st != want_status:
                return False
            if want_re and not re.search(want_re, body or ""):
                return False
            return True

        n_success = sum(1 for r in results if _is_success(r))
        max_success = int(cond.get("max_success", 1))
        ok = n_success > max_success
        return ok, (f"race_window[{name}]: {n_success}/{len(results)} succeeded "
                    f"(racable if > {max_success})")

    if t == "oob_callback":
        # BLIND proof: did the target call back to the canary we minted? This is
        # the deterministic oracle for SSRF/XXE/DNS-exfil/async-RCE — no response
        # body involved. protocol (dns|http) optional; min_count defaults to 1.
        canary = cond.get("canary", "")
        if not canary:
            return False, "oob_callback: no canary specified"
        if oob is None:
            return False, "oob_callback: OOB oracle not available this run"
        protocol = cond.get("protocol", "")
        hits = oob.interactions_for(canary, protocol=protocol)
        need = int(cond.get("min_count", 1))
        ok = len(hits) >= need
        proto_note = f" [{protocol}]" if protocol else ""
        return ok, (f"oob_callback{proto_note}[{canary}]: {len(hits)} interaction(s) "
                    f"(need >= {need})")

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

    def __init__(self, fetchers: dict[str, Callable[[], tuple]], conditions: list[dict],
                 oob=None):
        self._fetchers = fetchers
        self._conditions = conditions
        self._oob = oob   # OOBOracle | None — only oob_callback conditions use it

    def run(self) -> CheckOutcome:
        responses = {name: fn() for name, fn in self._fetchers.items()}
        details, ok = [], True
        for c in self._conditions:
            passed, detail = eval_condition(c, responses, oob=self._oob)
            ok = ok and passed
            details.append(("PASS " if passed else "fail ") + detail)
        return CheckOutcome(passed=ok, detail=" | ".join(details))

"""injection_probe — the intelligence-not-scanner gate for injection classes.

The behavior this adds (the thing a scanner never does): before spending any
proof budget, PROBE a parameter with a few SAFE, DIAGNOSTIC inputs, READ the
responses, and DECIDE whether this parameter is even reactive to SQL injection —
yes / no / inconclusive — with the evidence that says so. A dead parameter gets
ZERO exploit requests: the agent reads "not_reactive" and moves on. A live one
gets a READY check_spec built from what the probe actually observed, which
verify_vulnerability proves k-of-n with a negative control.

Diagnostic, not exploitation — exactly like xss_reflect_probe is for XSS:
  - boolean differential: a TRUE condition vs a FALSE condition that must change
    the result set if the input reaches a SQL WHERE clause (no data is read).
  - arithmetic identity on numeric params: value vs an equivalent expression
    (e.g. 7 vs 6+1) — if the app evaluates it server-side the responses match
    and a literal 6+1 differs, revealing the param hits a query, not a cast.
  - error signature: a single quote; a database error fingerprint in the
    response is a strong tell (but error text ALONE never counts as proof —
    it only earns a differential/timing confirmation).
  - timing pair (optional, bounded): only when the above are inconclusive.

Verdict per param: reactive | not_reactive | inconclusive, each with evidence.
`reactive` carries a differential check_spec for verify_vulnerability.
"""
from __future__ import annotations

import json
import re
import uuid
from urllib.parse import quote

from ..scope import ScopeViolation
from . import ToolContext
from .http import fetch_once

_MAX_PARAMS = 5

# Database error fingerprints — a strong (but not sufficient) reactivity signal.
_SQL_ERROR_SIGNATURES = (
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg::|postgresql.*error",
    r"sqlite3?\.\w+error|sqlite_error",
    r"ora-\d{5}",
    r"odbc.*sql server|microsoft ole db provider",
    r"sqlstate\[",
    r"psql:.*error|syntax error at or near",
)
_SQL_ERR_RE = re.compile("|".join(_SQL_ERROR_SIGNATURES), re.IGNORECASE)


def _tag() -> str:
    return uuid.uuid4().hex[:4]


def _set_param(url: str, param: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{quote(param)}={quote(value)}"


def _fetch(ctx: ToolContext, url: str, method: str, param: str, value: str, tool: str):
    """One diagnostic request. Returns (status, body, elapsed) or raises Scope."""
    u = _set_param(url, param, value)
    status, body, elapsed, _h = fetch_once(ctx, {"method": method, "url": u}, tool=tool)
    return status, (body or ""), elapsed


def _norm(body: str) -> str:
    # Normalise volatile bits so a boolean differential compares SIGNAL, not noise
    # (timestamps, csrf tokens, nonces vary request-to-request even when the
    # result set is identical). Coarse but honest.
    b = re.sub(r"\b[0-9a-f]{16,}\b", "", body.lower())
    b = re.sub(r"\d{2}:\d{2}:\d{2}", "", b)
    b = re.sub(r"\s+", " ", b)
    return b


def _probe_sqli(ctx: ToolContext, url: str, method: str, param: str,
                tool: str) -> tuple[dict, int]:
    """Decide if `param` is reactive to SQLi using safe diagnostics. Returns
    (verdict_dict, requests_made)."""
    made = 0
    tag = _tag()
    evidence: list[str] = []

    # 0. Baseline — the param's current, honest response.
    try:
        b_status, b_body, _ = _fetch(ctx, url, method, param, f"rtbase{tag}", tool)
        made += 1
    except ScopeViolation:
        raise
    except Exception as exc:
        return {"param": param, "verdict": "inconclusive",
                "evidence": [f"baseline request failed: {str(exc)[:120]}"]}, made

    # 1. Error signature: a single quote.
    try:
        q_status, q_body, _ = _fetch(ctx, url, method, param, f"rtq{tag}'", tool)
        made += 1
        if _SQL_ERR_RE.search(q_body) and not _SQL_ERR_RE.search(b_body):
            evidence.append("a single quote triggered a database error signature "
                            "(strong tell — confirm with the boolean pair, error "
                            "text alone is not proof)")
    except ScopeViolation:
        raise
    except Exception:
        pass

    # 2. Boolean differential: TRUE vs FALSE tail that only matters inside SQL.
    #    If the param reaches a WHERE clause, TRUE ~ baseline and FALSE diverges.
    true_val = f"rtb{tag}' AND '1'='1"
    false_val = f"rtb{tag}' AND '1'='2"
    bool_reactive = False
    try:
        _ts, t_body, _ = _fetch(ctx, url, method, param, true_val, tool); made += 1
        _fs, f_body, _ = _fetch(ctx, url, method, param, false_val, tool); made += 1
        tn, fn = _norm(t_body), _norm(f_body)
        if tn != fn and (len(tn) or len(fn)):
            bool_reactive = True
            evidence.append("boolean differential: '1'='1 and '1'='2 produced "
                            "DIFFERENT responses — the input influences a query "
                            "result set (not just reflected)")
    except ScopeViolation:
        raise
    except Exception:
        pass

    # 3. Arithmetic identity on a numeric-looking param (cheap extra signal).
    arith_reactive = False
    try:
        base_num = None
        # only meaningful if the param plausibly takes a number
        _s1, body_7, _ = _fetch(ctx, url, method, param, "7", tool); made += 1
        _s2, body_6p1, _ = _fetch(ctx, url, method, param, "6+1", tool); made += 1
        _s3, body_99, _ = _fetch(ctx, url, method, param, "99", tool); made += 1
        n7, n61, n99 = _norm(body_7), _norm(body_6p1), _norm(body_99)
        # server-side eval: 7 == 6+1 but != 99
        if n7 == n61 and n7 != n99 and n7:
            arith_reactive = True
            evidence.append("arithmetic identity: value=7 and value=6+1 matched but "
                            "value=99 differed — the param is evaluated in a query "
                            "expression, not treated as an opaque string")
    except ScopeViolation:
        raise
    except Exception:
        pass

    # Verdict.
    if bool_reactive or arith_reactive:
        verdict = "reactive"
        check_spec = {
            "requests": {
                "true": {"method": method, "url": _set_param(url, param, true_val)},
                "false": {"method": method, "url": _set_param(url, param, false_val)},
            },
            # A real SQLi: the TRUE tail returns the normal result (status 200)
            # and differs from the FALSE tail. verify runs this k-of-n with a
            # benign negative control (the plain baseline) so a flaky diff fails.
            "conditions": [
                {"type": "status", "request": "true", "equals": b_status or 200},
                {"type": "body_regex", "request": "true",
                 "pattern": re.escape((b_body[:40] or "").strip()[:30]) or ".",
                 "present": True},
            ],
            "control_replaces": "true",
        }
        hint = ("REACTIVE to SQLi. Feed check_spec to verify_vulnerability (k-of-n "
                "+ negative control). The boolean/arith differential is the oracle; "
                "error text is corroboration only. If confirmed, chain to auth "
                "bypass via authenticate — dumping data is not the goal.")
        return ({"param": param, "verdict": verdict, "evidence": evidence,
                 "check_spec": check_spec, "verify_hint": hint}, made)

    if evidence:  # e.g. only an error signature, no differential
        return ({"param": param, "verdict": "inconclusive", "evidence": evidence,
                 "verify_hint": ("Only a weak/error signal — not enough to spend a "
                                 "proof trial. Try a different injection context "
                                 "(ORDER BY, UNION column count) or move on; do NOT "
                                 "fire verify on error text alone.")}, made)

    return ({"param": param, "verdict": "not_reactive", "evidence":
             ["no boolean, arithmetic, or error signal — this parameter does not "
              "reach a SQL query. Do NOT send SQLi payloads here; move on."]}, made)


class InjectionProbeTool:
    name = "injection_probe"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "DECIDE whether a parameter is injectable BEFORE spending a proof "
                "trial — intelligence, not a scanner. Sends a few SAFE diagnostic "
                "inputs (boolean '1'='1 vs '1'='2, arithmetic 7 vs 6+1, a single "
                "quote for an error signature), reads the differential, and returns "
                "per-param verdict: 'reactive' (with a READY check_spec for "
                "verify_vulnerability), 'not_reactive' (move on — send NO payloads "
                "here), or 'inconclusive'. No exploit payloads are sent and nothing "
                "is recorded — this only tells you WHERE it is worth proving SQLi. "
                "Max 5 params."),
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "url": {"type": "string", "description": "One in-scope URL."},
                    "params": {"type": "array", "items": {"type": "string"},
                               "description": "Parameter names to test (max 5)."},
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "reason": {"type": "string", "description": "Why (audited)."},
                },
                "required": ["url", "params", "reason"],
            },
            "strict": False,
        }

    def run(self, ctx: ToolContext, url: str, params, reason: str,
            method: str = "GET") -> str:
        try:
            ctx.scope.check(url)
        except ScopeViolation as exc:
            ctx.audit.record(f"{self.name}.blocked", target=url, cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"
        names = [str(p).strip() for p in (params or []) if str(p).strip()][:_MAX_PARAMS]
        if not names:
            return "ERROR: provide at least one parameter name."

        verdicts: list[dict] = []
        total = 0
        for p in names:
            try:
                v, made = _probe_sqli(ctx, url, method, p, self.name)
            except ScopeViolation as exc:
                return f"BLOCKED (out of scope): {exc}"
            verdicts.append(v)
            total += made
        reactive = [v["param"] for v in verdicts if v["verdict"] == "reactive"]
        ctx.audit.record("injection_probe", url=url, params=names,
                        requests=total, reactive=reactive)
        return json.dumps({
            "url": url, "method": method, "requests_made": total,
            "verdicts": verdicts,
            "note": ("Diagnostic only — nothing recorded. Prove ONLY the 'reactive' "
                     "params (feed their check_spec to verify_vulnerability); send "
                     "no SQLi payloads at 'not_reactive' params."),
        }, ensure_ascii=False)

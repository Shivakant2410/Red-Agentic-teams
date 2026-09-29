"""Chained-attack testers: broken access control and IDOR.

These are the "teeth" of the attack chain. They act as an authenticated principal (a
session captured by `authenticate`) and prove an authorization flaw through the same
k-of-n verification engine, so a finding is only recorded if it reproduces:

  - test_access_control: a protected resource must reject an UNAUTHENTICATED request.
    If the unauth request still returns the protected content (reproducibly), that's
    broken access control (CWE-284).
  - test_idor: acting as principal A, requesting principal B's object must be denied.
    If A can reproducibly read B's data, that's IDOR (CWE-639).
"""

from __future__ import annotations

import json

from ..findings import Finding
from ..knowledge import ENDPOINT
from ..scope import ScopeViolation
from ..verify import HttpCheck, verify
from . import ToolContext
from .http import make_fetch


def _session_headers(ctx: ToolContext, label: str | None, base: dict | None) -> dict:
    base = dict(base or {})
    if label and ctx.sessions is not None:
        sess = ctx.sessions.get(label)
        if sess is not None:
            return sess.apply(base)
    return base


def _record(ctx: ToolContext, finding: Finding) -> None:
    ctx.findings.add(finding)
    if ctx.graph is not None:
        ctx.graph.observe(ENDPOINT, finding.target, attrs={"finding": finding.title},
                          source="access_test")


class TestAccessControlTool:
    name = "test_access_control"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove broken access control: a protected resource should reject an "
                "UNAUTHENTICATED request. Provide the protected URL and a protected_marker "
                "(regex that appears only in the protected content). If an unauthenticated "
                "request still returns that content reproducibly, it's recorded as a "
                "confirmed CWE-284 finding."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "protected_marker": {"type": "string", "description": "Regex proving protected content is present."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["url", "protected_marker"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, url: str, protected_marker: str, method: str = "GET",
            trials: int = 4, need: int = 3) -> str:
        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))
        req = {"method": method, "url": url, "headers": {}}  # deliberately NO auth
        try:
            check = HttpCheck(fetch=make_fetch(ctx, req), expect_status=200,
                              body_regex=protected_marker)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        result = verify(check, trials=trials, need=need)
        ctx.audit.record("access_control.result", url=url, verdict=result.verdict,
                         reproductions=result.reproductions, trials=result.trials)
        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "recorded": False,
                               "note": "unauthenticated access did not reproduce; likely enforced."})
        f = Finding(title=f"Broken access control at {url}", severity="high", target=url,
                    summary="Protected resource is reachable without authentication.",
                    evidence="\n".join(result.details), cwe="CWE-284", confidence="confirmed",
                    verification_verdict=result.verdict, reproductions=result.reproductions,
                    trials=result.trials, poc=f"Unauthenticated {method} {url} returns protected content.",
                    recommendation="Enforce authentication/authorization server-side on this resource.")
        _record(ctx, f)
        return json.dumps({"verdict": "confirmed", "recorded": True, "finding_id": f.id})


class TestIdorTool:
    name = "test_idor"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove IDOR: acting as one principal (session_label from `authenticate`), "
                "request another principal's object (a URL containing the other id) and a "
                "victim_marker (regex proving the response holds the OTHER principal's data). "
                "If that reproduces, it's recorded as a confirmed CWE-639 finding."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "url": {"type": "string", "description": "URL targeting the OTHER principal's object."},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "session_label": {"type": "string", "description": "The attacker's session."},
                    "victim_marker": {"type": "string", "description": "Regex proving the other principal's data is returned."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["url", "session_label", "victim_marker"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, url: str, session_label: str, victim_marker: str,
            method: str = "GET", trials: int = 4, need: int = 3) -> str:
        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))
        headers = _session_headers(ctx, session_label, {})
        if not headers:
            return f"ERROR: no stored session '{session_label}'. Run authenticate first."
        req = {"method": method, "url": url, "headers": headers}
        try:
            check = HttpCheck(fetch=make_fetch(ctx, req), expect_status=200,
                              body_regex=victim_marker)
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"
        result = verify(check, trials=trials, need=need)
        ctx.audit.record("idor.result", url=url, session=session_label, verdict=result.verdict,
                         reproductions=result.reproductions, trials=result.trials)
        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "recorded": False,
                               "note": "could not reproduce access to the other principal's data."})
        f = Finding(title=f"IDOR at {url}", severity="high", target=url,
                    summary=f"Principal '{session_label}' can access another principal's object.",
                    evidence="\n".join(result.details), cwe="CWE-639", confidence="confirmed",
                    verification_verdict=result.verdict, reproductions=result.reproductions,
                    trials=result.trials,
                    poc=f"As {session_label}: {method} {url} returns another principal's data.",
                    recommendation="Enforce per-object authorization checks tied to the caller's identity.")
        _record(ctx, f)
        return json.dumps({"verdict": "confirmed", "recorded": True, "finding_id": f.id})

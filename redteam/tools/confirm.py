"""confirm_finding — a finding must reproduce before it's recorded as confirmed.

This is the tool form of the false-positive moat. The agent doesn't get to *assert* a
vulnerability; it submits a finding plus a reproducible check, and this tool runs that
check k-of-n through the scope-enforced sandbox. Only a stable, reproducible result is
recorded with confidence="confirmed". A one-off or flaky result is reported back and
NOT recorded — the agent must find better evidence or drop it.

Checks fetch through the Kali sandbox's `curl`, so they inherit the egress firewall
(off-scope targets are unreachable). The verification math lives in verify.py.
"""

from __future__ import annotations

import json
import re
import time

import requests

from ..findings import Finding
from ..knowledge import ENDPOINT
from ..scope import ScopeViolation
from ..verify import DifferentialCheck, HttpCheck, verify
from . import ToolContext

_MARKER = "__RT_STATUS__"


def _make_fetch(ctx: ToolContext, req: dict):
    """Return a fetch() -> (status, body, elapsed) for one request.

    Uses the sandbox's scope-firewalled curl when a sandbox is running (remote targets),
    and falls back to a host-side request when there is no sandbox (e.g. a localhost
    benchmark target the container cannot reach). Both paths scope-check the URL first."""
    ctx.scope.check(req["url"])
    if ctx.sandbox is not None:
        return _sandbox_fetch(ctx, req)
    return _host_fetch(req)


def _host_fetch(req: dict):
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    headers = req.get("headers") or {}
    body = req.get("body")

    def fetch():
        start = time.monotonic()
        try:
            r = requests.request(method, url, headers=headers, data=body,
                                 timeout=20, allow_redirects=False)
            return r.status_code, r.text or "", time.monotonic() - start
        except requests.RequestException:
            return 0, "", time.monotonic() - start
    return fetch


def _sandbox_fetch(ctx: ToolContext, req: dict):
    """Run one request via sandbox curl -> (status, body, elapsed)."""
    method = (req.get("method") or "GET").upper()
    url = req["url"]
    headers = req.get("headers") or {}
    body = req.get("body")

    parts = ["curl", "-s", "-S", "-k", "-X", _shq(method)]
    for k, v in headers.items():
        parts += ["-H", _shq(f"{k}: {v}")]
    if body is not None:
        parts += ["--data-binary", _shq(body)]
    # Append a trailer we can split on: body, then STATUS<code> TIME<seconds>.
    parts += ["-w", _shq(f"\\n{_MARKER}%{{http_code}} %{{time_total}}"), _shq(url)]
    command = " ".join(parts)

    def fetch():
        res = ctx.sandbox.exec(command)
        out = res.stdout
        status, elapsed = 0, 0.0
        idx = out.rfind(_MARKER)
        if idx != -1:
            trailer = out[idx + len(_MARKER):].strip()
            body_text = out[:idx]
            m = re.match(r"(\d+)\s+([\d.]+)", trailer)
            if m:
                status, elapsed = int(m.group(1)), float(m.group(2))
        else:
            body_text = out
        return status, body_text, elapsed

    return fetch


def _shq(s: str) -> str:
    """Single-quote a string for safe use in a bash -lc command."""
    return "'" + str(s).replace("'", "'\\''") + "'"


class ConfirmFindingTool:
    name = "confirm_finding"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Reproduce a suspected vulnerability and, only if it reproduces reliably, "
                "record it as a CONFIRMED finding. Provide the finding details and a check: "
                "'http' asserts a response (status/body_regex/max_latency), 'differential' "
                "compares a baseline vs. a payload request (e.g. time-based blind injection). "
                "Requests are scope-checked before they run. If the check does not reproduce, "
                "the finding is NOT recorded — refine your evidence."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "target": {"type": "string"},
                    "summary": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "cwe": {"type": "string"},
                    "check_type": {"type": "string", "enum": ["http", "differential"]},
                    "request": {"type": "object", "description": "For http: {method,url,headers,body}."},
                    "baseline_request": {"type": "object", "description": "For differential."},
                    "payload_request": {"type": "object", "description": "For differential."},
                    "expect_status": {"type": "integer"},
                    "body_regex": {"type": "string"},
                    "max_latency": {"type": "number"},
                    "min_latency_delta": {"type": "number"},
                    "body_differs_regex": {"type": "string"},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["title", "severity", "target", "summary", "check_type"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, title: str, severity: str, target: str, summary: str,
            check_type: str, recommendation: str = "", cwe: str = "",
            request: dict | None = None, baseline_request: dict | None = None,
            payload_request: dict | None = None, expect_status: int | None = None,
            body_regex: str | None = None, max_latency: float | None = None,
            min_latency_delta: float | None = None, body_differs_regex: str | None = None,
            trials: int = 5, need: int = 4) -> str:
        trials = max(1, min(int(trials), 10))
        need = max(1, min(int(need), trials))

        try:
            if check_type == "http":
                if not request:
                    return "ERROR: http check requires 'request'."
                check = HttpCheck(fetch=_make_fetch(ctx, request),
                                  expect_status=expect_status, body_regex=body_regex,
                                  max_latency=max_latency)
            elif check_type == "differential":
                if not (baseline_request and payload_request):
                    return "ERROR: differential check requires baseline_request and payload_request."
                check = DifferentialCheck(
                    fetch_baseline=_make_fetch(ctx, baseline_request),
                    fetch_payload=_make_fetch(ctx, payload_request),
                    min_latency_delta=min_latency_delta, body_differs_regex=body_differs_regex)
            else:
                return f"ERROR: unknown check_type {check_type!r}"
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        result = verify(check, trials=trials, need=need)
        ctx.audit.record("confirm.result", title=title, verdict=result.verdict,
                         reproductions=result.reproductions, trials=result.trials)

        if result.verdict != "confirmed":
            return json.dumps({
                "verdict": result.verdict,
                "reproductions": result.reproductions,
                "trials": result.trials,
                "recorded": False,
                "note": "Not recorded — evidence did not reproduce reliably. Refine or drop it.",
                "details": result.details,
            }, ensure_ascii=False)

        poc = _poc_text(check_type, request, baseline_request, payload_request)
        finding = ctx.findings.add(Finding(
            title=title, severity=severity, target=target, summary=summary,
            evidence="\n".join(result.details), recommendation=recommendation, cwe=cwe,
            confidence="confirmed", verification_verdict=result.verdict,
            reproductions=result.reproductions, trials=result.trials, poc=poc,
        ))
        if ctx.graph is not None:
            ctx.graph.observe(ENDPOINT, target, attrs={"finding": title}, source="confirm_finding")
            try:
                ctx.graph.mark_coverage(target, _severity_check_hint(cwe), "finding")
            except Exception:
                pass
        return json.dumps({
            "verdict": "confirmed", "recorded": True, "finding_id": finding.id,
            "reproductions": result.reproductions, "trials": result.trials,
        }, ensure_ascii=False)


def _poc_text(check_type, request, baseline, payload) -> str:
    if check_type == "http" and request:
        return f"{request.get('method','GET')} {request.get('url','')}"
    if check_type == "differential":
        b = (baseline or {}).get("url", "")
        p = (payload or {}).get("url", "")
        return f"baseline: {b}\npayload:  {p}"
    return ""


def _severity_check_hint(cwe: str) -> str:
    cwe = (cwe or "").upper()
    mapping = {"CWE-89": "injection", "CWE-79": "xss", "CWE-918": "ssrf",
               "CWE-639": "idor", "CWE-284": "access_control", "CWE-287": "auth"}
    return mapping.get(cwe, "injection")

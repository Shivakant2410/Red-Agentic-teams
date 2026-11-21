"""crosscheck_lead — never believe a tool's direct output; verify by another method.

Discovery tools (ffuf/katana/arjun/nuclei/httpx/nmap/inspectors) produce *claims*.
A claim made by a tool and checked by the SAME tool is not verification — it is the
tool agreeing with itself. So every lead class in the registry has a TRUST entry here
naming a SECOND, structurally different method:

  - the producing tool ran a binary in the sandbox (ffuf, katana, arjun, nuclei,
    httpx, nmap) -> the second method is FIRST-PARTY python HTTP / a raw TCP socket
    through our own shared fetch path — different code, different process, same scope
    guard, so a parser bug or a binary flag mistake cannot survive both;
  - the producing tool was already first-party HTTP (the inspectors) -> the second
    method is a FRESH request with different inputs (a new marker, a differential
    pair), never a replay of the original response;
  - some claims have no cheap second method (graphql checklist semantics) — those
    come back "unverifiable", which is NOT "believed": it means spend proof budget
    (verify_vulnerability + negative control) or drop the lead.

Verdicts (never a finding; this tool does not touch the finding pipeline):
  corroborated  — a second method agrees. STILL A LEAD: promotion to confirmed only
                  happens through verify_finding_independently. What corroboration
                  buys is proof BUDGET: spend it here, not on the contradicted ones.
  contradicted  — the second method disagrees. Drop the lead; do not design a proof.
  unverifiable  — no second method available or the inputs were too thin to check.
                  Unverified-by-second-method leads are never "believed by default".

Exempt classes (documented, not silent): surface_scan reads the RoE allowlist itself
(operator ground truth, nothing to re-derive) and jwt_inspect is an offline
deterministic parse of a token we already hold (its verification is the proof
pipeline that USES the token). Everything else must cross-check.

Scope: every network path here runs through tools/http.fetch_once (scope-checked,
traffic-recorded, audit-on-denial) or an explicit ctx.scope.check before a socket —
the crosscheck can never widen what a lead was allowed to touch.
"""

from __future__ import annotations

import json
import secrets
import socket

from . import ToolContext
from .http import fetch_once

# Benign param value for the differential method: short, alphanumeric, payload-free.
_BENIGN_VALUE = "rbxverify1"

# Relative body-length delta below which two responses count as "identical" for the
# param_differential method (dynamic pages wobble; we only report honest, visible deltas).
_DELTA_FLOOR = 0.05

TCP_TIMEOUT_S = 3.0

# ---------------------------------------------------------------------------
# The trust matrix. tool -> claim -> method spec. A (tool, claim) pair that is
# absent FAILS CLOSED: "no independent method registered" is refused, not trusted.
# method: http_get | http_marker | param_differential | tcp_connect | None
# ---------------------------------------------------------------------------

TRUST_MATRIX: dict[str, dict] = {
    "content_discovery": {
        "endpoint": {"method": "http_get",
                     "rule": "ffuf said this path exists; a plain first-party GET must "
                             "reach it too (2xx/3xx). 404/410 contradicts."},
    },
    "crawl": {
        "endpoint": {"method": "http_get",
                     "rule": "katana saw this URL in a link/JS; a first-party GET must "
                             "return it. 404/410 contradicts."},
    },
    "host_probe": {
        "endpoint": {"method": "http_get",
                     "rule": "httpx probed content via binary; a first-party GET must "
                             "reach the same URL. 404/410 contradicts."},
    },
    "spa_recon": {
        "endpoint": {"method": "http_get",
                     "rule": "the SPA walk inferred this API route; a first-party GET "
                             "(or POST-able route still responds to GET with 405, not 404) "
                             "corroborates; a 404 contradicts the route guess."},
    },
    "param_discovery": {
        "hidden_param": {"method": "param_differential",
                         "rule": "arjun claims a hidden parameter changes the response; "
                                 "a first-party WITH/without pair (benign value) must "
                                 "actually differ — status or body. Identical contradicts."},
    },
    "nuclei_scan": {
        "template_match": {"method": "http_marker",
                           "rule": "nuclei matched a template; the FIRST-PARTY re-fetch "
                                   "must contain the extracted marker on a live page. "
                                   "Absent on a 2xx body contradicts."},
    },
    "xss_reflect_probe": {
        "reflection": {"method": "fresh_param_marker",
                       "rule": "the probe saw ITS marker reflect; a fresh first-party "
                               "request carrying a DIFFERENT benign marker in the same "
                               "param must also reflect it (the reflection exists). "
                               "Absent contradicts the mapping."},
    },
    "port_scan": {
        "service": {"method": "tcp_connect",
                    "rule": "nmap says the port is open; a raw first-party socket connect "
                            "must succeed. Connection-refused contradicts."},
    },
    "graphql_inspect": {},   # honest entry: no cheap second method -> unverifiable
}

EXEMPT: dict[str, str] = {
    "surface_scan": "operator RoE ground truth — it reads the allowlist itself; the "
                    "crosscheck for its endpoints is host_probe/http_probe, not a re-derivation.",
    "jwt_inspect": "offline deterministic parse of a token we already hold; its "
                   "verification is the proof pipeline that USES the token.",
    "asset_read": "readback of the inventory OUR OWN tools filled (surface_scan, the "
                  "fetch path) — it observes recorded state, it makes no new target "
                  "claim to crosscheck.",
    "evidence_search": "readback of the run's own evidence store — observations are "
                       "already provenance-tagged; searching makes no new claim.",
    "evidence_inspect": "readback of one evidence observation — same class as "
                        "evidence_search.",
    "proxy_history_query": "readback of the wire-evidence log — the record of what "
                           "our own requests actually did.",
    "observations": "read side of the run's own observation log — the log already "
                    "carries per-claim provenance and validation states; re-deriving "
                    "it would be the same method twice.",
    "proxy_status": "introspection of OUR evidence proxy's own listener state; "
                    "nothing here is a claim about the target.",
    "proxy_history": "read-back of exchanges OUR proxy already captured on the wire "
                     "— the wire row IS the first-party observation.",
    "proxy_inspect": "detail read-back of one already-captured exchange (masked "
                     "by the recorder); no new claim to verify.",
    "proxy_filter": "filtered read-back of already-captured exchanges; no new "
                    "claim to verify.",
}


def matrix_json() -> str:
    """Introspection (DX parity with `python -m redteam.states --json`): the whole
    trust surface — what may be cross-checked how, and what is exempt and why."""
    return json.dumps({
        "policy": "never believe a tool's direct output; every lead class carries a "
                  "second-method entry or is explicitly exempt",
        "verdicts": ["corroborated", "contradicted", "unverifiable"],
        "matrix": {t: {c: s["method"] for c, s in claims.items()}
                   for t, claims in TRUST_MATRIX.items()},
        "exempt": EXEMPT,
    }, ensure_ascii=False, indent=2)


class CrossCheckTool:
    name = "crosscheck_lead"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Second-method verification of a tool lead — the house rule is that a "
                "tool's DIRECT output is never believed on its own. Given a lead from a "
                "discovery/scan tool, this tool runs a structurally DIFFERENT check: "
                "binary-in-sandbox claims are re-tested first-party (plain HTTP fetch or "
                "raw TCP connect); first-party inspector claims are re-tested with fresh "
                "inputs (new marker / differential pair). Verdicts: corroborated (still a "
                "lead — promotion still needs the proof pipeline, but it has earned proof "
                "budget), contradicted (drop it, don't spend budget), unverifiable (no "
                "cheap second method or thin inputs — NOT believed by default; go prove "
                "it with verify_vulnerability or drop it). Never records findings.\n\n"
                "Examples: ffuf found /admin.bak -> crosscheck_lead(tool=content_discovery,"
                " claim=endpoint, url=...). arjun found 'debug' -> crosscheck_lead(tool="
                "param_discovery, claim=hidden_param, url=..., param=debug). nmap says "
                "8080 open -> crosscheck_lead(tool=port_scan, claim=service, host=..., "
                "port=8080)."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "tool": {"type": "string",
                             "description": "Producing tool, e.g. content_discovery, "
                                            "crawl, param_discovery, nuclei_scan, "
                                            "xss_reflect_probe, host_probe, port_scan, "
                                            "spa_recon, graphql_inspect."},
                    "claim": {"type": "string",
                              "description": "Claim class, e.g. endpoint, hidden_param, "
                                             "template_match, reflection, service."},
                    "url": {"type": "string", "description": "Target URL for HTTP methods."},
                    "param": {"type": "string", "description": "Param name (hidden_param)."},
                    "marker": {"type": "string",
                               "description": "String the fresh response must contain "
                                              "(template_match / reflection). For nuclei "
                                              "leads pass the extracted value."},
                    "host": {"type": "string", "description": "Host for service claims."},
                    "port": {"type": "integer", "description": "Port for service claims."},
                },
                "required": ["tool", "claim"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, tool: str, claim: str, url: str = "",
            param: str = "", marker: str = "", host: str = "", port: int = 0) -> str:
        tool, claim = (tool or "").strip(), (claim or "").strip()
        if tool in EXEMPT:
            result = {"tool": tool, "claim": claim, "verdict": "exempt",
                      "detail": EXEMPT[tool],
                      "promotion_rule": "no crosscheck owed; ordinary pipeline rules apply."}
            ctx.audit.record("crosscheck.result", **result)
            return json.dumps(result, ensure_ascii=False)

        entry = TRUST_MATRIX.get(tool)
        if entry is None:
            return json.dumps({"error": (
                f"no trust entry for tool {tool!r} — a lead with no registered "
                f"second method is never believed. Known: "
                f"{sorted(TRUST_MATRIX) + sorted(EXEMPT)}")}, ensure_ascii=False)
        spec = entry.get(claim)
        if spec is None:
            if not entry:
                # Deliberately registered empty (e.g. graphql_inspect): this tool's
                # claims have no cheap second method — honest "unverifiable", never
                # silent trust and never a hard error that blocks honest reporting.
                verdict = ("unverifiable",
                           f"{tool} claims have no cheap second method — NOT believed by "
                           "default; spend proof budget (verify_vulnerability + negative "
                           "control) or drop the lead")
                v, detail = verdict
                result = {"tool": tool, "claim": claim, "method": None, "verdict": v,
                          "detail": detail, "promotion_rule": "proof pipeline only"}
                ctx.audit.record("crosscheck.result", tool=tool, claim=claim,
                                 verdict=v, detail=detail)
                self._record_validation(ctx, tool, claim, url, param, host,
                                        port, v, detail)
                return json.dumps(result, ensure_ascii=False)
            return json.dumps({"error": (
                f"tool {tool!r} has no second method for claim {claim!r} "
                f"(known claims: {sorted(entry) or 'none — proof pipeline only'})")},
                ensure_ascii=False)

        method = spec["method"]
        if method == "http_get":
            verdict = self._http_get(ctx, url)
        elif method == "http_marker":
            verdict = self._http_marker(ctx, url, marker)
        elif method == "fresh_param_marker":
            verdict = self._fresh_param_marker(ctx, url, param)
        elif method == "param_differential":
            verdict = self._param_differential(ctx, url, param)
        elif method == "tcp_connect":
            verdict = self._tcp_connect(ctx, host, port)
        else:  # None registered
            verdict = ("unverifiable",
                       "no cheap second method for this claim — NOT believed by default; "
                       "spend proof budget (verify_vulnerability + negative control) or drop it")

        v, detail = verdict
        result = {"tool": tool, "claim": claim, "method": method, "verdict": v,
                  "detail": detail, "promotion_rule": spec["rule"]}
        ctx.audit.record("crosscheck.result", tool=tool, claim=claim, method=method,
                         verdict=v, detail=detail)
        self._record_validation(ctx, tool, claim, url, param, host, port,
                                v, detail)
        return json.dumps(result, ensure_ascii=False)

    # -- observation-log validation ------------------------------------------------

    def _record_validation(self, ctx: ToolContext, tool: str, claim: str,
                           url: str, param: str, host: str, port: int,
                           verdict: str, detail: str) -> None:
        """Land the verdict in the observation log's validation lifecycle so
        the whole team sees which leads are corroborated / contradicted /
        unverifiable (the audit record above is the legal trail; this is the
        working state — see observations.py). A corroborated lead is STILL a
        lead: this never creates or promotes a finding."""
        observations = getattr(ctx, "observations", None)
        if observations is None:
            return
        obs_type = {"endpoint": "endpoint", "hidden_param": "parameter",
                    "service": "service"}.get(claim, "endpoint")
        target = url or (f"{host}:{port}" if host else "")
        if not target:
            return
        base = target.split("?")[0]
        rows = observations.filter(obs_type=obs_type,
                                   target_contains=base, limit=20)
        for row in rows:
            if row["target"].startswith(base):
                observations.mark_validation(row["obs_id"], verdict,
                                             by=f"crosscheck_lead({tool})",
                                             reason=detail)
                return
        # No prior observation recorded this lead: enter it WITH its verdict
        # so the state is visible immediately (source = the claiming tool).
        try:
            stored = observations.record(obs_type, target,
                                         source_tool=tool, mode="active",
                                         metadata={"claim": claim,
                                                   "crosscheck": verdict,
                                                   "detail": detail})
            observations.mark_validation(stored["obs_id"], verdict,
                                         by=f"crosscheck_lead({tool})",
                                         reason=detail)
        except Exception:  # noqa: BLE001 — validation must never break the tool
            pass

    # -- methods -----------------------------------------------------------------

    def _http_get(self, ctx: ToolContext, url: str) -> tuple[str, str]:
        if not url:
            return "unverifiable", "no url supplied to cross-check"
        try:
            status, body, _, _ = fetch_once(ctx, {"method": "GET", "url": url},
                                             tool=self.name)
        except Exception as exc:  # scope denial already recorded by the fetch path
            return "unverifiable", f"request refused before it could check anything: {exc}"
        if 200 <= status < 400:
            return "corroborated", f"first-party GET reached it (status {status}, {len(body)} bytes)"
        if status in (404, 410):
            return "contradicted", f"first-party GET got {status} — the claimed endpoint is not there"
        if status >= 500:
            return "unverifiable", f"server error {status} — not evidence either way"
        return "unverifiable", f"status {status} is ambiguous for an existence claim"

    def _http_marker(self, ctx: ToolContext, url: str, marker: str) -> tuple[str, str]:
        if not url:
            return "unverifiable", "no url supplied to cross-check"
        if not marker:
            return ("unverifiable",
                    "no marker supplied — a reflection/match claim without the claimed "
                    "string cannot be second-checked")
        try:
            status, body, _, _ = fetch_once(ctx, {"method": "GET", "url": url},
                                             tool=self.name)
        except Exception as exc:
            return "unverifiable", f"request refused before it could check anything: {exc}"
        if status >= 400:
            return "unverifiable", f"fresh request returned {status} — cannot re-derive the match"
        if marker in body:
            return "corroborated", f"fresh first-party response contains the claimed marker ({len(body)} bytes)"
        return "contradicted", "fresh first-party response (2xx) does not contain the claimed marker"

    def _fresh_param_marker(self, ctx: ToolContext, url: str, param: str) -> tuple[str, str]:
        """Re-derive a reflection claim with a marker the ORIGINAL probe never saw.
        The point is independence: replaying the probe's own marker only proves the
        probe agrees with itself."""
        if not url or not param:
            return ("unverifiable",
                    "need both url and param to re-derive a reflection claim with a fresh marker")
        fresh = f"rbx2{secrets.token_hex(4)}"
        sep = "&" if "?" in url else "?"
        try:
            status, body, _, _ = fetch_once(
                ctx, {"method": "GET", "url": f"{url}{sep}{param}={fresh}"}, tool=self.name)
        except Exception as exc:
            return "unverifiable", f"request refused before it could check anything: {exc}"
        if status >= 400:
            return "unverifiable", f"fresh request returned {status} — cannot re-derive the reflection"
        if fresh in body:
            return "corroborated", (f"a marker this probe never generated was reflected too "
                                    f"(status {status}) — the reflection is real")
        return "contradicted", ("a fresh benign marker did NOT appear in the response — "
                                "the original reflection claim does not hold")

    def _param_differential(self, ctx: ToolContext, url: str, param: str) -> tuple[str, str]:
        if not url or not param:
            return ("unverifiable",
                    "need both url and param to run a WITH/without differential")
        sep = "&" if "?" in url else "?"
        with_url = f"{url}{sep}{param}={_BENIGN_VALUE}"
        try:
            s_base, b_base, _, _ = fetch_once(ctx, {"method": "GET", "url": url},
                                              tool=self.name)
            s_with, b_with, _, _ = fetch_once(ctx, {"method": "GET", "url": with_url},
                                              tool=self.name)
        except Exception as exc:
            return "unverifiable", f"request refused before it could check anything: {exc}"
        if s_base >= 500 or s_with >= 500:
            return "unverifiable", f"server error during pair ({s_base}/{s_with}) — not evidence"
        if s_base != s_with:
            return "corroborated", f"status changed with the param ({s_base} -> {s_with})"
        if not b_base and not b_with:
            return "unverifiable", "both responses empty — nothing to compare"
        delta = abs(len(b_with) - len(b_base)) / max(len(b_base), 1)
        if delta > _DELTA_FLOOR:
            return ("corroborated",
                    f"body changed with the param ({len(b_base)} -> {len(b_with)} bytes, "
                    f"{delta:.0%} delta)")
        return "contradicted", "responses identical with and without the param — no hidden param here"

    def _tcp_connect(self, ctx: ToolContext, host: str, port: int) -> tuple[str, str]:
        if not host or not port:
            return "unverifiable", "need host and port for a service claim"
        probe = f"https://{host}:{port}/" if port in (443, 8443) else f"http://{host}:{port}/"
        try:
            ctx.scope.check(probe)
        except Exception as exc:
            return "unverifiable", f"scope refuses the cross-check connect: {exc}"
        try:
            with socket.create_connection((host, port), timeout=TCP_TIMEOUT_S):
                return "corroborated", f"first-party TCP connect to {host}:{port} succeeded"
        except ConnectionRefusedError:
            return "contradicted", f"first-party connect to {host}:{port} refused — nothing listening"
        except Exception as exc:
            return "unverifiable", f"connect did not complete cleanly ({type(exc).__name__}) — not evidence"


if __name__ == "__main__":  # pragma: no cover
    print(matrix_json())

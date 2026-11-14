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
from dataclasses import dataclass, field
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
# the app's own action links: href/url/action pointing at a workflow surface
# WITH parameters (a redeem/apply/coupon link with a code in it)
WORKFLOW_LINK = re.compile(
    r"(?i)(?:href|url|action|link)[\"']?\s*[:=]\s*[\"']"
    r"(/[^\"'\s]*(?:cart|coupon|redeem|checkout|payment|order|apply|purchase|"
    r"transfer|withdraw|gift)[^\"'\s]*\?[^\"'\s]+)[\"']")
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
        url = _url_path(url.split("?")[0])
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
        if STACKISH.search(text):
            sigs.append(Signal("stack-detail", "", url, 0.7, "stack/verbose error"))

        self.state.signals.extend(sigs)
        return sigs

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
                        "unauth-access", "bearer-pivot", "workflow-chain"}

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
            cost = max(1, min(40, int(spec.get("cost", 6))))
        except (TypeError, ValueError):
            return False, "cost must be an integer"
        strength = min(0.9, max(0.0, float(spec.get("strength", 0.5))))
        self._seq += 1
        hid = f"llm-{kind}#{self._seq}"
        hyp = Hypothesis(
            id=hid, kind=kind,
            statement=spec["statement"], prediction=spec["prediction"],
            severity=severity, cwe=str(spec.get("cwe", "")), cost=cost,
            rank=round(_SEV[severity] * strength / cost, 4),
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

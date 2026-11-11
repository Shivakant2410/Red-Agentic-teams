"""webinspect — first W2 rungs: deterministic inspectors that emit READY proofs.

Phase W2 of docs/tool-integration-plan.md (the `jwt_inspect` pattern). These are
FIRST-PARTY tools: no new binary, every request rides the shared fetch path
(tools/http.py) so they inherit the scope guard, the rate limiter, session
handling, the traffic log, and graph observation like every other network tool.

THE SMART WIRING — the inspect -> spec -> prove chain:

    inspector lead (context-mapped) -> READY check_spec -> verify_vulnerability
                                     (k-of-n + negative control come free)
                                     -> verify_finding_independently

A generic scanner says "maybe XSS here". These inspectors answer the question a
prover actually needs: WHERE did my marker land (html body / attribute / JS /
JSON / response header), did the special characters survive or get entity-
encoded, and — when the sink is live — the exact `requests`+`conditions` payload
verify_vulnerability consumes 1:1. The agent stops designing proofs from
imagination and starts forwarding specs; the proof pipeline's k-of-n
reproducibility and negative-control discipline stay in charge of truth.

Everything is leads-only: markers are benign (a unique token, optionally plus
`'"><` to test quote/tag survival — NOT a payload), at most 2 requests per
parameter and 4 per GraphQL endpoint, and nothing here writes a finding.
"""

from __future__ import annotations

import json
import uuid
from urllib.parse import quote, urlencode

from ..knowledge import ENDPOINT, PARAMETER
from ..scope import ScopeViolation
from . import ToolContext
from .http import fetch_once

_MAX_PARAMS = 5
_MAX_LEADS = 200
_GRAPHQL_PROBES = 4

# Response headers checked for marker reflection. Deliberately EXCLUDES secret-
# adjacent headers (set-cookie / authorization / www-authenticate / x-api-key):
# their values are masked in the model transcript, so reflecting into them
# should not be waved at the agent either.
_HEADER_REFLECT_SKIP = {"set-cookie", "authorization", "www-authenticate",
                        "x-api-key", "x-auth-token", "proxy-authenticate"}

# Special characters used ONLY to test whether quotes/tags survive the sink.
# This is reflection mapping, not payload blasting: nothing here is executable.
_SPECIALS = "'\"><"

_ESCAPED_FORMS = ("&lt;", "&gt;", "&quot;", "&#39;", "&#x27;", "&#x2F;", "&apos;")


def _marker() -> str:
    return "rtx" + uuid.uuid4().hex[:6]


def _classify_context(body: str, token: str) -> str:
    """Where did the marker land? Coarse but honest sink classification."""
    idx = body.find(token)
    if idx == -1:
        return "none"
    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(body)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
    # Inside a <script>...</script> region?
    low = body.lower()
    pos = 0
    while True:
        s = low.find("<script", pos)
        if s == -1:
            break
        e = low.find("</script>", s)
        if e == -1:
            e = len(body)
        if s <= idx < e:
            return "js"
        pos = e + 1
    # Inside an OPEN tag? A token sits inside a tag only when the nearest "<"
    # before it has no closing ">" between them (otherwise the token is between
    # tags — plain html_body). "= " in the enclosing tag means an attribute value.
    tag_start = body.rfind("<", 0, idx)
    if tag_start != -1 and body.find(">", tag_start, idx) == -1:
        tag_end = body.find(">", idx)
        tag = body[tag_start:tag_end + 1] if tag_end != -1 else body[tag_start:]
        if len(tag) < 2000:
            return "attribute" if "=" in tag else "tag_name"
    return "html_body"


def _header_reflection(headers: dict, token: str) -> str | None:
    for k, v in (headers or {}).items():
        if str(k).lower() in _HEADER_REFLECT_SKIP:
            continue
        if token in str(v):
            return str(k)
    return None


def _escaped_forms_present(body: str) -> list[str]:
    """Which entity forms appear in the body (honest evidence of encoding)."""
    return [f for f in _ESCAPED_FORMS if f in body]


def _probe_param(ctx: ToolContext, url: str, method: str, param: str,
                 token: str, tool: str) -> tuple[dict | None, int]:
    """Reflect-map ONE parameter. Returns (lead | None, requests_made).

    Request 1 always fires (plain marker). Request 2 only when the marker
    reflected (quote/tag survival check). Markers are benign — the tool never
    sends an executable payload; proving impact stays verify's job."""
    requests_made = 0
    marker_url = f"{url}{'&' if '?' in url else '?'}{quote(param)}={quote(token)}"
    body = ""
    status = None
    headers: dict = {}
    try:
        status, body, _elapsed, headers = fetch_once(
            ctx, {"method": method, "url": marker_url}, tool=tool)
        requests_made += 1
    except ScopeViolation:
        raise
    except Exception as exc:  # degraded, never fatal
        return {"param": param, "error": str(exc)[:160]}, requests_made

    header_name = _header_reflection(headers or {}, token)
    reflected = token in (body or "") or header_name is not None
    if not reflected:
        return None, requests_made

    context = "response_header" if header_name else _classify_context(body, token)

    # Request 2: do quotes/tags survive the sink?
    full_token = token + _SPECIALS
    specials_survive = False
    escaped = []
    if header_name is None:
        probe2_url = f"{url}{'&' if '?' in url else '?'}{quote(param)}={quote(full_token)}"
        try:
            _status2, body2, _e2, _h2 = fetch_once(
                ctx, {"method": method, "url": probe2_url}, tool=tool)
            requests_made += 1
            specials_survive = full_token in (body2 or "")
            escaped = _escaped_forms_present(body2 or "")
        except ScopeViolation:
            raise
        except Exception:
            pass

    lead: dict = {
        "param": param,
        "context": context,
        "reflected": True,
        "specials_survive": specials_survive,
        "escaped_forms": sorted(set(escaped))[:4],
        "token": full_token,
        "url": url,
    }
    if header_name:
        lead["header"] = header_name
    if specials_survive:
        lead["check_spec"] = _ready_check_spec(url, method, param, full_token)
        lead["verify_hint"] = (
            f"Marker reflected in {context} WITH raw quote/tag chars. Feed "
            f"check_spec to verify_vulnerability as-is (k-of-n + negative control "
            f"run there), then verify_finding_independently. Context-correct "
            f"impact is YOUR job: {context} needs the right gadget, the pipeline "
            f"only proves the reflection.")
    else:
        lead["verify_hint"] = (
            f"Marker reflected in {context} but special chars were entity-encoded "
            f"(or dropped) — do NOT spend proof budget on a plain reflected_unescaped "
            f"here. Either find a context where escaping does not apply "
            f"(e.g. attribute without quotes, JS string, template) or move on.")
    return lead, requests_made


def _ready_check_spec(url: str, method: str, param: str, token: str) -> dict:
    """A payload verify_vulnerability consumes 1:1 — this is the 'smart use':
    discovery output IS the proof input, no redesign step in between."""
    full_url = f"{url}{'&' if '?' in url else '?'}{quote(param)}={quote(token)}"
    return {
        "requests": {"payload": {"method": method, "url": full_url}},
        "conditions": [{"type": "reflected_unescaped", "request": "payload",
                        "token": token}],
    }


class XssReflectProbeTool:
    name = "xss_reflect_probe"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Reflection MAPPING for ONE in-scope URL's parameters: a unique "
                "benign marker (rtxXXXXXX) is echoed through each parameter and the "
                "tool reports WHERE it landed (html_body / attribute / js / json / "
                "response_header) and whether quote/tag characters survive or get "
                "entity-encoded. NO payloads are sent — this is sink mapping, not "
                "exploitation. When the sink is live you get a READY check_spec: "
                "pass it to verify_vulnerability unchanged (it proves k-of-n with a "
                "negative control there). Max 5 params, max 2 requests per param."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "url": {"type": "string", "description": "One in-scope URL."},
                    "params": {"type": "array", "items": {"type": "string"},
                               "description": "Parameter names to map (max 5) — "
                                              "e.g. from param_discovery leads or a form."},
                    "method": {"type": "string", "enum": ["GET", "POST"],
                               "description": "How the parameter travels (default GET query; "
                                              "POST uses form encoding)."},
                    "reason": {"type": "string",
                               "description": "Why this mapping advances the test (audited)."},
                },
                "required": ["url", "params", "reason"],
            },
            "strict": True,
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
            return "ERROR: provide at least one parameter name to map."

        token = _marker()
        leads: list[dict] = []
        requests_made = 0
        for param in names:
            try:
                lead, made = _probe_param(ctx, url, method, param, token, self.name)
            except ScopeViolation as exc:
                ctx.audit.record(f"{self.name}.blocked", target=url,
                                 cause="out_of_scope_mid_probe", param=param)
                return f"BLOCKED (out of scope): {exc}"
            requests_made += made
            if lead is not None:
                leads.append(lead)
                try:
                    ctx.graph.observe(PARAMETER, f"{url}#{param}",
                                      attrs={"context": lead.get("context"),
                                             "reflected": True,
                                             "specials_survive": lead.get("specials_survive")},
                                      source=self.name)
                except Exception:
                    pass

        ctx.audit.record(self.name, target=url, params=names, method=method,
                         leads=len(leads), requests=requests_made, reason=reason)
        return json.dumps({
            "ok": True, "url": url, "token": token, "leads": leads,
            "lead_count": len(leads), "requests_made": requests_made,
            "note": ("Leads only. `specials_survive: true` leads carry a check_spec "
                     "ready for verify_vulnerability; escaped reflections are "
                     "documented so you do not waste proof budget on them."),
        }, ensure_ascii=False)


# -- graphql_inspect -------------------------------------------------------------------

_INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { queryType { name } } }"
_SUGGESTION_QUERY = "{ __thisfielddoesnotexist0x2c1 }"
_TYPENAME_QUERY = "{ __typename }"


def _looks_graphql_json(body: str) -> bool:
    try:
        row = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(row, dict) and ("data" in row or "errors" in row)


def _probe_graphql(ctx: ToolContext, url: str, tool: str) -> tuple[list[dict], int]:
    """The deterministic 4-request checklist. Each probe is honest about both
    outcomes; 'disabled' is recorded too (absence of a feature is a fact)."""
    leads: list[dict] = []
    made = 0

    def _post(body: str) -> tuple[int | None, str]:
        nonlocal made
        made += 1
        try:
            status, resp_body, _e, _h = fetch_once(
                ctx, {"method": "POST", "url": url,
                      "headers": {"Content-Type": "application/json"},
                      "body": body}, tool=tool)
            return status, resp_body or ""
        except ScopeViolation:
            raise
        except Exception as exc:
            return None, f'{{"errors": [{{"message": "probe failed: {exc}"}}]}}'

    def _get(query: str) -> tuple[int | None, str]:
        nonlocal made
        made += 1
        try:
            status, resp_body, _e, _h = fetch_once(
                ctx, {"method": "GET", "url": f"{url}?{urlencode({'query': query})}"},
                tool=tool)
            return status, resp_body or ""
        except ScopeViolation:
            raise
        except Exception as exc:
            return None, f'{{"errors": [{{"message": "probe failed: {exc}"}}]}}'

    # 1. introspection over POST
    status, body = _post(json.dumps({"query": _INTROSPECTION_QUERY}))
    introspection = "__schema" in body and status == 200 and _looks_graphql_json(body)
    leads.append({
        "check": "introspection_post", "result": "enabled" if introspection else "disabled",
        "status": status,
        "verify_hint": ("enabled: pull queryType/subscriptionType fields next and map "
                        "them for the authz matrix (find_techniques 'graphql' -> "
                        "exploit-graphql-authz; skills/categories/graphql/...). "
                        "disabled: schema recon must go through the suggestion oracle."
                        if introspection else
                        "No introspection: move to the suggestion oracle probe."),
    })

    # 2. GET-query support (queries over GET enable cache-poisoning and CSRF shapes)
    status, body = _get(_TYPENAME_QUERY)
    get_ok = status == 200 and _looks_graphql_json(body) and "__typename" in body
    leads.append({
        "check": "query_over_get", "result": "supported" if get_ok else "not_supported",
        "status": status,
        "verify_hint": ("supported: GET queries enable cache-key confusion and "
                        "cross-site query shapes (cache/* skills) — a differential "
                        "check in verify_vulnerability can prove it."
                        if get_ok else
                        "GET queries not supported: POST-only surface."),
    })

    # 3. field-suggestion oracle (clairvoyance-style schema reconstruction)
    status, body = _post(json.dumps({"query": _SUGGESTION_QUERY}))
    suggested = "did you mean" in (body or "").lower()
    leads.append({
        "check": "field_suggestions", "result": "leaky" if suggested else "quiet",
        "status": status,
        "verify_hint": ("leaky: repeated bogus fields harvest the schema WITHOUT "
                        "introspection — a schema-reconstruction lead. Pair with "
                        "exploit-graphql-authz once you have real field names."
                        if suggested else
                        "quiet: suggestions disabled; schema recon needs "
                        "introspection or documentation."),
    })

    # 4. JSON batching (array-of-queries enables alias/amplification abuse)
    status, body = _post(json.dumps([{"query": _TYPENAME_QUERY},
                                     {"query": _TYPENAME_QUERY}]))
    batched = (body or "").lstrip().startswith("[")
    leads.append({
        "check": "query_batching", "result": "accepted" if batched else "rejected",
        "status": status,
        "verify_hint": ("accepted: array batching bypasses per-request throttles "
                        "(skills/categories/graphql/alias_amplification) — prove "
                        "amplification with a differential check before claiming it."
                        if batched else
                        "rejected: single-query-per-request surface."),
    })
    return leads, made


class GraphqlInspectTool:
    name = "graphql_inspect"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Deterministic GraphQL checklist on ONE in-scope endpoint, exactly 4 "
                "benign requests: introspection (POST), query-over-GET support, "
                "field-suggestion leak (schema reconstruction without introspection), "
                "and JSON-array batching. Every check reports an honest result for "
                "BOTH outcomes with a verify_hint naming the next first-party move "
                "(find_techniques 'graphql', the authz-matrix playbook, cache "
                "skills). Leads only — nothing here is a finding until the proof "
                "pipeline confirms it."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "url": {"type": "string",
                            "description": "The GraphQL endpoint (e.g. https://host/graphql)."},
                    "reason": {"type": "string",
                               "description": "Why this inspection advances the test (audited)."},
                },
                "required": ["url", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, url: str, reason: str) -> str:
        try:
            ctx.scope.check(url)
        except ScopeViolation as exc:
            ctx.audit.record(f"{self.name}.blocked", target=url, cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        try:
            leads, requests_made = _probe_graphql(ctx, url, self.name)
        except ScopeViolation as exc:
            ctx.audit.record(f"{self.name}.blocked", target=url,
                             cause="out_of_scope_mid_probe")
            return f"BLOCKED (out of scope): {exc}"

        try:
            ctx.graph.observe(ENDPOINT, url,
                              attrs={"graphql": ";".join(
                                  f"{l['check']}={l['result']}" for l in leads)},
                              source=self.name)
        except Exception:
            pass

        ctx.audit.record(self.name, target=url, leads=len(leads),
                         requests=requests_made, reason=reason)
        return json.dumps({
            "ok": True, "url": url, "leads": leads, "lead_count": len(leads),
            "requests_made": requests_made,
            "note": ("Leads only. Enabled introspection and batching are facts about "
                     "the surface, not findings — the authz matrix and amplification "
                     "claims still need verify_vulnerability / verify_workflow_abuse "
                     "proofs."),
        }, ensure_ascii=False)

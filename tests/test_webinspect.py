"""W2 inspectors (xss_reflect_probe, graphql_inspect): the inspect -> spec -> prove chain.

The load-bearing assertion of this file: when the sink is live, the lead's
`check_spec` is EXACTLY the payload verify_vulnerability consumes 1:1 (named
requests + the reflected_unescaped condition), so discovery output IS the proof
input. Everything is markers-only (no payload blasting), request-capped,
scope-fenced, and leads-only (no finding writes).
"""

from __future__ import annotations

import json

import pytest

import redteam.tools.webinspect as wi
from redteam.tools.webinspect import (
    GraphqlInspectTool,
    XssReflectProbeTool,
    _classify_context,
    _header_reflection,
    _ready_check_spec,
)


class _Audit:
    def record(self, *a, **k):
        self.last = (a, k)


class _Scope:
    def check(self, url):
        pass


class _OutOfScope:
    def check(self, url):
        from redteam.scope import ScopeViolation
        raise ScopeViolation(f"{url} is out of scope")


class _Graph:
    def __init__(self):
        self.observed = []

    def observe(self, kind, key, attrs, source=None):
        self.observed.append((kind, key, dict(attrs), source))


class _Ctx:
    def __init__(self, scope=None, graph=None):
        self.scope = scope or _Scope()
        self.graph = graph
        self.audit = _Audit()
        self.sandbox = None


def _token_from(url: str) -> str:
    """Extract the runtime marker (rtxXXXXXX) from a probe URL."""
    return "rtx" + url.split("rtx")[1][:6]


def _scripted_fetch(responses):
    """responses: list of (status, body, headers) consumed in order."""
    calls = []

    def fetch(ctx, req, tool="", session=""):
        calls.append(dict(req))
        if not responses:
            return 404, "", 0.0, {}
        status, body, headers = responses.pop(0)
        return status, body, 0.01, headers
    return fetch, calls


# -- context classification ----------------------------------------------------------

def test_classify_context_variants():
    assert _classify_context("<p>hello rtx931abc world</p>", "rtx931abc") == "html_body"
    assert _classify_context('<a href="/x?name=rtx931abc">q</a>', "rtx931abc") == "attribute"
    assert _classify_context("<script>var q='rtx931abc';</script>", "rtx931abc") == "js"
    assert _classify_context('{"name": "rtx931abc"}', "rtx931abc") == "json"
    assert _classify_context("<p>nothing here</p>", "rtx931abc") == "none"


def test_header_reflection_skips_secret_adjacent_headers():
    assert _header_reflection({"Location": "https://t/?q=rtx931abc"}, "rtx931abc") == "Location"
    assert _header_reflection({"Set-Cookie": "sid=rtx931abc"}, "rtx931abc") is None
    assert _header_reflection({}, "rtx931abc") is None


# -- the ready check_spec ------------------------------------------------------------

def test_ready_check_spec_runs_through_the_real_predicate_engine():
    """Not just shape-compliant: the spec must EVALUATE correctly through
    redteam/proof.py's eval_condition — that is what 'consumed 1:1' means."""
    from redteam.proof import eval_condition
    spec = _ready_check_spec("https://t.example/search", "GET", "q", "rtx931abc'\"><")
    assert set(spec["requests"]) == {"payload"}
    req = spec["requests"]["payload"]
    assert req["method"] == "GET" and "q=rtx931abc%27%22%3E%3C" in req["url"]
    cond = spec["conditions"][0]
    assert cond["type"] == "reflected_unescaped" and cond["request"] == "payload"
    # a live sink echoes the raw token -> the proof PASSES
    ok, _ = eval_condition(cond, {"payload": (200, "<p>you searched: rtx931abc'\"><</p>", 0.01, {})})
    assert ok
    # an entity-encoded sink -> the proof FAILS (no false-ready specs)
    ok2, _ = eval_condition(cond, {"payload": (200, "<p>you searched: rtx931abc&#x27;&quot;&gt;&lt;</p>", 0.01, {})})
    assert not ok2


# -- xss_reflect_probe ---------------------------------------------------------------

def test_reflect_probe_emits_ready_spec_when_specials_survive(monkeypatch):
    def fetch(ctx, req, tool="", session=""):
        token = _token_from(req["url"])
        if len(req["url"].split("rtx")[1]) > 6:      # the specials probe
            return 200, f"<p>you searched: {token}'\"></p>", 0.01, {}
        return 200, f"<p>you searched: {token}</p>", 0.01, {}
    monkeypatch.setattr(wi, "fetch_once", fetch)

    ctx = _Ctx(graph=_Graph())
    out = json.loads(XssReflectProbeTool().run(ctx, "https://t.example/search",
                                               ["q"], "map reflection"))
    assert out["ok"] and out["requests_made"] == 2
    assert len(out["leads"]) == 1
    lead = out["leads"][0]
    assert lead["context"] == "html_body" and lead["specials_survive"] is True
    assert "check_spec" in lead
    assert lead["check_spec"]["conditions"][0]["type"] == "reflected_unescaped"
    kinds = {(k, key) for k, key, _, _ in ctx.graph.observed}
    assert ("parameter", "https://t.example/search#q") in kinds


def test_reflect_probe_escaped_reflection_holds_budget(monkeypatch):
    def fetch_escaped(ctx, req, tool="", session=""):
        t = _token_from(req["url"])
        if len(req["url"].split("rtx")[1]) > 6:     # the specials probe
            body = f"<p>{t}&lt;&#39;&quot;&gt;</p>"
        else:
            body = f"<p>{t}</p>"
        return 200, body, 0.01, {}
    monkeypatch.setattr(wi, "fetch_once", fetch_escaped)

    ctx = _Ctx()
    out = json.loads(XssReflectProbeTool().run(ctx, "https://t.example/search",
                                               ["q"], "map"))
    lead = out["leads"][0]
    assert lead["reflected"] and lead["specials_survive"] is False
    assert lead["escaped_forms"]                     # honest about the encoding
    assert "check_spec" not in lead                  # no false-ready spec
    assert "verify_finding_independently" not in lead["verify_hint"]
    assert "do NOT spend proof budget" in lead["verify_hint"]


def test_reflect_probe_no_reflection_costs_one_request(monkeypatch):
    fetch, calls = _scripted_fetch([(200, "<p>no marker here</p>", {})])
    monkeypatch.setattr(wi, "fetch_once", fetch)
    ctx = _Ctx()
    out = json.loads(XssReflectProbeTool().run(ctx, "https://t.example/s",
                                               ["q", "r"], "map"))
    assert out["leads"] == [] and out["requests_made"] == 2
    assert len(calls) == 2


def test_reflect_probe_blocks_out_of_scope_before_any_request(monkeypatch):
    monkeypatch.setattr(wi, "fetch_once",
                        lambda *a, **k: pytest.fail("must not send"))
    ctx = _Ctx(scope=_OutOfScope())
    out = XssReflectProbeTool().run(ctx, "https://evil.example/", ["q"], "nope")
    assert out.startswith("BLOCKED (out of scope)")


def test_reflect_probe_requires_params_and_caps_them(monkeypatch):
    monkeypatch.setattr(wi, "fetch_once", lambda *a, **k: (200, "", 0.01, {}))
    ctx = _Ctx()
    assert XssReflectProbeTool().run(ctx, "https://t.example/", [], "why").startswith("ERROR:")
    out = json.loads(XssReflectProbeTool().run(
        ctx, "https://t.example/", [f"p{i}" for i in range(20)], "cap"))
    assert out["requests_made"] <= 2 * 5               # max 5 params, <= 2 requests each


def test_reflect_probe_header_reflection_has_no_check_spec(monkeypatch):
    def fetch(ctx, req, tool="", session=""):
        token = _token_from(req["url"])
        return 302, "", 0.01, {"Location": f"https://t/next?q={token}"}
    monkeypatch.setattr(wi, "fetch_once", fetch)

    ctx = _Ctx()
    out = json.loads(XssReflectProbeTool().run(ctx, "https://t.example/redirect",
                                               ["q"], "map"))
    lead = out["leads"][0]
    assert lead["context"] == "response_header" and lead["header"] == "Location"
    assert "check_spec" not in lead                    # header reflection is not an XSS sink


# -- graphql_inspect -----------------------------------------------------------------

def test_graphql_inspect_full_checklist(monkeypatch):
    responses = [
        (200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}', {}),
        (200, '{"data":{"__typename":"Query"}}', {}),
        (400, '{"errors":[{"message":"Cannot query field \'__thisfielddoesnotexist0x2c1\' '
              'on type \'Query\'. Did you mean \'__typename\'?"}]}', {}),
        (200, '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]', {}),
    ]
    fetch, calls = _scripted_fetch(responses)
    monkeypatch.setattr(wi, "fetch_once", fetch)

    ctx = _Ctx(graph=_Graph())
    out = json.loads(GraphqlInspectTool().run(ctx, "https://t.example/graphql", "map api"))
    assert out["ok"] and out["requests_made"] == 4 and len(calls) == 4
    results = {l["check"]: l["result"] for l in out["leads"]}
    assert results == {"introspection_post": "enabled", "query_over_get": "supported",
                       "field_suggestions": "leaky", "query_batching": "accepted"}
    # batching probe really sent a JSON array
    assert calls[3]["body"].startswith("[")
    node = next(o for o in ctx.graph.observed if o[0] == "endpoint")
    assert "introspection_post=enabled" in node[2]["graphql"]
    hints = {l["check"]: l["verify_hint"] for l in out["leads"]}
    assert "find_techniques" in hints["introspection_post"]


def test_graphql_inspect_honest_on_disabled(monkeypatch):
    fetch, _calls = _scripted_fetch([
        (200, '{"errors":[{"message":"introspection disabled"}]}', {}),
        (405, "method not allowed", {}),
        (400, '{"errors":[{"message":"Cannot query field."}]}', {}),
        (400, '{"errors":[{"message":"batch not allowed"}]}', {}),
    ])
    monkeypatch.setattr(wi, "fetch_once", fetch)
    ctx = _Ctx()
    out = json.loads(GraphqlInspectTool().run(ctx, "https://t.example/graphql", "map"))
    results = {l["check"]: l["result"] for l in out["leads"]}
    assert results == {"introspection_post": "disabled", "query_over_get": "not_supported",
                       "field_suggestions": "quiet", "query_batching": "rejected"}


def test_graphql_inspect_degrades_never_raises(monkeypatch):
    def fetch_boom(ctx, req, tool="", session=""):
        raise RuntimeError("socket closed")
    monkeypatch.setattr(wi, "fetch_once", fetch_boom)
    ctx = _Ctx()
    out = json.loads(GraphqlInspectTool().run(ctx, "https://t.example/graphql", "why"))
    assert out["ok"] is True and out["lead_count"] == 4
    assert all(l["result"] in ("disabled", "not_supported", "quiet", "rejected")
               for l in out["leads"])


def test_graphql_inspect_blocks_out_of_scope(monkeypatch):
    monkeypatch.setattr(wi, "fetch_once",
                        lambda *a, **k: pytest.fail("must not send"))
    ctx = _Ctx(scope=_OutOfScope())
    out = GraphqlInspectTool().run(ctx, "https://evil.example/graphql", "nope")
    assert out.startswith("BLOCKED (out of scope)")

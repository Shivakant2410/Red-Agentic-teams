"""crosscheck_lead — the "never believe a tool's direct output" rule, tested.

Contract under test:
  - every (tool, claim) pair in TRUST_MATRIX returns corroborated / contradicted /
    unverifiable from a SECOND method, never from the producing tool's own output;
  - unknown tools and unknown claims FAIL CLOSED (no trust by default);
  - exempt classes are documented verdicts, not silent passes;
  - the reflection re-check uses a FRESH marker the original probe never generated;
  - the param differential compares WITH/without pairs and refuses to invent signal;
  - scope is enforced before any socket, and refusals are "unverifiable", not errors;
  - matrix introspection stays JSON-complete (every lead tool accounted for).
"""

from __future__ import annotations

import json

import pytest

from redteam.tools import build_registry
from redteam.tools.crosscheck import TRUST_MATRIX, CrossCheckTool, matrix_json


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, *a, **k):
        self.events.append((a, k))


class _Scope:
    def __init__(self, deny=False):
        self.denied = deny

    def check(self, url):
        if self.denied:
            from redteam.scope import ScopeViolation
            raise ScopeViolation(f"{url} is out of scope")


class _Ctx:
    def __init__(self, deny=False):
        self.scope = _Scope(deny)
        self.audit = _Audit()


def _run(monkeypatch, fetch, **kw):
    monkeypatch.setattr("redteam.tools.crosscheck.fetch_once", fetch)
    out = CrossCheckTool().run(_Ctx(), **kw)
    return json.loads(out)


# -- verdicts ----------------------------------------------------------------------

def test_endpoint_corroborated_then_contradicted(monkeypatch):
    # ffuf said /admin.bak exists; first-party GET must agree (or not).
    ok = _run(monkeypatch, lambda *a, **k: (200, "hello", 0.01, {}),
              tool="content_discovery", claim="endpoint", url="http://t/x")
    assert ok["verdict"] == "corroborated" and ok["method"] == "http_get"
    dead = _run(monkeypatch, lambda *a, **k: (404, "nope", 0.01, {}),
                tool="crawl", claim="endpoint", url="http://t/x")
    assert dead["verdict"] == "contradicted"


def test_5xx_is_not_evidence(monkeypatch):
    out = _run(monkeypatch, lambda *a, **k: (503, "down", 0.01, {}),
               tool="host_probe", claim="endpoint", url="http://t/")
    assert out["verdict"] == "unverifiable"


def test_nuclei_marker_check(monkeypatch):
    hit = _run(monkeypatch, lambda *a, **k: (200, "version: 2.3.1 here", 0.01, {}),
               tool="nuclei_scan", claim="template_match",
               url="http://t/status", marker="2.3.1")
    assert hit["verdict"] == "corroborated"
    miss = _run(monkeypatch, lambda *a, **k: (200, "nothing here", 0.01, {}),
                tool="nuclei_scan", claim="template_match",
                url="http://t/status", marker="2.3.1")
    assert miss["verdict"] == "contradicted"


def test_param_differential_detects_and_rejects(monkeypatch):
    # The with-param request gets a different body -> corroborated.
    calls = {"n": 0}

    def fetch(ctx, req, *a, **k):
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # the WITH variant
            return 200, "A" * 300, 0.01, {}
        return 200, "A" * 100, 0.01, {}

    out = _run(monkeypatch, fetch, tool="param_discovery", claim="hidden_param",
               url="http://t/search", param="debug")
    assert out["verdict"] == "corroborated" and "delta" in out["detail"]

    flat = _run(monkeypatch, lambda *a, **k: (200, "same", 0.01, {}),
                tool="param_discovery", claim="hidden_param",
                url="http://t/search", param="debug")
    assert flat["verdict"] == "contradicted"


def test_param_differential_needs_inputs(monkeypatch):
    out = _run(monkeypatch, lambda *a, **k: (200, "x", 0.01, {}),
               tool="param_discovery", claim="hidden_param", url="http://t/")
    assert out["verdict"] == "unverifiable"


def test_reflection_recheck_uses_a_fresh_marker(monkeypatch):
    seen = {}

    def fetch(ctx, req, *a, **k):
        seen["url"] = req["url"]
        fresh = req["url"].rsplit("=", 1)[1]
        return 200, f"<p>echo: {fresh}</p>", 0.01, {}

    out = _run(monkeypatch, fetch, tool="xss_reflect_probe", claim="reflection",
               url="http://t/hello", param="name")
    assert out["verdict"] == "corroborated"
    assert seen["url"].startswith("http://t/hello?name=rbx2")
    # A page that reflects NOTHING contradicts the mapping.
    blind = _run(monkeypatch, lambda *a, **k: (200, "static page", 0.01, {}),
                 tool="xss_reflect_probe", claim="reflection",
                 url="http://t/hello", param="name")
    assert blind["verdict"] == "contradicted"


def test_service_claim_via_raw_socket(monkeypatch):
    # A real loopback listener corroborates; a refused connect contradicts.
    import socket as _s
    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    out = _run(monkeypatch, lambda *a, **k: None, tool="port_scan", claim="service",
               host="127.0.0.1", port=port)
    assert out["verdict"] == "corroborated"
    srv.close()
    dead = _run(monkeypatch, lambda *a, **k: None, tool="port_scan", claim="service",
                host="127.0.0.1", port=port)
    assert dead["verdict"] == "contradicted"


def test_socket_is_scope_guarded(monkeypatch):
    out = _run(monkeypatch, lambda *a, **k: None, tool="port_scan", claim="service",
               host="127.0.0.1", port=1)
    ctx = _Ctx(deny=True)
    monkeypatch.setattr("redteam.tools.crosscheck.fetch_once", lambda *a, **k: None)
    blocked = json.loads(CrossCheckTool().run(ctx, tool="port_scan", claim="service",
                                              host="127.0.0.1", port=1))
    assert blocked["verdict"] == "unverifiable" and "scope" in blocked["detail"]


# -- fail-closed + exemptions ------------------------------------------------------

def test_unknown_tool_fails_closed():
    out = json.loads(CrossCheckTool().run(_Ctx(), tool="made_up", claim="endpoint"))
    assert "error" in out and "never believed" in out["error"]


def test_unknown_claim_fails_closed():
    out = json.loads(CrossCheckTool().run(_Ctx(), tool="content_discovery",
                                          claim="rce_surely"))
    assert "error" in out


def test_graphql_claims_are_unverifiable_not_believed():
    out = json.loads(CrossCheckTool().run(_Ctx(), tool="graphql_inspect",
                                          claim="introspection_post", url="http://t/gql"))
    assert out["verdict"] == "unverifiable" and "NOT believed" in out["detail"]


def test_exempt_classes_return_documented_verdicts():
    for tool in ("surface_scan", "jwt_inspect"):
        out = json.loads(CrossCheckTool().run(_Ctx(), tool=tool, claim="endpoint"))
        assert out["verdict"] == "exempt" and out["detail"]


def test_matrix_introspection_is_complete_and_json():
    m = json.loads(matrix_json())
    # Every lead-producing tool in the registry is either in the matrix or exempt.
    reg = build_registry(enable_sandbox=False, enable_browser=False)
    lead_tools = {"content_discovery", "crawl", "param_discovery", "nuclei_scan",
                  "host_probe", "port_scan", "spa_recon", "xss_reflect_probe",
                  "graphql_inspect", "surface_scan", "jwt_inspect"}
    assert lead_tools <= set(reg), "inventory drift: a lead tool vanished from the registry"
    covered = set(m["matrix"]) | set(m["exempt"])
    assert lead_tools <= covered, f"uncovered lead tools: {lead_tools - covered}"


def test_results_are_audited_never_findings(monkeypatch):
    ctx = _Ctx()
    monkeypatch.setattr("redteam.tools.crosscheck.fetch_once",
                        lambda *a, **k: (200, "ok", 0.01, {}))
    CrossCheckTool().run(ctx, tool="content_discovery", claim="endpoint",
                         url="http://t/x")
    assert any(a[0] == "crosscheck.result" for a, _ in ctx.audit.events)

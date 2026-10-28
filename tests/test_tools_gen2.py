"""jwt_inspect + nuclei_scan: deterministic analysis and lead-only scanning."""

from __future__ import annotations

import base64
import datetime as _dt
import json

import pytest

from redteam.tools.jwt import JwtInspectTool, analyze
from redteam.tools.nuclei import NucleiScanTool, _build_command, _parse_results


def _mk_jwt(header: dict, payload: dict, sig: str = "c2ln") -> str:
    def enc(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.{sig}"


# -- jwt_inspect -----------------------------------------------------------------

def test_jwt_alg_none_is_critical():
    r = analyze(_mk_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}))
    assert r["ok"]
    top = r["leads"][0]
    assert top["severity"] == "critical" and "none" in top["title"]
    assert any("replay" in l["verify_hint"].lower() for l in r["leads"])


def test_jwt_missing_exp_and_kid_and_jku():
    r = analyze(_mk_jwt({"alg": "HS256", "kid": "../../dev/null", "jku": "https://x/k"},
                        {"sub": "42"}))
    titles = [l["title"] for l in r["leads"]]
    assert any("kid" in t for t in titles)
    assert any("jku" in t for t in titles)
    assert any("no expiry" in t for t in titles)
    severities = {l["severity"] for l in r["leads"]}
    assert "high" in severities      # jku
    assert "medium" in severities    # kid + no-exp + sequential sub


def test_jwt_expired_and_long_lifetime_and_pii():
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    r = analyze(_mk_jwt({"alg": "HS256"}, {
        "sub": "1001", "email": "a@b.c", "iat": int(now - 400 * 86400),
        "exp": int(now - 86400)}))
    titles = [l["title"] for l in r["leads"]]
    assert any("expired" in t for t in titles)
    assert any("long-lived" in t for t in titles)
    assert any("personal data" in t for t in titles)
    assert any("sequential numeric" in t for t in titles)


def test_jwt_garbage_token_errors():
    r = analyze("not.a.jwt!!")
    assert r["ok"] is False and "error" in r


class _Audit:
    def record(self, *a, **k):
        pass


class _JwtCtx:
    audit = _Audit()


class _OutOfScope:
    def check(self, url):
        from redteam.scope import ScopeViolation
        raise ScopeViolation(f"{url} is out of scope")


class _OOSCtx:
    scope = _OutOfScope()
    sandbox = None
    graph = None
    audit = _Audit()


def test_jwt_tool_run_redacts_signature():
    tool = JwtInspectTool()
    token = _mk_jwt({"alg": "HS256"}, {"sub": "7"}, sig="REALSECRET-sig-bytes")
    out = json.loads(tool.run(ctx=_JwtCtx(), token=token))
    assert out["ok"]
    assert "REALSECRET" not in json.dumps(out)
    assert out["signature_present"] is True


# -- nuclei_scan -----------------------------------------------------------------

def test_nuclei_command_building_quotes_and_filters():
    cmd = _build_command("https://t.example", "cves,http/x.yaml", "critical,high",
                         50, 5, 10)
    assert cmd.startswith("nuclei -u https://t.example")
    assert "-tags cves" in cmd and "-t http/x.yaml" in cmd
    assert "-severity critical,high" in cmd and "-json" in cmd
    assert " -rl 50" in cmd and " -c 10" in cmd


def test_nuclei_parse_results_jsonl():
    rows = [
        json.dumps({"template-id": "CVE-2021-1", "info": {"name": "X", "severity": "high"},
                    "matched-at": "https://t/a", "host": "https://t"}),
        "not json",
        json.dumps({"templateID": "tech", "info": {"name": "Tech", "severity": "info"},
                    "matched": "https://t/b"}),
    ]
    leads = _parse_results("\n".join(rows))
    assert len(leads) == 2
    assert leads[0]["template_id"] == "CVE-2021-1" and leads[0]["severity"] == "high"
    assert leads[1]["template_id"] == "tech" and leads[1]["matched_at"] == "https://t/b"


def test_nuclei_blocks_out_of_scope():
    tool = NucleiScanTool()
    out = tool.run(ctx=_OOSCtx(), target="https://evil.example", reason="r")
    assert "BLOCKED" in out


def test_nuclei_leads_only_note_and_graph_fold():
    calls = {}

    class Scope:
        def check(self, url):
            calls["scoped"] = url

    class Sandbox:
        def exec(self, command, timeout=None):
            calls["cmd"] = command
            class R:
                exit_code = 0
                stdout = json.dumps({"template-id": "T-1", "info": {"name": "N",
                                    "severity": "high"}, "matched-at": "https://t.example/x",
                                    "host": "https://t.example"})
                stderr = ""
            return R()

    class Graph:
        def observe(self, kind, key, attrs, source=None):
            calls.setdefault("graph", []).append((kind, key, source))

    class Ctx:
        scope = Scope()
        sandbox = Sandbox()
        graph = Graph()
        audit = _Audit()

    out = json.loads(NucleiScanTool().run(
        ctx=Ctx(), target="https://t.example", reason="scan"))
    assert out["surface"] == "sandbox"
    assert out["lead_count"] == 1
    assert out["leads"][0]["template_id"] == "T-1"
    assert "not a finding" in out["note"]
    assert calls["graph"] and calls["graph"][0][0] == "endpoint"
    assert calls["graph"][0][2] == "nuclei_scan"


def test_nuclei_no_sandbox_no_binary_is_clear_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)

    class Scope:
        def check(self, url):
            pass

    class Ctx:
        scope = Scope()
        sandbox = None
        graph = None
        audit = _Audit()

    out = NucleiScanTool().run(ctx=Ctx(), target="https://t.example", reason="r")
    assert out.startswith("ERROR") and "nuclei" in out

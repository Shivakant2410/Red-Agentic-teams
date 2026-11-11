"""W1b deep probes (host_probe/httpx, port_scan/nmap): leads only, RoE-fenced.

Mirrors the test_webdiscover.py contract: fixed allowlist command building,
junk-tolerant capped parsers, out-of-scope BLOCKED, no-sandbox-no-binary is a
clear error, degradation never raises, and structured facts (ENDPOINT /
TECHNOLOGY / HOST / SERVICE) fold into the knowledge graph.
"""

from __future__ import annotations

import json

import pytest

from redteam.tools.hostprobe import (
    HostProbeTool,
    PortScanTool,
    _build_httpx_command,
    _build_nmap_command,
    _httpx_observations,
    _nmap_observations,
    _parse_httpx,
    _parse_nmap,
    _validate_portspec,
)


class _Audit:
    def record(self, *a, **k):
        self.last = (a, k)


class _OutOfScope:
    def check(self, url):
        from redteam.scope import ScopeViolation
        raise ScopeViolation(f"{url} is out of scope")

    allowed_ports = (80, 443)


class _Scope:
    def check(self, url):
        pass

    allowed_ports = (80, 443, 8080)


class _Graph:
    def __init__(self):
        self.observed = []

    def observe(self, kind, key, attrs, source=None):
        self.observed.append((kind, key, dict(attrs), source))


class _Ctx:
    def __init__(self, scope=None, sandbox=None, graph=None):
        self.scope = scope or _Scope()
        self.sandbox = sandbox
        self.graph = graph
        self.audit = _Audit()


class _Result:
    def __init__(self, exit_code=0, stdout="", stderr=""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class _Sandbox:
    def __init__(self, result=None):
        self._result = result or _Result()
        self.commands = []

    def exec(self, command, timeout=None):
        self.commands.append(command)
        return self._result


# -- command building ---------------------------------------------------------------

def test_httpx_command_is_fixed_allowlist():
    cmd = _build_httpx_command("https://t.example/app", 8)
    assert cmd.startswith("httpx -u https://t.example/app")
    assert "-json -silent -no-color" in cmd
    assert "-status-code" in cmd and "-title" in cmd and "-tech-detect" in cmd
    assert "-ip" in cmd and "-timeout 8" in cmd
    # no free-form flags can sneak in
    assert cmd.count("-u ") == 1


def test_nmap_command_polite_and_xml_to_stdout():
    cmd = _build_nmap_command("203.0.113.5", 100, "")
    assert cmd.startswith("nmap -Pn -sV --version-light -T3 --open -oX -")
    assert "--top-ports 100" in cmd and "203.0.113.5" in cmd
    cmd2 = _build_nmap_command("203.0.113.5", 100, "80,443,8080")
    assert "-p 80,443,8080" in cmd2 and "--top-ports" not in cmd2


def test_portspec_validation_fails_closed():
    allowed = (80, 443, 8080)
    assert _validate_portspec("80,443", allowed) == "80,443"
    assert _validate_portspec("8000-8100", allowed) is None        # out of RoE
    assert _validate_portspec("80; rm -rf /", allowed) is None     # not a port list
    assert _validate_portspec("", allowed) is None
    assert _validate_portspec("80," * 50 + "80", allowed) is None  # > 40 ports
    assert _validate_portspec("0,65536", allowed) is None          # out of range
    assert _validate_portspec("443", ()) is None                   # empty RoE ports = nothing allowed


# -- parsers -------------------------------------------------------------------------

def test_httpx_parser_ndjson_junk_tolerant_and_capped():
    lines = [
        "not json at all",
        '{"url":"https://t.example/","status_code":200,"title":"ACME Portal","technologies":["nginx","WordPress"],"host":"t.example","ip":"203.0.113.5","location":""}',
        '{"no_url_here": true}',
        "corrupt {json",
        '{"url":"https://t.example/admin","status_code":403,"title":"","technologies":"not-a-list"}',
    ]
    leads = _parse_httpx("\n".join(lines))
    assert len(leads) == 2
    assert leads[0]["status"] == 200 and leads[0]["title"] == "ACME Portal"
    assert leads[0]["tech"] == ["nginx", "WordPress"]
    assert leads[1]["tech"] == []                      # junk tech field tolerated
    assert _parse_httpx("garbage") == []


def test_nmap_parser_open_only_and_junk_tolerant():
    xml = """<nmaprun>
      <host><address addr="203.0.113.5" addrtype="ipv4"/>
        <hostnames><hostname name="web.acme.example"/></hostnames>
        <ports>
          <port protocol="tcp" portid="443"><state state="open"/>
            <service name="https" product="nginx" version="1.24.0"/></port>
          <port protocol="tcp" portid="22"><state state="closed"/>
            <service name="ssh"/></port>
          <port protocol="tcp" portid="8080"><state state="open"/>
            <service name="http-alt" product="Apache Tomcat" version="9"/></port>
        </ports>
      </host></nmaprun>"""
    leads = _parse_nmap(xml)
    assert [l["port"] for l in leads] == ["443", "8080"]     # closed ports never surface
    assert leads[0]["host"] == "web.acme.example" and leads[0]["ip"] == "203.0.113.5"
    assert leads[0]["product"] == "nginx"
    assert _parse_nmap("not xml at all <broken") == []
    assert _parse_nmap("<nmaprun></nmaprun>") == []


# -- graph folding -------------------------------------------------------------------

def test_httpx_observations_fold_endpoint_and_technology():
    leads = [{"url": "https://t.example/", "status": 200, "title": "T", "ip": "203.0.113.5",
              "tech": ["nginx", "django", "nginx"]}][:1]
    obs = _httpx_observations(leads + [{"url": "not-a-url", "tech": ["x"]}])
    kinds = [(k, key) for k, key, _ in obs]
    assert ("endpoint", "https://t.example/") in kinds
    assert ("technology", "nginx") in kinds and ("technology", "django") in kinds
    assert all("not-a-url" != key for _, key in kinds)


def test_nmap_observations_fold_host_service_and_web_endpoint():
    leads = [{"ip": "203.0.113.5", "host": "web.acme.example", "port": "443",
              "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24.0"},
             {"ip": "203.0.113.5", "host": "", "port": "22",
              "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9"}]
    obs = _nmap_observations(leads)
    kinds = [(k, key) for k, key, _ in obs]
    assert ("host", "203.0.113.5") in kinds
    assert ("service", "203.0.113.5:443") in kinds
    assert ("service", "203.0.113.5:22") in kinds
    assert ("endpoint", "https://203.0.113.5:443/") in kinds    # web-ish service gets a stub
    assert ("endpoint", "http://203.0.113.5:22/") not in kinds  # ssh does not


# -- tool behavior -------------------------------------------------------------------

def test_host_probe_runs_sandbox_folds_graph_and_audits():
    graph = _Graph()
    stdout = ('{"url":"https://t.example/","status_code":200,"title":"ACME",'
              '"technologies":["nginx"],"host":"t.example","ip":"203.0.113.5"}')
    ctx = _Ctx(sandbox=_Sandbox(_Result(stdout=stdout)), graph=graph)
    out = json.loads(HostProbeTool().run(ctx, "https://t.example/", "map perimeter"))
    assert out["ok"] and out["lead_count"] == 1
    assert out["surface"] == "sandbox"
    assert out["graph_updates"] >= 2                    # ENDPOINT + TECHNOLOGY
    kinds = {(k, key) for k, key, _, _ in graph.observed}
    assert ("endpoint", "https://t.example/") in kinds
    assert ctx.audit.last[0][0] == "host_probe"


def test_host_probe_out_of_scope_blocked():
    ctx = _Ctx(scope=_OutOfScope())
    out = HostProbeTool().run(ctx, "https://evil.example/", "nope")
    assert out.startswith("BLOCKED (out of scope)")
    assert ctx.audit.last[1]["cause"] == "out_of_scope"


def test_no_sandbox_no_binary_is_a_clear_error(monkeypatch):
    import redteam.tools.hostprobe as hp
    monkeypatch.setattr(hp.shutil, "which", lambda b: None)
    ctx = _Ctx()
    out = HostProbeTool().run(ctx, "https://t.example/", "no tools")
    assert out.startswith("ERROR:") and "httpx" in out


def test_port_scan_out_of_scope_host_blocked():
    ctx = _Ctx(scope=_OutOfScope())
    out = PortScanTool().run(ctx, "evil.example", "nope")
    assert out.startswith("BLOCKED (out of scope)")


def test_port_scan_refuses_out_of_roe_ports():
    ctx = _Ctx(scope=_Scope())
    out = PortScanTool().run(ctx, "203.0.113.5", "depth", ports="9999")
    assert out.startswith("BLOCKED:")
    assert ctx.audit.last[1]["cause"] == "invalid_or_out_of_scope_ports"


def test_port_scan_explicit_ports_validated_then_run():
    xml = ('<nmaprun><host><address addr="203.0.113.5" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="8080"><state state="open"/>'
           '<service name="http-alt" product="Tomcat" version="9"/></port>'
           '</ports></host></nmaprun>')
    sandbox = _Sandbox(_Result(stdout=xml))
    ctx = _Ctx(sandbox=sandbox, graph=_Graph())
    out = json.loads(PortScanTool().run(ctx, "203.0.113.5", "what is 8080",
                                        ports="8080,80"))
    assert out["ok"] and out["lead_count"] == 1 and out["leads"][0]["product"] == "Tomcat"
    assert "-p 8080,80" in sandbox.commands[0]
    assert ctx.audit.last[1]["ports"] == "8080,80"


def test_port_scan_degraded_never_raises():
    class Boom:
        def exec(self, command, timeout=None):
            raise RuntimeError("sandbox died")
    ctx = _Ctx(sandbox=Boom())
    out = json.loads(PortScanTool().run(ctx, "203.0.113.5", "depth"))
    assert out["ok"] is False and "port scan failed" in out["error"]

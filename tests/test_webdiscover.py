"""Phase W1 discovery tools (ffuf/katana/arjun): leads only, capped, scope-guarded.

Mirrors tests/test_tools_gen2.py's nuclei contract tests: command building is a
fixed allowlist, parsers are junk-tolerant and capped, out-of-scope is BLOCKED,
no sandbox + no binary is a clear error, degradation never raises, and endpoints
(but not parameters) fold into the knowledge graph.
"""

from __future__ import annotations

import json

import pytest

from redteam.tools.webdiscover import (
    ContentDiscoveryTool,
    CrawlTool,
    ParamDiscoveryTool,
    _build_arjun_command,
    _build_ffuf_command,
    _build_katana_command,
    _parse_arjun,
    _parse_ffuf,
    _parse_katana,
)


class _Audit:
    def record(self, *a, **k):
        self.last = (a, k)


class _OutOfScope:
    def check(self, url):
        from redteam.scope import ScopeViolation
        raise ScopeViolation(f"{url} is out of scope")


class _OOSCtx:
    scope = _OutOfScope()
    sandbox = None
    graph = None
    audit = _Audit()


class _Scope:
    def check(self, url):
        pass


class _Graph:
    def __init__(self):
        self.observed = []

    def observe(self, kind, key, attrs, source=None):
        self.observed.append((kind, key, dict(attrs), source))


# -- command building ---------------------------------------------------------------

def test_ffuf_command_fixed_allowlist_and_flags():
    cmd = _build_ffuf_command("https://t.example/app", "common", 50, 10, 5)
    assert cmd.startswith("ffuf -u https://t.example/appFUZZ")
    assert "/usr/share/seclists/Discovery/Web-Content/common.txt" in cmd
    assert "-json -s -ac" in cmd and "-rate 50" in cmd and "-t 10" in cmd
    assert "-of json" in cmd


def test_ffuf_unknown_wordlist_falls_back_to_common():
    commands = []

    class Sandbox:
        def exec(self, command, timeout=None):
            commands.append(command)
            class R:
                exit_code = 0
                stdout = ""
                stderr = ""
            return R()

    out = json.loads(ContentDiscoveryTool().run(
        ctx=_mk_ctx(sandbox=Sandbox()), target="https://t.example", reason="r",
        wordlist="../../etc/passwd"))
    assert out["ok"]
    assert "/usr/share/seclists/Discovery/Web-Content/common.txt" in commands[0]
    assert "../../etc/passwd" not in commands[0]   # never reaches the command line


def test_katana_command_scoped_and_capped():
    cmd = _build_katana_command("https://t.example", 99, 99, 999, 5)
    assert cmd.startswith("katana -u https://t.example")
    assert "-fs rdn" in cmd                      # cannot wander off-target
    assert "-d 5" in cmd and "-c 30" in cmd and "-rl 200" in cmd  # clamped
    assert "-jsonl" in cmd and "-silent" in cmd


def test_arjun_command_writes_tmp_and_cats():
    cmd = _build_arjun_command("https://t.example", 20, 5)
    assert cmd.startswith("arjun -u https://t.example")
    assert "-oJ /tmp/arjun_out.json" in cmd and "--stable" in cmd
    assert cmd.rstrip().endswith("cat /tmp/arjun_out.json")


# -- parsers ------------------------------------------------------------------------

def test_parse_ffuf_results_and_junk():
    good = json.dumps({
        "results": [
            {"url": "https://t.example/admin", "input": {"FUZZ": "admin"},
             "status": 200, "length": 1234, "words": 100, "lines": 10,
             "content-type": "text/html"},
            {"no-url": True},
            "junk-string",
        ]})
    leads = _parse_ffuf(good + "\nnot json\n" + json.dumps({"results": []}))
    assert len(leads) == 1
    assert leads[0]["url"] == "https://t.example/admin"
    assert leads[0]["word"] == "admin" and leads[0]["status"] == 200


def test_parse_ffuf_caps_at_max_leads():
    row = json.dumps({"results": [{"url": f"https://t.example/p{i}",
                                   "input": {"FUZZ": f"p{i}"}} for i in range(500)]})
    assert len(_parse_ffuf(row)) == 200


def test_parse_katana_jsonl_shapes():
    lines = [
        json.dumps({"request": {"method": "GET", "endpoint": "https://t.example/login"},
                    "response": {"status_code": 200}}),
        json.dumps({"endpoint": "https://t.example/legacy"}),   # older flat shape
        "not json",
        json.dumps({"request": {"method": "POST"}}),            # no endpoint -> skipped
    ]
    leads = _parse_katana("\n".join(lines))
    assert len(leads) == 2
    assert leads[0] == {"url": "https://t.example/login", "method": "GET", "status": 200}
    assert leads[1]["method"] == "GET" and leads[1]["status"] is None


def test_parse_arjun_flat_and_batch():
    flat = json.dumps({"params": ["id", "page", "", "debug"]})
    leads = _parse_arjun(flat)
    assert [l["param"] for l in leads] == ["id", "page", "debug"]

    batch = json.dumps({"https://a": {"params": ["x"]}, "https://b": {"params": ["y"]}})
    assert [l["param"] for l in _parse_arjun(batch)] == ["x", "y"]

    assert _parse_arjun("not json") == []
    assert _parse_arjun("[1,2]") == []


# -- tool behavior ------------------------------------------------------------------

class _Ctx:
    def __init__(self, sandbox=None, graph=None):
        self.scope = _Scope()
        self.audit = _Audit()
        self.sandbox = sandbox
        self.graph = graph


def _mk_ctx(sandbox=None, graph=None):
    return _Ctx(sandbox=sandbox, graph=graph)


def test_content_discovery_sandbox_path_graph_fold_and_note():
    class Sandbox:
        def exec(self, command, timeout=None):
            assert "ffuf" in command and "; true" in command
            class R:
                exit_code = 0
                stdout = json.dumps({"results": [
                    {"url": "https://t.example/api/v2", "input": {"FUZZ": "api"},
                     "status": 200, "length": 10, "words": 2, "lines": 1}]})
                stderr = ""
            return R()

    graph = _Graph()
    out = json.loads(ContentDiscoveryTool().run(
        ctx=_mk_ctx(sandbox=Sandbox(), graph=graph), target="https://t.example",
        reason="find surface"))
    assert out["surface"] == "sandbox" and out["lead_count"] == 1
    assert out["graph_updates"] == 1
    kind, url, attrs, source = graph.observed[0]
    assert kind == "endpoint" and url == "https://t.example/api/v2"
    assert source == "content_discovery"
    assert "not a finding" in out["note"]


def test_crawl_leads_only_note():
    class Sandbox:
        def exec(self, command, timeout=None):
            class R:
                exit_code = 0
                stdout = json.dumps({"request": {"method": "GET",
                                                 "endpoint": "https://t.example/x"},
                                     "response": {"status_code": 200}})
                stderr = ""
            return R()

    out = json.loads(CrawlTool().run(ctx=_mk_ctx(sandbox=Sandbox()),
                                     target="https://t.example", reason="r"))
    assert out["lead_count"] == 1 and "not a finding" in out["note"]


def test_param_discovery_no_graph_fold():
    class Sandbox:
        def exec(self, command, timeout=None):
            class R:
                exit_code = 0
                stdout = json.dumps({"params": ["id", "debug"]})
                stderr = ""
            return R()

    graph = _Graph()
    out = json.loads(ParamDiscoveryTool().run(
        ctx=_mk_ctx(sandbox=Sandbox(), graph=graph), target="https://t.example",
        reason="r"))
    assert out["lead_count"] == 2 and graph.observed == []   # params are not endpoints
    assert "until proven" in out["note"] or "proves nothing" in out["note"]


@pytest.mark.parametrize("tool", [ContentDiscoveryTool(), CrawlTool(), ParamDiscoveryTool()])
def test_all_tools_block_out_of_scope(tool):
    out = tool.run(ctx=_OOSCtx(), target="https://evil.example", reason="r")
    assert "BLOCKED" in out


@pytest.mark.parametrize("tool", [ContentDiscoveryTool(), CrawlTool(), ParamDiscoveryTool()])
def test_all_tools_clear_error_without_sandbox_or_binary(tool, monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    # also hide the on-requirement toolbox venv — it may legitimately contain
    # provisioned binaries (hermetic: no sandbox, no PATH, no venv)
    monkeypatch.setattr("redteam.sandbox.provision._DEFAULT_VENV",
                        tmp_path / "empty-venv")
    out = tool.run(ctx=_mk_ctx(), target="https://t.example", reason="r")
    assert out.startswith("ERROR")


@pytest.mark.parametrize("tool", [ContentDiscoveryTool(), CrawlTool(), ParamDiscoveryTool()])
def test_all_tools_degrade_on_sandbox_crash(tool):
    class Boom:
        def exec(self, command, timeout=None):
            raise RuntimeError("sandbox died")

    out = tool.run(ctx=_mk_ctx(sandbox=Boom()), target="https://t.example", reason="r")
    parsed = json.loads(out)
    assert parsed["ok"] is False and "failed" in parsed["error"]


def test_registry_includes_w1_tools():
    from redteam.tools import build_registry
    registry = build_registry(enable_sandbox=False, enable_browser=False)
    for name in ("content_discovery", "crawl", "param_discovery"):
        assert name in registry
        schema = registry[name].schema()
        assert schema["input_schema"]["required"] == ["target", "reason"]

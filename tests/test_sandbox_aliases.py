"""Loopback targets inside the Kali sandbox.

A lab published on the host is briefed to the agent as localhost:<port>. Inside the Kali
container that is Kali's own loopback, so every kali_exec against it failed (curl exit
7) and sandbox recon looked empty. The runner now writes sandbox.target_aliases, and
kali_exec rewrites exact in-scope host:port pairs onto the lab's Docker-network address.
"""

from __future__ import annotations

import json

import pytest
import yaml

from redteam.bench import runner
from redteam.bench.targets import get_target
from redteam.config import ConfigError, load_engagement
from redteam.tools.kali import KaliExecTool, rewrite_aliases

ALIASES = (("localhost:8090", "172.18.0.3:8080"), ("127.0.0.1:8090", "172.18.0.3:8080"))


def test_rewrites_exact_host_port_only():
    cmd, applied = rewrite_aliases(
        "curl http://localhost:8090/api && nmap -p 8090 127.0.0.1:8090", ALIASES)
    assert cmd == "curl http://172.18.0.3:8080/api && nmap -p 8090 172.18.0.3:8080"
    assert len(applied) == 2


@pytest.mark.parametrize("cmd", [
    "curl http://localhost:80900/",       # longer port
    "curl http://notlocalhost:8090/",     # different host
    "curl http://localhost:9000/",        # other port
    "curl http://a.localhost:8090/",      # subdomain
])
def test_leaves_near_misses_alone(cmd):
    assert rewrite_aliases(cmd, ALIASES) == (cmd, [])


def _engagement_file(tmp_path, aliases, hosts=("localhost", "127.0.0.1", "172.18.0.3")):
    doc = {"name": "t", "client": "c", "authorized_by": "a", "ticket": "x",
           "starts": "2020-01-01", "ends": "2099-01-01",
           "scope": {"allowed_hosts": list(hosts), "allow_private_ranges": True},
           "sandbox": {"target_aliases": aliases}}
    p = tmp_path / "e.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def test_alias_loads_when_both_sides_in_scope(tmp_path):
    eng = load_engagement(_engagement_file(tmp_path, {"localhost:8090": "172.18.0.3:8080"}))
    assert eng.sandbox.target_aliases == (("localhost:8090", "172.18.0.3:8080"),)


def test_alias_to_out_of_scope_host_refuses_to_load(tmp_path):
    with pytest.raises(ConfigError, match="not in scope"):
        load_engagement(_engagement_file(tmp_path, {"localhost:8090": "10.9.9.9:80"}))


@pytest.mark.parametrize("bad", ["http://172.18.0.3:8080", "172.18.0.3", "172.18.0.3:80/x"])
def test_alias_must_be_bare_host_port(tmp_path, bad):
    with pytest.raises(ConfigError, match="host:port"):
        load_engagement(_engagement_file(tmp_path, {"localhost:8090": bad}))


def test_runner_writes_aliases_for_networked_lab(tmp_path):
    target = get_target("lab-authz-broken")
    path = tmp_path / "engagement.yaml"
    runner._write_engagement(target, path, "172.18.0.3")
    eng = load_engagement(path)
    assert ("localhost:8090", "172.18.0.3:8080") in eng.sandbox.target_aliases
    assert ("127.0.0.1:8090", "172.18.0.3:8080") in eng.sandbox.target_aliases


def test_runner_writes_no_aliases_without_a_container_ip(tmp_path):
    path = tmp_path / "engagement.yaml"
    runner._write_engagement(get_target("lab-authz-broken"), path, None)
    assert load_engagement(path).sandbox.target_aliases == ()


class _Result:
    exit_code, timed_out, stdout, stderr = 0, False, "ok", ""


class _Sandbox:
    target_aliases = ALIASES

    def __init__(self):
        self.ran = []

    def exec(self, command, timeout=None):
        self.ran.append(command)
        return _Result()


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, event, **f):
        self.events.append((event, f))


class _Ctx:
    def __init__(self):
        self.sandbox, self.audit, self.graph = _Sandbox(), _Audit(), None
        self.approve = lambda *a: True


def test_kali_exec_runs_the_rewritten_command_and_says_so():
    ctx = _Ctx()
    out = json.loads(KaliExecTool().run(ctx, "curl -s http://localhost:8090/", "probe"))
    assert ctx.sandbox.ran == ["curl -s http://172.18.0.3:8080/"]
    assert out["sandbox_address_rewrites"] == ["localhost:8090 -> 172.18.0.3:8080"]
    assert any(e == "kali_exec.alias" for e, _ in ctx.audit.events)


def test_tamper_check_still_runs_before_any_rewrite():
    ctx = _Ctx()
    out = KaliExecTool().run(ctx, "iptables -F; curl http://localhost:8090/", "x")
    assert out.startswith("REFUSED") and ctx.sandbox.ran == []

"""The on-requirement toolbox: catalog integrity, provisioning channels,
image-layer determinism, and the resolve hooks the engine uses.

No network in unit tests: installers are faked, binaries are stubs.
"""
import os
import stat
import textwrap

import pytest

from redteam.sandbox import provision as prov
from redteam.sandbox.provision import (CATALOG, ToolProvisioner,
                                       ensure_tools_for_image)


# -- catalog integrity --------------------------------------------------------

def test_catalog_tools_are_unique_and_installable():
    binaries = [s.binary for s in CATALOG.values()]
    assert len(binaries) == len(set(binaries)), "duplicate binary names"
    for spec in CATALOG.values():
        assert spec.kali_pkg or spec.pip_pkg, f"{spec.name} has no channel"
        assert spec.verify_args and spec.purpose


# -- host resolution + provisioning -------------------------------------------

def _stub(tmp_path, name, body="#!/bin/sh\necho ok\n"):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def test_resolve_prefers_venv_over_nothing(tmp_path):
    _stub(tmp_path / "bin", "arjun")
    p = ToolProvisioner(venv_dir=tmp_path)
    st = p.resolve("arjun")
    assert st.available and st.where == "venv"
    assert p.resolve("nmap").available is False


def test_ensure_installs_via_fake_pip_then_resolves(tmp_path, monkeypatch):
    calls = []

    def fake_pip(pkg, venv_dir):
        calls.append(pkg)
        _stub(venv_dir / "bin", "wafw00f")
        return True, ""

    monkeypatch.setattr(prov, "_pip_install", fake_pip)
    p = ToolProvisioner(venv_dir=tmp_path / "venv")
    st = p.ensure("wafw00f")
    assert st.available and st.note == "installed via pip venv"
    assert calls == ["wafw00f"]
    # second ensure is a no-op resolve (no re-install)
    calls.clear()
    assert p.ensure("wafw00f").available and not calls


def test_ensure_reports_failure_honestly(tmp_path, monkeypatch):
    monkeypatch.setattr(prov, "_pip_install", lambda *a: (False, "egress denied"))
    monkeypatch.setattr(prov, "_apt_install", lambda *a: (False, "no root"))
    st = ToolProvisioner(venv_dir=tmp_path / "venv").ensure("nmap")
    assert st.available is False
    assert "no install channel" in st.note


def test_unknown_tool_is_refused(tmp_path):
    st = ToolProvisioner(venv_dir=tmp_path).ensure("metasploit")
    assert st.available is False and "unknown" in st.note


# -- Kali image layer ----------------------------------------------------------

class FakeRun:
    def __init__(self):
        self.cmds = []

    def __call__(self, cmd, timeout=None):
        self.cmds.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_ensure_tools_builds_extra_tools_layer(tmp_path):
    fake = FakeRun()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM kali\nARG EXTRA_TOOLS\n")
    tag, pkgs = ensure_tools_for_image(
        "redteam-kali:latest", dockerfile, ["nmap", "arjun", "nope"],
        run_fn=fake)
    assert "nmap" in pkgs and "arjun" in pkgs   # 'nope' filtered by catalog
    build = next(c for c in fake.cmds if c[:2] == ["docker", "build"])
    arg = build[build.index("--build-arg") + 1]
    assert arg.startswith("EXTRA_TOOLS=") and "nmap" in arg
    assert tag.startswith("redteam-kali:tools-")


def test_ensure_tools_is_cached_per_toolset(tmp_path):
    fake = FakeRun()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM kali\n")
    tag1, _ = ensure_tools_for_image("redteam-kali:latest", dockerfile,
                                     ["arjun"], run_fn=fake)
    builds = [c for c in fake.cmds if c[:2] == ["docker", "build"]]
    tag2, pkgs = ensure_tools_for_image("redteam-kali:latest", dockerfile,
                                        ["arjun"], run_fn=fake)
    # same toolset -> same tag, and the docker build for it already exists
    # (image inspect finds it), so no second build command was issued
    assert tag1 == tag2 and pkgs == ["arjun"]
    assert len(builds) == 1


def test_ensure_tools_empty_names_never_builds():
    fake = FakeRun()
    tag, pkgs = ensure_tools_for_image("redteam-kali:latest",
                                       __import__("pathlib").Path("x"), [],
                                       run_fn=fake)
    assert tag == "redteam-kali:latest" and pkgs == [] and not fake.cmds


# -- engine resolve hooks --------------------------------------------------------

def test_portscan_scan_uses_provisioned_nmap(tmp_path):
    stub = _stub(tmp_path, "nmap", textwrap.dedent("""\
        #!/bin/sh
        cat <<'XML'
        <nmaprun><host><ports>
        <port protocol="tcp" portid="8898"><state state="open"/>
          <service name="http" product="StubNmap" version="1"/></port>
        </ports></host></nmaprun>
        XML
        """))
    from redteam.portscan import scan
    result = scan("127.0.0.1", [8898, 9], timeout=5.0,
                  resolve=lambda name: type(
                      "S", (), {"available": True, "path": str(stub)})())
    assert result[8898]["product"] == "StubNmap"
    assert 9 not in result


def test_hostprobe_exec_resolves_venv_binary(tmp_path, monkeypatch):
    stub = _stub(tmp_path / "bin", "arjun", "#!/bin/sh\necho STUB-RAN \"$@\"\n")
    monkeypatch.setattr(prov, "_DEFAULT_VENV", tmp_path)
    import types
    from redteam.tools.hostprobe import _exec
    ctx = types.SimpleNamespace(sandbox=None)
    exit_code, out, err, surface = _exec("arjun -u http://x -oJ f.json", ctx)
    assert exit_code == 0 and "STUB-RAN" in out and surface == "local"


def test_hostprobe_exec_honest_error_without_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(prov, "_DEFAULT_VENV", tmp_path / "none")
    monkeypatch.setattr(os, "environ", {**os.environ, "PATH": "/nonexistent"})
    import types
    from redteam.tools.hostprobe import _exec
    with pytest.raises(FileNotFoundError, match="tool_provision"):
        _exec("arjun -u http://x", types.SimpleNamespace(sandbox=None))

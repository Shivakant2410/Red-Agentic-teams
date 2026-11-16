"""On-requirement tool provisioning — the Kali toolbox that fills itself.

The plan this implements: tools are downloaded BASED ON REQUIREMENT, into a
sandboxed environment where the agent can run pentest tools. Two environments,
and the split matters:

  docker/Kali    — the container's egress firewall is default-DROP (by design;
                   RoE-derived). Runtime installs INSIDE it are therefore
                   impossible — correctly so. Provisioning happens at the
                   IMAGE BUILD layer instead (host network, outside the RoE
                   boundary): KaliSandbox.ensure_tools() rebuilds the image
                   with an EXTRA_TOOLS build-arg of kali-repo packages, tagged
                   per toolset so different engagements get different images.

  host / no docker — a project-scoped venv (repo/.tools/venv) receives the
                   pip-installable tools; the apt channel is tried only when
                   actually running as root. Used by this dev sandbox, where
                   docker is absent but pip egress works.

Every check, attempt and result is audited. Nothing here initiates network
scans: provisioning only puts BINARIES in place — the engine's workflows still
pass RoE-checked targets through the usual discipline, and `resolve()` (the
read-only lookup the engine calls mid-run) never installs; requirement-driven
installs happen through the tool_provision tool, the CLI, or ensure_tools at
sandbox start, so provisioning traffic stays distinguishable from test traffic
in the audit trail.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_DEFAULT_VENV = _REPO / ".tools" / "venv"
_VENV_BOOTSTRAP_TIMEOUT = 120
_PIP_TIMEOUT = 300


@dataclass(frozen=True)
class ToolSpec:
    """One pentest tool: where it lives in Kali repos, what to verify, who needs it."""
    name: str                 # canonical catalog name (agent-facing)
    binary: str               # executable to look for
    kali_pkg: str = ""        # apt package in kali-rolling ("" = not packaged)
    pip_pkg: str = ""         # PyPI package ("" = no pip distribution)
    verify_args: tuple = ("--version",)
    purpose: str = ""         # which engine workflow consumes it


CATALOG: dict[str, ToolSpec] = {s.name: s for s in (
    ToolSpec("nmap", "nmap", "nmap", "",
             ("--version",), "port scanning + service fingerprints"),
    ToolSpec("arjun", "arjun", "arjun", "arjun",
             ("-h",), "hidden-parameter discovery (param_discovery)"),
    ToolSpec("ffuf", "ffuf", "ffuf", "", ("-V",), "fast content discovery"),
    ToolSpec("gobuster", "gobuster", "gobuster", "", ("version",),
             "directory/DNS/vhost brute force"),
    ToolSpec("nuclei", "nuclei", "nuclei", "", ("-version",),
             "template-based vulnerability scanning"),
    ToolSpec("whatweb", "whatweb", "whatweb", "", ("--version",),
             "technology fingerprinting"),
    ToolSpec("nikto", "nikto", "nikto", "", ("-Version",), "web server scanner"),
    ToolSpec("wafw00f", "wafw00f", "wafw00f", "wafw00f", ("-V",), "WAF fingerprinting"),
    ToolSpec("sqlmap", "sqlmap", "sqlmap", "sqlmap", ("--version",),
             "SQL injection exploration"),
)}


@dataclass
class ToolStatus:
    name: str
    available: bool = False
    where: str = ""      # "path" | "venv" | "sandbox" | "" when unavailable
    path: str = ""
    note: str = ""


# -- host channels (injectable for tests) ------------------------------------

def resolve_binary(binary: str) -> str:
    """PATH first, then the provisioning venv. Empty string when absent —
    the read-only lookup every engine tool uses before invoking a binary."""
    found = shutil.which(binary)
    if found:
        return found
    cand = _DEFAULT_VENV / "bin" / binary
    if cand.exists() and os.access(cand, os.X_OK):
        return str(cand)
    return ""


def _bootstrap_venv(venv_dir: Path) -> bool:
    if (venv_dir / "bin" / "python").exists():
        return True
    try:
        proc = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)],
                              capture_output=True, timeout=_VENV_BOOTSTRAP_TIMEOUT)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _pip_install(pkg: str, venv_dir: Path) -> tuple[bool, str]:
    if not _bootstrap_venv(venv_dir):
        return False, "venv bootstrap failed"
    try:
        proc = subprocess.run(
            [str(venv_dir / "bin" / "pip"), "install", "--no-input", pkg],
            capture_output=True, text=True, timeout=_PIP_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[:200]
    return proc.returncode == 0, (proc.stderr or proc.stdout)[-200:]


def _apt_install(pkg: str) -> tuple[bool, str]:
    if os.geteuid() != 0 or shutil.which("apt-get") is None:
        return False, "apt channel requires root; skipping"
    try:
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True,
                       timeout=120, check=False)
        proc = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", pkg],
            capture_output=True, text=True, timeout=_PIP_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[:200]
    return proc.returncode == 0, (proc.stderr or "")[-200:]


class ToolProvisioner:
    """Host-side resolver/installer. `resolve` is read-only (engine-safe);
    `ensure` downloads on requirement."""

    def __init__(self, audit=None, venv_dir: Path | None = None):
        self._audit = audit
        self._venv = Path(venv_dir) if venv_dir else _DEFAULT_VENV

    def _log(self, event: str, **f) -> None:
        if self._audit is not None:
            self._audit.record(event, **f)

    def _search(self, binary: str) -> str:
        found = shutil.which(binary)
        if found:
            return found
        cand = self._venv / "bin" / binary
        return str(cand) if cand.exists() and os.access(cand, os.X_OK) else ""

    def resolve(self, name: str) -> ToolStatus:
        """Read-only: PATH, then the provisioning venv. No downloads."""
        spec = CATALOG.get(name)
        if spec is None:
            return ToolStatus(name=name, note="unknown tool")
        path = self._search(spec.binary)
        if not path:
            return ToolStatus(name=name, note="not provisioned")
        return ToolStatus(name=name, available=True,
                          where="venv" if str(self._venv) in path else "path",
                          path=path)

    def ensure(self, name: str) -> ToolStatus:
        """Requirement-driven: resolve, else pip into the project venv, else
        apt as root. Every attempt and outcome audited."""
        spec = CATALOG.get(name)
        if spec is None:
            return ToolStatus(name=name, note=f"unknown tool '{name}'")
        st = self.resolve(name)
        if st.available:
            return st
        self._log("toolkit.provision.start", tool=name)
        if spec.pip_pkg:
            ok, tail = _pip_install(spec.pip_pkg, self._venv)
            self._log("toolkit.provision.pip", tool=name, ok=ok, tail=tail)
            if ok:
                st = self.resolve(name)
                if st.available:
                    st.note = "installed via pip venv"
                    self._log("toolkit.provision.done", tool=name,
                              where=st.where, path=st.path)
                    return st
        if spec.kali_pkg:
            ok, tail = _apt_install(spec.kali_pkg)
            self._log("toolkit.provision.apt", tool=name, ok=ok, tail=tail)
            if ok:
                st = self.resolve(name)
                if st.available:
                    st.note = "installed via apt"
                    self._log("toolkit.provision.done", tool=name,
                              where=st.where, path=st.path)
                    return st
        st.note = "no install channel succeeded (pip egress / root required)"
        self._log("toolkit.provision.failed", tool=name, note=st.note)
        return st

    def status(self) -> dict:
        return {n: {"available": (st := self.resolve(n)).available,
                    "where": st.where, "path": st.path, "note": st.note}
                for n in CATALOG}


# -- docker/Kali mode: the image build layer -----------------------------------

def ensure_tools_for_image(base_image: str, dockerfile: Path, names,
                           run_fn=None, build_timeout: int = 3600) -> tuple[str, list[str]]:
    """Return (image_tag, installed_pkgs) for a Kali image that includes the
    named catalog tools, rebuilding with the EXTRA_TOOLS build-arg when the
    exact toolset has no image yet. Tags are content-addressed per toolset so
    repeat runs reuse the cached layer. run_fn is injectable for tests."""
    pkgs: list[str] = []
    for n in names:
        spec = CATALOG.get(n)
        if spec is None or not spec.kali_pkg:
            continue
        if spec.kali_pkg not in pkgs:
            pkgs.append(spec.kali_pkg)
    if not pkgs:
        return base_image, []
    digest = hashlib.sha1(",".join(sorted(pkgs)).encode()).hexdigest()[:8]
    tag = f"{base_image.rsplit(':', 1)[0]}:tools-{digest}"
    run = run_fn or (lambda cmd, timeout=None: subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout))
    exists = run(["docker", "image", "inspect", tag], timeout=30)
    if getattr(exists, "returncode", 1) != 0:
        proc = run(["docker", "build", "-t", tag, "-f", str(dockerfile),
                    "--build-arg", f"EXTRA_TOOLS={' '.join(pkgs)}",
                    str(dockerfile.parent)], timeout=build_timeout)
        if getattr(proc, "returncode", 1) != 0:
            raise RuntimeError(
                f"tool-layer build failed: {(getattr(proc, 'stderr', '') or '')[-1500:]}")
    return tag, pkgs

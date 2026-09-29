"""KaliSandbox — manage the Kali Docker container and run commands inside it.

Shells out to the `docker` CLI (no extra Python dependency). Lifecycle:

    sb = KaliSandbox(engagement, audit)
    sb.start()                      # build image if needed, apply egress, run container
    result = sb.exec("nmap -sV ...")
    sb.stop()

The container starts with --cap-add=NET_ADMIN so entrypoint.sh can install the egress
firewall, and with the RoE-derived allowlist passed in ALLOWED_CIDRS. Tool commands run
as the non-root `operator` user, which cannot alter the firewall.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config import Engagement
from .egress import EgressPlan, build_egress_plan


class SandboxError(Exception):
    pass


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class KaliSandbox:
    def __init__(self, engagement: Engagement, audit=None):
        self._eng = engagement
        self._cfg = engagement.sandbox
        self._audit = audit
        self._plan: EgressPlan | None = None
        self._started = False

    # -- helpers ---------------------------------------------------------------

    def _log(self, event: str, **f) -> None:
        if self._audit:
            self._audit.record(event, **f)

    @staticmethod
    def _require_docker() -> None:
        if shutil.which("docker") is None:
            raise SandboxError("docker CLI not found on PATH. Install Docker to use the sandbox.")

    def _image_exists(self) -> bool:
        proc = _run(["docker", "image", "inspect", self._cfg.image])
        return proc.returncode == 0

    # -- lifecycle -------------------------------------------------------------

    def build(self) -> None:
        self._require_docker()
        dockerfile = Path(self._cfg.dockerfile)
        if not dockerfile.exists():
            raise SandboxError(f"Dockerfile not found: {dockerfile}")
        self._log("sandbox.build.start", image=self._cfg.image)
        proc = _run(
            ["docker", "build", "-t", self._cfg.image, "-f", str(dockerfile), str(dockerfile.parent)],
            timeout=3600,
        )
        if proc.returncode != 0:
            raise SandboxError(f"docker build failed:\n{proc.stderr[-2000:]}")
        self._log("sandbox.build.done", image=self._cfg.image)

    def _ensure_network(self) -> None:
        proc = _run(["docker", "network", "inspect", self._cfg.network_name])
        if proc.returncode != 0:
            _run(["docker", "network", "create", self._cfg.network_name])

    def start(self) -> EgressPlan:
        self._require_docker()
        if not self._image_exists():
            self.build()

        self._plan = build_egress_plan(self._eng)
        for w in self._plan.warnings:
            self._log("sandbox.egress.warning", message=w)

        self._ensure_network()
        # Remove any stale container with the same name.
        _run(["docker", "rm", "-f", self._cfg.container_name])

        allowed = " ".join(self._plan.allowed_cidrs)
        dns = " ".join(self._cfg.dns)
        cmd = [
            "docker", "run", "-d",
            "--name", self._cfg.container_name,
            "--network", self._cfg.network_name,
            "--cap-add=NET_ADMIN",           # required to install the egress firewall
            "--cap-drop=ALL",                # drop everything else
            "--cap-add=NET_RAW",             # nmap/ping raw sockets
            "--security-opt", "no-new-privileges",
            "--memory", self._cfg.memory,
            "--cpus", self._cfg.cpus,
            "--pids-limit", "512",
        ]
        for d in self._cfg.dns:
            cmd += ["--dns", d]
        cmd += [
            "-e", f"ALLOWED_CIDRS={allowed}",
            "-e", f"DNS_SERVERS={dns}",
            self._cfg.image,
        ]
        self._log("sandbox.start", image=self._cfg.image, allowed_cidrs=self._plan.allowed_cidrs)
        proc = _run(cmd, timeout=120)
        if proc.returncode != 0:
            raise SandboxError(f"docker run failed:\n{proc.stderr[-2000:]}")

        # Confirm the entrypoint reached "ready" (egress installed) before we proceed.
        logs = _run(["docker", "logs", self._cfg.container_name], timeout=30)
        if "ready" not in (logs.stdout + logs.stderr):
            self.stop()
            raise SandboxError(
                "sandbox did not confirm egress lockdown; refusing to run tools.\n"
                + (logs.stdout + logs.stderr)[-1500:]
            )
        self._started = True
        return self._plan

    def exec(self, command: str, timeout: int | None = None) -> ExecResult:
        if not self._started:
            raise SandboxError("sandbox not started")
        timeout = timeout or self._cfg.command_timeout
        # Run as the non-root operator user; bash -lc so pipes/globs work.
        docker_cmd = [
            "docker", "exec", "-u", "operator", self._cfg.container_name,
            "bash", "-lc", command,
        ]
        self._log("sandbox.exec", command=command)
        try:
            proc = _run(docker_cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._log("sandbox.exec.timeout", command=command, timeout=timeout)
            return ExecResult(exit_code=124, stdout="", stderr=f"timed out after {timeout}s", timed_out=True)
        self._log("sandbox.exec.done", command=command, exit_code=proc.returncode,
                  stdout_len=len(proc.stdout), stderr_len=len(proc.stderr))
        return ExecResult(exit_code=proc.returncode, stdout=proc.stdout,
                          stderr=proc.stderr, timed_out=False)

    def stop(self) -> None:
        _run(["docker", "rm", "-f", self._cfg.container_name])
        self._log("sandbox.stop", container=self._cfg.container_name)
        self._started = False

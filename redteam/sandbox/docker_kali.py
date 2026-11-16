"""KaliSandbox — manage the Kali Docker container and run commands inside it.

Shells out to the `docker` CLI (no extra Python dependency). Lifecycle:

    sb = KaliSandbox(engagement, audit)
    sb.start()                      # build image if needed, apply egress, run container
    result = sb.exec("nmap -sV ...")
    sb.stop()

The container starts with --cap-add=NET_ADMIN so entrypoint.sh can install the egress
firewall, and with the RoE-derived allowlist passed in ALLOWED_CIDRS. Tool commands run
as the non-root `operator` user, which cannot alter the firewall.

Evidence plane (optional): start(proxy_url=..., ca_cert=...) wires the sandbox's tool
environment to the run's EvidenceProxy — HTTP(S)_PROXY env so HTTP-speaking tools
(nuclei, bandit, curl, requests, ...) route their traffic through the recording proxy,
and the run CA installed into the container trust store so TLS interception is trusted
there. The proxy host is reachable via host.docker.internal (mapped to the bridge
gateway by `--add-host ... host-gateway`); the proxy's TCP port on that gateway (passed
as ALLOWED_PROXY, never the whole address) is the one deliberate, documented exception
to the egress allowlist: the evidence plane is part of the trusted control path,
everything else stays default-DROP.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ..config import Engagement
from .egress import EgressPlan, build_egress_plan


class SandboxError(Exception):
    pass


# TEST-NET-1 (RFC 5737) — reserved for documentation, never a real route, and never
# something an engagement's allowed_hosts would legitimately list. Used as the egress
# self-test's canary: if the sandbox can reach it, the firewall did not actually apply,
# regardless of what the entrypoint log claims.
_EGRESS_CANARY = "192.0.2.1"
# How long the entrypoint gets to install the firewall and print "ready".
_READY_TIMEOUT_S = 30


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

    @property
    def target_aliases(self) -> tuple[tuple[str, str], ...]:
        return tuple(getattr(self._cfg, "target_aliases", ()) or ())

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

    def _running(self) -> bool:
        proc = _run(["docker", "inspect", "-f", "{{.State.Running}}", self._cfg.container_name])
        return proc.stdout.strip() == "true"

    def _ensure_network(self) -> None:
        proc = _run(["docker", "network", "inspect", self._cfg.network_name])
        if proc.returncode != 0:
            _run(["docker", "network", "create", self._cfg.network_name])

    def _network_gateway(self) -> str:
        """The bridge gateway IP of our network (the host side, as seen from the
        container). Empty string when docker does not tell us — callers must
        treat that as 'cannot run the evidence proxy in-path' and say so."""
        proc = _run(["docker", "network", "inspect", "-f",
                     "{{json .IPAM.Config}}", self._cfg.network_name], timeout=30)
        if proc.returncode != 0:
            return ""
        try:
            configs = json.loads(proc.stdout or "[]")
            for cfg in configs:
                gw = (cfg or {}).get("Gateway") or ""
                if gw:
                    return gw.split("/")[0]
        except (ValueError, TypeError, IndexError):
            pass
        return ""

    def start(self, proxy_url: str = "", ca_cert: Path | None = None) -> EgressPlan:
        self._require_docker()
        if not self._image_exists():
            self.build()

        self._plan = build_egress_plan(self._eng)
        proxy_allow = ""
        if proxy_url:
            # The evidence proxy runs host-side; the container reaches it through the
            # bridge gateway. Open exactly the proxy's TCP port on that address — the ONE
            # deliberate exception to the default-DROP egress, for the control path
            # itself. Opening the whole gateway address would expose every service the
            # host listens on (its own control plane, other containers' published ports).
            gw = self._network_gateway()
            port = urlsplit(proxy_url).port
            if gw and port and ":" not in gw:
                proxy_allow = f"{gw}:{port}"
            else:
                self._log("sandbox.egress.warning",
                          message="proxy requested but the bridge gateway or proxy port is "
                                  "unknown (or the gateway is IPv6); sandbox will start "
                                  "WITHOUT proxy env (tools bypass the evidence plane; the "
                                  "firewall still bounds them)")
                proxy_url = ""
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
        if proxy_url:
            cmd += ["--add-host", "host.docker.internal:host-gateway"]
        for d in self._cfg.dns:
            cmd += ["--dns", d]
        cmd += [
            "-e", f"ALLOWED_CIDRS={allowed}",
            "-e", f"DNS_SERVERS={dns}",
            "-e", f"ALLOWED_PROXY={proxy_allow}",
        ]
        if proxy_url:
            for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
                cmd += ["-e", f"{var}={proxy_url}"]
            cmd += ["-e", "NO_PROXY=localhost,127.0.0.1,::1"]
        cmd += [self._cfg.image]
        self._log("sandbox.start", image=self._cfg.image, allowed_cidrs=self._plan.allowed_cidrs,
                  proxy=proxy_url or None)
        proc = _run(cmd, timeout=120)
        if proc.returncode != 0:
            raise SandboxError(f"docker run failed:\n{proc.stderr[-2000:]}")

        if proxy_url and ca_cert is not None:
            self._install_ca(ca_cert)

        # Confirm the entrypoint reached "ready" (egress installed) before we proceed.
        # `docker run -d` returns as soon as the container starts, before the firewall
        # script finishes, so wait for the line — but stop waiting the moment the
        # container exits (the script failed closed).
        text = ""
        deadline = time.monotonic() + _READY_TIMEOUT_S
        while True:
            logs = _run(["docker", "logs", self._cfg.container_name], timeout=30)
            text = logs.stdout + logs.stderr
            if "ready" in text or time.monotonic() >= deadline or not self._running():
                break
            time.sleep(0.5)
        if "ready" not in text:
            self.stop()
            raise SandboxError(
                "sandbox did not confirm egress lockdown; refusing to run tools.\n"
                + text[-1500:]
            )
        self._started = True

        # The log line only proves the entrypoint script RAN to that point — not that the
        # firewall rules actually took effect (a kernel without iptables support, a
        # container runtime quirk, or a rule-ordering bug could all still print "ready"
        # while egress stays wide open). Prove it instead: try to reach a destination that
        # is never legitimately in scope (TEST-NET-1) and fail closed if that succeeds.
        self._verify_egress_blocks_canary()
        return self._plan

    def _verify_egress_blocks_canary(self) -> None:
        # --noproxy: with the evidence proxy on, HTTP_PROXY would send this probe to the
        # proxy (which refuses it with a 403) and the firewall would never be tested.
        probe = (f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' --noproxy '*' "
                f"--connect-timeout 2 http://{_EGRESS_CANARY}/ || echo BLOCKED")
        result = self.exec(probe, timeout=10)
        # Only a probe that RAN and reported BLOCKED proves the block. A probe that failed
        # to run at all (exec error, missing user, timeout) proves nothing, so it counts
        # as reached: fail closed.
        reached = result.timed_out or result.exit_code != 0 or "BLOCKED" not in result.stdout
        self._log("sandbox.egress_selftest", canary=_EGRESS_CANARY,
                  reached=reached, stdout=result.stdout[:200])
        if reached:
            self.stop()
            ran = not result.timed_out and result.exit_code == 0
            what = (f"the sandbox reached {_EGRESS_CANARY} (a destination that should "
                    "never be in scope), meaning the egress firewall did not actually apply "
                    "despite the entrypoint reporting ready" if ran else
                    f"the canary probe could not run (exit {result.exit_code}: "
                    f"{result.stderr.strip()[:300]}), so the block is unproven")
            raise SandboxError(
                f"EGRESS SELF-TEST FAILED: {what}. Refusing to run any tool against a "
                "sandbox with unconfirmed scope enforcement — this is fail-closed, not a "
                "false alarm to work around."
            )

    def _install_ca(self, ca_cert: Path) -> None:
        """Trust the run's evidence-proxy CA inside the container so TLS
        interception is transparent to tools there. Best-effort: if the install
        fails we SAY SO (tools will see cert errors on proxied TLS and the
        operator knows the wire evidence degraded to metadata) — the run is not
        silently blinded."""
        name = "rt-evidence-proxy-ca.crt"
        target = f"/usr/local/share/ca-certificates/{name}"
        cp = _run(["docker", "cp", str(ca_cert),
                   f"{self._cfg.container_name}:{target}"], timeout=30)
        upd = _run(["docker", "exec", "-u", "root", self._cfg.container_name,
                    "update-ca-certificates"], timeout=120)
        ok = cp.returncode == 0 and upd.returncode == 0
        self._log("sandbox.proxy_ca", installed=ok, target=target)
        if not ok:
            self._log("sandbox.egress.warning",
                      message="evidence-proxy CA NOT installed in sandbox; proxied TLS "
                              "will fail cert validation inside the container "
                              f"(cp rc={cp.returncode}, update rc={upd.returncode})")

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

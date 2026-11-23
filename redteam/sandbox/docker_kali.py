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
gateway by `--add-host ... host-gateway`); that gateway /32 is appended to the egress
allowlist — a deliberate, documented exception: the evidence plane is part of the
trusted control path, everything else stays default-DROP.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import Engagement
from .egress import EgressPlan, build_egress_plan


class SandboxError(Exception):
    pass


# TEST-NET-1 (RFC 5737) — reserved for documentation, never a real route, and never
# something an engagement's allowed_hosts would legitimately list. Used as the egress
# self-test's canary: if the sandbox can reach it, the firewall did not actually apply,
# regardless of what the entrypoint log claims.
_EGRESS_CANARY = "192.0.2.1"


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


def _rewrite_proxy_host(proxy_url: str, new_host: str) -> str:
    """Replace the host in a proxy URL, keeping scheme/port/path. Used to pin the
    evidence-proxy URL to the numeric IPv4 gateway so the container never reaches it
    over an IPv6 path the egress allow does not cover."""
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(proxy_url)
    netloc = new_host if parts.port is None else f"{new_host}:{parts.port}"
    return urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, parts.fragment))


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class KaliSandbox:
    def __init__(self, engagement: Engagement, audit=None, traffic=None):
        self._eng = engagement
        self._cfg = engagement.sandbox
        self._audit = audit
        self._traffic = traffic
        self._plan: EgressPlan | None = None
        self._started = False
        # requirement-driven tool layer: set by ensure_tools() before start()
        self._image: str | None = None
        self._build_args: list[str] = []

    # -- helpers ---------------------------------------------------------------

    def _log(self, event: str, **f) -> None:
        if self._audit:
            self._audit.record(event, **f)

    @staticmethod
    def _require_docker() -> None:
        if shutil.which("docker") is None:
            raise SandboxError("docker CLI not found on PATH. Install Docker to use the sandbox.")

    def _image_exists(self) -> bool:
        proc = _run(["docker", "image", "inspect", self._image or self._cfg.image])
        return proc.returncode == 0

    # -- lifecycle -------------------------------------------------------------

    def build(self) -> None:
        self._require_docker()
        dockerfile = Path(self._cfg.dockerfile)
        if not dockerfile.exists():
            raise SandboxError(f"Dockerfile not found: {dockerfile}")
        self._log("sandbox.build.start", image=self._image or self._cfg.image)
        proc = _run(
            ["docker", "build", "-t", self._image or self._cfg.image,
             "-f", str(dockerfile),
             *self._build_args, str(dockerfile.parent)],
            timeout=3600,
        )
        if proc.returncode != 0:
            raise SandboxError(f"docker build failed:\n{proc.stderr[-2000:]}")
        self._log("sandbox.build.done", image=self._image or self._cfg.image)

    # -- requirement-driven tool layer -----------------------------------------

    def ensure_tools(self, names) -> tuple[str, list[str]]:
        """Provision catalog tools BEFORE start(): rebuilds the image with the
        EXTRA_TOOLS build-arg (host network — the sandbox egress rightly
        blocks runtime installs) and pins the image override for this run.
        Returns (image_tag, kali_pkgs_installed)."""
        from .provision import ensure_tools_for_image
        tag, pkgs = ensure_tools_for_image(self._cfg.image,
                                           Path(self._cfg.dockerfile), names)
        if tag != self._cfg.image:
            self._image = tag
            self._log("sandbox.tool_layer", image=tag, packages=pkgs)
        return tag, pkgs

    def has_tool(self, binary: str) -> bool:
        """Whether `binary` is executable inside the (running) sandbox."""
        if not self._started:
            return False
        probe = f"command -v {binary} >/dev/null 2>&1 && echo yes || echo no"
        result = self.exec(probe, timeout=15)
        return "yes" in result.stdout and not result.timed_out

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

    def _resolve_host_gateway_ip(self) -> str:
        """The IPv4 that host.docker.internal resolves to FROM INSIDE a container with
        --add-host host.docker.internal:host-gateway. Linux: the bridge gateway. Docker
        Desktop: a dedicated host IP (192.168.65.254). Returns "" if it can't be found,
        and the caller falls back to the bridge gateway."""
        probe = _run([
            "docker", "run", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            "--entrypoint", "getent", self._image or self._cfg.image,
            "ahostsv4", "host.docker.internal",
        ], timeout=30)
        for line in (probe.stdout or "").splitlines():
            ip = line.split()[0] if line.split() else ""
            if ip and ":" not in ip:
                return ip
        # Fall back to the bridge gateway (correct on native Linux).
        return self._network_gateway()

    def start(self, proxy_url: str = "", ca_cert: Path | None = None) -> EgressPlan:
        self._require_docker()
        if not self._image_exists():
            self.build()

        self._plan = build_egress_plan(self._eng)
        if proxy_url:
            # The evidence proxy runs host-side; the container reaches it through the
            # bridge gateway. Open exactly that /32 — the ONE deliberate exception to
            # the default-DROP egress, for the control path itself.
            # The host address the CONTAINER actually reaches the proxy on is whatever
            # host.docker.internal resolves to from inside it — the bridge gateway on
            # Linux (172.x), but a separate host IP on Docker Desktop (192.168.65.254
            # on Windows/macOS). Allowing only the bridge gateway (self._network_gateway)
            # opened the wrong IP there, so every proxied fetch hit the default DROP and
            # timed out (HTTP 000). Resolve the name as the container sees it and allow
            # THAT /32, then pin the proxy env to the same numeric IP (curl must not pick
            # an IPv6 alias the v4 allow would not cover).
            host_ip = self._resolve_host_gateway_ip()
            if host_ip:
                host_cidr = f"{host_ip}/32" if ":" not in host_ip else f"{host_ip}/128"
                if host_cidr not in self._plan.allowed_cidrs:
                    self._plan.allowed_cidrs.append(host_cidr)
                proxy_url = _rewrite_proxy_host(proxy_url, host_ip)
            else:
                self._log("sandbox.egress.warning",
                          message="proxy requested but bridge gateway unknown; "
                                  "sandbox will start WITHOUT proxy env (tools bypass "
                                  "the evidence plane; the firewall still bounds them)")
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
        ]
        if proxy_url:
            for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
                cmd += ["-e", f"{var}={proxy_url}"]
            cmd += ["-e", "NO_PROXY=localhost,127.0.0.1,::1"]
        cmd += [self._image or self._cfg.image]
        self._log("sandbox.start", image=self._cfg.image, allowed_cidrs=self._plan.allowed_cidrs,
                  proxy=proxy_url or None)
        proc = _run(cmd, timeout=120)
        if proc.returncode != 0:
            raise SandboxError(f"docker run failed:\n{proc.stderr[-2000:]}")

        if proxy_url and ca_cert is not None:
            self._install_ca(ca_cert)

        # Confirm the entrypoint reached "ready" (egress installed) before we proceed.
        logs = _run(["docker", "logs", self._cfg.container_name], timeout=30)
        if "ready" not in (logs.stdout + logs.stderr):
            self.stop()
            raise SandboxError(
                "sandbox did not confirm egress lockdown; refusing to run tools.\n"
                + (logs.stdout + logs.stderr)[-1500:]
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
        # --noproxy '*': the sandbox has HTTP_PROXY set to the evidence proxy, which
        # REFUSES off-scope hosts with a 403. Without this flag the canary curl goes to
        # the proxy, gets that 403 (exit 0), and the test reads it as "canary reached" —
        # a FALSE egress failure that tears the sandbox down right after the self-test
        # (every run then loses the whole Kali toolset and falls back to browser-only).
        # The probe must hit the firewall directly, not the proxy.
        probe = (f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' --noproxy '*' "
                f"--connect-timeout 2 http://{_EGRESS_CANARY}/ || echo BLOCKED")
        result = self.exec(probe, timeout=10)
        reached = not result.timed_out and "BLOCKED" not in result.stdout and result.exit_code == 0
        self._log("sandbox.egress_selftest", canary=_EGRESS_CANARY,
                  reached=reached, stdout=result.stdout[:200])
        if reached:
            self.stop()
            raise SandboxError(
                f"EGRESS SELF-TEST FAILED: the sandbox reached {_EGRESS_CANARY} "
                "(a destination that should never be in scope), meaning the egress "
                "firewall did not actually apply despite the entrypoint reporting ready. "
                "Refusing to run any tool against a sandbox with unconfirmed scope "
                "enforcement — this is fail-closed, not a false alarm to work around."
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
        # Land in the operator-owned /work so tools that emit output files
        # (nmap -oN, gobuster -o) can write without a permission error in the
        # root-owned default dir. We `cd` inside the command rather than pass
        # `docker exec --workdir /work`: on Docker Desktop/Windows that flag is
        # mangled by path translation and fails with "Cwd must be an absolute
        # path", which would break every exec. `cd` inside the container is
        # immune to host-side path translation.
        docker_cmd = [
            "docker", "exec", "-u", "operator", self._cfg.container_name,
            "bash", "-lc", f"cd /work 2>/dev/null; {command}",
        ]
        from ..traffic import redact_command
        safe_command = redact_command(command)
        self._log("sandbox.exec", command=safe_command)
        started = time.monotonic()
        if self._traffic is not None:
            self._traffic.record_event(
                event_type="bash_command_started", source="bash",
                metadata={"command": safe_command})
        try:
            proc = _run(docker_cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - started) * 1000)
            self._log("sandbox.exec.timeout", command=safe_command, timeout=timeout)
            if self._traffic is not None:
                self._traffic.record_event(
                    event_type="bash_command_timeout", source="bash",
                    metadata={"command": safe_command, "exit_code": 124,
                              "timed_out": True, "duration_ms": duration_ms})
            return ExecResult(exit_code=124, stdout="", stderr=f"timed out after {timeout}s", timed_out=True)
        except OSError as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            self._log("sandbox.exec.error", command=safe_command, error=str(exc)[:240])
            if self._traffic is not None:
                self._traffic.record_event(
                    event_type="bash_command_error", source="bash",
                    metadata={"command": safe_command, "exit_code": 127,
                              "timed_out": False, "duration_ms": duration_ms})
            raise
        duration_ms = int((time.monotonic() - started) * 1000)
        self._log("sandbox.exec.done", command=safe_command, exit_code=proc.returncode,
                  stdout_len=len(proc.stdout), stderr_len=len(proc.stderr))
        if self._traffic is not None:
            self._traffic.record_event(
                event_type="bash_command_completed", source="bash",
                metadata={"command": safe_command, "exit_code": proc.returncode,
                          "timed_out": False, "duration_ms": duration_ms})
        return ExecResult(exit_code=proc.returncode, stdout=proc.stdout,
                          stderr=proc.stderr, timed_out=False)

    def stop(self) -> None:
        _run(["docker", "rm", "-f", self._cfg.container_name])
        self._log("sandbox.stop", container=self._cfg.container_name)
        self._started = False

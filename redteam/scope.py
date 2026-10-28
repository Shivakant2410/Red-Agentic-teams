"""Scope enforcement — the hard boundary of the whole system.

Every tool that touches the network routes through ScopeGuard.check() before it acts.
The guard fails closed: anything not explicitly allowed by the engagement is rejected.

Two independent checks run for each target:
  1. The hostname (or its wildcard parent) must be on the allowlist and not excluded.
  2. Every IP the hostname resolves to must be allowed. Private/loopback/link-local/
     reserved ranges are rejected unless the RoE explicitly opts in. This blocks the
     agent from being redirected (by DNS, a redirect chain, or its own reasoning) to
     internal hosts that were never in scope — the SSRF-pivot class of mistakes.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import Engagement


class ScopeViolation(Exception):
    """Raised when a target falls outside the authorized engagement scope."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int


def parse_target(url: str, default_scheme: str = "https") -> Target:
    """Parse a URL or bare host[:port] into a normalized Target."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"{default_scheme}://{candidate}"
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower()
    if not host:
        raise ScopeViolation(f"could not parse a host from {url!r}")
    scheme = (parts.scheme or default_scheme).lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Target(scheme=scheme, host=host, port=port)


def _host_matches(host: str, pattern: str) -> bool:
    """Match a host against an allowlist entry: exact, wildcard domain, IP, or CIDR."""
    host = host.lower()
    pattern = pattern.lower().strip()

    # CIDR / IP-network entry — resolve the match at the IP layer instead.
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False  # host is a name, not an IP; names are matched by string rules
    except ValueError:
        pass

    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


class ScopeGuard:
    """Validates targets against a frozen Engagement. Construct once, share everywhere."""

    def __init__(self, engagement: Engagement, resolver=socket.getaddrinfo):
        self._eng = engagement
        self._resolver = resolver  # injectable for testing

    # Read-only RoE exposure: the surface_scan tool sweeps exactly the authorized
    # surface (hosts x ports), so it needs the allowlist itself — never a mutated
    # copy. Returning tuples keeps the frozen-Engagement discipline intact.
    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        return tuple(self._eng.allowed_hosts)

    @property
    def allowed_ports(self) -> tuple[int, ...]:
        return tuple(self._eng.allowed_ports)

    def _resolved_ips(self, host: str) -> list[ipaddress._BaseAddress]:
        try:
            ipaddress.ip_address(host)
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        try:
            infos = self._resolver(host, None)
        except socket.gaierror as exc:
            raise ScopeViolation(f"cannot resolve {host!r}: {exc}") from exc
        ips: list[ipaddress._BaseAddress] = []
        for info in infos:
            addr = info[4][0]
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
        if not ips:
            raise ScopeViolation(f"{host!r} resolved to no usable IP addresses")
        return ips

    def _ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        # An IP explicitly listed (or inside a listed CIDR) is always allowed.
        for entry in self._eng.allowed_hosts:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        # Otherwise, reject non-public ranges unless the RoE opts in.
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return self._eng.allow_private_ranges
        return True

    def check(self, url: str) -> Target:
        """Validate a target end to end. Returns the parsed Target or raises ScopeViolation."""
        if not self._eng.is_active:
            raise ScopeViolation(
                f"engagement window is not active (valid {self._eng.starts}..{self._eng.ends})"
            )

        target = parse_target(url, default_scheme=self._eng.allowed_schemes[0]
                              if self._eng.allowed_schemes else "https")

        if target.scheme not in self._eng.allowed_schemes:
            raise ScopeViolation(f"scheme {target.scheme!r} not in allowed schemes "
                                 f"{self._eng.allowed_schemes}")
        if target.port not in self._eng.allowed_ports:
            raise ScopeViolation(f"port {target.port} not in allowed ports "
                                 f"{self._eng.allowed_ports}")

        # Exclusions always win.
        for entry in self._eng.excluded_hosts:
            if _host_matches(target.host, entry):
                raise ScopeViolation(f"{target.host!r} is explicitly excluded by the RoE")

        if not any(_host_matches(target.host, entry) for entry in self._eng.allowed_hosts):
            raise ScopeViolation(f"{target.host!r} is not in the engagement allowlist")

        # IP-layer check: guard against a hostname that resolves off-scope.
        for ip in self._resolved_ips(target.host):
            if not self._ip_allowed(ip):
                raise ScopeViolation(
                    f"{target.host!r} resolves to {ip}, which is out of scope "
                    f"(private/reserved ranges are blocked unless the RoE opts in)"
                )
        return target


# Loopback is ONE host wearing several names: an engagement that allows "localhost"
# authorizes 127.0.0.1 (and ::1), and a control plane bound to 127.0.0.1 IS reachable
# as localhost. String-matching the bind host against the allowlist misses that —
# found by an adversarial test before it could be found by an agent.
_LOOPBACK_ALIASES = {"localhost", "127.0.0.1", "::1"}


def _bind_host_is_covered(bind_host: str, allowed_hosts: tuple[str, ...]) -> bool:
    """Could the control plane's bind host be reached through an allowed host entry?

    A wildcard bind (0.0.0.0/::/empty) listens on EVERY interface, so any allowed
    entry could reach it — we cannot prove otherwise, and scope fails closed. A
    loopback bind is covered when any loopback name is allowed. A specific non-
    loopback bind host is covered when an allowlist entry matches it directly, or
    when an entry is itself a wildcard/CIDR that cannot be excluded by name.
    """
    bh = (bind_host or "").strip().lower().strip("[]")
    if bh in ("", "0.0.0.0", "::", "*", "any"):
        return True
    candidates = {bh}
    if bh in _LOOPBACK_ALIASES:
        candidates |= _LOOPBACK_ALIASES
    for entry in allowed_hosts:
        e = entry.lower().strip()
        # A wildcard/CIDR allowlist entry is assumed to cover everything it can
        # match; matching it exactly against one bind address is the honest check.
        if e in ("*", "0.0.0.0/0", "::/0"):
            return True
        if any(_host_matches(c, e) for c in candidates):
            return True
    return False


def check_control_plane_overlap(engagement: Engagement, bind_host: str, bind_port: int) -> None:
    """Refuse to arm a run whose scope includes the platform's own control plane.

    Live-fire lesson: an engagement YAML scoped to `localhost` + a port list that
    happened to include the API server's port let the agent legally send requests to
    its OWN control plane — reading run state, resolving its own approvals. The agent
    behaved correctly (it probed what the scope allowed); the SCOPE was wrong, and a
    wrong scope that includes the operator's console is a run-killing misconfiguration
    that must be caught before any agent step, not blamed on the agent after.

    Raises ConfigError when the control plane is inside the engagement blast radius.
    """
    from .config import ConfigError
    if not engagement.allowed_ports:
        return
    if bind_port in engagement.allowed_ports and \
            _bind_host_is_covered(bind_host, engagement.allowed_hosts):
        raise ConfigError(
            f"scope self-targeting: the control plane binds {bind_host}:{bind_port}, "
            f"which is inside the engagement scope (allowed_hosts={list(engagement.allowed_hosts)}, "
            f"allowed_ports={list(engagement.allowed_ports)}). The agent would be authorized to "
            f"attack its own API server. Remove {bind_port} from scope.allowed_ports (or bind "
            f"the control plane elsewhere) before launching."
        )

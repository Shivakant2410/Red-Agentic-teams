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

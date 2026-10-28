"""Turn the RoE scope into a concrete egress allowlist for the sandbox firewall.

The Kali container runs default-DROP on OUTPUT; only the CIDRs computed here are
reachable. We derive them from the engagement:

  - Explicit IPs / CIDRs in allowed_hosts are used directly.
  - Exact hostnames are resolved now and their IPs added as /32 (or /128) entries.
  - Wildcard entries (*.example.com) cannot be pre-enumerated to IPs. We cannot open
    egress for an unbounded set of future subdomains, so we WARN and skip them: to test
    wildcard scope through the sandbox, also list the covering CIDR in allowed_hosts.

This is intentionally strict. A tool that can't reach an off-scope host can't harm it.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from ..config import Engagement


@dataclass
class EgressPlan:
    allowed_cidrs: list[str]
    resolved: dict[str, list[str]]   # hostname -> IPs
    skipped_wildcards: list[str]
    warnings: list[str]


def build_egress_plan(engagement: Engagement, resolver=socket.getaddrinfo) -> EgressPlan:
    cidrs: set[str] = set()
    resolved: dict[str, list[str]] = {}
    skipped: list[str] = []
    warnings: list[str] = []

    for entry in engagement.allowed_hosts:
        e = entry.strip()
        # IP or CIDR literal?
        try:
            net = ipaddress.ip_network(e, strict=False)
            cidrs.add(str(net))
            continue
        except ValueError:
            pass
        # Wildcard domain — cannot resolve to a bounded IP set.
        if e.startswith("*."):
            skipped.append(e)
            warnings.append(
                f"wildcard {e!r} skipped for egress; add its covering CIDR to allowed_hosts "
                f"to reach its subdomains from the sandbox"
            )
            continue
        # Exact hostname — resolve now.
        try:
            infos = resolver(e, None)
        except socket.gaierror as exc:
            warnings.append(f"could not resolve {e!r}: {exc}")
            continue
        ips = sorted({info[4][0] for info in infos})
        resolved[e] = ips
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            cidrs.add(f"{ip}/32" if addr.version == 4 else f"{ip}/128")

    if not cidrs:
        warnings.append(
            "egress allowlist is EMPTY — the sandbox will have no outbound network. "
            "Add resolvable hostnames, IPs, or CIDRs to scope.allowed_hosts."
        )

    return EgressPlan(
        allowed_cidrs=sorted(cidrs),
        resolved=resolved,
        skipped_wildcards=skipped,
        warnings=warnings,
    )

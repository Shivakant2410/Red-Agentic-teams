"""TCP service discovery — the network-layer sense the HTTP-only recon lacked.

Strategy: nmap drives the scan when the binary exists (service fingerprints,
OS heuristics, timing discipline we should not reinvent); otherwise a bounded
pure-stdlib connect scan runs, because a missing binary must never mean a
blind spot. Either way the result is the same contract: a list of OPEN ports
on a host the ScopeGuard already allowed, which the engine then HTTP-probes
through the normal observe pipeline (so every fingerprint, gate and token the
new service emits flows into the brain like any first-party observation).

RoE: the engine only ever passes ports from engagement.allowed_ports here —
the scanner itself re-checks and refuses out-of-RoE ports as defense in depth.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

NMAP_TIMEOUT = 45.0


def tcp_connect_scan(host: str, ports, timeout: float = 1.0,
                     max_ports: int = 32) -> list[int]:
    """Bounded TCP connect scan. SYN-less, three-way only: every probe is a
    normal connection a firewall would allow from any client. Returns OPEN
    ports, sorted."""
    open_ports: list[int] = []
    for port in list(ports)[:max_ports]:
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue   # garbage entry: skip, never crash the scan
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            pass   # refused/filtered: not open, not interesting
    return sorted(open_ports)


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(host: str, ports, timeout: float = NMAP_TIMEOUT,
              binary: str = "nmap") -> dict | None:
    """`nmap -Pn -sV` service scan parsed from XML: {port: {'service', 'product',
    'version', 'extrainfo'}}. None when the binary is missing or fails — the
    caller falls back to tcp_connect_scan. -Pn because a scoped lab host may drop
    ICMP; -sV because a port number is not a service."""
    import os
    if binary != "nmap" and not os.path.exists(binary):
        return None
    if binary == "nmap" and not nmap_available():
        return None
    if not ports:
        return None
    port_spec = ",".join(str(int(p)) for p in ports)
    try:
        proc = subprocess.run(
            [binary, "-Pn", "-sV", "--version-light", "-oX", "-",
             "-p", port_spec, host],
            capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return None
    services: dict = {}
    for port_el in root.iter("port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port_el.find("service")
        rec = {k: (svc.get(k) or "") if svc is not None else ""
               for k in ("name", "product", "version", "extrainfo")}
        services[int(port_el.get("portid"))] = rec
    return services


def scan(host: str, ports, timeout: float = 1.0, resolve=None) -> dict:
    """The one entry point the engine calls. nmap first (PATH, or a
    provisioned binary via the `resolve` hook — the on-requirement toolbox),
    connect-scan fallback; the contract is {port: detail} either way (detail
    is a fingerprint dict for nmap, 'open/connect' for the stdlib scan)."""
    hosts = [p for p in ports]
    nmap_bin = ""
    if resolve is not None:
        st = resolve("nmap")
        nmap_bin = st.path if st.available else ""
    elif nmap_available():
        nmap_bin = "nmap"
    if nmap_bin:
        res = nmap_scan(host, hosts, binary=nmap_bin)
        if res is not None:
            return {p: (rec or {}) for p, rec in res.items()}
    return {p: {"name": "open/connect"} for p in tcp_connect_scan(host, hosts,
                                                                 timeout=timeout)}

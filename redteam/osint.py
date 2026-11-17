"""Passive/OSINT surface discovery — the senses the HTTP-only recon lacked.

This module covers what page-crawling cannot see:
  - crt.sh certificate-transparency subdomains (PASSIVE: we query a public
    CT log aggregator, never the target)
  - DNS wordlist subdomain resolution (ACTIVE against DNS only, not the app)
  - TLS certificate SAN extraction (PASSIVE against the in-scope origin)

RoE discipline: none of this points a single packet at the app. Results feed
the AssetInventory as CANDIDATES — a resolved host becomes a TARGET only if
the engagement's scope already allows it (the ScopeGuard still decides).
OSINT runs only when the engagement explicitly enables it ("osint:" block)
and the base host is a real domain — never for localhost/IP-literal labs.
"""

from __future__ import annotations

import json
import re
import ssl
import socket

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# small high-yield DNS wordlist (nuclei-style): infra names an org actually uses
DNS_WORDLIST = (
    "www", "api", "dev", "staging", "stage", "test", "qa", "admin", "portal",
    "app", "web", "mail", "vpn", "git", "ci", "cd", "jenkins", "db", "mysql",
    "internal", "intranet", "cdn", "assets", "static", "grafana", "kibana",
    "prometheus", "ollama", "llm", "ai", "chatgpt", "agent",
)


def osint_fetch(url: str, timeout: float) -> tuple[int, str]:
    """The production fetch callable for passive sources. Failures are EMPTY
    answers — OSINT must never take a run down."""
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={"User-Agent":
                              "redteam-agent-osint/1.0"})
        return r.status_code, r.text or ""
    except Exception:
        return 0, ""

# hostnames that mean "a local lab", not an internet domain
_LOCAL_HOST = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?)$",
    re.I)


def is_osint_eligible(host: str) -> bool:
    """True only for real internet domains — never localhost, never bare IPs."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or _LOCAL_HOST.match(host):
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return False
    if ":" in host:          # ipv6 literal or host:port
        return False
    return "." in host


def crtsh_subdomains(domain: str, fetch, timeout: float = 25.0) -> list[str]:
    """Query the public certificate-transparency aggregator for names the
    domain has EVER been issued certs for. `fetch` is a callable
    (url, timeout) -> (status:int, text:str) so tests (and air-gapped runs)
    can inject a fake.

    Returns sorted unique subdomains of `domain` (wildcards stripped, exact
    domain itself excluded). Raises nothing: a failed CT query is an EMPTY
    answer, not an error — OSINT must never take a run down.
    """
    try:
        status, text = fetch(CRTSH_URL.format(domain=domain), timeout)
    except Exception:
        return []
    if status != 200 or not (text or "").strip():
        return []
    try:
        entries = json.loads(text)
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    domain = domain.lower().rstrip(".")
    out: set[str] = set()
    for e in entries:
        names = str((e or {}).get("name_value", "")).replace("*.", "")
        for raw in names.split("\n"):
            name = raw.strip().lower().rstrip(".")
            if not name or name == domain:
                continue
            if name.endswith("." + domain) and "/" not in name and " " not in name:
                out.add(name)
    return sorted(out)


def dns_bruteforce(domain: str, wordlist, resolve, timeout: float = 2.0) -> dict:
    """Resolve wordlist.<domain> via an injected resolver (socket.getaddrinfo
    in production, a fake in tests). Returns {subdomain: ip}. DNS servers are
    queried, the APP is not — this is still discovery, not exploitation."""
    hits: dict = {}
    for word in wordlist:
        sub = str(word).strip().lower()
        if not sub or "." in sub:
            continue
        host = f"{sub}.{domain.rstrip('.')}"
        try:
            ip = resolve(host, timeout)
        except Exception:
            ip = None
        if ip:
            hits[host] = ip
    return hits


def cert_san(host: str, port: int = 443, timeout: float = 10.0,
             get_cert=None) -> list[str]:
    """Subject-alternative names from the origin's TLS certificate. `get_cert`
    injectable for tests. No cert / no TLS / parse failure -> empty list."""
    if get_cert is None:
        def get_cert(h, p, t):
            der = ssl.get_server_certificate((h, p), timeout=t)
            return der.encode() if isinstance(der, str) else der
    try:
        pem = get_cert(host, port, timeout)
    except Exception:
        return []
    try:
        # stdlib only: avoid a cryptography dependency for one list
        import subprocess
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName"],
            input=pem, capture_output=True, timeout=timeout)
        text = proc.stdout.decode("utf-8", "replace")
    except Exception:
        return []
    sans: set[str] = set()
    for m in re.finditer(r"DNS:([^,\s]+)", text):
        name = m.group(1).lower().lstrip("*.").rstrip(".")
        if name and name != host.lower().rstrip("."):
            sans.add(name)
    return sorted(sans)


def merge_candidates(base_host: str, *sources) -> list[str]:
    """Union of subdomain candidates across sources, normalized against the
    base domain. Inventory-only: scope still decides what may be FETCHED."""
    base_host = base_host.lower().rstrip(".")
    out: set[str] = set()
    for src in sources:
        for name in src or []:
            name = str(name).lower().lstrip("*.").rstrip(".")
            if name.endswith("." + base_host) and name != base_host:
                out.add(name)
    return sorted(out)

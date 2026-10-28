"""Passive/deterministic surface mapping: robots.txt, sitemap.xml, and common API-schema
paths — fetched directly (no LLM call) and seeded straight into the knowledge graph and
attack tree, so RECON's first LLM turn already knows what exists instead of discovering
it one guessed URL at a time.

Every request here still goes through ScopeGuard first, same as every other tool in this
codebase — passive recon is "don't ask the model," not "skip authorization."
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

import requests

from ..scope import ScopeGuard, ScopeViolation

_TIMEOUT = 8
_MAX_BODY = 512 * 1024

# Common machine-readable surface-description paths worth a free, zero-token GET.
_SCHEMA_PATHS = (
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/api/openapi.json", "/api/swagger.json", "/.well-known/openapi.json",
)
# XML namespace sitemaps use; stripped so we can match tags without the {ns} prefix dance.
_SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def _get(guard: ScopeGuard, url: str) -> tuple[int, str]:
    try:
        guard.check(url)
    except ScopeViolation:
        return 0, ""
    try:
        r = requests.get(url, timeout=_TIMEOUT, allow_redirects=True,
                         headers={"User-Agent": "redteam-agent-recon/1.0"})
        return r.status_code, r.text[:_MAX_BODY]
    except requests.RequestException:
        return 0, ""


def _candidate_base_urls(engagement) -> list[str]:
    """Concrete, fetchable base URLs derived from signed scope — never invented. Wildcard
    domains (*.example.com) and CIDRs have no single concrete host to hit, so they're
    skipped here; the agent still discovers those hosts the normal way."""
    bases = []
    schemes = engagement.allowed_schemes or ["https"]
    ports = engagement.allowed_ports or [443]
    for host in engagement.allowed_hosts:
        h = host.strip()
        if h.startswith("*.") or "/" in h:   # wildcard domain or CIDR — not a concrete host
            continue
        for scheme in schemes:
            default_port = 443 if scheme == "https" else 80
            for port in ports:
                if port == default_port:
                    bases.append(f"{scheme}://{h}")
                else:
                    bases.append(f"{scheme}://{h}:{port}")
    return bases


def _parse_robots(body: str) -> list[str]:
    paths = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() in ("disallow", "allow") and value.strip() not in ("", "/"):
            paths.append(value.strip())
    return paths


def _parse_sitemap(body: str) -> list[str]:
    urls = []
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return urls
    for loc in root.iter(f"{_SITEMAP_NS}loc"):
        if loc.text:
            urls.append(loc.text.strip())
    if not urls:   # namespace-less sitemap — fall back to a tagless scan
        for loc in root.iter("loc"):
            if loc.text:
                urls.append(loc.text.strip())
    return urls


def _looks_like_schema(body: str) -> dict | None:
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc or "paths" in doc):
        return doc
    return None


def _endpoints_from_schema(doc: dict, base_url: str) -> list[str]:
    paths = doc.get("paths") or {}
    out = []
    for path in paths:
        out.append(urljoin(base_url + "/", path.lstrip("/")))
    return out


def run_passive_recon(engagement, graph, attack_tree=None, audit=None) -> dict:
    """Fetch robots.txt, sitemap.xml, and common API-schema paths for every concrete
    host in scope; seed discovered endpoints into the knowledge graph (and attack tree,
    if given). Returns a summary dict for logging. Pure HTTP GETs, no LLM calls."""
    from ..knowledge import ENDPOINT, TECHNOLOGY

    guard = ScopeGuard(engagement)
    discovered: set[str] = set()
    schemas_found = 0

    for base in _candidate_base_urls(engagement):
        status, body = _get(guard, f"{base}/robots.txt")
        if status and 200 <= status < 300:
            for p in _parse_robots(body):
                discovered.add(urljoin(base + "/", p.lstrip("/")))

        status, body = _get(guard, f"{base}/sitemap.xml")
        if status and 200 <= status < 300:
            for u in _parse_sitemap(body):
                host = urlsplit(u).hostname
                if host and host == urlsplit(base).hostname:
                    discovered.add(u)

        for schema_path in _SCHEMA_PATHS:
            status, body = _get(guard, f"{base}{schema_path}")
            if not status or not (200 <= status < 300):
                continue
            doc = _looks_like_schema(body)
            if doc is None:
                continue
            schemas_found += 1
            for ep in _endpoints_from_schema(doc, base):
                discovered.add(ep)
            title = ((doc.get("info") or {}).get("title") or "").strip()
            if title:
                graph.observe(TECHNOLOGY, f"{base}:api-schema", attrs={"title": title},
                              source="passive_recon")

    for ep in discovered:
        graph.observe(ENDPOINT, ep, source="passive_recon")
        if attack_tree is not None:
            attack_tree.seed_endpoint(ep)

    if audit is not None:
        audit.record("recon.passive", endpoints=len(discovered), schemas=schemas_found)

    return {"endpoints_discovered": len(discovered), "schemas_found": schemas_found}

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
# Per-endpoint cap on schema description prose we carry into the graph. API docs are a
# prime leak source (service-account tokens, internal hostnames, "internal use only"
# notes) — but they are also attacker/target-controlled text that later gets rendered
# into agent context, so the surface is bounded: no 200KB description bloats a briefing.
_MAX_DOC = 400
# Operation keys an OpenAPI path item can carry (plus path-item-level summary/description).
_METHOD_KEYS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

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


def _docs_from_path_item(item) -> list[str]:
    """summary/description prose from the path item itself and every operation on it.
    This is the text real-world API docs leak credentials in ('auth: Bearer tok-...' in
    the /import description) — live-fire 2026-11-02 the recon layer fetched the doc but
    dropped exactly this, so the plant stayed on the wire yet invisible."""
    if not isinstance(item, dict):
        return []
    texts: list[str] = []
    for field in ("summary", "description"):        # path-item level
        v = item.get(field)
        if isinstance(v, str) and v.strip():
            texts.append(v.strip())
    for key in _METHOD_KEYS:                        # per-operation level
        op = item.get(key)
        if not isinstance(op, dict):
            continue
        for field in ("summary", "description"):
            v = op.get(field)
            if isinstance(v, str) and v.strip():
                texts.append(v.strip())
    return texts


def _endpoints_from_schema(doc: dict, base_url: str) -> dict[str, str]:
    """path URL -> capped description prose ('' when the path is undocumented). Same URL
    set as before; the values are the operation docs a pentester reads but a stripped
    index discards."""
    paths = doc.get("paths") or {}
    out: dict[str, str] = {}
    for path, item in paths.items():
        url = urljoin(base_url + "/", path.lstrip("/"))
        docs = _docs_from_path_item(item)
        out[url] = " | ".join(docs)[:_MAX_DOC] if docs else ""
    return out


def run_passive_recon(engagement, graph, attack_tree=None, audit=None) -> dict:
    """Fetch robots.txt, sitemap.xml, and common API-schema paths for every concrete
    host in scope; seed discovered endpoints into the knowledge graph (and attack tree,
    if given). Returns a summary dict for logging. Pure HTTP GETs, no LLM calls."""
    from ..knowledge import ENDPOINT, TECHNOLOGY

    guard = ScopeGuard(engagement)
    discovered: set[str] = set()
    doc_notes: dict[str, str] = {}
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
            for ep, doc_text in _endpoints_from_schema(doc, base).items():
                discovered.add(ep)
                if doc_text:
                    doc_notes[ep] = doc_text
            info = doc.get("info") or {}
            title = (info.get("title") or "").strip()
            if title:
                attrs = {"title": title}
                # Top-level API description: same leak class as operation descriptions.
                api_desc = (info.get("description") or "").strip()
                if api_desc:
                    attrs["doc"] = api_desc[:_MAX_DOC]
                graph.observe(TECHNOLOGY, f"{base}:api-schema", attrs=attrs,
                              source="passive_recon")

    for ep in sorted(discovered):
        note = doc_notes.get(ep)
        graph.observe(ENDPOINT, ep, attrs=({"doc": note} if note else None),
                      source="passive_recon")
        if attack_tree is not None:
            attack_tree.seed_endpoint(ep)

    if audit is not None:
        audit.record("recon.passive", endpoints=len(discovered), schemas=schemas_found,
                     doc_leads=len(doc_notes))

    return {"endpoints_discovered": len(discovered), "schemas_found": schemas_found,
            "doc_leads": len(doc_notes)}

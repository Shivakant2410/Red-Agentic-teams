"""RECON V2 specialized capabilities.

Each function is ONE recon capability that produces scoped, provenance-tagged
Observations in the shared evidence store. They wrap the primitives that
already exist in the repo (osint.py crt.sh/DNS/SAN, the passive-recon fetchers,
the browser controller, the traffic recorder) instead of re-implementing them —
RECON V2 is integration, not duplication.

Capabilities (directive §2):
  - external_asset_intel      crt.sh CT-log subdomains → domain/subdomain assets
  - dns_cert_intel            DNS wordlist + TLS SAN → dns_record/certificate assets
  - api_recon                 OpenAPI/Swagger discovery → api_spec/endpoint
  - js_recon                  in-scope JS endpoint extraction → js_endpoint
  - validate_and_attribute    corroboration pass + scope re-attribution
"""
from __future__ import annotations

import re as _re
from urllib.parse import urlsplit

from .evidence_store import EvidenceStore, scope_status_for
from .observations import (
    KIND_API_SPEC, KIND_ENDPOINT, KIND_JS_ENDPOINT, KIND_PAGE,
    KIND_SUBDOMAIN, KIND_DNS_RECORD, KIND_CERTIFICATE, KIND_DOMAIN,
    PROVENANCE_ACTIVE, PROVENANCE_PASSIVE, EvidenceRef,
)

_MAX_JS_BYTES = 512 * 1024
# Strings that look like same-origin API paths inside JS bundles.
_JS_PATH_RE = _re.compile(r'["\'](/[A-Za-z0-9_\-./]{2,80})["\']')
_JS_NOISE = _re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|ico|map|webp)$", _re.IGNORECASE)
_SCHEMA_PATHS = ("/openapi.json", "/swagger.json", "/api/v1/swagger.json",
                 "/api/openapi.json", "/api-docs", "/api/swagger.json",
                 "_next/data")


def external_asset_intel(store: EvidenceStore, assets, domain: str, *,
                         fetch, timeout: float = 25.0, max_items: int = 200,
                         limiter=None, audit=None) -> dict:
    """Certificate-transparency subdomain intelligence (crt.sh) — passive:
    the target is never touched. Third-party hosts are recorded with their
    honest scope status (usually out_of_scope) and linked to the parent
    domain — NEVER added to the authorized scope."""
    from ..osint import crtsh_subdomains
    found = crtsh_subdomains(domain, fetch, timeout=timeout)[:max_items]
    parent_id = None
    if found:
        parent_id = assets.record(
            KIND_DOMAIN, domain, tool="external_asset_intel",
            provenance=PROVENANCE_PASSIVE,
            evidence=[EvidenceRef(kind="tool",
                                  ref="osint.crtsh_subdomains", tool="crt.sh")
                      .to_json()])
    for sub in found:
        sub_id = assets.record(
            KIND_SUBDOMAIN, sub, tool="external_asset_intel",
            provenance=PROVENANCE_PASSIVE, related_to=parent_id or "",
            relation="has_subdomain",
            evidence=[EvidenceRef(kind="tool", ref=f"crt.sh#{domain}",
                                  tool="crt.sh").to_json()])
        if limiter is not None:
            try:
                limiter.acquire()
            except Exception:
                pass
    if audit is not None:
        audit.record("reconv2.external_asset_intel", domain=domain,
                     found=len(found))
    return {"domain": domain, "subdomains": len(found)}


def dns_cert_intel(store: EvidenceStore, assets, domain: str, *, resolve,
                   wordlist=None, cert_probe=None, limiter=None,
                   audit=None, max_items: int = 100) -> dict:
    """DNS wordlist enumeration + TLS certificate SAN harvesting. DNS queries
    hit RESOLVERS, not the target web stack (passive-with-regard-to-target);
    the certificate probe touches the target — it acquires rate budget."""
    from ..osint import cert_san, dns_bruteforce
    dns_hits = 0
    if wordlist:
        result = dns_bruteforce(domain, wordlist, resolve)
        for host, ips in (result.get("resolved") or {}).items():
            dns_id = assets.record(
                KIND_DNS_RECORD, host, tool="dns_cert_intel",
                provenance=PROVENANCE_PASSIVE,
                attrs={"a": list(ips)[:8]},
                evidence=[EvidenceRef(kind="tool", ref=f"dns#{host}",
                                      tool="dns_bruteforce").to_json()])
            for ip in list(ips)[:4]:
                ip_id = assets.record(
                    "ip", str(ip), tool="dns_cert_intel",
                    provenance=PROVENANCE_PASSIVE,
                    related_to=dns_id, relation="resolves_to",
                    evidence=[EvidenceRef(kind="tool",
                                          ref=f"dns#{host}->{ip}",
                                          tool="dns_bruteforce").to_json()])
                del ip_id
            dns_hits += 1
            if dns_hits >= max_items:
                break
    cert_count = 0
    if cert_probe is not None:
        if limiter is not None:
            limiter.acquire()
        try:
            cert = cert_probe(domain)
        except Exception as exc:
            cert = {"error": str(exc)[:120]}
        if cert and not cert.get("error"):
            assets.record(
                KIND_CERTIFICATE, domain, tool="dns_cert_intel",
                provenance=PROVENANCE_ACTIVE,
                attrs={"subject_cn": cert.get("subject_cn", ""),
                       "issuer_cn": cert.get("issuer_cn", ""),
                       "san": list(cert.get("san") or [])[:16]},
                evidence=[EvidenceRef(kind="tool", ref=f"tls#{domain}",
                                      tool="cert_san").to_json()])
            for san in list(cert.get("san") or [])[:16]:
                assets.record(
                    KIND_SUBDOMAIN, str(san).lower(), tool="dns_cert_intel",
                    provenance=PROVENANCE_ACTIVE,
                    related_to="", relation="",
                    attrs={"from_san": domain},
                    evidence=[EvidenceRef(kind="tool",
                                          ref=f"tls#{domain}#san",
                                          tool="cert_san").to_json()])
            cert_count = 1
    if audit is not None:
        audit.record("reconv2.dns_cert_intel", domain=domain,
                     dns_hosts=dns_hits, certificate=cert_count)
    return {"dns_hosts": dns_hits, "certificate": cert_count}


def api_recon(store: EvidenceStore, base_url: str, *, fetch, limiter=None,
              audit=None, max_specs: int = 4) -> dict:
    """API contract discovery: probe the well-known schema paths on an
    in-scope base URL; every hit becomes an api_spec observation and every
    documented path an endpoint observation with provenance."""
    from ..osint import is_osint_eligible
    host = urlsplit(base_url).hostname or ""
    specs_found = 0
    endpoints = 0
    for path in _SCHEMA_PATHS:
        if specs_found >= max_specs:
            break
        url = f"{base_url.rstrip('/')}{path}"
        try:
            scope_status_for(store._scope, KIND_ENDPOINT, url)
        except Exception:
            pass
        if limiter is not None:
            limiter.acquire()
        try:
            status, body = fetch(url)
        except Exception:
            continue
        if not status or not body:
            continue
        text = body[:65536]
        is_spec = (('"openapi"' in text or '"swagger"' in text
                    or '"paths"' in text) and "{" in text)
        spec_id = store.observe(
            KIND_API_SPEC, url, tool="api_recon", provenance=PROVENANCE_ACTIVE,
            attrs={"status": status, "eligible_host": is_osint_eligible(host)},
            evidence=[EvidenceRef(kind="traffic", ref=f"api_recon#{url}",
                                  tool="api_recon").to_json()])
        del spec_id
        specs_found += 1
        if is_spec:
            for m in _re.finditer(r'"(/[^"]{2,120})"\s*:', text):
                ep = m.group(1)
                if _JS_NOISE.search(ep) or ep.startswith("/openapi"):
                    continue
                store.observe(
                    KIND_ENDPOINT, f"{base_url.rstrip('/')}{ep}",
                    tool="api_recon", provenance=PROVENANCE_ACTIVE,
                    attrs={"from_spec": url},
                    evidence=[EvidenceRef(kind="tool", ref=f"openapi#{url}",
                                          tool="api_recon").to_json()])
                endpoints += 1
                if endpoints >= 200:
                    break
    if audit is not None:
        audit.record("reconv2.api_recon", base_url=base_url,
                     specs=specs_found, endpoints=endpoints)
    return {"specs": specs_found, "endpoints": endpoints}


def js_recon(store: EvidenceStore, base_url: str, *, fetch, js_urls: list[str],
             limiter=None, audit=None, max_files: int = 10) -> dict:
    """JavaScript reconnaissance: pull in-scope JS bundles, extract same-origin
    API paths. Only paths that stay on the in-scope host are recorded."""
    seen: set[str] = set()
    files = 0
    for js_url in js_urls[:max_files]:
        if urlsplit(js_url).hostname != urlsplit(base_url).hostname:
            continue   # third-party bundles never enter the evidence plane
        if limiter is not None:
            limiter.acquire()
        try:
            status, body = fetch(js_url)
        except Exception:
            continue
        if not status or not body:
            continue
        files += 1
        text = body[:_MAX_JS_BYTES]
        for m in _JS_PATH_RE.finditer(text):
            path = m.group(1)
            if (_JS_NOISE.search(path) or len(path) < 4
                    or path.startswith("/static") or path in seen):
                continue
            seen.add(path)
            store.observe(
                KIND_JS_ENDPOINT, f"{base_url.rstrip('/')}{path}",
                tool="js_recon", provenance=PROVENANCE_ACTIVE,
                attrs={"from_js": js_url},
                evidence=[EvidenceRef(kind="tool", ref=f"js#{js_url}",
                                      tool="js_recon").to_json()])
    if audit is not None:
        audit.record("reconv2.js_recon", base_url=base_url, files=files,
                     endpoints=len(seen))
    return {"files": files, "endpoints": len(seen)}


def validate_and_attribute(store: EvidenceStore, assets, scope,
                           audit=None) -> dict:
    """Evidence validation pass (directive §2/§8): recompute scope attribution
    for every observation and mark corroboration where two INDEPENDENT tools
    produced the same subject. Missing evidence never upgrades anything."""
    corroborated = 0
    reattributed = 0
    by_subject: dict[str, set] = {}
    for obs in store.query(limit=10_000):
        tools = by_subject.setdefault((obs.kind, obs.subject), set())
        if obs.tool:
            tools.add(obs.tool)
        if obs.scope_status == "unattributed" and scope is not None:
            new_status = scope_status_for(scope, obs.kind, obs.subject)
            if new_status != obs.scope_status:
                obs.scope_status = new_status
                reattributed += 1
    for (kind, subject), tools in by_subject.items():
        if len(tools) >= 2:
            for obs in store.query(kind=kind, subject_contains=subject,
                                   limit=10):
                if obs.subject == subject and obs.tool in tools:
                    if obs.validation_status == "unvalidated":
                        obs.validation_status = "corroborated"
                        obs.confidence = "corroborated"
                        corroborated += 1
    if audit is not None:
        audit.record("reconv2.validate_and_attribute",
                     corroborated=corroborated, reattributed=reattributed)
    return {"corroborated": corroborated, "reattributed": reattributed}


def record_page_evidence(store: EvidenceStore, url: str, *, title: str,
                         status: int | None, console_errors: list[str],
                         screenshot_path: str = "", tool: str = "browser",
                         evidence_refs: list | None = None) -> dict:
    """Browser-based web reconnaissance evidence: the page, its console errors
    and its screenshot become observations (with evidence pointers), not just
    narration."""
    refs = list(evidence_refs or [])
    page = store.observe(
        KIND_PAGE, url, tool=tool, provenance=PROVENANCE_ACTIVE,
        attrs={"title": title[:200], "status": status},
        evidence=refs)
    out = {"page_id": page.id, "console": 0, "screenshot": ""}
    for msg in (console_errors or [])[:20]:
        store.observe(
            KIND_CONSOLE_ERROR, url, tool=tool, provenance=PROVENANCE_ACTIVE,
            attrs={"message": str(msg)[:300]},
            evidence=refs + [EvidenceRef(kind="console",
                                         ref=f"{url}#{msg[:60]}",
                                         tool=tool).to_json()])
        out["console"] += 1
    if screenshot_path:
        shot = store.observe(
            KIND_SCREENSHOT, url, tool=tool, provenance=PROVENANCE_ACTIVE,
            attrs={"path": screenshot_path},
            evidence=refs + [EvidenceRef(kind="screenshot",
                                         ref=screenshot_path,
                                         tool=tool).to_json()])
        out["screenshot"] = shot.id
    return out

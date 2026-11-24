"""Run the first-party root-domain RECON pipeline before LLM agents start.

The pipeline composes existing RECON V2 capabilities and tool wrappers. It always
starts from the engagement's configured domain(s), records passive discoveries,
and performs HTTP work only for hosts already accepted by the engagement scope.
Missing external binaries degrade to the built-in HTTP/HTML path rather than
turning a valid root-domain run into an empty RECON result.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..events import safe_emit
from ..osint import DNS_WORDLIST, crtsh_subdomains, dns_bruteforce, osint_fetch
from ..tools.http import fetch_once
from .capabilities import api_recon, js_recon, record_page_evidence
from .observations import (
    KIND_DOMAIN, KIND_DNS_RECORD, KIND_ENDPOINT, KIND_IP, KIND_SUBDOMAIN,
    PROVENANCE_PASSIVE, EvidenceRef,
)


class _PageLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag.lower() == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        elif tag.lower() == "link" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag.lower() in ("form", "iframe") and attrs.get(
                "action" if tag.lower() == "form" else "src"):
            self.links.append(attrs.get("action" if tag.lower() == "form" else "src"))
        elif tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 240:
            self.title += data.strip()


def _domain_roots(allowed_hosts) -> list[str]:
    """Return concrete domain roots; wildcard entries contribute their suffix."""
    roots = set()
    for entry in allowed_hosts or ():
        host = str(entry).strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if not host or "/" in host or ":" in host:
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if "." in host and all(part for part in host.split(".")):
            roots.add(host)
    return sorted(roots)


def _base_url(host: str, engagement) -> str:
    schemes = list(engagement.allowed_schemes or ("https", "http"))
    ports = list(engagement.allowed_ports or ())
    # Prefer HTTPS, but only choose a port the engagement actually permits.
    schemes.sort(key=lambda s: 0 if s == "https" else 1)
    for scheme in schemes:
        default = 443 if scheme == "https" else 80
        if default in ports:
            return f"{scheme}://{host}"
        if ports:
            return f"{scheme}://{host}:{ports[0]}"
    return ""


def _resolve(host: str, timeout: float = 2.0):
    del timeout  # socket.getaddrinfo uses the system resolver timeout policy
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except (OSError, ValueError):
        return None


def _same_origin_urls(base_url: str, candidates: list[str]) -> list[str]:
    origin = urlsplit(base_url)
    origin_port = origin.port or (443 if origin.scheme == "https" else 80)
    found = []
    seen = set()
    for candidate in candidates:
        try:
            url = urljoin(base_url, str(candidate).strip())
            parsed = urlsplit(url)
            parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        if (parsed.scheme not in ("http", "https")
                or parsed.hostname != origin.hostname
                or parsed_port != origin_port
                or parsed.username is not None or parsed.password is not None):
            continue
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/",
                            parsed.query, ""))
        if clean not in seen:
            seen.add(clean)
            found.append(clean)
    return found


def _fetch(ctx, url: str, tool: str, *, acquire: bool = True):
    if acquire:
        ctx.limiter.acquire()
    status, body, elapsed, headers = fetch_once(
        ctx, {"method": "GET", "url": url}, tool=tool)
    return status, body, headers


def _record_subdomain(assets, root_id: str, host: str, source: str,
                      evidence_ref: str):
    obs_id = assets.record(
        KIND_SUBDOMAIN, host, tool=source, provenance=PROVENANCE_PASSIVE,
        related_to=root_id, relation="has_subdomain",
        evidence=[EvidenceRef(kind="tool", ref=evidence_ref, tool=source).to_json()])
    return obs_id


def _available(ctx, binary: str) -> bool:
    try:
        if ctx.sandbox is not None:
            result = ctx.sandbox.exec(f"command -v {binary} || true", timeout=10)
            return bool((getattr(result, "stdout", "") or "").strip())
        from ..sandbox.provision import resolve_binary
        return bool(resolve_binary(binary))
    except Exception:
        return False


def _run_optional_tool(ctx, tool, **kwargs) -> dict:
    try:
        ctx.limiter.acquire()
        raw = tool.run(ctx, **kwargs)
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return {"ok": False, "error": str(raw)[:300]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}


def run_domain_recon(ctx, reconv2, engagement, *, proxy_active: bool = False) -> dict:
    """Enumerate configured root domains, then map their authorized web surface."""
    store, assets = reconv2.store, reconv2.assets
    roots = _domain_roots(engagement.allowed_hosts)
    summary = {
        "domains": roots, "passive_subdomains": 0, "dns_hosts": 0,
        "active_hosts": 0, "pages": 0, "endpoints": 0, "js_files": 0,
        "api_specs": 0, "tools": {}, "errors": [],
    }
    if not roots:
        summary["errors"].append("No concrete domain root found in scope.allowed_hosts")
        return summary

    # The adapter is created before the optional Kali container. Attach the
    # already-running sandbox executor now, so PD tools use the same run context.
    if reconv2.adapter is not None:
        reconv2.adapter._sandbox_exec = ctx.sandbox.exec if ctx.sandbox is not None else None

    from ..tools.hostprobe import HostProbeTool
    from ..tools.webdiscover import CrawlTool

    for domain in roots:
        safe_emit(ctx.events, "recon.domain.started", domain=domain)
        root_id = assets.record(
            KIND_DOMAIN, domain, tool="domain_pipeline",
            provenance=PROVENANCE_PASSIVE,
            evidence=[EvidenceRef(kind="event", ref=f"domain_pipeline#{domain}",
                                  tool="domain_pipeline").to_json()])

        candidates: set[str] = set()
        # Certificate transparency is passive: retain third-party relationships
        # as out-of-scope observations instead of silently discarding them.
        try:
            ct_names = crtsh_subdomains(domain, osint_fetch)
            for host in ct_names:
                candidates.add(host)
                _record_subdomain(assets, root_id, host, "crt.sh",
                                  f"crt.sh#{domain}")
        except Exception as exc:
            summary["errors"].append(f"{domain}: crt.sh: {str(exc)[:160]}")

        # Subfinder is optional. Its JSONL observations are normalized by the
        # existing adapter and passive out-of-scope names remain visible.
        if reconv2.adapter is not None:
            try:
                result = reconv2.adapter.run(
                    "subfinder", ["-d", domain, "-silent", "-json"],
                    target=domain, authorized=True)
                summary["tools"][f"subfinder:{domain}"] = result
                for host in result.get("subjects", []):
                    host = str(host).lower().rstrip(".")
                    if host and host != domain:
                        candidates.add(host)
                        _record_subdomain(assets, root_id, host, "subfinder",
                                          f"subfinder#{domain}")
            except Exception as exc:
                summary["tools"][f"subfinder:{domain}"] = {
                    "available": False, "error": str(exc)[:160]}

        # DNSX enriches the root domain with A/AAAA/CNAME records. This is
        # resolver-side intelligence, so the adapter stores it as passive data.
        if reconv2.adapter is not None:
            try:
                result = reconv2.adapter.run(
                    "dnsx", ["-d", domain, "-a", "-aaaa", "-cname", "-json", "-silent"],
                    target=domain, authorized=True)
                summary["tools"][f"dnsx:{domain}"] = result
            except Exception as exc:
                summary["tools"][f"dnsx:{domain}"] = {
                    "available": False, "error": str(exc)[:160]}

        # Small DNS wordlist adds common service names without sending HTTP to
        # them. DNS discoveries are retained independently of active scope.
        try:
            dns_hits = dns_bruteforce(domain, DNS_WORDLIST, _resolve)
            for host, addresses in dns_hits.items():
                candidates.add(host)
                _record_subdomain(assets, root_id, host, "dns_wordlist",
                                  f"dns#{host}")
                ips = addresses if isinstance(addresses, list) else [addresses]
                store.observe(KIND_DNS_RECORD, host, tool="dns_wordlist",
                              provenance=PROVENANCE_PASSIVE,
                              attrs={"a": [str(ip) for ip in ips[:8]]},
                              evidence=[EvidenceRef(kind="tool", ref=f"dns#{host}",
                                                    tool="dns_wordlist").to_json()])
                for ip in ips[:4]:
                    assets.record(KIND_IP, str(ip), tool="dns_wordlist",
                                  provenance=PROVENANCE_PASSIVE,
                                  related_to=root_id, relation="resolves_to",
                                  evidence=[EvidenceRef(kind="tool",
                                                        ref=f"dns#{host}->{ip}",
                                                        tool="dns_wordlist").to_json()])
            summary["dns_hosts"] += len(dns_hits)
        except Exception as exc:
            summary["errors"].append(f"{domain}: DNS enumeration: {str(exc)[:160]}")

        # Only hosts the engagement already permits are actively contacted.
        active_hosts = []
        if ctx.scope.host_scope_status(domain):
            active_hosts.append(domain)
        active_hosts.extend(sorted(h for h in candidates
                                   if h != domain and ctx.scope.host_scope_status(h)))
        active_hosts = list(dict.fromkeys(active_hosts))[:30]

        for host in active_hosts:
            base = _base_url(host, engagement)
            if not base:
                continue
            try:
                ctx.scope.check(base)
            except Exception as exc:
                summary["errors"].append(f"{host}: {str(exc)[:120]}")
                continue
            summary["active_hosts"] += 1

            # External crawlers can follow redirects and fan out to many
            # discovered URLs. Run them only when this run has the shared
            # evidence proxy in front of sandbox egress; the proxy enforces the
            # existing scope and request budget on every wire request.
            if proxy_active and ctx.sandbox is not None and _available(ctx, "httpx"):
                result = _run_optional_tool(
                    ctx, HostProbeTool(), target=base,
                    reason="Baseline root-domain service and technology discovery")
                summary["tools"][f"httpx:{host}"] = result
                for lead in result.get("leads", []) if isinstance(result, dict) else []:
                    url = lead.get("url")
                    if url:
                        store.observe("service", url, tool="httpx",
                                      provenance="active", attrs=lead,
                                      evidence=[EvidenceRef(kind="tool",
                                                            ref=f"httpx#{url}",
                                                            tool="httpx").to_json()])
            if proxy_active and ctx.sandbox is not None and _available(ctx, "katana"):
                result = _run_optional_tool(
                    ctx, CrawlTool(), target=base, depth=3, rate_limit=10,
                    concurrency=5,
                    reason="Baseline root-domain web and JavaScript endpoint crawl")
                summary["tools"][f"katana:{host}"] = result
                for lead in result.get("leads", []) if isinstance(result, dict) else []:
                    url = lead.get("url")
                    if url:
                        store.observe(KIND_ENDPOINT, url, tool="katana",
                                      provenance="active", attrs=lead,
                                      evidence=[EvidenceRef(kind="tool",
                                                            ref=f"katana#{url}",
                                                            tool="katana").to_json()])
                        summary["endpoints"] += 1

            # Built-in same-origin crawl ensures the root domain still works
            # when optional binaries are absent. All requests use the existing
            # fetch_once scope, rate-budget and traffic-evidence path.
            queue = [base]
            visited: set[str] = set()
            js_urls: set[str] = set()
            while queue and len(visited) < 15:
                url = queue.pop(0)
                if url in visited:
                    continue
                try:
                    status, body, headers = _fetch(ctx, url, "domain_recon")
                except Exception as exc:
                    summary["errors"].append(f"{url}: {str(exc)[:120]}")
                    continue
                visited.add(url)
                if not status:
                    continue
                parser = _PageLinks()
                try:
                    parser.feed(body or "")
                except Exception:
                    pass
                summary["pages"] += 1
                record_page_evidence(
                    store, url, title=parser.title, status=status,
                    console_errors=[], tool="domain_recon",
                    evidence_refs=[EvidenceRef(kind="traffic",
                                               ref=f"domain_recon#{url}",
                                               tool="domain_recon").to_json()])
                links = _same_origin_urls(url, parser.links)
                scripts = _same_origin_urls(url, parser.scripts)
                js_urls.update(u for u in scripts if urlsplit(u).path.lower().endswith(".js"))
                for link in links:
                    store.observe(KIND_ENDPOINT, link, tool="domain_recon",
                                  provenance="active",
                                  evidence=[EvidenceRef(kind="tool",
                                                        ref=f"crawl#{url}",
                                                        tool="domain_recon").to_json()])
                    summary["endpoints"] += 1
                    if link not in visited and link not in queue and len(queue) < 60:
                        queue.append(link)

            # API schema discovery and JS bundle endpoint extraction share the
            # same traffic recorder and request budget as the baseline crawl.
            def api_fetch(url):
                status, body, _headers = _fetch(ctx, url, "api_recon", acquire=False)
                return status, body

            try:
                api_result = api_recon(
                    store, base, fetch=api_fetch, limiter=ctx.limiter,
                    audit=ctx.audit)
                summary["api_specs"] += api_result.get("specs", 0)
                summary["endpoints"] += api_result.get("endpoints", 0)
            except Exception as exc:
                summary["errors"].append(f"{host}: API recon: {str(exc)[:160]}")

            try:
                js_result = js_recon(store, base, fetch=api_fetch,
                                     js_urls=sorted(js_urls), limiter=ctx.limiter,
                                     audit=ctx.audit)
                summary["js_files"] += js_result.get("files", 0)
                summary["endpoints"] += js_result.get("endpoints", 0)
            except Exception as exc:
                summary["errors"].append(f"{host}: JS recon: {str(exc)[:160]}")

        summary["passive_subdomains"] += len(candidates)
        safe_emit(ctx.events, "recon.domain.completed", domain=domain,
                  passive_subdomains=len(candidates),
                  active_hosts=len(active_hosts))
        ctx.audit.record("recon.domain.completed", domain=domain,
                         passive_subdomains=len(candidates),
                         active_hosts=len(active_hosts))

    return summary

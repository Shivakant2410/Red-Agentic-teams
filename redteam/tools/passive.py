"""passive_recon — DNS/TLS/metadata/technology fingerprinting with provenance.

Passive vs light vs active (honest classification, carried on every
observation):
  passive — NO contact with the target: DNS resolution (A/AAAA/CNAME), and
            optional certificate-transparency lookups (opt-in, see below).
  light   — metadata-class wire touches: TLS handshake for certificate
            metadata (no HTTP request), robots.txt, sitemap.xml, one GET on
            the base URL for security-header/cookie/technology fingerprinting.
  active  — everything else (crawls, content discovery, param probing) lives
            in the other discovery tools.

External data sources (crt.sh certificate transparency) are OPT-IN via
RED_CT_LOGS=1 and off by default — the run must never silently transmit
engagement identifiers to third parties. Every observation records its
source tool, timestamp and mode; nothing here can confirm a vulnerability —
leads stay leads (the validation lifecycle in observations.py owns trust).
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import time

from . import ToolContext
from .http import fetch_once

_SECURITY_HEADERS = ("content-security-policy", "strict-transport-security",
                     "x-content-type-options", "x-frame-options",
                     "referrer-policy", "permissions-policy")
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator",
                 "x-drupal-cache", "x-runtime", "via")
_MAX_HOSTS = 4
_MAX_SITEMAP_URLS = 50
_MAX_CT_ENTRIES = 20


def _safe(fn, default=""):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — report, never crash the sweep
        return default if default != "" else f"unavailable: {exc}"


def _dns_records(host: str) -> dict:
    """A/AAAA/CNAME via stdlib; MX/NS/TXT via dnspython when installed."""
    out: dict = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": []}
    try:
        infos = socket.getaddrinfo(host, None)
        out["a"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        out["aaaa"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    except Exception as exc:
        out["a"] = [f"resolve failed: {exc}"]
    try:
        _, _, addresses = socket.gethostbyname_ex(host)
        out["cname"] = list(addresses)[:8]
    except Exception:
        pass
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        out["note"] = ("MX/NS/TXT need dnspython (pip install dnspython); "
                       "A/AAAA/CNAME resolved with stdlib")
        return out
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
    except Exception as exc:
        out["note"] = f"dnspython resolver unusable ({exc}); stdlib records only"
        return out
    for rtype, key in (("MX", "mx"), ("NS", "ns"), ("TXT", "txt")):
        try:
            out[key] = [str(r).strip('"')[:200]
                        for r in resolver.resolve(host, rtype)][:16]
        except Exception:
            pass
    return out


def _tls_certificate(host: str, port: int) -> dict:
    """Fetch the serving certificate (one handshake, no HTTP) and parse it."""
    try:
        pem = ssl.get_server_certificate((host, port), timeout=6)
    except Exception as exc:
        return {"error": f"no TLS service on {host}:{port} ({type(exc).__name__})"}
    info: dict = {"port": port}
    try:
        import cryptography.x509 as x509
        cert = x509.load_pem_x509_certificate(pem.encode())
        info["subject_cn"] = cert.subject.rfc4514_string()[:200]
        info["issuer"] = cert.issuer.rfc4514_string()[:200]
        info["not_before"] = cert.not_valid_before_utc.isoformat()
        info["not_after"] = cert.not_valid_after_utc.isoformat()
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            info["san_domains"] = san.get_values_for_type(
                x509.DNSName)[:32]
        except Exception:
            info["san_domains"] = []
        import datetime as _dt
        info["expired"] = cert.not_valid_after_utc < _dt.datetime.now(
            _dt.timezone.utc)
    except ImportError:
        info["note"] = ("cryptography not installed — DER kept unParsed; "
                        "SAN extraction skipped")
        info["pem_sha256_prefix"] = pem[:0] or ""
    except Exception as exc:
        info["parse_error"] = str(exc)[:160]
    return info


def _robots_and_sitemap(ctx, base: str, observations) -> dict:
    out: dict = {"robots": {}, "sitemap": {}}
    limiter = ctx.limiter
    # robots.txt
    try:
        limiter.acquire()
        status, body, _, headers = fetch_once(
            ctx, {"url": f"{base}/robots.txt", "method": "GET"},
            tool="passive_recon")
        out["robots"]["status"] = status
        if status == 200 and body:
            disallow = [ln.split(":", 1)[1].strip()[:200] for ln in
                        body.splitlines()
                        if ln.lower().startswith("disallow:")
                        and len(ln.split(":", 1)) > 1
                        and ln.split(":", 1)[1].strip()]
            allow = [ln.split(":", 1)[1].strip()[:200] for ln in
                     body.splitlines()
                     if ln.lower().startswith("allow:")
                     and len(ln.split(":", 1)) > 1]
            sitemaps = [ln.split(":", 1)[1].strip()[:300] for ln in
                        body.splitlines()
                        if ln.lower().startswith("sitemap:")
                        and len(ln.split(":", 1)) > 1]
            out["robots"] = {"status": 200, "disallow": disallow[:24],
                             "allow": allow[:12], "sitemaps_declared": sitemaps[:6],
                             "disallow_count": len(disallow)}
            for path in disallow[:24]:
                # A disallowed path is a STRONG declared-exists lead, not a
                # confirmed endpoint — recorded awaiting corroboration.
                if observations is not None:
                    observations.record(
                        "endpoint", f"{base}{path}", source_tool="passive_recon",
                        mode="light",
                        metadata={"source": "robots.txt", "declared": "disallow"})
    except Exception as exc:
        out["robots"] = {"status": 0, "error": str(exc)[:160]}
    # sitemap.xml
    try:
        limiter.acquire()
        status, body, _, _ = fetch_once(
            ctx, {"url": f"{base}/sitemap.xml", "method": "GET"},
            tool="passive_recon")
        out["sitemap"]["status"] = status
        if status == 200 and body and "<loc>" in body:
            urls = []
            for chunk in body.split("<loc>")[1:_MAX_SITEMAP_URLS + 1]:
                url = chunk.split("</loc>")[0].strip()[:300]
                if url:
                    urls.append(url)
            out["sitemap"]["url_count"] = len(urls)
            out["sitemap"]["sample"] = urls[:12]
            if observations is not None:
                for url in urls[:_MAX_SITEMAP_URLS]:
                    observations.record("endpoint", url,
                                        source_tool="passive_recon",
                                        mode="light",
                                        metadata={"source": "sitemap.xml"})
    except Exception as exc:
        out["sitemap"] = {"status": 0, "error": str(exc)[:160]}
    return out


def _headers_and_tech(ctx, base: str, observations) -> dict:
    try:
        ctx.limiter.acquire()
        status, body, _, headers = fetch_once(
            ctx, {"url": base + "/", "method": "GET"}, tool="passive_recon")
    except Exception as exc:
        return {"status": 0, "error": str(exc)[:160]}
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    findings = {
        "status": status,
        "security_headers": {name: ("present" if lower.get(name) else "MISSING")
                             for name in _SECURITY_HEADERS},
        "technologies": {h: lower[h][:160] for h in _TECH_HEADERS if h in lower},
        "cookies": [],
    }
    set_cookie = lower.get("set-cookie", "")
    if set_cookie:
        flags = {"secure": "secure" in set_cookie.lower() or
                 "secure" in str(headers).lower(),
                 "httponly": "httponly" in str(headers).lower(),
                 "samesite": "samesite" in str(headers).lower()}
        findings["cookies"] = [{k: v for k, v in flags.items()}]
        findings["cookie_names"] = [c.split("=", 1)[0][:60] for c in
                                    set_cookie.split(";")[:6] if "=" in c]
    if observations is not None:
        for name, present in findings["security_headers"].items():
            observations.record("header", f"{base}#{name}",
                                source_tool="passive_recon", mode="light",
                                metadata={"header": name, "state": present,
                                          "http_status": status})
        for header, value in findings["technologies"].items():
            observations.record("technology", f"{value[:120]}",
                                source_tool="passive_recon", mode="light",
                                metadata={"via_header": header, "base": base})
        for cookie in findings["cookies"]:
            observations.record("header", f"{base}#set-cookie",
                                source_tool="passive_recon", mode="light",
                                metadata={**cookie,
                                          "names": findings.get("cookie_names", [])})
        # HTML generator meta (framework/CMS fingerprint)
        marker = '<meta name="generator"'
        if body and marker in body.lower():
            idx = body.lower().find(marker)
            snippet = body[idx:idx + 200]
            gen = snippet.split('content="', 1)[-1].split('"', 1)[0][:120]
            if gen:
                findings["generator_meta"] = gen
                observations.record("technology", gen,
                                    source_tool="passive_recon", mode="light",
                                    metadata={"via": "meta generator", "base": base})
    return findings


class PassiveReconTool:
    """passive_recon — DNS/TLS/metadata/technology sweep with provenance."""

    name = "passive_recon"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Passive + light-touch reconnaissance sweep for in-scope "
                "hosts: DNS records (A/AAAA/CNAME, MX/NS/TXT when dnspython "
                "is installed), TLS certificate metadata (issuer, validity, "
                "SAN domains), robots.txt and sitemap.xml declared paths, "
                "security-header and cookie-flag analysis, technology "
                "fingerprints (Server/X-Powered-By/generator meta). "
                "Everything is recorded with source + timestamp + mode "
                "(passive/light/active) into the observation log. NO "
                "exploitation, NO fuzzing — metadata-class requests only. "
                "External certificate-transparency lookups run ONLY when "
                "RED_CT_LOGS=1 is set (off by default; never transmit "
                "engagement data to third parties silently)."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string",
                               "description": "in-scope host or base URL; "
                                              "default: every allowed host "
                                              "(capped at 4)"},
                },
            },
        }

    def run(self, ctx, target: str = "") -> str:
        observations = getattr(ctx, "observations", None)
        scope = ctx.scope
        # Resolve the host list (explicit target must be in scope).
        try:
            if target:
                parsed = scope.check(target)   # raises when out of scope
                hosts = [parsed.host]
            else:
                hosts = [h for h in scope.allowed_hosts
                         if "*" not in h][:4]
        except Exception as exc:
            return f"BLOCKED (out of scope): {exc}"
        if not hosts:
            return "No concrete in-scope hosts to sweep (RoE lists only wildcards/CIDRs)."
        ct_enabled = os.environ.get("RED_CT_LOGS") == "1"

        summary: dict = {"hosts": [], "ct_logs": "disabled (RED_CT_LOGS not set)"
                         if not ct_enabled else "enabled"}
        recorded = 0
        for host in hosts:
            host_block: dict = {"host": host}
            dns_info = _dns_records(host)
            host_block["dns"] = {k: v for k, v in dns_info.items()
                                 if v and k != "note"}
            if dns_info.get("note"):
                host_block["dns_note"] = dns_info["note"]
            if observations is not None:
                observations.record("host", host, source_tool="passive_recon",
                                    mode="passive",
                                    metadata={"resolved_ips": dns_info["a"][:8],
                                              "aaaa": dns_info["aaaa"][:8]})
                for alias in dns_info["cname"][:8]:
                    observations.record("domain", alias,
                                        source_tool="passive_recon",
                                        mode="passive",
                                        metadata={"relation": "cname-of",
                                                  "of": host})
                recorded += 1 + len(dns_info["cname"][:8])

            tls_blocks = []
            https_ports = [p for p in scope.allowed_ports][:2] or [443]
            for port in https_ports:
                cert = _tls_certificate(host, port)
                if "error" not in cert:
                    tls_blocks.append(cert)
                    if observations is not None:
                        observations.record(
                            "service", f"{host}:{port} https",
                            source_tool="passive_recon", mode="light",
                            metadata={"tls": {k: cert.get(k) for k in
                                              ("subject_cn", "issuer",
                                               "not_after", "expired")
                                              if k in cert}})
                        for san in cert.get("san_domains", [])[:16]:
                            observations.record("domain", san,
                                                source_tool="passive_recon",
                                                mode="passive",
                                                metadata={"relation": "san-of",
                                                          "of": host})
                        recorded += 1 + len(cert.get("san_domains", [])[:16])
            host_block["tls"] = tls_blocks or [
                {"error": f"no TLS answered on tried ports {https_ports}"}]

            # Metadata + fingerprint planes over in-scope base URLs. ScopeGuard
            # exposes hosts/ports (not schemes); try the conventional scheme
            # pairings and let scope.check() fail-closed on anything off-RoE.
            metadata_blocks = {}
            for port in https_ports[:1]:
                for scheme in ("http", "https"):
                    base = f"{scheme}://{host}:{port}"
                    try:
                        scope.check(base)   # port/scheme must be in RoE
                    except Exception:
                        continue
                    metadata_blocks[scheme] = {
                        "metadata": _robots_and_sitemap(ctx, base, observations),
                        "fingerprint": _headers_and_tech(ctx, base, observations),
                    }
                    recorded += 2
            host_block["http_metadata"] = metadata_blocks
            summary["hosts"].append(host_block)

        # Optional, opt-in external CT lookup.
        if ct_enabled and observations is not None:
            domain = hosts[0].split(".", 1)[-1] or hosts[0]
            try:
                ctx.limiter.acquire()
                status, body, _, _ = fetch_once(
                    ctx, {"url": f"https://crt.sh/?q={domain}&output=json",
                          "method": "GET"}, tool="passive_recon/ct")
                if status == 200 and body:
                    entries = json.loads(body)[:_MAX_CT_ENTRIES]
                    names = sorted({n for e in entries
                                    for n in str(e.get("name_value", "")).split("\\n")
                                    if n})[:_MAX_CT_ENTRIES]
                    for name in names:
                        observations.record("domain", name,
                                            source_tool="passive_recon/ct_logs",
                                            mode="passive",
                                            metadata={"source": "crt.sh",
                                                      "relation": "ct-logged",
                                                      "queried_domain": domain})
                    summary["ct_logs"] = {"entries": len(entries),
                                          "names": names[:_MAX_CT_ENTRIES]}
                else:
                    summary["ct_logs"] = f"lookup failed (HTTP {status})"
            except Exception as exc:
                summary["ct_logs"] = f"lookup failed: {str(exc)[:120]}"

        if observations is not None:
            summary["observations_recorded"] = recorded
        summary["_meta"] = {"tool": "passive_recon",
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "modes": ["passive", "light"],
                            "note": "all output is LEADS: corroborate before trusting"}
        return json.dumps(summary, default=str)

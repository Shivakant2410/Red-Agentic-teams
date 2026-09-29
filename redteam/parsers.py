"""Structured tool-output parsers — turn raw Kali stdout into typed beliefs.

A generic wrapper dumps nmap/ffuf/nuclei stdout back into the model's context and lets it
re-read the same walls of text every turn until it drowns. This module instead parses that
output into normalized Observations and folds them into the knowledge graph, deduped and
correlated. The model then reasons over *state* (structured, compact, growing) instead of
re-parsing text — which is most of why a specialized agent outperforms a general one.

Supported: nmap, gobuster/ffuf/dirb-style dir busting, nuclei (JSONL), HTTP response
headers (curl -i/-I). Add parsers as you add tools; each returns list[Observation].
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .knowledge import ENDPOINT, HOST, SERVICE, TECHNOLOGY, KnowledgeGraph


@dataclass
class Observation:
    kind: str
    key: str
    attrs: dict = field(default_factory=dict)
    relate_to: str | None = None
    relation: str = "has"


# --- individual parsers ------------------------------------------------------

_NMAP_HOST = re.compile(r"Nmap scan report for (?:([^\s()]+) \(([\d.]+)\)|([\d.]+))")
_NMAP_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$")


def parse_nmap(text: str) -> list[Observation]:
    obs: list[Observation] = []
    current_host: str | None = None
    for line in text.splitlines():
        line = line.strip()
        m = _NMAP_HOST.search(line)
        if m:
            name, ip, bare_ip = m.groups()
            host_key = ip or bare_ip or name
            current_host = host_key
            attrs = {}
            if name and ip:
                attrs["hostname"] = name
            obs.append(Observation(HOST, host_key, attrs))
            continue
        pm = _NMAP_PORT.match(line)
        if pm and current_host:
            port, proto, state, service, version = pm.groups()
            if state != "open":
                continue
            svc_key = f"{current_host}:{port}"
            attrs = {"port": int(port), "proto": proto, "service": service}
            if version:
                attrs["version"] = version.strip()
            obs.append(Observation(SERVICE, svc_key, attrs,
                                   relate_to=f"{HOST}:{current_host}", relation="runs"))
            if version:
                obs.append(Observation(TECHNOLOGY, version.strip(), {"from": "nmap"},
                                       relate_to=f"{SERVICE}:{svc_key}", relation="identifies"))
    return obs


_DIR_LINE = re.compile(r"(/[^\s]*)\s*\(Status:\s*(\d+)\)")            # gobuster
_FFUF_JSON_HINT = re.compile(r'"url"\s*:\s*"([^"]+)".*?"status"\s*:\s*(\d+)', re.DOTALL)


def parse_dir(text: str, base_url: str | None = None) -> list[Observation]:
    obs: list[Observation] = []
    for path, status in _DIR_LINE.findall(text):
        url = (base_url.rstrip("/") + path) if base_url else path
        obs.append(Observation(ENDPOINT, url, {"status": int(status), "from": "dirbust"}))
    # ffuf -o json (array of results) — best-effort
    for url, status in _FFUF_JSON_HINT.findall(text):
        obs.append(Observation(ENDPOINT, url, {"status": int(status), "from": "ffuf"}))
    return obs


def parse_nuclei(text: str) -> list[Observation]:
    """nuclei -jsonl: one JSON object per line."""
    obs: list[Observation] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        matched = row.get("matched-at") or row.get("host") or ""
        if matched:
            obs.append(Observation(ENDPOINT, matched, {
                "nuclei_template": row.get("template-id"),
                "nuclei_name": info.get("name"),
                "nuclei_severity": info.get("severity"),
            }))
    return obs


_HDR = re.compile(r"^([A-Za-z0-9-]+):\s*(.+)$")
_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")


def parse_http_headers(text: str, url: str | None = None) -> list[Observation]:
    obs: list[Observation] = []
    status = None
    tech: list[str] = []
    for line in text.splitlines():
        sm = _STATUS.match(line.strip())
        if sm:
            status = int(sm.group(1))
            continue
        hm = _HDR.match(line.strip())
        if hm:
            name, value = hm.group(1).lower(), hm.group(2).strip()
            if name in ("server", "x-powered-by"):
                tech.append(value)
    if url:
        attrs = {"from": "headers"}
        if status is not None:
            attrs["status"] = status
        obs.append(Observation(ENDPOINT, url, attrs))
        for t in tech:
            obs.append(Observation(TECHNOLOGY, t, {"from": "http-header"},
                                   relate_to=f"{ENDPOINT}:{url}", relation="identifies"))
    return obs


def parse_sqlmap(text: str, base_url: str | None = None) -> list[Observation]:
    """Flag a confirmed SQL injection point and the affected parameter(s)."""
    if not re.search(r"(is vulnerable|injection point|identified the following injection)", text, re.I):
        return []
    params = re.findall(r"Parameter:\s*([^\s(]+)", text)
    attrs = {"sqli": True, "from": "sqlmap"}
    if params:
        attrs["parameters"] = sorted(set(params))
    key = base_url or "sqlmap-target"
    return [Observation(ENDPOINT, key, attrs)]


def parse_nikto(text: str, base_url: str | None = None) -> list[Observation]:
    obs: list[Observation] = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"\+\s*Server:\s*(.+)$", line)
        if m:
            obs.append(Observation(TECHNOLOGY, m.group(1).strip(), {"from": "nikto"}))
            continue
        pm = re.match(r"\+\s*(/\S+):\s*(.+)$", line)
        if pm and base_url:
            url = base_url.rstrip("/") + pm.group(1)
            obs.append(Observation(ENDPOINT, url, {"nikto_note": pm.group(2)[:120], "from": "nikto"}))
    return obs


def parse_whatweb(text: str) -> list[Observation]:
    # WhatWeb prints e.g.  nginx[1.24.0], HTTPServer[nginx], JQuery[3.6]
    obs: list[Observation] = []
    for name, ver in re.findall(r"([A-Za-z][\w .-]*?)\[([^\]]+)\]", text):
        name = name.strip()
        if name.lower() in ("country", "ip", "title", "status", "redirectlocation"):
            continue
        obs.append(Observation(TECHNOLOGY, f"{name} {ver}".strip(), {"from": "whatweb"}))
    return obs


def parse_httpx(text: str) -> list[Observation]:
    """httpx -json: one JSON object per line."""
    obs: list[Observation] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url") or row.get("input")
        if not url:
            continue
        attrs = {"from": "httpx"}
        if "status_code" in row:
            attrs["status"] = row["status_code"]
        ep = Observation(ENDPOINT, url, attrs)
        obs.append(ep)
        for t in (row.get("tech") or []):
            obs.append(Observation(TECHNOLOGY, str(t), {"from": "httpx"},
                                   relate_to=f"{ENDPOINT}:{url}", relation="identifies"))
        if row.get("webserver"):
            obs.append(Observation(TECHNOLOGY, row["webserver"], {"from": "httpx"},
                                   relate_to=f"{ENDPOINT}:{url}", relation="identifies"))
    return obs


# --- dispatch + ingest -------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s'\"]+")


def _url_in_command(command: str) -> str | None:
    m = _URL_RE.search(command)
    return m.group(0) if m else None


def parse_by_command(command: str, stdout: str, base_url: str | None = None) -> list[Observation]:
    """Pick a parser from the command that produced the output."""
    cmd = command.strip().lower()
    first = cmd.split()[0] if cmd.split() else ""
    base_url = base_url or _url_in_command(command)
    if "nmap" in first:
        return parse_nmap(stdout)
    if first in ("gobuster", "ffuf", "dirb", "feroxbuster") or "ffuf" in cmd or "gobuster" in cmd:
        return parse_dir(stdout, base_url=base_url)
    if "nuclei" in first or "nuclei" in cmd:
        return parse_nuclei(stdout)
    if "sqlmap" in cmd:
        return parse_sqlmap(stdout, base_url=base_url)
    if "nikto" in cmd:
        return parse_nikto(stdout, base_url=base_url)
    if "whatweb" in cmd:
        return parse_whatweb(stdout)
    if "httpx" in first or "httpx" in cmd:
        return parse_httpx(stdout)
    if first in ("curl", "http") and re.search(r"\s-[iI]\b", cmd):
        return parse_http_headers(stdout, url=base_url)
    return []


def ingest(graph: KnowledgeGraph, command: str, stdout: str, source: str,
           base_url: str | None = None) -> list[Observation]:
    """Parse output and fold every observation into the graph. Returns what was added."""
    observations = parse_by_command(command, stdout, base_url=base_url)
    for o in observations:
        graph.observe(o.kind, o.key, attrs=o.attrs, source=source,
                      relate_to=o.relate_to, relation=o.relation)
    return observations

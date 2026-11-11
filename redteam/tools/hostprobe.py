"""hostprobe — W1b: the agent-directed deep probes (httpx, nmap) as LEAD GENERATORS.

Phase W1b of docs/tool-integration-plan.md — completes the W1 exit criteria.
Same discipline as webdiscover.py: these binaries produce *to-do lists*, not
reports. Everything returns leads, folds structured facts into the knowledge
graph (which is what the planner, the bandit buckets, and the attack-tree
seeding actually read), and never records a finding.

Why BOTH a port knocker (surface_scan) and these exist, and where each is smart:

  - surface_scan (first-party)  = the RoE grid itself: knock every allowed
    host:port once. Inventory, not reasoning.
  - port_scan (nmap)            = the agent picks ONE allowed host that deserves
    depth (a weird open port, a perimeter host) and asks WHAT the services are
    (-sV --version-light). Service/product/version facts fold in as SERVICE
    nodes — prior/exposure reasoning (priors.py, knowledge.py) reads them.
  - host_probe (httpx)          = content-level probe of ONE in-scope URL: title,
    status, TECHNOLOGY fingerprints. Technology nodes feed bucket_for_endpoint's
    shape reasoning and the playbooks' technique selection.

  port_scan -> SERVICE nodes -> host_probe on the web-ish ones -> ENDPOINT +
  TECHNOLOGY nodes -> content_discovery/crawl -> xss_reflect_probe/graphql_inspect
  -> check_spec -> verify_vulnerability. Every arrow feeds the graph, never the
  finding pipeline.

Execution surface: Kali sandbox when running (egress firewall-enforced), else
the local binary. Command lines are fixed allowlists; numeric args are clamped;
the port list for nmap is validated against the RoE's allowed_ports (an empty
RoE port list means nothing is allowed — fail closed, like scope.check does).
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import shutil
import xml.etree.ElementTree as ET

from ..knowledge import ENDPOINT, HOST, SERVICE, TECHNOLOGY
from ..scope import ScopeViolation
from . import ToolContext

_MAX_RUNTIME_S = 900       # hard wall for the whole run of one tool
_MAX_LEADS = 100
_MAX_TECHNOLOGIES = 20
_MAX_TOP_PORTS = 1000
_MAX_PORTSPECS = 40        # individual ports after expanding an explicit list

_NMAP_PORTS_RE = re.compile(r"^\d{1,5}([\-,\d]{0,64})\d{0,5}$")


def _clamp(value, default, low, high):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(v, high))


def _exec(command: str, ctx: ToolContext) -> tuple[int, str, str, str]:
    """Run through the sandbox, else the local binary. Returns (exit, out, err, surface)."""
    if ctx.sandbox is not None:
        result = ctx.sandbox.exec(f"{command} ; true", timeout=_MAX_RUNTIME_S)
        return result.exit_code, result.stdout, result.stderr, "sandbox"
    binary = command.split()[0]
    if shutil.which(binary) is None:
        raise FileNotFoundError(
            f"no sandbox running and no local {binary} binary found. Start the "
            f"sandbox (ships in the Kali image) or install {binary} locally.")
    import subprocess
    proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                          timeout=_MAX_RUNTIME_S)
    return proc.returncode, proc.stdout, proc.stderr, "local"


def _fold(ctx: ToolContext, observations: list[tuple[str, str, dict]],
          source: str) -> int:
    """Fold (kind, key, attrs) triples into the graph; best-effort, never fatal."""
    if ctx.graph is None:
        return 0
    updates = 0
    for kind, key, attrs in observations[:_MAX_LEADS]:
        try:
            ctx.graph.observe(kind, key, attrs, source=source)
            updates += 1
        except Exception:
            break
    return updates


def _blocked(ctx: ToolContext, tool: str, target: str, exc: Exception) -> str:
    ctx.audit.record(f"{tool}.blocked", target=target, cause="out_of_scope",
                     detail=str(exc)[:160])
    return f"BLOCKED (out of scope): {exc}"


# -- host_probe (httpx, projectdiscovery) ---------------------------------------------

def _build_httpx_command(target: str, timeout: int) -> str:
    timeout = _clamp(timeout, 8, 1, 30)
    parts = ["httpx", "-u", target, "-json", "-silent", "-no-color",
             "-status-code", "-content-length", "-title", "-tech-detect",
             "-location", "-ip", "-timeout", str(timeout)]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_httpx(stdout: str) -> list[dict]:
    """httpx emits NDJSON; junk-tolerant, capped."""
    leads = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not row.get("url"):
            continue
        tech = row.get("technologies")
        if isinstance(tech, list):
            tech = [str(t) for t in tech if t][:5]
        else:
            tech = []
        leads.append({
            "url": row.get("url", ""),
            "status": row.get("status_code"),
            "title": (row.get("title") or "")[:200],
            "tech": tech,
            "host": row.get("host", ""),
            "ip": row.get("ip", ""),
            "location": (row.get("location") or "")[:300],
        })
    return leads[:_MAX_LEADS]


def _httpx_observations(leads: list[dict]) -> list[tuple[str, str, dict]]:
    """ENDPOINT nodes with status/title; TECHNOLOGY nodes from fingerprints."""
    out = []
    for lead in leads:
        url = lead.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        attrs = {}
        if lead.get("status"):
            attrs["status"] = lead["status"]
        if lead.get("title"):
            attrs["title"] = lead["title"]
        if lead.get("ip"):
            attrs["ip"] = lead["ip"]
        out.append((ENDPOINT, url, attrs))
        for tech in lead.get("tech") or [][:5]:
            out.append((TECHNOLOGY, str(tech), {}))
    return out


class HostProbeTool:
    name = "host_probe"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Content-level probe of ONE in-scope HTTP(S) URL with httpx "
                "(projectdiscovery): status code, title, technology fingerprints, "
                "IP, redirect location. Complements surface_scan (which only knocks "
                "on allowed ports) with what the service actually SERVES. Output is "
                "a LEAD — a live URL with metadata is a to-do, not a finding; fold "
                "it into your next move (content_discovery on the URL, "
                "xss_reflect_probe on its params, verify before anything else). "
                "Runs inside the Kali sandbox when available, else the local httpx "
                "binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string",
                               "description": "One in-scope URL (scheme://host[:port]/path)."},
                    "reason": {"type": "string",
                               "description": "Why this probe advances the test (audited)."},
                },
                "required": ["target", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, target: str, reason: str) -> str:
        try:
            ctx.scope.check(target)
        except ScopeViolation as exc:
            return _blocked(ctx, self.name, target, exc)

        command = _build_httpx_command(target, 8)
        try:
            exit_code, stdout, stderr, surface = _exec(command, ctx)
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:  # degraded, never fatal
            ctx.audit.record(f"{self.name}.error", target=target, error=str(exc)[:200])
            return json.dumps({"ok": False, "error": f"host probe failed: {exc}"})

        leads = _parse_httpx(stdout)
        graph_updates = _fold(ctx, _httpx_observations(leads), self.name)
        ctx.audit.record(self.name, target=target, surface=surface, leads=len(leads),
                         exit_code=exit_code, reason=reason)
        return json.dumps({
            "ok": True, "target": target, "surface": surface, "exit_code": exit_code,
            "leads": leads, "lead_count": len(leads), "graph_updates": graph_updates,
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. A live URL with a title/tech stack tells you WHAT "
                     "to try next (use find_techniques with the tech name); it "
                     "proves nothing by itself."),
        }, ensure_ascii=False)


# -- port_scan (nmap) -----------------------------------------------------------------

def _validate_portspec(portspec: str, allowed: tuple[int, ...]) -> str | None:
    """Explicit port list -> validated spec string, or None if invalid/out of scope."""
    spec = (portspec or "").strip()
    if not spec or len(spec) > 100 or not _NMAP_PORTS_RE.match(spec):
        return None
    ports: list[int] = []
    try:
        for chunk in spec.split(","):
            if "-" in chunk:
                lo, hi = chunk.split("-")
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(chunk))
    except ValueError:
        return None
    if not ports or len(ports) > _MAX_PORTSPECS:
        return None
    if any(p < 1 or p > 65535 for p in ports):
        return None
    # Fail closed exactly like scope.check does: an empty RoE port list means
    # nothing is allowed, so every port fails the membership test.
    if any(p not in allowed for p in ports):
        return None
    return ",".join(str(p) for p in ports[:_MAX_PORTSPECS])


def _build_nmap_command(host: str, top_ports: int, portspec: str) -> str:
    top_ports = _clamp(top_ports, 100, 1, _MAX_TOP_PORTS)
    # -Pn: we probe hosts the RoE already allows; -sV --version-light: service
    # fingerprints, not script sweeping; -T3: no timing aggression; --open:
    # only report what is actually reachable. -oX - : XML to stdout (no temp file).
    parts = ["nmap", "-Pn", "-sV", "--version-light", "-T3", "--open", "-oX", "-"]
    if portspec:
        parts += ["-p", portspec]
    else:
        parts += ["--top-ports", str(top_ports)]
    parts += [host]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_nmap(stdout: str) -> list[dict]:
    try:
        root = ET.fromstring((stdout or "").strip())
    except (ET.ParseError, ValueError):
        return []
    leads: list[dict] = []
    for host_el in root.iter("host"):
        addr = ""
        hostname = ""
        for a in host_el.iter("address"):
            if a.get("addrtype") == "ipv4" and not addr:
                addr = a.get("addr", "")
            if a.get("addrtype") == "ipv6" and not addr:
                addr = a.get("addr", "")
        for hn in host_el.iter("hostname"):
            if hn.get("name"):
                hostname = hn.get("name")
                break
        for port_el in host_el.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port_el.find("service")
            lead = {
                "host": hostname or addr,
                "ip": addr,
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol") or "tcp",
                "state": "open",
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            }
            leads.append(lead)
            if len(leads) >= _MAX_LEADS:
                return leads
    return leads


def _nmap_observations(leads: list[dict]) -> list[tuple[str, str, dict]]:
    """HOST + SERVICE nodes; the web-ish services get an ENDPOINT stub so the
    normal endpoint pipeline (buckets, seeding, coverage) can pick them up."""
    out = []
    for lead in leads:
        ip = lead.get("ip") or lead.get("host") or ""
        if not ip or not lead.get("port"):
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = ""
        if ip:
            out.append((HOST, ip, {"hostname": lead.get("host")} if lead.get("host") else {}))
        port = str(lead["port"])
        key = f"{ip or lead.get('host')}:{port}"
        attrs = {"protocol": lead.get("protocol") or "tcp"}
        for k in ("service", "product", "version"):
            if lead.get(k):
                attrs[k] = lead[k][:120]
        out.append((SERVICE, key, attrs))
        if lead.get("service") in ("http", "http-alt", "https", "https-alt"):
            scheme = "https" if "https" in (lead.get("service") or "") else "http"
            out.append((ENDPOINT, f"{scheme}://{key}/", {"status": None}))
    return out


class PortScanTool:
    name = "port_scan"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Deep service probe of ONE in-scope host with nmap (-sV "
                "--version-light, top-ports or an explicit RoE-validated list). "
                "surface_scan decides WHAT is reachable from the RoE grid; use THIS "
                "when one host deserves depth (identify the product/version behind "
                "an open port). Output is a list of LEADS (open services with "
                "fingerprints) folded into the graph as HOST/SERVICE nodes — a "
                "service banner is a lead, not a finding. Ports outside the RoE's "
                "allowed_ports are refused (fail closed). Runs in the Kali sandbox "
                "when available, else the local nmap binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "host": {"type": "string",
                             "description": "One in-scope hostname or IP (no scheme)."},
                    "ports": {"type": "string",
                              "description": "Optional explicit list like '80,443,8000-8100' "
                                             "(validated against the RoE; max 40 ports). "
                                             "Omit to use top-ports."},
                    "top_ports": {"type": "integer",
                                  "description": "When `ports` omitted: N most common ports "
                                                 "(default 100, max 1000)."},
                    "reason": {"type": "string",
                               "description": "Why this scan advances the test (audited)."},
                },
                "required": ["host", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, host: str, reason: str, ports: str = "",
            top_ports: int = 100) -> str:
        probe_url = f"https://{host}/" if not host.startswith(("http://", "https://")) else host
        try:
            ctx.scope.check(probe_url)
        except ScopeViolation as exc:
            return _blocked(ctx, self.name, host, exc)

        portspec = ""
        if (ports or "").strip():
            portspec = _validate_portspec(ports, ctx.scope.allowed_ports)
            if portspec is None:
                ctx.audit.record(f"{self.name}.blocked", target=host,
                                 cause="invalid_or_out_of_scope_ports", ports=str(ports)[:100])
                return ("BLOCKED: `ports` must be a valid list (e.g. '80,443,8000-8100', "
                        "max 40 ports) and every port must be in the RoE's allowed_ports.")
        command = _build_nmap_command(host, top_ports, portspec)

        try:
            exit_code, stdout, stderr, surface = _exec(command, ctx)
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:
            ctx.audit.record(f"{self.name}.error", target=host, error=str(exc)[:200])
            return json.dumps({"ok": False, "error": f"port scan failed: {exc}"})

        leads = _parse_nmap(stdout)
        graph_updates = _fold(ctx, _nmap_observations(leads), self.name)
        ctx.audit.record(self.name, target=host, surface=surface, leads=len(leads),
                         ports=portspec or f"top:{_clamp(top_ports, 100, 1, _MAX_TOP_PORTS)}",
                         exit_code=exit_code, reason=reason)
        return json.dumps({
            "ok": True, "host": host, "surface": surface, "exit_code": exit_code,
            "leads": leads, "lead_count": len(leads), "graph_updates": graph_updates,
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. Product/version banners feed find_techniques and "
                     "priors; probe web-ish services with host_probe, then verify "
                     "anything you suspect. Banners can lie — verification is the "
                     "arbiter."),
        }, ensure_ascii=False)

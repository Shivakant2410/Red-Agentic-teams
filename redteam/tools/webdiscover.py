"""webdiscover — structured discovery tools: ffuf, katana, arjun as LEAD GENERATORS.

Phase W1 of docs/tool-integration-plan.md. Same discipline as nuclei_scan: these
binaries are to-do lists, not reports. Everything here returns *leads* (candidate
endpoints, candidate parameters), folds them into the knowledge graph so the
planner can reason over them, and never records a finding or touches the
verification pipeline's write side.

  discovery lead -> verify hint -> verify_vulnerability (k-of-n + negative control)
                 -> verify_finding_independently -> record_finding

Execution surface: through the Kali sandbox when one is running (egress is then
firewall-enforced — exactly what we want for active discovery); otherwise the local
binary if installed. No sandbox + no binary -> a clear error, never a silent no-op.
Command lines are built from fixed allowlists (no free-form agent-supplied args);
numeric arguments are clamped; every tool declares its risk class per
docs/tool-integration-plan.md §2 (all three here are class 1: active, conventional,
rate-capped enumeration).
"""

from __future__ import annotations

import json
import shlex
import shutil

from ..knowledge import ENDPOINT
from ..scope import ScopeViolation
from . import ToolContext

_MAX_RUNTIME_S = 900       # hard wall for the whole run of one tool
_MAX_LEADS = 200

# Fixed in-image wordlist allowlist (no agent-supplied paths). These live in the
# Kali image via the seclists package; a missing list surfaces as a visible
# ffuf error in stderr_tail, never a silent empty result.
_WORDLISTS = {
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "raft-small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "api-endpoints": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
}

_MAX_RATE = 200
_MAX_CONCURRENCY = 30
_MAX_DEPTH = 5
_MAX_TIMEOUT = 10


def _clamp(value, default, low, high):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(v, high))


def _exec(command: str, ctx: ToolContext) -> tuple[int, str, str, str]:
    """Run through the sandbox, else the local/provisioned binary.
    Returns (exit, out, err, surface)."""
    if ctx.sandbox is not None:
        result = ctx.sandbox.exec(f"{command} ; true", timeout=_MAX_RUNTIME_S)
        return result.exit_code, result.stdout, result.stderr, "sandbox"
    binary = command.split()[0]
    from ..sandbox.provision import resolve_binary
    where = resolve_binary(binary)
    if not where:
        raise FileNotFoundError(
            f"no sandbox running and {binary} not provisioned. Run the "
            f"tool_provision tool (downloads on requirement into .tools/venv), "
            f"add it to the engagement sandbox.extra_tools (Kali image layer), "
            f"or start the Kali sandbox (ships kali-linux-headless).")
    import subprocess
    proc = subprocess.run(where + command[len(binary):], shell=True,
                          capture_output=True, text=True, timeout=_MAX_RUNTIME_S)
    return proc.returncode, proc.stdout, proc.stderr, "local"


def _fold_endpoints(ctx: ToolContext, leads: list[dict], url_key: str, source: str) -> int:
    """Fold discovered URLs into the graph (reasoning state, independent of proof)."""
    updates = 0
    if ctx.graph is None:
        return 0
    for lead in leads:
        url = lead.get(url_key) or ""
        if url.startswith(("http://", "https://")):
            try:
                attrs = {k: lead[k] for k in ("method", "status") if lead.get(k)}
                ctx.graph.observe(ENDPOINT, url, attrs, source=source)
                updates += 1
            except Exception:
                break
    return updates


# -- content_discovery (ffuf) -----------------------------------------------------

def _build_ffuf_command(target: str, wordlist: str, rate: int, concurrency: int,
                        timeout: int) -> str:
    path = _WORDLISTS[wordlist]
    rate = _clamp(rate, 50, 1, _MAX_RATE)
    concurrency = _clamp(concurrency, 10, 1, _MAX_CONCURRENCY)
    timeout = _clamp(timeout, 5, 1, _MAX_TIMEOUT)
    parts = ["ffuf", "-u", f"{target}FUZZ", "-w", path, "-json", "-s",
             "-ac", "-rate", str(rate), "-t", str(concurrency),
             "-timeout", str(timeout), "-of", "json"]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_ffuf(stdout: str) -> list[dict]:
    leads = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        for hit in row.get("results") or []:
            if not isinstance(hit, dict) or not hit.get("url"):
                continue
            fuzz = ""
            inputs = hit.get("input")
            if isinstance(inputs, dict):
                fuzz = str(inputs.get("FUZZ", ""))
            leads.append({
                "url": hit.get("url", ""),
                "word": fuzz,
                "status": hit.get("status"),
                "length": hit.get("length"),
                "words": hit.get("words"),
                "lines": hit.get("lines"),
                "content_type": hit.get("content-type", ""),
            })
    return leads[:_MAX_LEADS]


class ContentDiscoveryTool:
    name = "content_discovery"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Content discovery on ONE in-scope base URL with ffuf (wordlist "
                "fuzzing of path positions). Output is a list of LEADS (candidate "
                "endpoints, may include false positives from auto-calibration) — "
                "interesting ones must be probed with http_probe and proven through "
                "the verification pipeline before any finding. Runs inside the Kali "
                "sandbox when available (egress firewall-enforced), else the local "
                "ffuf binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string",
                               "description": "In-scope base URL; FUZZ is appended to it."},
                    "wordlist": {"type": "string",
                                 "enum": sorted(_WORDLISTS),
                                 "description": "Wordlist preset: common (default), "
                                                "raft-small, api-endpoints."},
                    "rate_limit": {"type": "integer",
                                   "description": "Requests per second (default 50, max 200)."},
                    "concurrency": {"type": "integer",
                                    "description": "Parallel threads (default 10, max 30)."},
                    "reason": {"type": "string",
                               "description": "Why this discovery step advances the test (audited)."},
                },
                "required": ["target", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, target: str, reason: str, wordlist: str = "common",
            rate_limit: int = 50, concurrency: int = 10) -> str:
        try:
            ctx.scope.check(target)
        except ScopeViolation as exc:
            ctx.audit.record("content_discovery.blocked", target=target,
                             cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        wordlist = wordlist if wordlist in _WORDLISTS else "common"
        command = _build_ffuf_command(target, wordlist, rate_limit, concurrency, 5)

        try:
            exit_code, stdout, stderr, surface = _exec(command, ctx)
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:  # degraded, never fatal
            ctx.audit.record("content_discovery.error", target=target, error=str(exc)[:200])
            return json.dumps({"ok": False, "error": f"discovery failed: {exc}"})

        leads = _parse_ffuf(stdout)
        graph_updates = _fold_endpoints(ctx, leads, "url", self.name)
        ctx.audit.record(self.name, target=target, wordlist=wordlist, surface=surface,
                         leads=len(leads), exit_code=exit_code, reason=reason)

        return json.dumps({
            "ok": True, "target": target, "surface": surface, "exit_code": exit_code,
            "leads": leads, "lead_count": len(leads), "graph_updates": graph_updates,
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. Probe interesting endpoints with http_probe; a "
                     "discovered URL alone is not a finding."),
        }, ensure_ascii=False)


# -- crawl (katana) ---------------------------------------------------------------

def _build_katana_command(target: str, depth: int, concurrency: int, rate: int,
                          timeout: int) -> str:
    depth = _clamp(depth, 3, 1, _MAX_DEPTH)
    concurrency = _clamp(concurrency, 10, 1, _MAX_CONCURRENCY)
    rate = _clamp(rate, 50, 1, _MAX_RATE)
    timeout = _clamp(timeout, 5, 1, _MAX_TIMEOUT)
    parts = ["katana", "-u", target, "-jsonl", "-silent", "-fs", "rdn",
             "-d", str(depth), "-c", str(concurrency), "-rl", str(rate),
             "-timeout", str(timeout)]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_katana(stdout: str) -> list[dict]:
    leads = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        req = row.get("request") or {}
        resp = row.get("response") or {}
        endpoint = (req.get("endpoint") if isinstance(req, dict) else "") or row.get("endpoint", "")
        if not endpoint:
            continue
        leads.append({
            "url": endpoint,
            "method": (req.get("method") if isinstance(req, dict) else "") or "GET",
            "status": resp.get("status_code") if isinstance(resp, dict) else None,
        })
    return leads[:_MAX_LEADS]


class CrawlTool:
    name = "crawl"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "JS-aware web crawl of ONE in-scope URL with katana (follows links "
                "found in JavaScript, domain-field-scoped so it cannot wander off "
                "target). Output is a list of LEADS (endpoints + methods + status) "
                "folded into the surface graph — a crawled URL still needs probing "
                "and verification. Runs inside the Kali sandbox when available, else "
                "the local katana binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string", "description": "In-scope URL to crawl from."},
                    "depth": {"type": "integer",
                              "description": "Max crawl depth (default 3, max 5)."},
                    "rate_limit": {"type": "integer",
                                   "description": "Requests per second (default 50, max 200)."},
                    "concurrency": {"type": "integer",
                                    "description": "Parallel requests (default 10, max 30)."},
                    "reason": {"type": "string",
                               "description": "Why this crawl advances the test (audited)."},
                },
                "required": ["target", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, target: str, reason: str, depth: int = 3,
            rate_limit: int = 50, concurrency: int = 10) -> str:
        try:
            ctx.scope.check(target)
        except ScopeViolation as exc:
            ctx.audit.record("crawl.blocked", target=target, cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        command = _build_katana_command(target, depth, concurrency, rate_limit, 5)

        try:
            exit_code, stdout, stderr, surface = _exec(command, ctx)
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:
            ctx.audit.record("crawl.error", target=target, error=str(exc)[:200])
            return json.dumps({"ok": False, "error": f"crawl failed: {exc}"})

        leads = _parse_katana(stdout)
        graph_updates = _fold_endpoints(ctx, leads, "url", self.name)
        ctx.audit.record(self.name, target=target, surface=surface, leads=len(leads),
                         exit_code=exit_code, reason=reason)

        return json.dumps({
            "ok": True, "target": target, "surface": surface, "exit_code": exit_code,
            "leads": leads, "lead_count": len(leads), "graph_updates": graph_updates,
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. A crawled endpoint is a to-do, not a finding — "
                     "probe with http_probe and verify before recording anything."),
        }, ensure_ascii=False)


# -- param_discovery (arjun) ------------------------------------------------------

_ARJUN_STYLE: dict = {}   # one CLI probe per process, cached


def _arjun_style(ctx: ToolContext) -> str:
    """Detect the arjun CLI generation once: Kali's 1.x (--stable, -T, -rate)
    vs the pip distribution's 2.x (-d, -t, -o). The provisioned toolbox may
    deliver either, and the flag sets are incompatible."""
    if "style" in _ARJUN_STYLE:
        return _ARJUN_STYLE["style"]
    style = "pip"
    try:
        if ctx.sandbox is not None:
            out = ctx.sandbox.exec("arjun -h 2>&1", timeout=15).stdout
        else:
            from ..sandbox.provision import resolve_binary
            where = resolve_binary("arjun")
            if where:
                import subprocess as _sp
                proc = _sp.run(f"{where} -h 2>&1", shell=True, capture_output=True,
                               text=True, timeout=15)
                out = (proc.stdout or "") + (proc.stderr or "")
        if "--rate-limit" in (out or ""):
            style = "pip"   # pip 2.x long flag; kali 1.x uses single-dash -rate
        else:
            style = "kali"
    except Exception:
        style = "pip"   # default to the pip CLI; a Kali arjun without -h is rare
    _ARJUN_STYLE["style"] = style
    return style


def _build_arjun_command(target: str, rate: int, timeout: int,
                         ctx: ToolContext | None = None) -> str:
    if ctx is not None and _arjun_style(ctx) == "pip":
        # pip arjun 2.x: -t threads, -d delay; the JSON file appears only on
        # hits. Shell operators are real here (engine-authored template; only
        # the target is agent-influenced, so only it gets quoted).
        return (f"arjun -u {shlex.quote(target)} -o /tmp/arjun_out.json "
                f"-t 5 -d 0.25 >/dev/null 2>&1 ; "
                f"cat /tmp/arjun_out.json 2>/dev/null ; true")
    rate = _clamp(rate, 20, 1, _MAX_RATE)
    timeout = _clamp(timeout, 5, 1, _MAX_TIMEOUT)
    parts = ["arjun", "-u", target, "-oJ", "/tmp/arjun_out.json", "-rate", str(rate),
             "-t", "5", "--stable", "-T", str(timeout), ">/dev/null", "2>&1", ";",
             "cat", "/tmp/arjun_out.json"]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_arjun(stdout: str) -> list[dict]:
    try:
        row = json.loads((stdout or "").strip())
    except json.JSONDecodeError:
        return []
    if not isinstance(row, dict):
        return []
    leads = []
    if isinstance(row.get("params"), list):
        params = row["params"]
    else:
        # arjun batch mode: {url: {"params": [...]}}
        params = []
        for value in row.values():
            if isinstance(value, dict) and isinstance(value.get("params"), list):
                params.extend(value["params"])
    for name in params[:_MAX_LEADS]:
        if isinstance(name, str) and name.strip():
            leads.append({"param": name.strip()})
    return leads


class ParamDiscoveryTool:
    name = "param_discovery"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Hidden-parameter discovery on ONE in-scope URL with arjun. Output "
                "is a list of LEADS (candidate parameter names the app accepts but "
                "does not surface) — feed them into verify hints (authorization "
                "matrix, reflection, mass-assignment checks); a parameter name alone "
                "proves nothing. Runs inside the Kali sandbox when available, else "
                "the local arjun binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string", "description": "In-scope URL to probe."},
                    "rate_limit": {"type": "integer",
                                   "description": "Requests per second (default 20, max 200)."},
                    "reason": {"type": "string",
                               "description": "Why this probe advances the test (audited)."},
                },
                "required": ["target", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, target: str, reason: str, rate_limit: int = 20) -> str:
        try:
            ctx.scope.check(target)
        except ScopeViolation as exc:
            ctx.audit.record("param_discovery.blocked", target=target,
                             cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        command = _build_arjun_command(target, rate_limit, 5, ctx=ctx)
        try:
            exit_code, stdout, stderr, surface = _exec(command, ctx)
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:
            ctx.audit.record("param_discovery.error", target=target, error=str(exc)[:200])
            return json.dumps({"ok": False, "error": f"param discovery failed: {exc}"})

        leads = _parse_arjun(stdout)
        # Parameters are not endpoints: no graph fold — they ride the lead payload
        # into the briefing/verify hints instead.
        ctx.audit.record(self.name, target=target, surface=surface, leads=len(leads),
                         exit_code=exit_code, reason=reason)

        return json.dumps({
            "ok": True, "target": target, "surface": surface, "exit_code": exit_code,
            "leads": leads, "lead_count": len(leads),
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. Candidate parameters feed verification hints "
                     "(authorization matrix, reflection, mass-assignment); none of "
                     "this is a finding until proven."),
        }, ensure_ascii=False)

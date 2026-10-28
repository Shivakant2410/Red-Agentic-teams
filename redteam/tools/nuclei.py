"""nuclei_scan — run ProjectDiscovery nuclei templates as a LEAD GENERATOR.

A scanner is a to-do list, not a report. Nuclei matches are heuristics with real
false-positive rates; this project's core discipline is that nothing counts until it
is independently proven. So this tool deliberately returns *leads*:

  nuclei match -> lead (this output)
               -> verify_vulnerability (k-of-n + negative control)
               -> verify_finding_independently (fresh context)
               -> record_finding / objective credit

It also folds matched endpoints into the knowledge graph so the planner can reason
over them even if no lead survives verification.

Execution surface: through the Kali sandbox when one is running (egress is then
firewall-enforced — exactly what we want for a signature scanner); otherwise the
local `nuclei` binary if installed. No sandbox + no binary -> a clear error, never a
silent no-op. The command line is built from a fixed allowlist (no free-form args).
"""

from __future__ import annotations

import json
import shlex
import shutil

from ..knowledge import ENDPOINT
from ..scope import ScopeViolation
from . import ToolContext

_DEFAULT_RATE = 50
_DEFAULT_TIMEOUT = 5       # nuclei per-request timeout, seconds
_DEFAULT_CONCURRENCY = 10
_MAX_RUNTIME_S = 600       # hard wall for the whole scan
_MAX_LEADS = 100


def _build_command(target: str, templates: str, severity: str,
                   rate_limit: int, timeout: int, concurrency: int) -> str:
    parts = ["nuclei", "-u", target, "-silent", "-json",
             "-rl", str(rate_limit), "-c", str(concurrency),
             "-timeout", str(timeout)]
    if severity:
        parts += ["-severity", severity]
    for tpl in [t.strip() for t in (templates or "").split(",") if t.strip()]:
        # A template arg is either a path (exists on disk -> -t) or a tag word (-tags).
        if "/" in tpl or tpl.endswith(".yaml"):
            parts += ["-t", tpl]
        else:
            parts += ["-tags", tpl]
    return " ".join(shlex.quote(p) for p in parts)


def _parse_results(stdout: str) -> list[dict]:
    leads = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        leads.append({
            "template_id": row.get("template-id") or row.get("templateID", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "matched_at": row.get("matched-at") or row.get("matched", ""),
            "host": row.get("host", ""),
            "type": row.get("type", ""),
            "extracted": row.get("extracted", []),
        })
    return leads[:_MAX_LEADS]


class NucleiScanTool:
    name = "nuclei_scan"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Scan ONE in-scope URL with nuclei templates. Output is a list of LEADS "
                "(heuristic matches, may be wrong) — each must be proven with "
                "verify_vulnerability and independently verified before recording a "
                "finding. Runs inside the Kali sandbox when available (egress "
                "firewall-enforced), else the local nuclei binary."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target": {"type": "string", "description": "In-scope base URL to scan."},
                    "templates": {"type": "string", "description":
                                  "Optional comma-separated template paths and/or tag words "
                                  "(e.g. 'cves', 'http/cves/2023', ' exposures'). Empty = all."},
                    "severity": {"type": "string", "description":
                                 "Optional severity filter, e.g. 'critical,high'."},
                    "rate_limit": {"type": "integer", "description": "Requests per second (default 50)."},
                    "concurrency": {"type": "integer", "description": "Parallel templates (default 10)."},
                    "reason": {"type": "string", "description": "Why this scan advances the test (audited)."},
                },
                "required": ["target", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, target: str, reason: str, templates: str = "",
            severity: str = "", rate_limit: int = _DEFAULT_RATE,
            concurrency: int = _DEFAULT_CONCURRENCY) -> str:
        try:
            ctx.scope.check(target)
        except ScopeViolation as exc:
            ctx.audit.record("nuclei_scan.blocked", target=target, cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        command = _build_command(target, templates, severity,
                                 max(1, min(int(rate_limit or _DEFAULT_RATE), 500)),
                                 _DEFAULT_TIMEOUT,
                                 max(1, min(int(concurrency or _DEFAULT_CONCURRENCY), 50)))

        if ctx.sandbox is not None:
            result = ctx.sandbox.exec(f"{command} ; true", timeout=_MAX_RUNTIME_S)
            exit_code, stdout, stderr = result.exit_code, result.stdout, result.stderr
            surface = "sandbox"
        else:
            binary = shutil.which("nuclei")
            if binary is None:
                return ("ERROR: no sandbox running and no local nuclei binary found. "
                        "Start the sandbox (nuclei ships in the Kali image) or install "
                        "nuclei locally.")
            import subprocess
            proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                                  timeout=_MAX_RUNTIME_S)
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
            surface = "local"

        leads = _parse_results(stdout)
        ctx.audit.record("nuclei_scan", target=target, surface=surface,
                         leads=len(leads), exit_code=exit_code, reason=reason)

        # Fold matched endpoints into the graph (reasoning state, independent of proof).
        graph_updates = 0
        if ctx.graph is not None:
            for lead in leads:
                url = lead.get("matched_at") or lead.get("host")
                if url and url.startswith(("http://", "https://")):
                    try:
                        ctx.graph.observe(ENDPOINT, url, {"nuclei_lead": lead["template_id"]},
                                          source="nuclei_scan")
                        graph_updates += 1
                    except Exception:
                        break

        return json.dumps({
            "ok": True, "target": target, "surface": surface, "exit_code": exit_code,
            "leads": leads,
            "lead_count": len(leads),
            "graph_updates": graph_updates,
            "stderr_tail": (stderr or "")[-500:],
            "note": ("Leads only. For each: verify with verify_vulnerability (k-of-n + "
                     "negative control), then verify_finding_independently, THEN "
                     "record_finding. A nuclei match alone is not a finding."),
        }, ensure_ascii=False)

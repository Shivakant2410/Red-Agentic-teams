"""kali_exec — run a command inside the Kali sandbox.

Scope is enforced at the network layer (the container's egress firewall), so this tool
does not try to parse every command for targets. It does two things on top of the
sandbox:
  1. Blocks commands that would tamper with the egress firewall, the network namespace,
     or try to gain privileges — the agent must not be able to widen its own scope.
  2. Requires human approval for commands that match destructive/DoS patterns.
Every command is audited regardless.
"""

from __future__ import annotations

import json
import re

from . import ToolContext

# Attempts to alter the sandbox's own confinement. These are refused outright.
_TAMPER_PATTERNS = [
    r"\biptables\b", r"\bip6tables\b", r"\bnft\b", r"\bipset\b",
    r"\bip\s+(route|addr|link|netns)\b", r"\broute\b\s+add",
    r"\bsudo\b", r"\bsu\b\s", r"\bsetcap\b", r"\bunshare\b", r"\bnsenter\b",
    r"/etc/resolv\.conf", r"\bmount\b",
]

# Destructive / DoS-shaped commands. Allowed only after explicit human approval.
_DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\s+/", r"\bmkfs\b", r"\bdd\s+if=",
    r"\bhping3\b.*(--flood|--faster)", r"\bslowloris\b", r"\bt50\b",
    r"--flood\b", r"\bstress\b", r":\(\)\s*\{",  # fork bomb
]


def _matches(command: str, patterns: list[str]) -> str | None:
    for p in patterns:
        if re.search(p, command, flags=re.IGNORECASE):
            return p
    return None


class KaliExecTool:
    name = "kali_exec"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Run a shell command inside the Kali Linux sandbox (nmap, ffuf, sqlmap, "
                "nikto, curl, gobuster, etc.). Network egress is restricted to in-scope "
                "targets by the sandbox firewall — off-scope hosts are simply unreachable. "
                "Commands that alter the sandbox firewall/network or escalate privileges "
                "are refused. Destructive or denial-of-service commands require approval."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "command": {"type": "string", "description": "The shell command to run."},
                    "reason": {"type": "string", "description": "Why this advances the test (audited)."},
                    "timeout": {"type": "integer", "description": "Optional per-command timeout (seconds)."},
                },
                "required": ["command", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, command: str, reason: str, timeout: int | None = None) -> str:
        if ctx.sandbox is None:
            return "ERROR: sandbox is not running; kali_exec is unavailable."

        tamper = _matches(command, _TAMPER_PATTERNS)
        if tamper:
            ctx.audit.record("kali_exec.refused", command=command, reason=reason,
                             cause=f"tamper_pattern:{tamper}")
            return ("REFUSED: this command would alter the sandbox's confinement "
                    "(firewall/network/privileges) and is not permitted.")

        destructive = _matches(command, _DESTRUCTIVE_PATTERNS)
        if destructive:
            if not ctx.approve("destructive_command",
                               {"command": command, "reason": reason, "pattern": destructive}):
                ctx.audit.record("kali_exec.denied", command=command, cause="approval_denied")
                return "DENIED: a human declined this destructive/DoS command."

        result = ctx.sandbox.exec(command, timeout=timeout)
        out = {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "stdout": result.stdout[-8000:],
            "stderr": result.stderr[-2000:],
            "stdout_truncated": len(result.stdout) > 8000,
        }

        # Fold structured observations into the knowledge graph so the model reasons over
        # state, not raw text. The delta is surfaced back so the model sees what was learned.
        if ctx.graph is not None and result.stdout:
            try:
                from ..parsers import ingest
                added = ingest(ctx.graph, command, result.stdout, source="kali_exec")
                if added:
                    out["graph_updates"] = [f"{o.kind}:{o.key}" for o in added][:40]
                    ctx.audit.record("graph.ingest", command=command, added=len(added))
            except Exception as exc:  # parsing must never break the tool
                ctx.audit.record("graph.ingest_error", error=str(exc))

        return json.dumps(out, ensure_ascii=False)

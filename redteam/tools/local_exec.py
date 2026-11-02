"""local_exec — run a shell command on the operator host (opt-in terminal plane).

Docker is the intended terminal plane: kali_exec runs inside the Kali sandbox with
its egress firewall enforcing scope at the network layer. On hosts without Docker
(CI containers, dev sandboxes) there is NO confinement layer — so this tool is
registered ONLY when the operator explicitly opts in with RED_LOCAL_EXEC=1, pins
its working directory to RED_LOCAL_EXEC_ROOT (default /tmp/rtbench), copies
KaliExecTool's destructive-command approval gate, and audits every invocation.
Terminal-benchmark runs (credential hunts, local recon chains) need a shell; an
operator who sets the env var accepts the blast radius. It is NEVER registered by
default. Scope note: with the tool enabled, web-bench agents get DISTRACTED by it
(observed: hand-rolled raw-socket HTTP instead of http_probe) — enable per run,
not globally.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from . import ToolContext
from .kali import _DESTRUCTIVE_PATTERNS, _matches

_MAX_TIMEOUT_S = 120
_STDOUT_CAP = 65536
_STDERR_CAP = 16384


class LocalExecTool:
    name = "local_exec"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Run one bash command on the operator host, cwd pinned to the "
                "engagement root (RED_LOCAL_EXEC_ROOT). For local/terminal work: "
                "enumerate files, read configs, decode secrets. Destructive commands "
                "require explicit approval. Audited. Opt-in (RED_LOCAL_EXEC=1)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string",
                                "description": "The bash command to run."},
                    "timeout_s": {"type": "integer",
                                  "description": "Kill the command after this many "
                                                 "seconds (1-120, default 30)."},
                },
                "required": ["command"],
            },
        }

    def run(self, ctx: ToolContext, command: str, timeout_s: int = 30) -> str:
        command = (command or "").strip()
        if not command:
            return "ERROR: empty command."
        try:
            timeout = min(max(int(timeout_s), 1), _MAX_TIMEOUT_S)
        except (TypeError, ValueError):
            timeout = 30

        if _matches(command, _DESTRUCTIVE_PATTERNS):
            approve = ctx.approve or (lambda action, details: False)
            if not approve("destructive_command",
                           {"tool": self.name, "command": command[:300]}):
                ctx.audit.record("local_exec.blocked", command=command[:300],
                                 reason="destructive_pattern")
                return ("BLOCKED: this command matches a destructive pattern and was "
                        "not approved. Ask the operator or choose another approach.")

        root = Path(os.environ.get("RED_LOCAL_EXEC_ROOT", "/tmp/rtbench"))
        root.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        try:
            proc = subprocess.run(["bash", "-lc", command], cwd=str(root),
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            ctx.audit.record("local_exec.timeout", command=command[:300],
                             timeout_s=timeout)
            return json.dumps({"exit_code": None, "timed_out": True,
                               "stdout": "", "stderr": f"killed after {timeout}s"})
        except OSError as exc:
            ctx.audit.record("local_exec.error", command=command[:300],
                             error=str(exc)[:200])
            return f"ERROR: {exc}"

        elapsed_ms = int((time.monotonic() - started) * 1000)
        ctx.audit.record("local_exec.ok", command=command[:300],
                         exit_code=proc.returncode, elapsed_ms=elapsed_ms)
        return json.dumps({
            "exit_code": proc.returncode,
            "timed_out": False,
            "stdout": (proc.stdout or "")[-_STDOUT_CAP:],
            "stderr": (proc.stderr or "")[-_STDERR_CAP:],
        }, ensure_ascii=False)

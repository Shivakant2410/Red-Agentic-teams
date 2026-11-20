"""tool_provision — the agent's on-requirement toolbox entry point.

The plan this implements: tools are downloaded BASED ON REQUIREMENT, into a
sandboxed environment where the agent can run pentest tools. When the agent
needs a tool that isn't present, this tool provisions it — into the Kali
image layer when a sandbox is configured (before start: the container's
egress is default-DROP, so runtime fetches are impossible BY DESIGN), or
into the project's provisioning venv when running sandbox-less (pip egress;
apt only as root).

Every request, channel attempt and outcome is audited. Provisioning places
BINARIES only — any actual use of them still goes through kali_exec /
param_discovery / port_scan with RoE and scope enforcement.
"""

from __future__ import annotations

import json

from . import ToolContext


class ToolProvisionTool:
    name = "tool_provision"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Provision a pentest tool on requirement. With a Kali sandbox: "
                "reports whether the tool is in the image; if not, says exactly "
                "how the tool layer gets it (image rebuild before start — the "
                "sandbox egress blocks runtime installs by design). Without a "
                "sandbox: installs into the project venv (.tools/venv) via pip, "
                "or apt when running as root. Catalog: nmap, arjun, ffuf, "
                "gobuster, nuclei, whatweb, nikto, wafw00f, sqlmap, subfinder, "
                "httpx, katana, dnsx, tlsx, naabu and amass. Provisioning never "
                "runs the tool or touches the target — execution stays with the "
                "existing RECON and assessment workflows under the engagement RoE."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "tool": {"type": "string",
                             "description": "Catalog tool name, e.g. 'arjun'."},
                    "reason": {"type": "string",
                               "description": "Why the test needs it (audited)."},
                },
                "required": ["tool", "reason"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, tool: str, reason: str) -> str:
        from ..sandbox.provision import CATALOG, ToolProvisioner

        spec = CATALOG.get(tool)
        if spec is None:
            ctx.audit.record("tool_provision.unknown", tool=tool, reason=reason)
            return json.dumps({
                "ok": False,
                "error": f"unknown tool '{tool}'",
                "catalog": sorted(CATALOG),
            })
        ctx.audit.record("tool_provision.requested", tool=tool, reason=reason,
                         purpose=spec.purpose)

        provisioner = ToolProvisioner(audit=ctx.audit)
        if ctx.sandbox is not None:
            in_sandbox = ctx.sandbox.has_tool(spec.binary)
            ctx.audit.record("tool_provision.sandbox_check", tool=tool,
                             present=in_sandbox)
            if in_sandbox:
                return json.dumps({
                    "ok": True, "where": "sandbox", "binary": spec.binary,
                    "note": "available in the Kali sandbox — run it via kali_exec.",
                })
            # A RUNNING sandbox cannot fetch packages: its egress is
            # default-DROP and must stay that way. Say so honestly.
            ctx.audit.record("tool_provision.rebuild_required", tool=tool)
            return json.dumps({
                "ok": False, "where": None,
                "note": (
                    f"'{tool}' ({spec.binary}) is not in the running sandbox image, "
                    "and the sandbox egress firewall blocks runtime installs by "
                    "design. The tool layer builds on the HOST network: add "
                    f"'{tool}' to the engagement's sandbox.extra_tools (or call "
                    "tool_provision before the sandbox starts) and restart the "
                    "run — ensure_tools bakes it into the image as an "
                    "EXTRA_TOOLS layer, tagged per toolset."
                ),
                "purpose": spec.purpose,
            })

        st = provisioner.ensure(tool)
        ctx.audit.record("tool_provision.result", tool=tool, ok=st.available,
                         where=st.where, note=st.note)
        return json.dumps({
            "ok": st.available, "where": st.where or None,
            "path": st.path or None, "note": st.note,
            "usage": ("invoke through param_discovery / port_scan / kali_exec "
                      "as usual — resolution now finds it in .tools/venv"),
        })

#!/usr/bin/env python3
"""Toolbox CLI — status / on-requirement provisioning, host mode.

    python3 scripts/tool_provision.py status
    python3 scripts/tool_provision.py ensure --tool arjun [--tool wafw00f]

With a running Kali sandbox use the engagement's sandbox.extra_tools (the
image layer); this CLI provisions into the project venv (.tools/venv) and is
the dev-sandbox path. Everything is audited to <repo>/data/audit/toolkit.jsonl
when the audit dir exists, and always printed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from redteam.sandbox.provision import CATALOG, ToolProvisioner  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="what is provisioned right now")
    p_ensure = sub.add_parser("ensure", help="download on requirement")
    p_ensure.add_argument("--tool", action="append", required=True,
                          choices=sorted(CATALOG))
    args = ap.parse_args()

    audit_path = REPO / "data" / "audit"
    audit = None
    if audit_path.parent.exists():
        try:
            from redteam.audit import AuditLog
            audit = AuditLog(audit_path / "toolkit.jsonl")
        except Exception:
            audit = None

    prov = ToolProvisioner(audit=audit)
    if args.cmd == "status":
        print(json.dumps(prov.status(), indent=2))
        return 0
    rc = 0
    for tool in args.tool:
        st = prov.ensure(tool)
        print(json.dumps({"tool": tool, "available": st.available,
                          "where": st.where, "path": st.path,
                          "note": st.note}))
        rc = rc or (0 if st.available else 1)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

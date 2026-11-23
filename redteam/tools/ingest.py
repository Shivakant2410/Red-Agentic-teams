"""ingest_sessions — the agent picks up human-assisted sessions (ARTEX).

The loop this closes: a finding needs the authenticated area, but the way in
runs through 2FA / SSO / captcha that the operator completes in THEIR browser
— faster and more honest than any Playwright-only auth emulation. The ARTEX
browser extension captures the surviving session (cookies/auth headers) and
POSTs it to ``POST /api/traffic/ingest``; the server scope-checks and stores
it under ``<run>/ingest/sessions.jsonl``; THIS tool registers it into the
run's SessionStore with the same discipline as set_session:

  - auth-bearing headers only (``_looks_auth_header``);
  - values are stored, never echoed (masked ack);
  - audit carries header NAMES only;
  - the foothold is recorded with source "extension_ingest" — a session alone
    never satisfies an objective criterion (same rule as operator_token).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import ToolContext
from .authsession import _hold_foothold, _looks_auth_header


def _run_dir(ctx: ToolContext) -> Path | None:
    traffic = getattr(ctx, "traffic", None)
    if traffic is None:
        return None
    try:
        path = traffic.summary().get("path", "")
        return Path(path).parent if path else None
    except Exception:  # noqa: BLE001 — telemetry read must never break a tool
        return None


class IngestSessionsTool:
    """ingest_sessions — list/register sessions shared by the operator's browser."""

    name = "ingest_sessions"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Sessions the OPERATOR captured in their real browser (2FA/SSO/"
                "captcha completed by the human) and shared via the ARTEX "
                "browser extension + POST /api/traffic/ingest. Lists pending "
                "sessions and registers them into the run's session store — "
                "from then on use http_probe/browser requests with "
                "as_session/<label> exactly like a set_session session. Values "
                "are never echoed; header names only in the acknowledgment. "
                "Call this when mapping authenticated areas — do NOT re-run "
                "Playwright logins the operator already completed."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "label": {"type": "string",
                              "description": "register only this pending "
                                             "session (default: all pending)"},
                    "list_only": {"type": "boolean",
                                  "description": "true = only list pending "
                                                 "sessions, register nothing"},
                },
            },
        }

    def run(self, ctx: ToolContext, label: str = "", list_only: bool = False) -> str:
        if ctx.sessions is None:
            return "ERROR: no session store in this run."
        run_dir = _run_dir(ctx)
        if run_dir is None:
            return ("No traffic artifact dir in this run — nothing can have "
                    "been ingested (the extension posts to /api/traffic/ingest "
                    "with the run_id).")
        sessions_path = run_dir / "ingest" / "sessions.jsonl"
        if not sessions_path.exists():
            return ("No sessions shared yet. The operator uses the ARTEX "
                    "browser extension (load unpacked from extension/) with "
                    "this run's id, completes the 2FA/SSO step in their own "
                    "browser, and presses Share session; then call this again.")
        registered_path = run_dir / "ingest" / "registered.json"
        try:
            done = set(_json_list(registered_path))
        except Exception:
            done = set()
        pending: list[dict] = []
        try:
            for line in sessions_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("id") and row["id"] not in done:
                    pending.append(row)
        except OSError as exc:
            return f"ERROR: cannot read ingest log: {exc}"

        wanted = [p for p in pending
                  if not label or p.get("label") == label
                  or p.get("label") == f"ext:{label}"]
        if list_only or label and not wanted and pending:
            pass  # listing falls through below
        masked_pending = [{"id": p.get("id"), "label": p.get("label"),
                           "note": p.get("note", ""),
                           "headers": sorted((p.get("headers") or {}).keys())}
                          for p in pending]

        if list_only:
            return json.dumps({"pending": masked_pending, "registered_none": True})
        if not wanted:
            return json.dumps({"pending": masked_pending, "registered": [],
                               "note": "no pending session matches; nothing registered"})

        registered: list[dict] = []
        for sess in wanted:
            clean = {str(k): str(v) for k, v in (sess.get("headers") or {}).items()
                     if _looks_auth_header(str(k)) and str(v).strip()}
            if not clean:
                continue
            use_label = str(sess.get("label") or f"ext-{sess.get('id', 'x')}")[:64]
            ctx.sessions.set(use_label, clean)
            captured = sorted(clean)
            _hold_foothold(ctx, use_label,
                           evidence="session shared by the operator's browser "
                                    "extension (human completed the auth step)",
                           captured=captured, source="extension_ingest")
            ctx.audit.record("set_session.ok", label=use_label,
                             headers=captured,
                             note="extension_ingest (human-assisted 2FA/SSO)")
            done.add(str(sess.get("id")))
            registered.append({"label": use_label,
                               "headers": {k: f"<{len(v)} chars>"
                                           for k, v in clean.items()}})
        try:
            registered_path.write_text(json.dumps(sorted(done)))
        except Exception:  # noqa: BLE001 — registration already succeeded
            pass
        return json.dumps({
            "registered": registered,
            "note": "sessions now usable via as_session=<label>; values are "
                    "held, never echoed; source recorded as extension_ingest",
            "pending": [m for m in masked_pending
                        if m["id"] not in {str(w.get("id")) for w in wanted}],
        })


def _json_list(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:  # noqa: BLE001 — first run: no file yet
        return []

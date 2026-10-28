"""TrafficRecorder — per-run HTTP traffic evidence, ARTEX-style, with our discipline.

ARTEX ("Traffic Recording and Execution Monitoring") records what its agents put on
the wire so an operator can watch/replay execution. We port the idea but keep the
Gen-2 secrets discipline: the traffic log is OPERATOR-FACING EVIDENCE, so held
credential material (Authorization/Cookie/API-key values, Set-Cookie) is masked in
BOTH directions before it ever touches disk — the same rule tools/probe.py applies
to the model transcript. Bodies are truncated (default 16 KB) and bodies can be
disabled entirely for the most sensitive RoE (--no-traffic-bodies).

Where it hooks: the single shared fetch path (tools/http.py) records every in-scope
request/response — probes, proofs, verify passes, workflow chains — plus the
scope-DENIED attempts (a blocked request is evidence that the boundary held, and the
audit log already treats it that way; now the operator can see the wire-level shape).

Storage contract mirrors events.py: append-only JSONL (traffic.jsonl in the run dir),
flush per record, tolerant reader with the same cursor semantics (after=last seq).
Emission must NEVER break a run — record() swallows sink failures (same design rule
as the EventBus), because a full disk or a read-only directory must not kill an
engagement that is mid-proof.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from pathlib import Path

# Header names whose VALUES are credential-adjacent. Applied to BOTH request and
# response headers. Names stay (shape is signal); values become a withheld marker.
MASKED_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authenticate",
})

DEFAULT_BODY_LIMIT = 16 * 1024
_TRUNCATED = " [truncated]"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _mask_headers(headers: dict | None) -> dict:
    out: dict = {}
    for k, v in (headers or {}).items():
        name = str(k)
        if name.lower() in MASKED_HEADERS:
            out[name] = f"<withheld:{len(str(v))} chars>"
        else:
            out[name] = str(v)
    return out


def _clip(body: str | None, limit: int, record_bodies: bool) -> str:
    if not record_bodies or body is None:
        return ""
    body = str(body)
    if len(body) <= limit:
        return body
    return body[:limit] + _TRUNCATED


class TrafficRecorder:
    """Append-only, thread-safe JSONL traffic log for one run."""

    def __init__(self, path: str | Path, max_body_bytes: int = DEFAULT_BODY_LIMIT,
                 record_bodies: bool = True):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._max_body = max(0, int(max_body_bytes))
        self._bodies = bool(record_bodies)
        self._seq = 0
        self.count = 0
        # Best-effort: a read-only disk / weird parent must not prevent CONSTRUCTING
        # the recorder (record() swallows the later open failure — run survives).
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def record_http(self, *, method: str, url: str, status: int, elapsed_ms: int,
                    tool: str = "", session: str = "",
                    req_headers: dict | None = None, req_body: str | None = None,
                    resp_headers: dict | None = None, resp_body: str | None = None,
                    error: str = "", source: str = "") -> None:
        """Record one request/response exchange (or a failed/denied attempt).

        `source` marks where the exchange came from for the operator scanning the
        log: '' (unmarked, a real wire exchange), 'mock' (fulfilled locally by a
        stub — the SPA walkthrough's credential-free bootstrap — never touched
        the target), or any tool-chosen label. Mocked rows are evidence of what
        the CLIENT asked for, not of what the server said — keep them distinct."""
        rec = {
            "seq": None,  # assigned under lock
            "ts": _now(),
            "kind": "http",
            "source": str(source or ""),
            "tool": tool,
            "method": str(method or "GET").upper(),
            "url": url,
            "status": int(status),
            "elapsed_ms": int(elapsed_ms),
            "session": session or "",
            "error": error,
            "req_headers": _mask_headers(req_headers),
            "req_body": _clip(req_body, self._max_body, self._bodies),
            "resp_headers": _mask_headers(resp_headers),
            "resp_body": _clip(resp_body, self._max_body, self._bodies),
        }
        # Telemetry must never break a run (EventBus design rule): a full disk, a
        # vanished directory, or any serialization surprise is swallowed here.
        try:
            with self._lock:
                self._seq += 1
                rec["seq"] = self._seq
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                self.count += 1   # only written records count — the operator briefs off this
        except Exception:
            pass

    def summary(self) -> dict:
        return {"recorded": self.count, "path": str(self._path)}


def read_traffic(path: str | Path, after: int = 0, limit: int = 1000) -> list[dict]:
    """Replay traffic records with seq > after — the same cursor contract as
    events.read_events, so the API serves both the same way. Tolerant of a torn
    last line (a writer mid-flush)."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("seq", 0) > after:
                out.append(rec)
                if len(out) >= limit:
                    break
    return out

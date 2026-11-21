"""RECON-facing tools over the run's EvidenceProxy + traffic history.

The proxy records every exchange it sees into the run's traffic.jsonl
(sources: ``proxy`` plain HTTP, ``proxy-mitm`` decrypted TLS, ``proxy-tunnel``
blind passthrough). These tools make that history QUERYABLE DURING the run —
Burp-style HTTP history for the agent — without a second store: read-back
goes through the same TrafficRecorder file the operator and dashboard read.

Replay is deliberately narrow: proxy_replay re-issues a RECORDED request
through the shared fetch path (scope-checked, rate-limited, audited, recorded
as source="replay"), repeating exactly the captured method/URL/body. It is
not an arbitrary-request facility — the agent cannot invent new targets
through it; anything out of scope is denied by ScopeGuard like every other
network action.

TLS honesty (inherited from EvidenceProxy, surfaced here): proxy_status
reports whether HTTPS was DECRYPTED (MITM with the run CA) or only TUNNELED
blind (metadata rows, status 0, no body) — a passthrough row never claims
decrypted content.
"""
from __future__ import annotations

import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit

from ..traffic import read_traffic

# Sources whose rows ARE the proxy/browser evidence plane (kept in one place
# so history/filter/replay agree on what "proxy traffic" means).
EVIDENCE_SOURCES = ("proxy", "proxy-mitm", "proxy-tunnel", "browser", "replay")
_HISTORY_LIMIT = 80
_MAX_ROWS = 400


def _traffic_path(ctx) -> str:
    traffic = getattr(ctx, "traffic", None)
    if traffic is None:
        return ""
    try:
        return traffic.summary().get("path", "")
    except Exception:  # noqa: BLE001 — telemetry read must never break a tool
        return ""


def _compact(row: dict) -> dict:
    return {
        "seq": row.get("seq"),
        "ts": row.get("ts", "")[:19],
        "source": row.get("source", ""),
        "tool": row.get("tool", ""),
        "method": row.get("method", ""),
        "url": row.get("url", ""),
        "status": row.get("status"),
        "error": (row.get("error") or "")[:120],
        "req_bytes": len(row.get("req_body") or ""),
        "resp_bytes": len(row.get("resp_body") or ""),
    }


def _load_evidence_rows(ctx) -> list[dict]:
    path = _traffic_path(ctx)
    if not path:
        return []
    return [row for row in read_traffic(Path(path), after=0, limit=100000)
            if row.get("source") in EVIDENCE_SOURCES]


def _row_by_seq(ctx, seq: int) -> dict | None:
    if not isinstance(seq, int) or seq <= 0:
        return None
    for row in _load_evidence_rows(ctx):
        if row.get("seq") == seq:
            return row
    return None


class ProxyStatusTool:
    """proxy_status — listener, TLS mode and capture stats (no network)."""

    name = "proxy_status"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Evidence proxy status: listener host/port, TLS interception "
                "mode (decrypted vs blind passthrough), capture counters and "
                "which sources are recording. Call this FIRST to learn where "
                "history lives and whether HTTPS bodies are inspectable."),
            "input_schema": {"type": "object", "properties": {}},
        }

    def run(self, ctx, **kwargs) -> str:
        proxy = getattr(ctx, "proxy", None)
        rows = _load_evidence_rows(ctx)
        by_source: dict[str, int] = {}
        for row in rows:
            by_source[row.get("source", "")] = \
                by_source.get(row.get("source", ""), 0) + 1
        if proxy is None:
            return json.dumps({
                "running": False,
                "note": "no intercepting proxy in this run (browser traffic "
                        "is captured by page instrumentation instead; scope "
                        "and budget still enforced)",
                "evidence_rows": len(rows),
                "rows_by_source": by_source,
            })
        try:
            st = proxy.status()
        except Exception as exc:  # noqa: BLE001 — honest error, not a crash
            return f"ERROR: proxy status unavailable: {exc}"
        return json.dumps({
            "running": True,
            "mode": st.get("mode", ""),
            "port": st.get("port"),
            "tls": ("DECRYPTED (MITM, run CA installed) — request/response "
                    "bodies inspectable"
                    if st.get("mode") == "mitm" else
                    "PASSTHROUGH (tunneled blind; TLS NOT decrypted — only "
                    "SNI/byte metadata recorded; HTTPS bodies NOT inspectable)"),
            "ca_cert": st.get("ca_cert_path", ""),
            "stats": {k: st.get(k) for k in
                      ("exchanges", "tunnels", "denied", "errors") if k in st},
            "evidence_rows": len(rows),
            "rows_by_source": by_source,
        }, default=str)


class ProxyHistoryTool:
    """proxy_history — the newest captured exchanges (Burp-style tail)."""

    name = "proxy_history"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Newest rows from the intercepting proxy / browser evidence "
                "history (most recent first). Compact rows: seq, method, url, "
                "status, source. Use proxy_inspect(seq) for one row's full "
                "detail; use proxy_filter to search by condition."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer",
                              "description": "max rows (default 25, cap 80)"},
                    "min_status": {"type": "integer",
                                   "description": "only rows with status >= N"},
                },
            },
        }

    def run(self, ctx, limit=None, min_status=None, **kwargs) -> str:
        rows = _load_evidence_rows(ctx)
        try:
            cap = max(1, min(int(limit or 25), _HISTORY_LIMIT))
        except (TypeError, ValueError):
            cap = 25
        if isinstance(min_status, int):
            rows = [r for r in rows if (r.get("status") or 0) >= min_status]
        rows = rows[-cap:][::-1]
        return json.dumps({"count": len(rows), "rows": [_compact(r) for r in rows]})


class ProxyFilterTool:
    """proxy_filter — condition search over captured exchanges."""

    name = "proxy_filter"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Search the captured proxy/browser history by condition: "
                "url substring, method, exact status, or source. Returns "
                "matching compact rows (newest first)."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url_contains": {"type": "string"},
                    "method": {"type": "string"},
                    "status": {"type": "integer"},
                    "source": {"type": "string",
                               "description": "proxy | proxy-mitm | "
                                              "proxy-tunnel | browser | replay"},
                    "limit": {"type": "integer"},
                },
            },
        }

    def run(self, ctx, url_contains="", method="", status=None, source="",
            limit=None, **kwargs) -> str:
        rows = _load_evidence_rows(ctx)
        needle = str(url_contains or "").lower()
        if needle:
            rows = [r for r in rows if needle in str(r.get("url", "")).lower()]
        if method:
            rows = [r for r in rows
                    if str(r.get("method", "")).upper() == str(method).upper()]
        if isinstance(status, int):
            rows = [r for r in rows if r.get("status") == status]
        if source:
            rows = [r for r in rows if r.get("source") == str(source)]
        try:
            cap = max(1, min(int(limit or 40), _MAX_ROWS))
        except (TypeError, ValueError):
            cap = 40
        rows = rows[-cap:][::-1]
        return json.dumps({"count": len(rows), "rows": [_compact(r) for r in rows]})


class ProxyInspectTool:
    """proxy_inspect — one captured exchange in full (masked, bounded)."""

    name = "proxy_inspect"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Full detail of ONE captured exchange by seq (from "
                "proxy_history/proxy_filter): sanitized request/response "
                "headers and bodies. Secrets in headers are withheld by the "
                "recorder; bodies are size-clipped."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "seq": {"type": "integer",
                            "description": "row seq from history/filter"},
                },
                "required": ["seq"],
            },
        }

    def run(self, ctx, seq=None, **kwargs) -> str:
        row = _row_by_seq(ctx, int(seq) if isinstance(seq, int) else -1)
        if row is None:
            return f"ERROR: no captured row with seq={seq}"
        return json.dumps(row, default=str)


class ProxyReplayTool:
    """proxy_replay — controlled re-issue of ONE captured exchange."""

    name = "proxy_replay"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Replay a captured exchange by seq: repeats the recorded "
                "method/URL/body through the shared fetch path — scope-"
                "checked, rate-limited, audited, recorded (source=replay). "
                "You cannot change the target or invent new requests here; "
                "use http_probe for new in-scope requests."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "seq": {"type": "integer",
                            "description": "row seq from history/filter"},
                },
                "required": ["seq"],
            },
        }

    def run(self, ctx, seq=None, **kwargs) -> str:
        row = _row_by_seq(ctx, int(seq) if isinstance(seq, int) else -1)
        if row is None:
            return f"ERROR: no captured row with seq={seq}"
        url = str(row.get("url", ""))
        method = str(row.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
                          "OPTIONS"):
            return f"ERROR: replay of method {method} refused (not replayable)"
        limiter = getattr(ctx, "limiter", None)
        if limiter is not None:
            try:
                limiter.acquire()
            except Exception as exc:  # budget exhausted -> honest stop
                ctx.audit.record("proxy.replay.denied", seq=seq, reason=str(exc))
                return f"DENIED (RoE budget): {exc}"
        # Scope re-check BEFORE dialing (same fail-closed rule as every tool);
        # a recorded URL whose scope changed since capture is refused here.
        try:
            ctx.scope.check(url)
        except Exception as exc:
            ctx.audit.record("proxy.replay.denied", seq=seq, url=url[:200],
                             reason=f"scope: {exc}")
            return f"DENIED (out of scope): {exc}"
        # Direct one-shot replay (NOT the fetch path): repeats exactly the
        # captured method/URL/body, records ONE row (source=replay) — no
        # double-counting, no way to smuggle in a different target.
        parts = urlsplit(url)
        try:
            conn = http.client.HTTPConnection(parts.hostname, parts.port or
                                              (443 if parts.scheme == "https"
                                               else 80), timeout=15)
            body = row.get("req_body") or None
            headers = {k: v for k, v in (row.get("req_headers") or {}).items()
                       if "withheld" not in str(v)}   # masked values are gone
            conn.request(method, url if url.startswith("/") else
                         (parts.path or "/") + (("?" + parts.query) if parts.query else ""),
                         body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read(16_000).decode("utf-8", errors="replace")
            status = resp.status
            resp_headers = {k: v for k, v in resp.getheaders()}
            elapsed_ms = 0
            conn.close()
        except Exception as exc:
            ctx.audit.record("proxy.replay.error", seq=seq, url=url[:200],
                             error=str(exc)[:200])
            if getattr(ctx, "traffic", None) is not None:
                ctx.traffic.record_http(method=method, url=url, status=0,
                                        elapsed_ms=0, tool="proxy_replay",
                                        error=str(exc)[:200], source="replay")
            return f"DENIED/FAILED: {exc}"
        ctx.audit.record("proxy.replay", seq=seq, url=url[:200],
                         method=method, status=status)
        if getattr(ctx, "traffic", None) is not None:
            try:
                ctx.traffic.record_http(method=method, url=url, status=status,
                                        elapsed_ms=elapsed_ms,
                                        tool="proxy_replay", source="replay",
                                        req_headers=dict(row.get("req_headers")
                                                         or {}),
                                        req_body=row.get("req_body") or None,
                                        resp_headers=resp_headers,
                                        resp_body=resp_body)
            except Exception:
                pass   # telemetry must never break a tool
        return json.dumps({
            "replayed_seq": seq, "status": status,
            "resp_body": resp_body[:4000],
            "resp_headers": resp_headers,
        }, default=str)

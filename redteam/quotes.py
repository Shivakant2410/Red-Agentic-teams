"""ARTEX quote extraction — verbatim decoded response evidence for findings.

The ARTEX rule: a finding is only as auditable as the wire evidence it is
bound to. This module joins a finding to the run's traffic.jsonl — the
CA-traced proxy/fetch log — and extracts a VERBATIM, DECODED response quote
(proxy bodies are identity-rewritten and gzip/deflate-decoded for evidence;
see proxy._decoded_text) with its traffic row seq, so a report reader can
open the exact exchange the proof ran against.

Quotes are deliberately verbatim and size-bounded (default 400 chars). The
row carries the authoritative masked headers; quotes are body text only.
"""
from __future__ import annotations

from pathlib import Path

from .traffic import read_traffic

_DEFAULT_QUOTE_CHARS = 400
_SCAN_LIMIT = 100_000


def _traffic_rows(traffic_path) -> list[dict]:
    if not traffic_path:
        return []
    try:
        return read_traffic(Path(traffic_path), after=0, limit=_SCAN_LIMIT)
    except Exception:  # noqa: BLE001 — evidence read must never break a proof
        return []


def find_quote(traffic_path, *, url: str = "", method: str = "",
               seq: int | None = None, max_chars: int = _DEFAULT_QUOTE_CHARS,
               require_body: bool = True) -> dict | None:
    """Find the most recent matching traffic row and quote its response body.

    Match rules, most specific first:
      - seq          -> that exact row (the agent cites a captured exchange)
      - url (+method)-> exact URL match; fallback: same path, any query
    Returns {seq, ts, method, url, status, tool, source, quote} or None.
    """
    rows = _traffic_rows(traffic_path)
    if seq is not None:
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            return None
        rows = [r for r in rows if r.get("seq") == seq]
        rows.reverse()
    else:
        if not url:
            return None
        base = url.split("?")[0]
        if method:
            rows = [r for r in rows
                    if str(r.get("method", "")).upper() == str(method).upper()
                    and (r.get("url") == url or str(r.get("url", "")).split("?")[0] == base)]
        else:
            rows = [r for r in rows
                    if r.get("url") == url or str(r.get("url", "")).split("?")[0] == base]
        rows.reverse()
    for row in rows:
        body = str(row.get("resp_body") or "")
        if require_body and not body:
            continue
        return {
            "seq": row.get("seq"),
            "ts": row.get("ts", ""),
            "method": row.get("method", ""),
            "url": row.get("url", ""),
            "status": row.get("status"),
            "tool": row.get("tool", ""),
            "source": row.get("source", ""),
            "quote": body[:max(1, int(max_chars))],
        }
    return None


def quote_evidence(traffic_path, *, url: str = "", method: str = "",
                   seq: int | None = None,
                   max_chars: int = _DEFAULT_QUOTE_CHARS) -> tuple[list[dict], str]:
    """(evidence_refs, evidence_line) for a finding — empty pair when no row
    matches (honest absence: no fabricated quotes, ever)."""
    q = find_quote(traffic_path, url=url, method=method, seq=seq,
                   max_chars=max_chars)
    if q is None:
        return [], ""
    ref = {"kind": "traffic", "seq": q["seq"], "url": q["url"][:300],
           "status": q["status"], "source": q["source"] or "fetch",
           "ts": q["ts"]}
    line = (f"[ARTEX quote — traffic seq {q['seq']}, {q['method']} {q['url']}"
            f" -> {q['status']}]\n{q['quote']}")
    return [ref], line

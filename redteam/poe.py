"""Proof-of-Evidence (POE) — bind a finding to a recorded exchange and grade it.

A finding is only as trustworthy as the wire evidence under it. POE enforces a
MECHANICAL link between a finding's claim and an actual captured HTTP exchange:
the finding references a traffic record by seq (evidence_ref) and supplies
VERBATIM quotes that must appear in that exchange's recorded request/response.
The verifier re-reads the bound record from traffic.jsonl and checks each quote
literally — if a quote the LLM claimed is not in the real response, the finding
is unproven, full stop. This catches hallucinated / exaggerated findings that a
re-run check alone can miss (e.g. a quote that was never there).

Because the evidence proxy now decodes gzip/deflate bodies before storing them
(see proxy.py), quote-matching runs against real plaintext, not compressed bytes.

POE LEVELS (proof strength), independent of the verification funnel:
  poe3  — every quote found in the BOUND response body (strongest: server said it)
  poe2  — every quote found, but in request or headers only (weaker: client-side)
  poe1  — bound exchange exists and some quotes matched (partial)
  poe0  — no binding, or no quote matched (unproven on the wire)
A finding carries its POE next to its confidence; a report shows both.
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path

from .traffic import read_traffic

POE3, POE2, POE1, POE0 = "poe3", "poe2", "poe1", "poe0"


@dataclass
class PoeResult:
    level: str
    verified: bool            # True only at poe3/poe2 with all quotes matched
    matched: list[str]
    missing: list[str]
    note: str
    exchange_seq: int = 0


def _exchange_by_seq(traffic_path: Path, seq: int) -> dict | None:
    # read_traffic returns seq > after, so after=seq-1 yields the one we want first.
    for rec in read_traffic(traffic_path, after=max(0, seq - 1), limit=5):
        if rec.get("seq") == seq:
            return rec
    return None


def decode_body(body: str | bytes | None, encoding: str = "") -> str:
    """Decode a recorded body without weakening its evidence binding.

    Supports plaintext, gzip, zlib/raw deflate, and base64-wrapped compressed
    payloads. Decode failures fall back to readable text; they never broaden
    matching to another traffic record.
    """
    if body is None:
        return ""
    if isinstance(body, str):
        text = body
        # Browser/proxy adapters sometimes serialize binary bodies as base64.
        if (encoding.lower() in ("gzip", "deflate") or
                text.startswith(("H4sI", "eJx", "eJw"))):
            try:
                raw = base64.b64decode(text, validate=False)
                decoded = decode_body(raw, encoding)
                if decoded and decoded != raw.decode("utf-8", errors="replace"):
                    return decoded
            except Exception:
                pass
        if not encoding:
            return text
        try:
            raw = text.encode("latin-1")
        except UnicodeEncodeError:
            raw = text.encode("utf-8", errors="replace")
    else:
        raw = bytes(body)

    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw).decode("utf-8", errors="replace")
        except Exception:
            pass
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(raw, wbits).decode("utf-8", errors="replace")
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _header(headers: dict, name: str) -> str:
    wanted = name.lower()
    return next((str(v) for k, v in (headers or {}).items()
                 if str(k).lower() == wanted), "")


def _haystacks(rec: dict) -> tuple[str, str]:
    """(response_blob, request_blob) — decoded body + headers, for quote search."""
    def _blob(headers, body):
        hs = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        encoding = _header(headers or {}, "content-encoding")
        decoded = decode_body(body, encoding)
        return hs + "\n" + decoded
    resp = _blob(rec.get("resp_headers"), rec.get("resp_body"))
    req = _blob(rec.get("req_headers"), rec.get("req_body"))
    return resp, req


def grade(traffic_path: str | Path, evidence_seq: int, quotes: list[str]) -> PoeResult:
    """Grade a finding's proof strength against its bound traffic exchange."""
    quotes = [q for q in (quotes or []) if isinstance(q, str) and q.strip()]
    if not evidence_seq:
        return PoeResult(POE0, False, [], quotes, "no evidence_ref bound to a traffic exchange")
    rec = _exchange_by_seq(Path(traffic_path), int(evidence_seq))
    if rec is None:
        return PoeResult(POE0, False, [], quotes,
                         f"bound exchange seq={evidence_seq} not found in traffic store")
    if not quotes:
        return PoeResult(POE1, False, [], [],
                         f"bound to exchange seq={evidence_seq} but no verbatim quotes supplied")

    resp_blob, req_blob = _haystacks(rec)
    in_resp = [q for q in quotes if q in resp_blob]
    in_req = [q for q in quotes if q not in resp_blob and q in req_blob]
    matched = in_resp + in_req
    missing = [q for q in quotes if q not in matched]

    if missing:
        # Any claimed quote absent from the real exchange => not verified on the wire.
        lvl = POE1 if matched else POE0
        return PoeResult(lvl, False, matched, missing, exchange_seq=int(evidence_seq),
                         note=f"{len(missing)}/{len(quotes)} quote(s) NOT present in the "
                              f"bound exchange — unproven claim")
    if in_resp and not in_req:
        return PoeResult(POE3, True, matched, [], exchange_seq=int(evidence_seq),
                         note=f"all {len(quotes)} quote(s) present in the bound RESPONSE body")
    return PoeResult(POE2, True, matched, [], exchange_seq=int(evidence_seq),
                     note=f"all quote(s) present, but in the REQUEST/headers only "
                          f"(weaker — client-controlled)")


def grade_run(run_dir: str | Path) -> dict:
    """Read-only POE report for one run, grading each finding against ONLY its
    own evidence_ref traffic sequence. Quotes found in another exchange do not
    satisfy the binding.
    """
    directory = Path(run_dir)
    findings_path = directory / "findings.json"
    try:
        rows = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rows = []
    findings = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        result = grade(directory / "traffic.jsonl", row.get("evidence_ref", 0),
                       row.get("quotes") or [])
        findings.append({
            "id": row.get("id", ""),
            "title": row.get("title", ""),
            "confidence": row.get("confidence", ""),
            "evidence_ref": row.get("evidence_ref", 0),
            "level": result.level,
            "verified": result.verified,
            "matched": result.matched,
            "missing": result.missing,
            "note": result.note,
            "exchange_seq": result.exchange_seq,
        })
    summary = {level: sum(1 for item in findings if item["level"] == level)
               for level in (POE3, POE2, POE1, POE0)}
    return {"findings": findings, "summary": summary}

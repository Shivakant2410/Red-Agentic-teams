"""POE — Proof-of-Exploitation grading for findings, ARTEX-style.

A finding's confidence lifecycle (tentative → … → confirmed, findings.py) says
whether the behavior is REAL. POE grades HOW STRONG THE PROOF BINDING is, as a
separate axis an operator can sort on:

  POE-0  claim only — narration, no recorded check
  POE-1  self-graded — the proposing agent's own k-of-n check passed
         (poc / verification_verdict recorded) — still self-grading
  POE-2  independently confirmed — a fresh context reproduced the check
         (tools/independent_verify.py), the only self-grading-free state
  POE-3  quote-bound — POE-2 AND every verbatim quote in the finding's
         evidence appears in a CA-traced proxy response body, DECODED first
         (gzip / deflate / raw). A gzipped body is evidence nobody can read,
         so validation decodes before matching — an agent cannot inflate POE
         by quoting a byte string that only exists inside compressed wire
         bytes, and cannot fake a match by paraphrasing: the quote must be
         verbatim.

Quotes are extracted from the evidence text the finding itself carries, then
matched against the run's traffic log (traffic.jsonl records from the evidence
proxy, the shared fetch path, and extension ingest). Grading is READ-ONLY: it
never promotes a finding or changes confidence — it annotates what an operator
can trust and writes the annotation onto the finding (poe_level / poe_detail)
for the report and the /api/runs/{id}/poe endpoint.
"""

from __future__ import annotations

import base64
import gzip
import json
import re as _re
import zlib
from pathlib import Path

# Quotes shorter than this are prose noise ("the", "200"), not evidence spans.
_MIN_QUOTE = 8
_MAX_QUOTES = 12

_QUOTE_RE = _re.compile(r'"([^"\\\n]{%d,}?)"' % _MIN_QUOTE)
_TICK_RE = _re.compile(r"`([^`\n]{%d,}?)`" % _MIN_QUOTE)

POE_0 = "POE-0"
POE_1 = "POE-1"
POE_2 = "POE-2"
POE_3 = "POE-3"
POE_LEVELS = (POE_0, POE_1, POE_2, POE_3)


def decode_body(body: str | bytes | None, encoding: str = "") -> str:
    """Decode a recorded response body to human-readable text.

    Handles Content-Encoding gzip / deflate, sniffs the magic bytes for the
    same (a record whose headers were lost must still validate), tolerates
    base64-wrapped bodies, and never raises: a decode failure returns the
    lossy-text form rather than breaking grading."""
    if body is None:
        return ""
    if isinstance(body, str):
        # A string may still be a base64-wrapped gzip payload from a binary-safe
        # ingest path; sniff and try, but fall through to plain text.
        if encoding in ("gzip", "deflate") or (
            not encoding and body[:4] in ("H4sI", "eJxT", "eJwz", "eJyr")
        ):
            try:
                return decode_body(base64.b64decode(body, validate=False), encoding)
            except Exception:
                return body
        return body
    raw = bytes(body)
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw).decode("utf-8", errors="replace")
        except Exception:
            pass
    # zlib deflate (with header) or raw deflate — try both, pick the first that works.
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(raw, wbits).decode("utf-8", errors="replace")
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def quote_candidates(evidence: str) -> list[str]:
    """Extract verbatim quoted spans from a finding's evidence text.

    Double-quoted and backtick spans of at least _MIN_QUOTE chars. Duplicates
    collapse; order preserved; capped at _MAX_QUOTES so a sprawling evidence
    blob cannot drown the grader."""
    out: list[str] = []
    for m in _QUOTE_RE.finditer(evidence or ""):
        out.append(m.group(1))
    for m in _TICK_RE.finditer(evidence or ""):
        out.append(m.group(1))
    seen: set[str] = set()
    uniq: list[str] = []
    for q in out:
        if q not in seen:
            seen.add(q)
            uniq.append(q)
    return uniq[:_MAX_QUOTES]


def _decoded_bodies(records: list[dict]) -> list[tuple[int, str]]:
    """(seq, decoded_text) for every traffic record that carries a body."""
    out: list[tuple[int, str]] = []
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        body = rec.get("resp_body") or ""
        enc = str(rec.get("resp_encoding") or rec.get("content_encoding") or "")
        text = decode_body(body, enc)
        if text:
            out.append((rec.get("seq", 0), text))
    return out


def grade_finding(finding, records: list[dict]) -> dict:
    """Grade ONE finding against the run's traffic records. Read-only."""
    level = POE_0
    if getattr(finding, "poc", "") or getattr(finding, "verification_verdict", ""):
        level = POE_1
    if getattr(finding, "independent_verdict", "") == "confirmed":
        level = POE_2

    quotes = quote_candidates(getattr(finding, "evidence", "") or "")
    quote_checks: list[dict] = []
    if level == POE_2 and quotes:
        bodies = _decoded_bodies(records)
        for q in quotes:
            hit = next((seq for seq, text in bodies if q in text), None)
            quote_checks.append({"quote": q[:120], "matched": hit is not None,
                                 "seq": hit})
        if quote_checks and all(c["matched"] for c in quote_checks):
            level = POE_3

    return {
        "id": getattr(finding, "id", ""),
        "title": getattr(finding, "title", ""),
        "poe": level,
        "confidence": getattr(finding, "confidence", ""),
        "quotes_total": len(quotes),
        "quotes_matched": sum(1 for c in quote_checks if c["matched"]),
        "quote_checks": quote_checks,
    }


def grade_all(findings, records: list[dict]) -> dict:
    """Grade a collection (FindingStore.all() or a list of Finding) → report."""
    rows = [grade_finding(f, records) for f in findings]
    summary = {lvl: 0 for lvl in POE_LEVELS}
    for row in rows:
        summary[row["poe"]] += 1
    return {"findings": rows, "summary": summary}


def grade_run(run_dir: str | Path, store=None) -> dict:
    """Grade every finding of a run against its traffic.jsonl. Server-side."""
    from .traffic import read_traffic
    d = Path(run_dir)
    records = read_traffic(d / "traffic.jsonl")
    if store is None:
        findings: list = []
        findings_path = d / "findings.json"
        if findings_path.exists():
            try:
                rows = json.loads(findings_path.read_text(encoding="utf-8"))
                from .findings import Finding
                findings = [Finding(**row) for row in rows
                            if isinstance(row, dict)]
            except Exception:
                findings = []
    else:
        findings = store.all()
    return grade_all(findings, records)


def annotate(store, records: list[dict]) -> dict:
    """Grade the store's findings and PERSIST the annotation on each finding
    (poe_level / poe_detail) — used after an independent verify pass lands, so
    the stored record itself carries its proof-binding grade."""
    report = grade_all(store.all(), records)
    for row in report["findings"]:
        store.annotate_poe(row["id"], row["poe"], {
            "quotes_total": row["quotes_total"],
            "quotes_matched": row["quotes_matched"],
            "quote_checks": row["quote_checks"],
        })
    return report

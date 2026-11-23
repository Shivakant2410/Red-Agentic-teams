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


def _haystacks(rec: dict) -> tuple[str, str]:
    """(response_blob, request_blob) — body + headers, for quote search."""
    def _blob(headers, body):
        hs = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        return (hs + "\n" + (body or ""))
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

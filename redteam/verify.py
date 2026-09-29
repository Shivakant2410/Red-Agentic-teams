"""Verification engine — the false-positive killer.

The dominant failure mode of LLM security agents is confident hallucination: the model
"finds" SQL injection that isn't there. This module makes a finding earn the word
"confirmed". A finding carries a VerificationSpec — a deterministic, reproducible check.
We run it k-of-n times; only a stable, reproducible result promotes the finding to
"confirmed". Anything else stays "tentative" (or is rejected outright).

Two check kinds ship here:
  - HttpCheck: an assertion over an HTTP response (status/regex/timing), re-run n times.
  - DifferentialCheck: a baseline vs. payload request pair, where the vuln is a *stable
    difference* (the basis of real injection/IDOR evidence, not a one-off blip).

Checks are pluggable: implement `run() -> CheckOutcome`.
"""

from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol


@dataclass
class CheckOutcome:
    passed: bool
    detail: str
    signal: float = 0.0  # optional numeric signal (e.g. timing delta) for the record


class Check(Protocol):
    def run(self) -> CheckOutcome: ...


@dataclass
class VerificationResult:
    verdict: str          # confirmed | not_reproducible | rejected
    reproductions: int
    trials: int
    confidence: float     # reproductions / trials
    details: list[str] = field(default_factory=list)


def verify(check: Check, trials: int = 5, need: int = 4, settle: float = 0.0) -> VerificationResult:
    """Run `check` `trials` times; require `need` passes to confirm.

    k-of-n (not 1-of-1) is deliberate: a single pass can be luck, load, or a transient.
    A finding that can't reproduce consistently is not a finding.
    """
    passes = 0
    details: list[str] = []
    for i in range(trials):
        outcome = check.run()
        details.append(f"trial {i + 1}: {'PASS' if outcome.passed else 'fail'} — {outcome.detail}")
        if outcome.passed:
            passes += 1
        if settle:
            time.sleep(settle)
    confidence = passes / trials if trials else 0.0
    if passes >= need:
        verdict = "confirmed"
    elif passes == 0:
        verdict = "rejected"
    else:
        verdict = "not_reproducible"
    return VerificationResult(verdict=verdict, reproductions=passes, trials=trials,
                              confidence=round(confidence, 2), details=details)


# --- concrete checks ---------------------------------------------------------

@dataclass
class HttpCheck:
    """Assert something about a single response. `fetch` returns (status, body, elapsed)."""
    fetch: Callable[[], tuple[int, str, float]]
    expect_status: int | None = None
    body_regex: str | None = None
    max_latency: float | None = None

    def run(self) -> CheckOutcome:
        status, body, elapsed = self.fetch()
        reasons = []
        ok = True
        if self.expect_status is not None and status != self.expect_status:
            ok = False
            reasons.append(f"status {status} != {self.expect_status}")
        if self.body_regex is not None and not re.search(self.body_regex, body or ""):
            ok = False
            reasons.append(f"body did not match /{self.body_regex}/")
        if self.max_latency is not None and elapsed > self.max_latency:
            ok = False
            reasons.append(f"latency {elapsed:.2f}s > {self.max_latency}s")
        return CheckOutcome(passed=ok, detail="; ".join(reasons) or "all assertions held",
                            signal=elapsed)


@dataclass
class DifferentialCheck:
    """Confirm a vuln by a STABLE difference between a baseline and a payload request.

    Example — time-based blind SQLi: baseline is fast, payload (SLEEP(5)) is slow, and the
    gap must hold across trials. A real signal is reproducible; noise isn't.
    `fetch_baseline` / `fetch_payload` each return (status, body, elapsed).
    """
    fetch_baseline: Callable[[], tuple[int, str, float]]
    fetch_payload: Callable[[], tuple[int, str, float]]
    min_latency_delta: float | None = None       # payload slower than baseline by >= this
    body_differs_regex: str | None = None         # regex that should appear ONLY in payload resp

    def run(self) -> CheckOutcome:
        b_status, b_body, b_elapsed = self.fetch_baseline()
        p_status, p_body, p_elapsed = self.fetch_payload()
        reasons = []
        ok = True
        delta = p_elapsed - b_elapsed
        if self.min_latency_delta is not None:
            if delta < self.min_latency_delta:
                ok = False
                reasons.append(f"latency delta {delta:.2f}s < {self.min_latency_delta}s")
            else:
                reasons.append(f"latency delta {delta:.2f}s")
        if self.body_differs_regex is not None:
            in_payload = bool(re.search(self.body_differs_regex, p_body or ""))
            in_baseline = bool(re.search(self.body_differs_regex, b_body or ""))
            if not (in_payload and not in_baseline):
                ok = False
                reasons.append("differential body marker not isolated to payload response")
            else:
                reasons.append("differential body marker present only in payload response")
        return CheckOutcome(passed=ok, detail="; ".join(reasons) or "differential held",
                            signal=delta)

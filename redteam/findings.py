"""Findings data model and store.

A finding is a single, defensible security observation the agent recorded during the
run. The store keeps them in memory and persists to JSON so the report generator and
a human reviewer can work from the same source of truth.
"""

from __future__ import annotations

import datetime as _dt
import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    title: str
    severity: str
    target: str
    summary: str
    evidence: str = ""
    recommendation: str = ""
    cwe: str = ""  # e.g. "CWE-89"
    # tentative | pending_verification | confirmed | falsified | not_reproducible
    #
    # pending_verification = the proposing agent's own k-of-n check passed, but no
    # independent re-check has run yet. Nothing may credit an objective criterion or an
    # access-graph "held" node from a pending_verification finding — only "confirmed" is
    # self-grading-free (see tools/independent_verify.py). falsified/not_reproducible are
    # terminal: the finding stays on record (so false-positive attempts are auditable) but
    # never counts toward anything.
    confidence: str = "tentative"
    # Verification record (populated when a finding was reproduced by verify.py).
    verification_verdict: str = ""   # confirmed | not_reproducible | rejected
    reproductions: int = 0
    trials: int = 0
    poc: str = ""                    # reproducible proof-of-concept steps
    # Replay material so an INDEPENDENT context can re-run the exact same proof without
    # trusting the proposing agent's narration of what it did. Populated by whichever tool
    # ran the original check (confirm_finding / verify_vulnerability / prove_privilege).
    check_type: str = ""             # "http" | "differential" | "proof" | "privilege"
    check_spec: dict = field(default_factory=dict)   # requests/conditions/etc. to rebuild the check
    independent_verdict: str = ""    # confirmed | falsified | not_reproducible (set by the re-check)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")


class FindingStore:
    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._findings: list[Finding] = []
        if self._path.exists():
            for row in json.loads(self._path.read_text(encoding="utf-8")):
                self._findings.append(Finding(**row))

    def add(self, finding: Finding) -> Finding:
        # Deduplicate: the agent sometimes proves the same bug twice. A finding on the same
        # target with the same CWE (or, absent a CWE, the same title) is treated as a repeat
        # and merged rather than recorded again, so repeated proof doesn't inflate the count.
        existing = self._find_duplicate(finding)
        if existing is not None:
            if finding.reproductions > existing.reproductions:
                existing.reproductions = finding.reproductions
                existing.trials = finding.trials
            self._flush()
            return existing
        self._findings.append(finding)
        self._flush()
        return finding

    @staticmethod
    def _norm_target(target: str) -> str:
        # Agents sometimes append prose to the target ("http://.../ftp/ (path traversal)").
        # Compare on the leading URL/token only so such near-duplicates still collapse.
        return (target or "").strip().split()[0].rstrip("/").lower() if target else ""

    def _find_duplicate(self, finding: Finding) -> Finding | None:
        nt = self._norm_target(finding.target)
        for f in self._findings:
            if self._norm_target(f.target) != nt:
                continue
            if finding.cwe and f.cwe == finding.cwe:
                return f
            if not finding.cwe and f.title == finding.title:
                return f
        return None

    def all(self) -> list[Finding]:
        order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        return sorted(self._findings, key=lambda f: order.get(f.severity, 99))

    def get(self, finding_id: str) -> Finding | None:
        return next((f for f in self._findings if f.id == finding_id), None)

    def pending(self) -> list[Finding]:
        """Findings whose own k-of-n check passed but have not survived an independent
        re-check yet — the worklist for the VERIFY specialist/tool."""
        return [f for f in self._findings if f.confidence == "pending_verification"]

    def promote(self, finding_id: str, verdict: str, detail: str = "") -> Finding | None:
        """Apply an INDEPENDENT re-check's verdict. Only this path may set confidence to
        'confirmed' — closing the self-grading loop (see tools/independent_verify.py)."""
        f = self.get(finding_id)
        if f is None:
            return None
        f.independent_verdict = verdict
        if verdict == "confirmed":
            f.confidence = "confirmed"
        elif verdict == "falsified":
            f.confidence = "falsified"
        else:
            f.confidence = "not_reproducible"
        if detail:
            f.evidence = (f.evidence + "\n[independent re-check] " + detail).strip()
        self._flush()
        return f

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(f) for f in self._findings], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

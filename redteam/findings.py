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
    confidence: str = "tentative"  # tentative | firm | confirmed
    # Verification record (populated when a finding was reproduced by verify.py).
    verification_verdict: str = ""   # confirmed | not_reproducible | rejected
    reproductions: int = 0
    trials: int = 0
    poc: str = ""                    # reproducible proof-of-concept steps
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

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(f) for f in self._findings], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

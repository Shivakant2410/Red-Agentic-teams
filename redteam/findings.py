"""Findings data model and store.

A finding is a single, defensible security observation the agent recorded during the
run. The store keeps them in memory and persists to JSON so the report generator and
a human reviewer can work from the same source of truth.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")

_CWE_ID = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
# Headers that carry the requesting identity. Shared with the independent re-check, which
# strips them to build a no-credentials control for authorization findings.
CREDENTIAL_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token")


def normalize_cwe(cwe: str) -> str:
    """'CWE-639 Authorization Bypass…', 'cwe 639', '(CWE-639)' -> 'CWE-639'; else as given."""
    m = _CWE_ID.search(cwe or "")
    return f"CWE-{m.group(1)}" if m else (cwe or "").strip()


def proof_request(check_type: str, spec: dict) -> dict | None:
    """The request whose response carries a finding's signal, from its replay spec."""
    if check_type == "http":
        return spec.get("request")
    if check_type == "differential":
        return spec.get("payload_request")
    if check_type == "proof":
        reqs = spec.get("requests") or {}
        return reqs.get(spec.get("control_replaces") or "payload")
    return None


def request_principal(req: dict) -> str:
    """Who made the request: its credential header, else its session label, else ''."""
    headers = {str(k).lower(): v for k, v in (req.get("headers") or {}).items()}
    for name in CREDENTIAL_HEADERS:
        if headers.get(name):
            return f"{name}:{headers[name]}"
    return f"session:{req['session_label']}" if req.get("session_label") else ""


def _observation_key(f: "Finding") -> tuple | None:
    """Same request + same identity = same observation, however the model titled it."""
    req = proof_request(f.check_type, f.check_spec or {})
    if not req or not req.get("url"):
        return None
    body = req.get("body")
    return (str(req.get("method") or "GET").upper(), req["url"].split("#", 1)[0],
            json.dumps(body, sort_keys=True, default=str) if body is not None else "",
            request_principal(req))


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
    duplicate_hits: int = 0          # times an agent re-proved this same observation
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        self.cwe = normalize_cwe(self.cwe)


class FindingStore:
    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._findings: list[Finding] = []
        # Shared across a parallel exploit swarm's threads (see orchestrator.py) — every
        # mutating method below and the list-returning reads take this lock so concurrent
        # add()/promote() calls from different specialist contexts can't race (lost
        # findings, or dedup matching against a half-updated list).
        self._lock = threading.Lock()
        # Per-thread ("added" | "duplicate", finding_id) events, so each swarm worker's
        # agent loop learns about its OWN adds (to verify them at once) and duplicates (to
        # stop re-proving) without seeing other workers'.
        self._events: dict[int, list[tuple[str, str]]] = defaultdict(list)
        if self._path.exists():
            for row in json.loads(self._path.read_text(encoding="utf-8")):
                self._findings.append(Finding(**row))

    def add(self, finding: Finding) -> Finding:
        # Deduplicate: the agent sometimes proves the same bug twice. A finding on the same
        # target with the same CWE (or, absent a CWE, the same title) is treated as a repeat
        # and merged rather than recorded again, so repeated proof doesn't inflate the count.
        with self._lock:
            existing = self._find_duplicate(finding)
            if existing is not None:
                if finding.reproductions > existing.reproductions:
                    existing.reproductions = finding.reproductions
                    existing.trials = finding.trials
                if finding.cwe and not existing.cwe:
                    existing.cwe = finding.cwe
                existing.duplicate_hits += 1
                self._events[threading.get_ident()].append(("duplicate", existing.id))
                self._flush()
                return existing
            self._findings.append(finding)
            self._events[threading.get_ident()].append(("added", finding.id))
            self._flush()
            return finding

    def pop_events(self) -> list[tuple[str, str]]:
        """Drain the calling thread's ("added" | "duplicate", finding_id) events."""
        with self._lock:
            return self._events.pop(threading.get_ident(), [])

    @staticmethod
    def _norm_target(target: str) -> str:
        # Agents sometimes append prose to the target ("http://.../ftp/ (path traversal)").
        # Compare on the leading URL/token only so such near-duplicates still collapse.
        return (target or "").strip().split()[0].rstrip("/").lower() if target else ""

    def _find_duplicate(self, finding: Finding) -> Finding | None:
        key = _observation_key(finding)
        if key is not None:
            for f in self._findings:
                if _observation_key(f) == key:
                    return f
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
        with self._lock:
            order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
            return sorted(self._findings, key=lambda f: order.get(f.severity, 99))

    def get(self, finding_id: str) -> Finding | None:
        with self._lock:
            return next((f for f in self._findings if f.id == finding_id), None)

    def pending(self) -> list[Finding]:
        """Findings whose own k-of-n check passed but have not survived an independent
        re-check yet — the worklist for the VERIFY specialist/tool."""
        with self._lock:
            return [f for f in self._findings if f.confidence == "pending_verification"]

    def promote(self, finding_id: str, verdict: str, detail: str = "") -> Finding | None:
        """Apply an INDEPENDENT re-check's verdict. Only this path may set confidence to
        'confirmed' — closing the self-grading loop (see tools/independent_verify.py)."""
        with self._lock:
            f = next((x for x in self._findings if x.id == finding_id), None)
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

"""Tests for report generation (redaction, confirmed/tentative) and audit-chain integrity."""

from __future__ import annotations

import datetime as _dt
import json

from redteam.audit import AuditLog
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.findings import Finding, FindingStore
from redteam.report import build_html_report, build_report, redact


def _engagement():
    return Engagement(
        name="Test Eng", client="Acme", authorized_by="CISO", ticket="SOW-1",
        starts=_dt.date.today(), ends=_dt.date.today() + _dt.timedelta(days=5),
        allowed_hosts=("api.acme.example",), excluded_hosts=(),
        allowed_ports=(443,), allowed_schemes=("https",),
        max_requests_per_second=3.0, max_total_requests=100,
        allow_private_ranges=False, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


def test_redaction_masks_secrets():
    assert "[REDACTED]" in redact("Authorization: Bearer abc123def456ghi")
    assert "[REDACTED]" in redact('{"password":"hunter2"}')
    assert "[REDACTED-JWT]" in redact("token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")


def test_report_separates_confirmed_and_tentative(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    store.add(Finding(title="SQLi", severity="critical", target="https://api.acme.example/login",
                      summary="s", confidence="confirmed", reproductions=5, trials=5,
                      poc="GET /login?id=1'", cwe="CWE-89"))
    store.add(Finding(title="Maybe XSS", severity="low", target="https://api.acme.example/q",
                      summary="s2", confidence="tentative"))
    md = build_report(_engagement(), store)
    assert "Confirmed findings" in md and "Tentative findings" in md
    assert "Reproduced 5/5" in md
    html = build_html_report(_engagement(), store)
    assert "confirmed" in html and "SQLi" in html


def test_report_redacts_evidence(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    store.add(Finding(title="Leak", severity="high", target="https://api.acme.example/x",
                      summary="s", evidence="Authorization: Bearer supersecrettoken123456",
                      confidence="confirmed"))
    md = build_report(_engagement(), store)
    assert "supersecrettoken" not in md and "[REDACTED]" in md


def test_audit_chain_intact_then_broken(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("a", x=1)
    log.record("b", y=2)
    log.record("c", z=3)
    assert log.verify_chain() is True

    # Tamper with a middle line — the chain must detect it.
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["y"] = 999
    lines[1] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert AuditLog(path).verify_chain() is False


def test_audit_chain_resumes(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("a", x=1)
    log2 = AuditLog(path)          # resume from existing file
    log2.record("b", y=2)
    assert log2.verify_chain() is True
    assert len(log2.read_all()) == 2

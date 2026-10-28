"""Tests for the benchmark scorer — the definition of 'better' as a number."""

from __future__ import annotations

from redteam.bench.scoring import GroundTruthVuln, score_run
from redteam.bench.targets import get_target


def _gt():
    return [
        GroundTruthVuln("sqli", "injection", cwe="CWE-89", endpoint_hint="/login"),
        GroundTruthVuln("idor", "idor", cwe="CWE-639", endpoint_hint="/basket/"),
        GroundTruthVuln("xss", "xss", cwe="CWE-79", endpoint_hint="/search"),
    ]


def test_perfect_run():
    findings = [
        {"title": "SQLi", "confidence": "confirmed", "cwe": "CWE-89", "target": "http://x/login"},
        {"title": "IDOR", "confidence": "confirmed", "cwe": "CWE-639", "target": "http://x/basket/1"},
        {"title": "XSS", "confidence": "confirmed", "cwe": "CWE-79", "target": "http://x/search"},
    ]
    card = score_run("t", findings, _gt())
    assert card.true_positives == 3 and card.false_positives == 0 and card.false_negatives == 0
    assert card.precision == 1.0 and card.recall == 1.0 and card.f1 == 1.0


def test_false_positive_hurts_precision():
    findings = [
        {"title": "SQLi", "confidence": "confirmed", "cwe": "CWE-89", "target": "http://x/login"},
        {"title": "Made up", "confidence": "confirmed", "cwe": "CWE-000", "target": "http://x/nope"},
    ]
    card = score_run("t", findings, _gt())
    assert card.true_positives == 1 and card.false_positives == 1
    assert card.false_negatives == 2
    assert card.precision == 0.5
    assert "Made up" in card.spurious


def test_tentative_findings_do_not_count():
    findings = [
        {"title": "Maybe SQLi", "confidence": "tentative", "cwe": "CWE-89", "target": "http://x/login"},
    ]
    card = score_run("t", findings, _gt())
    # A tentative guess is neither a true nor false positive — it isn't a claim.
    assert card.true_positives == 0 and card.false_positives == 0
    assert card.false_negatives == 3


def test_info_recon_findings_do_not_count_as_false_positives():
    # Confirmed recon notes at 'info' severity are not vulnerability claims.
    findings = [
        {"title": "SQLi", "confidence": "confirmed", "cwe": "CWE-89", "target": "http://x/login"},
        {"title": "Recon: login endpoint", "confidence": "confirmed", "severity": "info",
         "cwe": "", "target": "http://x/login"},
        {"title": "Recon: search API", "confidence": "confirmed", "severity": "info",
         "cwe": "", "target": "http://x/search"},
    ]
    card = score_run("t", findings, _gt())
    assert card.true_positives == 1
    assert card.false_positives == 0        # info recon excluded, not penalized
    assert card.precision == 1.0


def test_match_by_endpoint_hint_without_cwe():
    findings = [{"title": "XSS", "confidence": "confirmed", "cwe": "", "target": "http://x/search?q=1"}]
    card = score_run("t", findings, _gt())
    assert "xss" in card.matched


def test_targets_registry_has_ground_truth():
    js = get_target("juice-shop")
    assert js.ground_truth and js.base_url.startswith("http://localhost")

from dataclasses import replace

from agentic_setup.benchmark import (
    evaluate_local_header_benchmark,
    local_header_cases,
)
from agentic_setup.local_assessment import EvidenceVerifierAgent, Finding


def test_synthetic_local_header_benchmark_meets_under_two_percent_fpr():
    metrics = evaluate_local_header_benchmark()

    assert metrics.cases == 960
    assert metrics.applicable_labels == 288
    assert metrics.true_positive == 144
    assert metrics.true_negative == 144
    assert metrics.false_positive_rate < 0.02
    assert metrics.false_discovery_rate < 0.02
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_benchmark_includes_negative_http_and_non_html_cases():
    cases = local_header_cases()

    negatives = [
        case
        for case in cases
        if case.status != 200
        or not case.content_type.lower().startswith("text/html")
    ]
    assert len(negatives) == 896
    assert all(not case.expected_findings for case in negatives)


def test_evidence_verifier_rejects_unobserved_or_inapplicable_claims():
    from agentic_setup.local_assessment import HttpObservation, LocalScope

    scope = LocalScope("http://127.0.0.1:8080")
    observation = HttpObservation(
        url=scope.base_url + "/",
        status=200,
        elapsed_ms=1,
        content_type="text/html",
        content_length=1,
        security_headers=("content-security-policy",),
        title=None,
        body_excerpt=None,
        error=None,
    )
    unobserved = Finding(
        check_id="header-content-security-policy",
        severity="info",
        title="missing",
        evidence="not supported by observation",
        evidence_url=observation.url,
    )
    wrong_url = replace(
        unobserved,
        check_id="header-x-content-type-options",
        evidence_url="http://127.0.0.1:8080/other",
    )

    verified = EvidenceVerifierAgent().verify(
        scope,
        (observation,),
        (unobserved, wrong_url),
    )

    assert verified == ()


def test_benchmark_detects_deliberately_broken_finding_gate():
    cases = list(local_header_cases())
    case = next(case for case in cases if case.status == 302)
    scope, observations = case.observation()
    assert case.expected_findings == ()
    false_finding = Finding(
        check_id="header-content-security-policy",
        severity="info",
        title="hallucinated",
        evidence="no evidence",
        evidence_url=observations[0].url,
    )
    verified = EvidenceVerifierAgent().verify(scope, observations, (false_finding,))

    assert verified == ()

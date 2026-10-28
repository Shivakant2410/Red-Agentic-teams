"""Deterministic synthetic benchmark for the narrowly scoped header-posture agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from .local_assessment import (
    SECURITY_HEADERS,
    EvidenceVerifierAgent,
    HeaderPostureAgent,
    HttpObservation,
    LocalScope,
)


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    scheme: str
    status: int
    content_type: str
    present_headers: tuple[str, ...]
    expected_findings: tuple[str, ...]

    def observation(self) -> tuple[LocalScope, tuple[HttpObservation, ...]]:
        scope = LocalScope(f"{self.scheme}://127.0.0.1:8080")
        observation = HttpObservation(
            url=scope.base_url + "/",
            status=self.status,
            elapsed_ms=1,
            content_type=self.content_type,
            content_length=128,
            security_headers=self.present_headers,
            title="fixture",
            body_excerpt=None,
            error=None,
        )
        return scope, (observation,)


@dataclass(frozen=True)
class BenchmarkMetrics:
    benchmark: str
    cases: int
    applicable_labels: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    false_positive_rate: float
    false_discovery_rate: float
    precision: float
    recall: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


@dataclass(frozen=True)
class CORSFixtureResult:
    fixture: str
    expected_finding: bool
    actual_finding: bool
    evidence: str


@dataclass(frozen=True)
class CORSFixtureMetrics:
    benchmark: str
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    false_positive_rate: float
    results: tuple[CORSFixtureResult, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def evaluate_cors_fixture_results(
    safe_report,
    vulnerable_report,
) -> CORSFixtureMetrics:
    safe_found = any(
        finding.check_id == "cors-reflected-origin-with-credentials"
        for finding in safe_report.findings
    )
    vulnerable_finding = next(
        (
            finding
            for finding in vulnerable_report.findings
            if finding.check_id == "cors-reflected-origin-with-credentials"
        ),
        None,
    )
    vulnerable_found = vulnerable_finding is not None
    false_positive = int(safe_found)
    false_negative = int(not vulnerable_found)
    true_positive = int(vulnerable_found)
    true_negative = int(not safe_found)
    negatives = false_positive + true_negative
    return CORSFixtureMetrics(
        benchmark="disposable-local-cors-fixture-v1",
        cases=2,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        true_negative=true_negative,
        false_positive_rate=false_positive / negatives if negatives else 0.0,
        results=(
            CORSFixtureResult(
                "safe-fixed-origin",
                False,
                safe_found,
                "No reflected assessment-origin credentialed CORS finding expected.",
            ),
            CORSFixtureResult(
                "intentionally-reflected-origin-with-credentials",
                True,
                vulnerable_found,
                vulnerable_finding.evidence if vulnerable_finding else "Expected finding was absent.",
            ),
        ),
    )


def local_header_cases() -> tuple[BenchmarkCase, ...]:
    cases: list[BenchmarkCase] = []
    content_types = (
        "text/html; charset=utf-8",
        "application/json",
        "text/plain",
    )
    statuses = (200, 204, 302, 401, 500)
    for scheme in ("http", "https"):
        for status in statuses:
            for content_type in content_types:
                for mask in range(1 << len(SECURITY_HEADERS)):
                    present = tuple(
                        header
                        for bit, header in enumerate(SECURITY_HEADERS)
                        if mask & (1 << bit)
                    )
                    applicable: tuple[str, ...] = ()
                    if status == 200 and content_type.lower().startswith("text/html"):
                        applicable = tuple(
                            header
                            for header in SECURITY_HEADERS
                            if header != "strict-transport-security" or scheme == "https"
                        )
                    expected = tuple(
                        f"header-{header}"
                        for header in applicable
                        if header not in present
                    )
                    cases.append(
                        BenchmarkCase(
                            case_id=f"{scheme}-{status}-{len(cases):04d}",
                            scheme=scheme,
                            status=status,
                            content_type=content_type,
                            present_headers=present,
                            expected_findings=expected,
                        )
                    )
    return tuple(cases)


def evaluate_local_header_benchmark(
    cases: tuple[BenchmarkCase, ...] | None = None,
) -> BenchmarkMetrics:
    cases = cases or local_header_cases()
    analyzer = HeaderPostureAgent()
    verifier = EvidenceVerifierAgent()
    true_positive = false_positive = false_negative = true_negative = 0
    applicable_label_count = 0

    for case in cases:
        scope, observations = case.observation()
        proposed = analyzer.analyze(scope, observations)
        verified = verifier.verify(scope, observations, proposed)
        expected = set(case.expected_findings)
        actual = {finding.check_id for finding in verified}
        applicable_labels = {
            f"header-{header}" for header in _applicable_headers(case)
        }
        applicable_label_count += len(applicable_labels)
        # Treat every eligible header/check pair as a binary label.
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        true_negative += len(applicable_labels - expected - actual)

    fpr_denominator = false_positive + true_negative
    emitted_denominator = true_positive + false_positive
    positive_denominator = true_positive + false_negative
    return BenchmarkMetrics(
        benchmark="synthetic-local-http-header-posture-v1",
        cases=len(cases),
        applicable_labels=applicable_label_count,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        true_negative=true_negative,
        false_positive_rate=false_positive / fpr_denominator if fpr_denominator else 0.0,
        false_discovery_rate=(
            false_positive / emitted_denominator if emitted_denominator else 0.0
        ),
        precision=true_positive / emitted_denominator if emitted_denominator else 1.0,
        recall=true_positive / positive_denominator if positive_denominator else 1.0,
    )


def _applicable_headers(case: BenchmarkCase) -> set[str]:
    if (
        case.status != 200
        or not case.content_type.lower().startswith("text/html")
    ):
        return set()
    return {
        header
        for header in SECURITY_HEADERS
        if header != "strict-transport-security" or case.scheme == "https"
    }

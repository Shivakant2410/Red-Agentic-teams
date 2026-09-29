"""Read-only object-level authorization checks for the seeded local API lab."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Protocol


PRINCIPAL_TENANTS = {
    "tenant-a-user": "tenant-a",
    "tenant-b-user": "tenant-b",
}
RECORD_TENANTS = {
    "record-a": "tenant-a",
    "record-b": "tenant-b",
}


@dataclass(frozen=True)
class AuthorizationObservation:
    principal: str
    record_id: str
    expected_tenant: str
    status: int | None
    returned_record_id: str | None
    returned_tenant: str | None
    response_bytes: int
    elapsed_ms: int
    error: str | None


@dataclass(frozen=True)
class AuthorizationFinding:
    check_id: str
    severity: str
    title: str
    evidence: str


@dataclass(frozen=True)
class AuthorizationReport:
    observations: tuple[AuthorizationObservation, ...]
    findings: tuple[AuthorizationFinding, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class AuthorizationProbe(Protocol):
    def get_record(
        self, principal: str, record_id: str
    ) -> AuthorizationObservation: ...


class ObjectAuthorizationAssessment:
    """Tests a fixed 2x2 principal/resource matrix; never mutates lab data."""

    def run(self, probe: AuthorizationProbe) -> AuthorizationReport:
        observations = tuple(
            probe.get_record(principal, record_id)
            for principal in PRINCIPAL_TENANTS
            for record_id in RECORD_TENANTS
        )
        findings = tuple(
            AuthorizationFinding(
                check_id=f"object-authorization:{item.principal}:{item.record_id}",
                severity="high",
                title="Cross-tenant record was returned to an unauthorized identity",
                evidence=(
                    f"Principal {item.principal} received record {item.returned_record_id} "
                    f"owned by {item.returned_tenant}; this lab principal belongs to "
                    f"{PRINCIPAL_TENANTS[item.principal]}."
                ),
            )
            for item in observations
            if item.status is not None
            and 200 <= item.status < 300
            and item.returned_record_id == item.record_id
            and item.returned_tenant == item.expected_tenant
            and item.expected_tenant != PRINCIPAL_TENANTS[item.principal]
        )
        return AuthorizationReport(observations=observations, findings=findings)


@dataclass(frozen=True)
class AuthorizationBenchmarkMetrics:
    benchmark: str
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    false_positive_rate: float
    recall: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def evaluate_authorization_fixtures(
    safe_report: AuthorizationReport,
    vulnerable_report: AuthorizationReport,
) -> AuthorizationBenchmarkMetrics:
    expected_pairs = {
        (principal, record_id)
        for principal in PRINCIPAL_TENANTS
        for record_id in RECORD_TENANTS
    }
    for fixture_name, report in (
        ("safe", safe_report),
        ("vulnerable", vulnerable_report),
    ):
        actual_pairs = {
            (item.principal, item.record_id) for item in report.observations
        }
        if (
            len(report.observations) != len(expected_pairs)
            or actual_pairs != expected_pairs
            or any(item.status is None for item in report.observations)
        ):
            raise ValueError(
                f"{fixture_name} authorization fixture did not produce a complete "
                "2x2 response matrix"
            )

    safe_findings = {finding.check_id for finding in safe_report.findings}
    vulnerable_findings = {
        finding.check_id for finding in vulnerable_report.findings
    }
    cross_tenant_checks = {
        f"object-authorization:{principal}:{record_id}"
        for principal, tenant in PRINCIPAL_TENANTS.items()
        for record_id, owner in RECORD_TENANTS.items()
        if tenant != owner
    }
    false_positive = len(safe_findings & cross_tenant_checks)
    true_negative = len(cross_tenant_checks - safe_findings)
    true_positive = len(vulnerable_findings & cross_tenant_checks)
    false_negative = len(cross_tenant_checks - vulnerable_findings)
    negatives = false_positive + true_negative
    positives = true_positive + false_negative
    return AuthorizationBenchmarkMetrics(
        benchmark="disposable-local-object-authorization-v1",
        cases=len(cross_tenant_checks) * 2,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        true_negative=true_negative,
        false_positive_rate=false_positive / negatives if negatives else 0.0,
        recall=true_positive / positives if positives else 1.0,
    )

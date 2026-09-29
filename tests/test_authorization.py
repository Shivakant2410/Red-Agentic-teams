from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from agentic_setup.authorization import (
    AuthorizationObservation,
    ObjectAuthorizationAssessment,
    evaluate_authorization_fixtures,
)
from lab import server as lab_server
from agentic_setup.tool_broker import (
    DockerExecAuthorizationProbe,
    ToolPolicyError,
)


class FixtureProbe:
    def __init__(self, broken: bool):
        self.broken = broken
        self.calls = []

    def get_record(self, principal, record_id):
        self.calls.append((principal, record_id))
        tenant = "tenant-a" if record_id == "record-a" else "tenant-b"
        caller = principal.removeprefix("tenant-").removesuffix("-user")
        allowed = caller == tenant.removeprefix("tenant-") or self.broken
        return AuthorizationObservation(
            principal=principal,
            record_id=record_id,
            expected_tenant=tenant,
            status=200 if allowed else 403,
            returned_record_id=record_id if allowed else None,
            returned_tenant=tenant if allowed else None,
            response_bytes=48 if allowed else 21,
            elapsed_ms=1,
            error=None,
        )


def test_assessment_runs_fixed_two_by_two_matrix_and_reports_cross_tenant_leaks():
    probe = FixtureProbe(broken=True)

    report = ObjectAuthorizationAssessment().run(probe)

    assert probe.calls == [
        ("tenant-a-user", "record-a"),
        ("tenant-a-user", "record-b"),
        ("tenant-b-user", "record-a"),
        ("tenant-b-user", "record-b"),
    ]
    assert {
        finding.check_id for finding in report.findings
    } == {
        "object-authorization:tenant-a-user:record-b",
        "object-authorization:tenant-b-user:record-a",
    }
    assert all(finding.severity == "high" for finding in report.findings)


def test_benchmark_measures_safe_and_broken_fixtures_separately():
    safe = ObjectAuthorizationAssessment().run(FixtureProbe(broken=False))
    broken = ObjectAuthorizationAssessment().run(FixtureProbe(broken=True))

    metrics = evaluate_authorization_fixtures(safe, broken)

    assert metrics.cases == 4
    assert metrics.true_positive == 2
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.true_negative == 2
    assert metrics.false_positive_rate == 0
    assert metrics.recall == 1


def test_benchmark_rejects_incomplete_or_timed_out_fixture_reports():
    incomplete = ObjectAuthorizationAssessment().run(FixtureProbe(broken=False))
    incomplete = type(incomplete)(
        observations=incomplete.observations[:-1],
        findings=incomplete.findings,
    )
    complete_vulnerable = ObjectAuthorizationAssessment().run(FixtureProbe(broken=True))

    with pytest.raises(ValueError, match="complete 2x2"):
        evaluate_authorization_fixtures(incomplete, complete_vulnerable)


@pytest.mark.parametrize(
    ("status", "returned_record", "returned_tenant"),
    [
        (403, "record-b", "tenant-b"),
        (200, "record-a", "tenant-a"),
        (200, "record-b", "tenant-a"),
        (200, "record-b", None),
    ],
)
def test_finding_requires_success_and_matching_record_owner_evidence(
    status, returned_record, returned_tenant
):
    class EvidenceProbe:
        def get_record(self, principal, record_id):
            if (principal, record_id) == ("tenant-a-user", "record-b"):
                return AuthorizationObservation(
                    principal=principal,
                    record_id=record_id,
                    expected_tenant="tenant-b",
                    status=status,
                    returned_record_id=returned_record,
                    returned_tenant=returned_tenant,
                    response_bytes=16,
                    elapsed_ms=1,
                    error=None,
                )
            return AuthorizationObservation(
                principal=principal,
                record_id=record_id,
                expected_tenant="tenant-a" if record_id == "record-a" else "tenant-b",
                status=403 if principal.split("-")[1] != record_id[-1] else 200,
                returned_record_id=None,
                returned_tenant=None,
                response_bytes=16,
                elapsed_ms=1,
                error=None,
            )

    report = ObjectAuthorizationAssessment().run(EvidenceProbe())
    assert "object-authorization:tenant-a-user:record-b" not in {
        finding.check_id for finding in report.findings
    }


@pytest.mark.parametrize(
    ("profile", "token", "path", "expected_status"),
    [
        ("safe", "Bearer lab-token-a", "/api/records/record-a", 200),
        ("safe", "Bearer lab-token-a", "/api/records/record-b", 403),
        ("broken-owner-check", "Bearer lab-token-a", "/api/records/record-b", 200),
        ("safe", "Bearer invalid", "/api/records/record-a", 401),
    ],
)
def test_local_api_fixture_enforces_or_violates_tenant_ownership(
    profile, token, path, expected_status, monkeypatch
):
    monkeypatch.setenv("LAB_AUTHZ_PROFILE", profile)
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab_server.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request = Request(
        f"http://127.0.0.1:{server.server_port}{path}",
        headers={"Authorization": token},
        method="GET",
    )
    try:
        try:
            with urlopen(request, timeout=2) as response:
                status = response.status
        except HTTPError as response:
            status = response.code
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == expected_status


def test_docker_authz_probe_uses_fixed_command_and_rejects_unlisted_identity(
    monkeypatch,
):
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return __import__("subprocess").CompletedProcess(
            command,
            0,
            '{"status":200,"elapsed_ms":1,"response_bytes":40,'
            '"record_id":"record-b","tenant_id":"tenant-b","error":null}',
            "",
        )

    monkeypatch.setattr("agentic_setup.tool_broker.subprocess.run", fake_run)
    probe = DockerExecAuthorizationProbe("a" * 64)

    observation = probe.get_record("tenant-a-user", "record-b")

    command, options = commands[0]
    assert command[-3:] == ["authz", "tenant-a-user", "record-b"]
    assert command[command.index("--user") + 1] == "65534:65534"
    assert options["shell"] is False
    assert observation.returned_record_id == "record-b"
    assert observation.returned_tenant == "tenant-b"
    assert probe.events[0].tool == "authorization_get"
    with pytest.raises(ToolPolicyError, match="not allowlisted"):
        probe.get_record("attacker", "record-b")

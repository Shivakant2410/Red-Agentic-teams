from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from agentic_setup.local_assessment import (
    LocalAssessmentAgent,
    LocalHttpInventory,
    LocalScope,
    ReadOnlyPlannerAgent,
    SAFE_PATHS,
    TargetScopeError,
)


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://192.168.1.10:8080",
        "http://127.0.0.1/private/path",
        "http://127.0.0.1:8080/?q=1",
        "http://user:pass@localhost:8080",
        "file:///etc/passwd",
    ],
)
def test_local_scope_rejects_non_loopback_or_non_origin_urls(target):
    with pytest.raises(TargetScopeError):
        LocalScope.parse(target)


def test_explicit_confirmation_is_required_before_inventory():
    class NeverRunInventory:
        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            raise AssertionError("inventory must not run without confirmation")

    with pytest.raises(TargetScopeError, match="confirmation"):
        LocalAssessmentAgent(NeverRunInventory()).run(
            "http://127.0.0.1:8000",
            confirmed_local_lab=False,
        )


def test_local_assessment_uses_only_fixed_get_paths_and_reports_headers():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(200 if self.path == "/" else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<html><title>Local Lab</title><body>ok</body></html>")

        def do_POST(self):
            seen.append(("POST", self.path))
            self.send_error(405)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        report = LocalAssessmentAgent(
            LocalHttpInventory(timeout_seconds=1)
        ).run(
            f"http://127.0.0.1:{server.server_port}",
            confirmed_local_lab=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert seen == [("GET", path) for path in SAFE_PATHS]
    assert len(report.observations) == len(SAFE_PATHS)
    assert report.observations[0].title == "Local Lab"
    assert all(finding.severity == "info" for finding in report.findings)
    assert "no exploit actions ran" in report.summary.lower()
    assert len(report.tool_events) == len(SAFE_PATHS)
    assert {event.tool for event in report.tool_events} == {"http_get"}
    assert {event.method for event in report.tool_events} == {"GET"}


def test_redirects_are_not_followed():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        report = LocalAssessmentAgent(
            LocalHttpInventory(timeout_seconds=1)
        ).run(
            f"http://127.0.0.1:{server.server_port}",
            confirmed_local_lab=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert seen == list(SAFE_PATHS)
    assert report.observations[0].status == 302
    assert report.observations[0].error == "redirect not followed"


def test_model_summary_receives_metadata_without_body_excerpt():
    class StubInventory:
        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            from agentic_setup.local_assessment import HttpObservation

            return (
                HttpObservation(
                    url=scope.base_url + "/",
                    status=200,
                    elapsed_ms=2,
                    content_type="text/html",
                    content_length=30,
                    security_headers=(),
                    title="lab",
                    body_excerpt="secret page content",
                    error=None,
                ),
            )

    received = []
    report = LocalAssessmentAgent(StubInventory()).run(
        "http://localhost:9000",
        confirmed_local_lab=True,
        model_summary=lambda evidence: received.extend(evidence) or "summary",
    )

    assert report.model_summary == "summary"
    assert received == [
        {
            "url": "http://localhost:9000/",
            "status": 200,
            "content_type": "text/html",
            "cors_allow_origin": None,
            "cors_allow_credentials": None,
            "title": "lab",
            "error": None,
        }
    ]


def test_serialized_report_contains_no_response_body():
    class StubInventory:
        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            from agentic_setup.local_assessment import HttpObservation

            return (
                HttpObservation(
                    url=scope.base_url + "/",
                    status=200,
                    elapsed_ms=1,
                    content_type="text/plain",
                    content_length=12,
                    security_headers=(),
                    title=None,
                    body_excerpt="secret marker",
                    error=None,
                ),
            )

    report = LocalAssessmentAgent(StubInventory()).run(
        "http://127.0.0.1:9001",
        confirmed_local_lab=True,
    )

    assert "secret marker" not in report.to_json()
    assert report.observations[0].body_excerpt == "secret marker"


def test_planner_can_select_only_allowlisted_fixed_get_paths():
    planner = ReadOnlyPlannerAgent()
    plan = planner.create(
        lambda allowed: (
            '{"paths":["/","/health"],"rationale":"Check app and health"}'
        )
    )

    assert plan.paths == ("/", "/health")
    assert set(plan.paths).issubset(SAFE_PATHS)


@pytest.mark.parametrize(
    "model_output",
    [
        '{"paths":["http://example.com/"],"rationale":"escape"}',
        '{"paths":["/"],"command":"curl example.com"}',
        '{"paths":[],"rationale":"do nothing"}',
        "not-json",
    ],
)
def test_planner_rejects_invalid_or_unsafe_model_output(model_output):
    with pytest.raises((ValueError, TargetScopeError)):
        ReadOnlyPlannerAgent().create(lambda allowed: model_output)


def test_model_planned_checks_flow_into_tool_execution_and_report():
    class RecordingInventory:
        def __init__(self):
            self.paths = None

        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            self.paths = paths
            return ()

    inventory = RecordingInventory()
    report = LocalAssessmentAgent(inventory).run(
        "http://127.0.0.1:9002",
        confirmed_local_lab=True,
        model_plan=lambda allowed: '{"paths":["/robots.txt"],"rationale":"robots only"}',
    )

    assert inventory.paths == ("/robots.txt",)
    assert report.planned_paths == ("/robots.txt",)
    assert report.completed_phases == (
        "scope-validation",
        "read-only-planning",
        "read-only-inventory",
        "header-posture-analysis",
        "cors-policy-analysis",
        "evidence-verification",
        "reporting",
    )


def test_model_analysis_can_only_select_evidence_checked_candidate_ids():
    seen = []

    class Inventory:
        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            from agentic_setup.local_assessment import HttpObservation

            return (
                HttpObservation(
                    url=scope.base_url + "/",
                    status=200,
                    elapsed_ms=1,
                    content_type="text/html",
                    content_length=20,
                    security_headers=("x-content-type-options",),
                    title="lab",
                    body_excerpt="private body",
                    error=None,
                ),
            )

    def model_analysis(evidence, candidates):
        seen.append((evidence, candidates))
        return '{"supported_check_ids":["header-content-security-policy"]}'

    report = LocalAssessmentAgent(Inventory()).run(
        "http://127.0.0.1:9003",
        confirmed_local_lab=True,
        model_analysis=model_analysis,
    )

    assert [finding.check_id for finding in report.findings] == [
        "header-content-security-policy"
    ]
    assert seen[0][0][0]["content_type"] == "text/html"
    assert "private body" not in str(seen[0][0])


def test_cors_specialist_flags_only_observed_reflection_with_credentials():
    from agentic_setup.local_assessment import CorsPolicyAgent, HttpObservation, LocalScope

    scope = LocalScope("http://127.0.0.1:8080")
    vulnerable = HttpObservation(
        url=scope.base_url + "/cors-policy",
        status=200,
        elapsed_ms=1,
        content_type="application/json",
        content_length=20,
        security_headers=(),
        title=None,
        body_excerpt=None,
        error=None,
        cors_allow_origin="https://assessment.invalid",
        cors_allow_credentials="true",
    )
    safe = HttpObservation(
        url=scope.base_url + "/cors-policy",
        status=200,
        elapsed_ms=1,
        content_type="application/json",
        content_length=20,
        security_headers=(),
        title=None,
        body_excerpt=None,
        error=None,
        cors_allow_origin="https://trusted.example",
        cors_allow_credentials="true",
    )

    agent = CorsPolicyAgent()
    assert len(agent.analyze(scope, (vulnerable,))) == 1
    assert agent.analyze(scope, (safe,)) == ()


def test_cors_finding_requires_evidence_url_and_matching_observed_headers():
    from agentic_setup.local_assessment import (
        CorsPolicyAgent,
        EvidenceVerifierAgent,
        HttpObservation,
        LocalScope,
    )

    scope = LocalScope("http://127.0.0.1:8080")
    cors = HttpObservation(
        url=scope.base_url + "/cors-policy",
        status=200,
        elapsed_ms=1,
        content_type="application/json",
        content_length=20,
        security_headers=(),
        title=None,
        body_excerpt=None,
        error=None,
        cors_allow_origin="https://assessment.invalid",
        cors_allow_credentials="true",
    )
    candidate = CorsPolicyAgent().analyze(scope, (cors,))[0]
    assert EvidenceVerifierAgent().verify(scope, (cors,), (candidate,)) == (
        candidate,
    )

    from dataclasses import replace

    tampered = replace(candidate, evidence_url=scope.base_url + "/")
    assert EvidenceVerifierAgent().verify(scope, (cors,), (tampered,)) == ()


@pytest.mark.parametrize(
    ("status", "allow_origin", "allow_credentials"),
    [
        (200, "https://assessment.invalid", None),
        (200, "*", "true"),
        (200, "https://trusted.example", "true"),
        (403, "https://assessment.invalid", "true"),
    ],
)
def test_cors_specialist_ignores_other_policy_combinations(
    status, allow_origin, allow_credentials
):
    from agentic_setup.local_assessment import CorsPolicyAgent, HttpObservation, LocalScope

    scope = LocalScope("http://127.0.0.1:8080")
    observation = HttpObservation(
        url=scope.base_url + "/cors-policy",
        status=status,
        elapsed_ms=1,
        content_type="application/json",
        content_length=20,
        security_headers=(),
        title=None,
        body_excerpt=None,
        error=None,
        cors_allow_origin=allow_origin,
        cors_allow_credentials=allow_credentials,
    )

    assert CorsPolicyAgent().analyze(scope, (observation,)) == ()


@pytest.mark.parametrize(
    "response",
    [
        "not-json",
        '{"supported_check_ids":["invented-check"]}',
        '{"supported_check_ids":[],"extra":"no"}',
    ],
)
def test_model_analysis_rejects_malformed_or_invented_finding_ids(response):
    class Inventory:
        @property
        def events(self):
            return ()

        def collect(self, scope, paths):
            from agentic_setup.local_assessment import HttpObservation

            return (
                HttpObservation(
                    url=scope.base_url + "/",
                    status=200,
                    elapsed_ms=1,
                    content_type="text/html",
                    content_length=1,
                    security_headers=(),
                    title=None,
                    body_excerpt=None,
                    error=None,
                ),
            )

    with pytest.raises(ValueError):
        LocalAssessmentAgent(Inventory()).run(
            "http://127.0.0.1:9004",
            confirmed_local_lab=True,
            model_analysis=lambda evidence, candidates: response,
        )

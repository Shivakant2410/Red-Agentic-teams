"""Read-only assessment workflow restricted to explicitly confirmed loopback labs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import html.parser
import ipaddress
import json
import re
from typing import TYPE_CHECKING, Callable
from urllib.parse import urljoin, urlsplit

if TYPE_CHECKING:
    from .tool_broker import HttpTool, ToolEvent


MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0
SAFE_PATHS = ("/", "/robots.txt", "/openapi.json", "/health", "/cors-policy")
SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)


class TargetScopeError(ValueError):
    pass


@dataclass(frozen=True)
class LocalScope:
    base_url: str

    @classmethod
    def parse(cls, target: str) -> LocalScope:
        try:
            parsed = urlsplit(target)
            port = parsed.port
        except ValueError as error:
            raise TargetScopeError("Target URL is malformed") from error

        host = (parsed.hostname or "").lower().rstrip(".")
        is_localhost = host == "localhost"
        try:
            is_loopback_ip = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback_ip = False

        if parsed.scheme not in ("http", "https"):
            raise TargetScopeError("Only HTTP(S) local lab URLs are allowed")
        if not (is_localhost or is_loopback_ip):
            raise TargetScopeError("Target must use localhost or a loopback IP address")
        if parsed.username or parsed.password:
            raise TargetScopeError("Credentials in target URLs are not allowed")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise TargetScopeError("Provide only the local lab origin, without path or query")
        if port is not None and not 1 <= port <= 65535:
            raise TargetScopeError("Target port is invalid")

        netloc = parsed.netloc
        if not netloc:
            netloc = host
        return cls(base_url=f"{parsed.scheme}://{netloc}")

    def url_for(self, path: str) -> str:
        if path not in SAFE_PATHS:
            raise TargetScopeError("Requested path is not in the fixed read-only probe list")
        return urljoin(self.base_url + "/", path.lstrip("/"))


@dataclass(frozen=True)
class HttpObservation:
    url: str
    status: int | None
    elapsed_ms: int
    content_type: str | None
    content_length: int | None
    security_headers: tuple[str, ...]
    title: str | None
    body_excerpt: str | None
    error: str | None
    cors_allow_origin: str | None = None
    cors_allow_credentials: str | None = None


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    title: str
    evidence: str
    confidence: str = "informational"
    evidence_url: str = ""


@dataclass(frozen=True)
class AssessmentReport:
    scope: str
    observations: tuple[HttpObservation, ...]
    findings: tuple[Finding, ...]
    summary: str
    model_summary: str | None = None
    planned_paths: tuple[str, ...] = ()
    tool_events: tuple[ToolEvent, ...] = ()
    completed_phases: tuple[str, ...] = ()

    def to_json(self) -> str:
        report = asdict(self)
        for observation in report["observations"]:
            observation.pop("body_excerpt", None)
        return json.dumps(report, indent=2, sort_keys=True)


class LocalHttpInventory:
    """Adapts the bounded HTTP broker to the inventory phase."""

    def __init__(
        self,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self._events: tuple[ToolEvent, ...] = ()
        self._broker: HttpTool | None = None

    def use_broker(self, broker: HttpTool) -> None:
        self._broker = broker

    def collect(
        self,
        scope: LocalScope,
        paths: tuple[str, ...] = SAFE_PATHS,
    ) -> tuple[HttpObservation, ...]:
        from .tool_broker import LocalHttpToolBroker

        broker = self._broker or LocalHttpToolBroker(
            scope,
            paths,
            max_calls=len(paths),
            max_response_bytes=self.max_response_bytes,
            timeout_seconds=self.timeout_seconds,
        )
        observations = tuple(broker.http_get(path) for path in paths)
        self._events = broker.events
        return observations

    @property
    def events(self) -> tuple[ToolEvent, ...]:
        return self._events


class LocalAssessmentAgent:
    """Phased local assessment workflow with evidence-gated specialist findings."""

    def __init__(
        self,
        inventory: LocalHttpInventory | None = None,
        scope_agent: ScopeAgent | None = None,
        posture_agent: HeaderPostureAgent | None = None,
        cors_agent: CorsPolicyAgent | None = None,
        verifier: EvidenceVerifierAgent | None = None,
        reporter: ReportAgent | None = None,
        planner: ReadOnlyPlannerAgent | None = None,
    ) -> None:
        self.inventory_agent = InventoryAgent(inventory or LocalHttpInventory())
        self.scope_agent = scope_agent or ScopeAgent()
        self.posture_agent = posture_agent or HeaderPostureAgent()
        self.cors_agent = cors_agent or CorsPolicyAgent()
        self.verifier = verifier or EvidenceVerifierAgent()
        self.reporter = reporter or ReportAgent()
        self.planner = planner or ReadOnlyPlannerAgent()

    def run(
        self,
        target: str,
        confirmed_local_lab: bool,
        inventory: LocalHttpInventory | None = None,
        model_summary: Callable[[list[dict[str, object]]], str] | None = None,
        model_plan: Callable[[tuple[str, ...]], str] | None = None,
        model_analysis: Callable[
            [list[dict[str, object]], tuple[Finding, ...]], str
        ]
        | None = None,
    ) -> AssessmentReport:
        scope = self.scope_agent.validate(target, confirmed_local_lab)
        plan = self.planner.create(model_plan)
        inventory_agent = (
            self.inventory_agent
            if inventory is None
            else InventoryAgent(inventory)
        )
        observations = inventory_agent.run(scope, plan.paths)
        proposed_findings = (
            self.posture_agent.analyze(scope, observations)
            + self.cors_agent.analyze(scope, observations)
        )
        if model_analysis is not None:
            proposed_findings = _select_model_supported_findings(
                proposed_findings,
                model_analysis(
                    [
                        {
                            "url": observation.url,
                            "status": observation.status,
                            "content_type": observation.content_type,
                            "security_headers": observation.security_headers,
                            "cors_allow_origin": observation.cors_allow_origin,
                            "cors_allow_credentials": observation.cors_allow_credentials,
                            "error": observation.error,
                        }
                        for observation in observations
                    ],
                    proposed_findings,
                ),
            )
        findings = self.verifier.verify(scope, observations, proposed_findings)
        ai_summary = None
        if model_summary is not None:
            evidence = [
                {
                    "url": observation.url,
                    "status": observation.status,
                    "content_type": observation.content_type,
                    "cors_allow_origin": observation.cors_allow_origin,
                    "cors_allow_credentials": observation.cors_allow_credentials,
                    "title": observation.title,
                    "error": observation.error,
                }
                for observation in observations
            ]
            ai_summary = model_summary(evidence)
        return self.reporter.build(
            scope,
            observations,
            findings,
            planned_paths=plan.paths,
            tool_events=inventory_agent.events,
            model_summary=ai_summary,
        )


class ScopeAgent:
    def validate(self, target: str, confirmed_local_lab: bool) -> LocalScope:
        if not confirmed_local_lab:
            raise TargetScopeError(
                "Explicit confirmation is required before assessing a local lab"
            )
        return LocalScope.parse(target)


class InventoryAgent:
    def __init__(self, inventory: LocalHttpInventory) -> None:
        self.inventory = inventory

    def run(
        self,
        scope: LocalScope,
        paths: tuple[str, ...],
    ) -> tuple[HttpObservation, ...]:
        return self.inventory.collect(scope, paths)

    @property
    def events(self) -> tuple[ToolEvent, ...]:
        return self.inventory.events


@dataclass(frozen=True)
class ReadOnlyPlan:
    paths: tuple[str, ...]
    rationale: str


class ReadOnlyPlannerAgent:
    """Selects only fixed GET checks; model output cannot supply URLs or commands."""

    def create(
        self,
        model_plan: Callable[[tuple[str, ...]], str] | None = None,
    ) -> ReadOnlyPlan:
        if model_plan is None:
            return ReadOnlyPlan(
                paths=SAFE_PATHS,
                rationale="Run the complete predefined, read-only local inventory.",
            )

        raw = model_plan(SAFE_PATHS)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError("Planner response must be valid JSON") from error
        if not isinstance(payload, dict) or set(payload) - {"paths", "rationale"}:
            raise ValueError("Planner response contains unsupported fields")
        paths = payload.get("paths")
        rationale = payload.get("rationale", "")
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            raise ValueError("Planner paths must be a list of strings")
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("Planner must choose one or more unique safe paths")
        if any(path not in SAFE_PATHS for path in paths):
            raise TargetScopeError("Planner requested a path outside the fixed safe-check list")
        if not isinstance(rationale, str):
            raise ValueError("Planner rationale must be a string")
        return ReadOnlyPlan(paths=tuple(paths), rationale=rationale[:500])


class HeaderPostureAgent:
    def analyze(
        self,
        scope: LocalScope,
        observations: tuple[HttpObservation, ...],
    ) -> tuple[Finding, ...]:
        root = _root_observation(scope, observations)
        if (
            root is None
            or root.status is None
            or root.status != 200
            or not (root.content_type or "").lower().startswith("text/html")
        ):
            return ()

        applicable = list(SECURITY_HEADERS)
        if urlsplit(scope.base_url).scheme != "https":
            applicable.remove("strict-transport-security")
        present = set(root.security_headers)
        return tuple(
            Finding(
                check_id=f"header-{header}",
                severity="info",
                title=f"HTML response does not include {header}",
                evidence=(
                    f"GET {root.url} returned HTTP {root.status} with content type "
                    f"{root.content_type!r} and did not include {header}."
                ),
                evidence_url=root.url,
            )
            for header in applicable
            if header not in present
        )


class CorsPolicyAgent:
    """Flags a narrow reflected-origin plus credentialed-CORS policy signal."""

    check_id = "cors-reflected-origin-with-credentials"

    def analyze(
        self,
        scope: LocalScope,
        observations: tuple[HttpObservation, ...],
    ) -> tuple[Finding, ...]:
        expected_url = scope.base_url + "/cors-policy"
        observation = next(
            (item for item in observations if item.url == expected_url),
            None,
        )
        if (
            observation is None
            or observation.status != 200
            or observation.cors_allow_origin != "https://assessment.invalid"
            or (observation.cors_allow_credentials or "").lower() != "true"
        ):
            return ()
        return (
            Finding(
                check_id=self.check_id,
                severity="info",
                title="CORS policy reflects the assessment origin with credentials enabled",
                evidence=(
                    "A fixed GET with Origin https://assessment.invalid received "
                    "Access-Control-Allow-Origin with the same origin and "
                    "Access-Control-Allow-Credentials: true. This is a policy "
                    "signal requiring application-specific review, not proof of "
                    "exploitable cross-origin access."
                ),
                confidence="high for observed policy; impact unverified",
                evidence_url=observation.url,
            ),
        )


class EvidenceVerifierAgent:
    def verify(
        self,
        scope: LocalScope,
        observations: tuple[HttpObservation, ...],
        findings: tuple[Finding, ...],
    ) -> tuple[Finding, ...]:
        root = _root_observation(scope, observations)
        verified_headers: tuple[Finding, ...] = ()
        if (
            root is not None
            and root.status == 200
            and (root.content_type or "").lower().startswith("text/html")
        ):
            applicable = list(SECURITY_HEADERS)
            if urlsplit(scope.base_url).scheme != "https":
                applicable.remove("strict-transport-security")
            present = set(root.security_headers)
            verified_headers = tuple(
                finding
                for finding in findings
                if finding.check_id.startswith("header-")
                and finding.check_id.removeprefix("header-") in applicable
                and finding.check_id.removeprefix("header-") not in present
                and finding.evidence_url == root.url
                and finding.severity == "info"
            )
        cors_url = scope.base_url + "/cors-policy"
        cors = next((item for item in observations if item.url == cors_url), None)
        verified_cors = tuple(
            finding
            for finding in findings
            if finding.check_id == CorsPolicyAgent.check_id
            and cors is not None
            and cors.status == 200
            and cors.cors_allow_origin == "https://assessment.invalid"
            and (cors.cors_allow_credentials or "").lower() == "true"
            and finding.evidence_url == cors_url
            and finding.severity == "info"
        )
        return verified_headers + verified_cors


class ReportAgent:
    def build(
        self,
        scope: LocalScope,
        observations: tuple[HttpObservation, ...],
        findings: tuple[Finding, ...],
        planned_paths: tuple[str, ...],
        tool_events: tuple[object, ...] = (),
        model_summary: str | None = None,
    ) -> AssessmentReport:
        summary = (
            f"Performed {len(observations)} fixed, read-only GET checks against "
            f"{scope.base_url}. No redirects were followed and no exploit actions ran. "
            f"Reported {len(findings)} informational header/CORS policy observations."
        )
        return AssessmentReport(
            scope=scope.base_url,
            observations=observations,
            findings=findings,
            summary=summary,
            model_summary=model_summary,
            planned_paths=planned_paths,
            tool_events=tool_events,
            completed_phases=(
                "scope-validation",
                "read-only-planning",
                "read-only-inventory",
                "header-posture-analysis",
                "cors-policy-analysis",
                "evidence-verification",
                "reporting",
            ),
        )


def _root_observation(
    scope: LocalScope,
    observations: tuple[HttpObservation, ...],
) -> HttpObservation | None:
    root_url = scope.base_url + "/"
    return next(
        (observation for observation in observations if observation.url == root_url),
        None,
    )


def _select_model_supported_findings(
    candidates: tuple[Finding, ...],
    model_response: str,
) -> tuple[Finding, ...]:
    try:
        payload = json.loads(model_response)
    except json.JSONDecodeError as error:
        raise ValueError("Analysis agent response must be valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != {"supported_check_ids"}:
        raise ValueError("Analysis agent must return only supported_check_ids")
    ids = payload["supported_check_ids"]
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        raise ValueError("supported_check_ids must be a list of strings")
    if len(ids) != len(set(ids)):
        raise ValueError("Analysis agent returned duplicate check ids")
    candidate_map = {finding.check_id: finding for finding in candidates}
    if any(check_id not in candidate_map for check_id in ids):
        raise ValueError("Analysis agent referenced an unsupported finding")
    return tuple(candidate_map[check_id] for check_id in ids)


def _header_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None


class _TitleParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)


def _extract_title(body: bytes) -> str | None:
    parser = _TitleParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except (ValueError, AssertionError):
        return None
    title = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()
    return title[:200] or None

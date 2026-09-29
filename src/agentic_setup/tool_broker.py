"""Named, bounded HTTP capability for explicitly scoped local assessment runs."""

from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
import time
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .authorization import (
    AuthorizationObservation,
    PRINCIPAL_TENANTS,
    RECORD_TENANTS,
)
from .local_assessment import (
    HttpObservation,
    LocalScope,
    MAX_RESPONSE_BYTES,
    SAFE_PATHS,
    SECURITY_HEADERS,
    _extract_title,
    _header_int,
)


class ToolPolicyError(RuntimeError):
    """Raised when a requested capability violates its run scope."""


@dataclass(frozen=True)
class ToolEvent:
    tool: str
    method: str
    url: str
    outcome: str
    status: int | None
    elapsed_ms: int
    response_bytes: int


class HttpTool(Protocol):
    def http_get(self, path: str) -> HttpObservation: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class DockerExecHttpToolBroker:
    """Invokes the fixed probe inside the lab container via bounded docker exec."""

    def __init__(
        self,
        container_id: str,
        allowed_paths: tuple[str, ...],
        docker_executable: str = "docker",
        max_calls: int = 4,
        command_timeout_seconds: float = 5.0,
    ) -> None:
        if not container_id or any(char not in "0123456789abcdef" for char in container_id.lower()):
            raise ToolPolicyError("Invalid lab container identifier")
        if not allowed_paths or len(allowed_paths) != len(set(allowed_paths)):
            raise ToolPolicyError("Broker requires a non-empty unique path allowlist")
        if any(path not in SAFE_PATHS for path in allowed_paths):
            raise ToolPolicyError("Broker path allowlist contains an unsafe path")
        if max_calls < len(allowed_paths):
            raise ToolPolicyError("Call limit must cover the planned requests")
        if command_timeout_seconds <= 0:
            raise ValueError("Command timeout must be positive")

        self.container_id = container_id
        self.allowed_paths = frozenset(allowed_paths)
        self.docker_executable = docker_executable
        self.max_calls = max_calls
        self.command_timeout_seconds = command_timeout_seconds
        self._call_count = 0
        self._events: list[ToolEvent] = []

    @property
    def events(self) -> tuple[ToolEvent, ...]:
        return tuple(self._events)

    def http_get(self, path: str) -> HttpObservation:
        if not isinstance(path, str) or path not in self.allowed_paths:
            self._record_denial(path)
            raise ToolPolicyError("http_get path is not in the approved assessment plan")
        if self._call_count >= self.max_calls:
            self._record_denial(path)
            raise ToolPolicyError("http_get request budget exhausted")
        self._call_count += 1
        started = time.monotonic()
        command = [
            self.docker_executable,
            "exec",
            "--user",
            "65534:65534",
            self.container_id,
            "python",
            "/app/probe.py",
            path,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.command_timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            elapsed = int((time.monotonic() - started) * 1000)
            self._events.append(
                ToolEvent(
                    "http_get",
                    "GET",
                    f"container://{self.container_id}{path}",
                    "timeout",
                    None,
                    elapsed,
                    0,
                )
            )
            return HttpObservation(
                url=f"container://{self.container_id}{path}",
                status=None,
                elapsed_ms=elapsed,
                content_type=None,
                content_length=None,
                security_headers=(),
                title=None,
                body_excerpt=None,
                error="TimeoutExpired",
            )
        except OSError as error:
            raise ToolPolicyError(f"Could not run fixed Docker probe: {type(error).__name__}") from error
        elapsed = int((time.monotonic() - started) * 1000)
        if result.returncode != 0:
            self._events.append(
                ToolEvent(
                    "http_get",
                    "GET",
                    f"container://{self.container_id}{path}",
                    f"probe-error:{result.returncode}",
                    None,
                    elapsed,
                    0,
                )
            )
            raise ToolPolicyError("Fixed Docker probe failed")
        if len(result.stdout.encode("utf-8")) > 4096:
            raise ToolPolicyError("Fixed Docker probe returned excessive metadata")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ToolPolicyError("Fixed Docker probe returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise ToolPolicyError("Fixed Docker probe returned an invalid response")
        status = payload.get("status")
        if status is not None and not isinstance(status, int):
            raise ToolPolicyError("Fixed Docker probe returned an invalid status")
        response_bytes = payload.get("response_bytes", 0)
        if (
            not isinstance(response_bytes, int)
            or response_bytes < 0
            or response_bytes > MAX_RESPONSE_BYTES
        ):
            raise ToolPolicyError("Fixed Docker probe returned invalid response size")
        content_type = payload.get("content_type")
        if content_type is not None and not isinstance(content_type, str):
            raise ToolPolicyError("Fixed Docker probe returned invalid content type")
        security = payload.get("security_headers", [])
        if not isinstance(security, list) or any(
            header not in SECURITY_HEADERS for header in security
        ):
            raise ToolPolicyError("Fixed Docker probe returned invalid header metadata")
        cors_allow_origin = payload.get("cors_allow_origin")
        cors_allow_credentials = payload.get("cors_allow_credentials")
        if cors_allow_origin is not None and not isinstance(cors_allow_origin, str):
            raise ToolPolicyError("Fixed Docker probe returned invalid CORS origin")
        if cors_allow_credentials is not None and not isinstance(
            cors_allow_credentials, str
        ):
            raise ToolPolicyError("Fixed Docker probe returned invalid CORS credentials")
        excerpt = payload.get("body_excerpt")
        title = payload.get("title")
        if excerpt is not None and not isinstance(excerpt, str):
            raise ToolPolicyError("Fixed Docker probe returned invalid body excerpt")
        if title is not None and not isinstance(title, str):
            raise ToolPolicyError("Fixed Docker probe returned invalid title")

        observation_url = f"http://127.0.0.1:8080{path}"
        self._events.append(
            ToolEvent(
                "http_get",
                "GET",
                observation_url,
                "redirect-blocked" if status is not None and 300 <= status < 400 else "success",
                status,
                int(payload.get("elapsed_ms") or elapsed),
                response_bytes,
            )
        )
        return HttpObservation(
            url=observation_url,
            status=status,
            elapsed_ms=int(payload.get("elapsed_ms") or elapsed),
            content_type=content_type,
            content_length=_header_int(payload.get("content_length")),
            security_headers=tuple(security),
            title=title,
            body_excerpt=excerpt,
            error=payload.get("error"),
            cors_allow_origin=cors_allow_origin,
            cors_allow_credentials=cors_allow_credentials,
        )

    def _record_denial(self, path: object) -> None:
        safe_path = path if isinstance(path, str) and len(path) <= 128 else "<invalid>"
        self._events.append(
            ToolEvent(
                "http_get",
                "GET",
                f"container://{self.container_id}{safe_path}",
                "denied",
                None,
                0,
                0,
            )
        )


class DockerExecAuthorizationProbe:
    """Runs only fixed GETs as seeded lab identities against seeded records."""

    def __init__(
        self,
        container_id: str,
        docker_executable: str = "docker",
        command_timeout_seconds: float = 15.0,
    ) -> None:
        if not container_id or any(
            char not in "0123456789abcdef" for char in container_id.lower()
        ):
            raise ToolPolicyError("Invalid lab container identifier")
        if command_timeout_seconds <= 0:
            raise ValueError("Command timeout must be positive")
        self.container_id = container_id
        self.docker_executable = docker_executable
        self.command_timeout_seconds = command_timeout_seconds
        self._events: list[ToolEvent] = []
        self._calls = 0

    @property
    def events(self) -> tuple[ToolEvent, ...]:
        return tuple(self._events)

    def get_record(self, principal: str, record_id: str) -> AuthorizationObservation:
        if (
            not isinstance(principal, str)
            or principal not in PRINCIPAL_TENANTS
            or not isinstance(record_id, str)
            or record_id not in RECORD_TENANTS
        ):
            self._record_authz_denial(principal, record_id)
            raise ToolPolicyError("Authorization probe identity or record is not allowlisted")
        if self._calls >= len(PRINCIPAL_TENANTS) * len(RECORD_TENANTS):
            self._record_authz_denial(principal, record_id)
            raise ToolPolicyError("Authorization probe request budget exhausted")
        self._calls += 1
        started = time.monotonic()
        command = [
            self.docker_executable,
            "exec",
            "--user",
            "65534:65534",
            self.container_id,
            "python",
            "/app/probe.py",
            "authz",
            principal,
            record_id,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.command_timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return self._observation(
                principal, record_id, None, None, None, 0,
                int((time.monotonic() - started) * 1000), "TimeoutExpired",
            )
        except OSError as error:
            raise ToolPolicyError(
                f"Could not run fixed authorization probe: {type(error).__name__}"
            ) from error
        elapsed = int((time.monotonic() - started) * 1000)
        if result.returncode != 0:
            self._events.append(
                ToolEvent(
                    "authorization_get",
                    "GET",
                    f"container://{self.container_id}/api/records/{record_id}",
                    f"probe-error:{result.returncode}",
                    None,
                    elapsed,
                    0,
                )
            )
            raise ToolPolicyError("Fixed authorization probe failed")
        if len(result.stdout.encode("utf-8")) > 2048:
            raise ToolPolicyError("Authorization probe returned excessive metadata")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ToolPolicyError("Authorization probe returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise ToolPolicyError("Authorization probe returned invalid metadata")
        status = payload.get("status")
        response_bytes = payload.get("response_bytes")
        reported_elapsed = payload.get("elapsed_ms")
        returned_record = payload.get("record_id")
        returned_tenant = payload.get("tenant_id")
        error_text = payload.get("error")
        if status is not None and (not isinstance(status, int) or isinstance(status, bool)):
            raise ToolPolicyError("Authorization probe returned invalid status")
        if (
            not isinstance(response_bytes, int)
            or isinstance(response_bytes, bool)
            or not 0 <= response_bytes <= MAX_RESPONSE_BYTES
        ):
            raise ToolPolicyError("Authorization probe returned invalid response size")
        if (
            not isinstance(reported_elapsed, int)
            or isinstance(reported_elapsed, bool)
            or reported_elapsed < 0
        ):
            raise ToolPolicyError("Authorization probe returned invalid timing")
        if returned_record is not None and returned_record not in RECORD_TENANTS:
            raise ToolPolicyError("Authorization probe returned unknown record metadata")
        if returned_tenant is not None and returned_tenant not in set(RECORD_TENANTS.values()):
            raise ToolPolicyError("Authorization probe returned unknown tenant metadata")
        if error_text is not None and not isinstance(error_text, str):
            raise ToolPolicyError("Authorization probe returned invalid error metadata")
        return self._observation(
            principal,
            record_id,
            status,
            returned_record,
            returned_tenant,
            response_bytes,
            reported_elapsed or elapsed,
            error_text,
        )

    def _observation(
        self,
        principal: str,
        record_id: str,
        status: int | None,
        returned_record_id: str | None,
        returned_tenant: str | None,
        response_bytes: int,
        elapsed_ms: int,
        error: str | None,
    ) -> AuthorizationObservation:
        outcome = "success" if status is not None and 200 <= status < 300 else "denied"
        self._events.append(
            ToolEvent(
                "authorization_get",
                "GET",
                f"http://127.0.0.1:8080/api/records/{record_id}",
                outcome,
                status,
                elapsed_ms,
                response_bytes,
            )
        )
        return AuthorizationObservation(
            principal=principal,
            record_id=record_id,
            expected_tenant=RECORD_TENANTS[record_id],
            status=status,
            returned_record_id=returned_record_id,
            returned_tenant=returned_tenant,
            response_bytes=response_bytes,
            elapsed_ms=elapsed_ms,
            error=error,
        )

    def _record_authz_denial(self, principal: object, record_id: object) -> None:
        record_part = (
            record_id
            if isinstance(record_id, str) and record_id in RECORD_TENANTS
            else "<invalid>"
        )
        self._events.append(
            ToolEvent(
                "authorization_get",
                "GET",
                f"container://{self.container_id}/api/records/{record_part}",
                "denied",
                None,
                0,
                0,
            )
        )


class LocalHttpToolBroker:
    """Only exposes a fixed-path GET capability against one loopback origin."""

    def __init__(
        self,
        scope: LocalScope,
        allowed_paths: tuple[str, ...],
        max_calls: int = 4,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        timeout_seconds: float = 5.0,
        minimum_interval_seconds: float = 0.0,
        clock=time.monotonic,
    ) -> None:
        parsed_scope = LocalScope.parse(scope.base_url)
        if parsed_scope.base_url != scope.base_url:
            raise ToolPolicyError("Scope origin must be canonical")
        if not allowed_paths or len(allowed_paths) != len(set(allowed_paths)):
            raise ToolPolicyError("Broker requires a non-empty unique path allowlist")
        if any(path not in SAFE_PATHS for path in allowed_paths):
            raise ToolPolicyError("Broker path allowlist contains an unsafe path")
        if max_calls < 1 or max_calls < len(allowed_paths):
            raise ToolPolicyError("Call limit must cover the planned requests")
        if not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ToolPolicyError(
                f"Response size must be between 1 and {MAX_RESPONSE_BYTES} bytes"
            )
        if timeout_seconds <= 0 or minimum_interval_seconds < 0:
            raise ValueError("Timeout must be positive and interval non-negative")

        self.scope = scope
        self.allowed_paths = frozenset(allowed_paths)
        self.max_calls = max_calls
        self.max_response_bytes = max_response_bytes
        self.timeout_seconds = timeout_seconds
        self.minimum_interval_seconds = minimum_interval_seconds
        self.clock = clock
        self._call_count = 0
        self._last_call_at: float | None = None
        self._events: list[ToolEvent] = []
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    @property
    def events(self) -> tuple[ToolEvent, ...]:
        return tuple(self._events)

    def http_get(self, path: str) -> HttpObservation:
        if not isinstance(path, str) or path not in self.allowed_paths:
            self._record_denial(path)
            raise ToolPolicyError("http_get path is not in the approved assessment plan")
        if self._call_count >= self.max_calls:
            self._record_denial(path)
            raise ToolPolicyError("http_get request budget exhausted")

        now = self.clock()
        if (
            self._last_call_at is not None
            and now - self._last_call_at < self.minimum_interval_seconds
        ):
            self._record_denial(path)
            raise ToolPolicyError("http_get rate limit exceeded")
        self._call_count += 1
        self._last_call_at = now
        url = self.scope.url_for(path)
        started = self.clock()
        request_headers = {
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.1",
            "User-Agent": "AuthorizedLocalAssessment/0.1",
        }
        if path == "/cors-policy":
            request_headers["Origin"] = "https://assessment.invalid"
        request = Request(url, headers=request_headers, method="GET")
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read(self.max_response_bytes + 1)
                headers = response.headers
                status = response.status
                outcome = "success"
        except HTTPError as response:
            body = response.read(self.max_response_bytes + 1)
            headers = response.headers
            status = response.code
            outcome = "redirect-blocked" if 300 <= status < 400 else "http-error"
        except (TimeoutError, URLError, OSError) as error:
            elapsed = int((self.clock() - started) * 1000)
            self._events.append(
                ToolEvent(
                    "http_get",
                    "GET",
                    url,
                    f"network-error:{type(error).__name__}",
                    None,
                    elapsed,
                    0,
                )
            )
            return HttpObservation(
                url=url,
                status=None,
                elapsed_ms=elapsed,
                content_type=None,
                content_length=None,
                security_headers=(),
                title=None,
                body_excerpt=None,
                error=type(error).__name__,
            )

        elapsed = int((self.clock() - started) * 1000)
        truncated = len(body) > self.max_response_bytes
        body = body[: self.max_response_bytes]
        content_type = headers.get("Content-Type")
        title = (
            _extract_title(body)
            if content_type and "html" in content_type.lower()
            else None
        )
        excerpt = None
        if content_type and any(
            kind in content_type.lower() for kind in ("text/", "json", "xml")
        ):
            excerpt = body.decode("utf-8", errors="replace")[:512]
            if truncated:
                excerpt += " [truncated]"

        self._events.append(
            ToolEvent(
                "http_get",
                "GET",
                url,
                outcome,
                status,
                elapsed,
                len(body),
            )
        )
        return HttpObservation(
            url=url,
            status=status,
            elapsed_ms=elapsed,
            content_type=content_type,
            content_length=_header_int(headers.get("Content-Length")),
            security_headers=tuple(
                name
                for name in SECURITY_HEADERS
                if headers.get(name) is not None
            ),
            title=title,
            body_excerpt=excerpt,
            error="redirect not followed" if 300 <= status < 400 else None,
            cors_allow_origin=headers.get("Access-Control-Allow-Origin"),
            cors_allow_credentials=headers.get(
                "Access-Control-Allow-Credentials"
            ),
        )

    def _record_denial(self, path: object) -> None:
        safe_path = path if isinstance(path, str) and len(path) <= 128 else "<invalid>"
        self._events.append(
            ToolEvent(
                "http_get",
                "GET",
                f"{self.scope.base_url}{safe_path}",
                "denied",
                None,
                0,
                0,
            )
        )

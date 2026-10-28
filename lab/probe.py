"""Fixed read-only probes invoked via docker exec on the lab container."""

from __future__ import annotations

import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ALLOWED_PATHS = {"/", "/robots.txt", "/openapi.json", "/health", "/cors-policy"}
SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)
MAX_RESPONSE_BYTES = 64 * 1024
AUTHZ_PRINCIPALS = {"tenant-a-user": "lab-token-a", "tenant-b-user": "lab-token-b"}
AUTHZ_RECORDS = {"record-a", "record-b"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "authz":
        return probe_record(sys.argv[2], sys.argv[3])
    if len(sys.argv) != 2 or sys.argv[1] not in ALLOWED_PATHS:
        return 2

    path = sys.argv[1]
    headers = {"User-Agent": "AuthorizedLocalAssessment/0.1"}
    if path == "/cors-policy":
        headers["Origin"] = "https://assessment.invalid"
    request = Request(
        f"http://127.0.0.1:8080{path}",
        headers=headers,
        method="GET",
    )
    started = time.monotonic()
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=3.0) as response:
            status = response.status
            response_headers = response.headers
            body = response.read(MAX_RESPONSE_BYTES + 1)
            error = None
    except HTTPError as response:
        status = response.code
        response_headers = response.headers
        body = response.read(MAX_RESPONSE_BYTES + 1)
        error = "redirect not followed" if 300 <= status < 400 else None
    except (TimeoutError, URLError, OSError) as error_value:
        print(
            json.dumps(
                {
                    "status": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": type(error_value).__name__,
                },
                separators=(",", ":"),
            )
        )
        return 0

    truncated = len(body) > MAX_RESPONSE_BYTES
    body = body[:MAX_RESPONSE_BYTES]
    content_type = response_headers.get("Content-Type")
    excerpt = None
    if content_type and any(
        kind in content_type.lower() for kind in ("text/", "json", "xml")
    ):
        excerpt = body.decode("utf-8", errors="replace")[:512]
        if truncated:
            excerpt += " [truncated]"
    result = {
        "status": status,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "response_bytes": len(body),
        "content_type": content_type,
        "content_length": _header_int(response_headers.get("Content-Length")),
        "security_headers": [
            name
            for name in SECURITY_HEADERS
            if response_headers.get(name) is not None
        ],
        "cors_allow_origin": response_headers.get("Access-Control-Allow-Origin"),
        "cors_allow_credentials": response_headers.get(
            "Access-Control-Allow-Credentials"
        ),
        "title": (
            _extract_title(body)
            if content_type and "html" in content_type.lower()
            else None
        ),
        "body_excerpt": excerpt,
        "error": error,
    }
    print(json.dumps(result, separators=(",", ":")))
    return 0


def probe_record(principal: str, record_id: str) -> int:
    token = AUTHZ_PRINCIPALS.get(principal)
    if token is None or record_id not in AUTHZ_RECORDS:
        return 2
    request = Request(
        f"http://127.0.0.1:8080/api/records/{record_id}",
        headers={
            "User-Agent": "AuthorizedLocalAssessment/0.1",
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    started = time.monotonic()
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=3.0) as response:
            status = response.status
            response_headers = response.headers
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as response:
        status = response.code
        response_headers = response.headers
        body = response.read(MAX_RESPONSE_BYTES + 1)
    except (TimeoutError, URLError, OSError) as error_value:
        print(
            json.dumps(
                {
                    "status": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "response_bytes": 0,
                    "record_id": None,
                    "tenant_id": None,
                    "error": type(error_value).__name__,
                },
                separators=(",", ":"),
            )
        )
        return 0

    returned_record = None
    returned_tenant = None
    if (
        len(body) <= MAX_RESPONSE_BYTES
        and "json" in (response_headers.get("Content-Type") or "").lower()
    ):
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            returned_record = payload.get("record_id")
            returned_tenant = payload.get("tenant_id")
    print(
        json.dumps(
            {
                "status": status,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "response_bytes": min(len(body), MAX_RESPONSE_BYTES),
                "record_id": (
                    returned_record if isinstance(returned_record, str) else None
                ),
                "tenant_id": (
                    returned_tenant if isinstance(returned_tenant, str) else None
                ),
                "error": None,
            },
            separators=(",", ":"),
        )
    )
    return 0


def _header_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None


def _extract_title(body: bytes) -> str | None:
    from html.parser import HTMLParser
    import re

    class TitleParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.in_title = False
            self.parts: list[str] = []

        def handle_starttag(self, tag: str, attrs) -> None:
            if tag.lower() == "title":
                self.in_title = True

        def handle_endtag(self, tag: str) -> None:
            if tag.lower() == "title":
                self.in_title = False

        def handle_data(self, data: str) -> None:
            if self.in_title:
                self.parts.append(data)

    parser = TitleParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    title = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()
    return title[:200] or None


if __name__ == "__main__":
    raise SystemExit(main())

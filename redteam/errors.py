"""Structured, redacted reporting for recoverable runtime failures."""
from __future__ import annotations

import logging
import re
from typing import Any

_LOG = logging.getLogger("redteam.runtime")
_REDACT_PATTERNS = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[^\s,;]+"), r"\1 <redacted>"),
    (re.compile(r"(?i)(authorization|cookie|set-cookie|password|token|api[_-]?key)(\s*[:=]\s*)[^\s,;]+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)([?&](?:access_token|refresh_token|token|key|secret|code)=)[^&#\s]+"), r"\1<redacted>"),
)


def _redact(value: Any, limit: int = 400) -> str:
    text = str(value or "")
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]


def record_suppressed_error(audit, component: str, operation: str, exc: BaseException,
                            *, severity: str = "warning", **context: Any) -> None:
    """Record an exception that is intentionally contained at a subsystem boundary.

    The failure is never silent: emit a structured audit event when possible and
    fall back to the Python logger if the audit sink itself is unavailable. Error
    text and context values are bounded and credential-shaped strings are redacted.
    """
    payload = {
        "component": _redact(component, 80),
        "operation": _redact(operation, 120),
        "severity": severity,
        "exception_type": type(exc).__name__,
        "error": _redact(exc),
    }
    for key, value in list(context.items())[:12]:
        payload[_redact(key, 64)] = _redact(value, 200)
    try:
        if audit is not None and callable(getattr(audit, "record", None)):
            audit.record("runtime.error.suppressed", **payload)
            return
    except Exception as audit_exc:  # audit failure is separately surfaced below
        payload["audit_error_type"] = type(audit_exc).__name__
        payload["audit_error"] = _redact(audit_exc)
    _LOG.log(logging.ERROR if severity == "error" else logging.WARNING,
             "contained runtime failure", extra={"redteam_event": payload})

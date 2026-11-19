"""URL-first engagement creation (Builder 04).

The dashboard sends an authorized target URL plus authorization metadata; this
module validates that input FAIL-CLOSED and builds the internal Rules-of-
Engagement YAML that the existing pipeline enforces. The scope authority stays
exactly where it was:

  - the generated engagement is validated by the existing config loader
    (`redteam.config.load_engagement`) before any run is armed;
  - every request the agents make is still checked by ScopeGuard — including
    redirects, discovered hosts, and links — so scope is never silently widened
    by anything this module does;
  - AttackTree / MissionScheduler / FindingStore / independent verifier
    authorities are untouched (this module only authors the RoE document).

Rejection is a ValueError with an operator-actionable message; the server maps
it to HTTP 400. Secrets (LLM API keys) never pass through here — model
credentials travel as run-scoped in-memory options (see server._prepare_llm).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ip
import json
import re as _re
from pathlib import Path

# Permitted test intensity → (max_requests_per_second, max_total_requests).
# "high" is still far below scanner-grade aggression; the point is a bounded,
# operator-visible dial, not an unrestricted green light.
INTENSITY_PRESETS: dict[str, tuple[float, int]] = {
    "low": (0.5, 200),
    "standard": (3.0, 2000),
    "high": (8.0, 5000),
}

_DEFAULT_PORTS = {"http": 80, "https": 443}

# A hostname label: alphanumeric, may contain hyphens inside, 1-63 chars.
_LABEL_RE = _re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class LaunchError(ValueError):
    """A client-input rejection with an operator-actionable message."""


def parse_target_url(target_url: str,
                     allow_private_ranges: bool = False) -> dict:
    """Parse and normalize a target URL into (scheme, host, port).

    Rejects, with actionable errors:
      - missing/unsupported scheme (only http/https — no file:, ftp:, javascript:,
        browser-scheme or scheme-less input);
      - embedded credentials (user:pass@host is never acceptable for a target);
      - malformed or invalid host values (empty host, bad labels, >253 chars);
      - out-of-range ports;
      - private/loopback/link-local targets UNLESS the operator explicitly
        authorized private-range testing (local-lab support — the same opt-in
        ScopeGuard enforces per request).

    No DNS resolution happens here (resolution is ScopeGuard's per-request job);
    the URL is validated syntactically and normalized deterministically.
    """
    if not isinstance(target_url, str):
        raise LaunchError("target_url is required")
    raw = target_url.strip()
    if not raw:
        raise LaunchError("target_url is required — enter the web application URL you are authorized to test")

    from urllib.parse import urlsplit
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise LaunchError(f"target_url is malformed: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if not scheme:
        raise LaunchError("target_url needs a scheme — use https://demo.testfire.net (or http:// for a local lab)")
    if scheme not in _DEFAULT_PORTS:
        raise LaunchError(f"unsupported scheme '{scheme}:' — only http and https targets are supported")

    if parts.username or parts.password:
        raise LaunchError("target_url must not embed credentials (user:pass@host) — "
                          "assessment credentials are configured separately and handled as run-scoped secrets")

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise LaunchError("target_url has no host — enter the authorized hostname or IP")
    if len(host) > 253:
        raise LaunchError("target host is too long to be a valid hostname")

    # Port: explicit in the URL wins; otherwise the scheme default. Validate.
    try:
        port = parts.port  # raises ValueError for malformed ports
    except ValueError as exc:
        raise LaunchError(f"target_url has an invalid port: {exc}") from exc
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if not (1 <= port <= 65535):
        raise LaunchError(f"target port {port} is out of range (1-65535)")

    is_ip = False
    try:
        addr = _ip.ip_address(host)
        is_ip = True
        # brackets-stripped IPv6 from urlsplit already lands as a plain address
        host = str(addr)
    except ValueError:
        pass

    if not is_ip and host != "localhost":
        labels = host.split(".")
        if len(labels) < 2:
            raise LaunchError(f"'{host}' is not a valid public hostname — use a fully-qualified domain (e.g. demo.testfire.net), an IP, or 'localhost' for a local lab")
        for label in labels:
            if not _LABEL_RE.match(label):
                raise LaunchError(f"target host '{host}' contains invalid characters in '{label}' — hostnames may use letters, digits and inner hyphens only")

    if host == "localhost" or is_ip and _addr_is_private(addr):
        if not allow_private_ranges:
            kind = "loopback host" if host == "localhost" else "private/reserved address"
            raise LaunchError(
                f"target {host} is a {kind} — enable 'allow private ranges' in the "
                "authorization section to confirm you own this local-lab target")
    return {"scheme": scheme, "host": host, "port": port}


def _addr_is_private(addr: _ip._BaseAddress) -> bool:
    # Same family of ranges ScopeGuard blocks per request (scope.py): private,
    # loopback, link-local, reserved, multicast, unspecified.
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _iso_date(value: str, field: str) -> _dt.date:
    value = (value or "").strip()
    if not value:
        raise LaunchError(f"authorization {field} date is required (YYYY-MM-DD)")
    try:
        return _dt.date.fromisoformat(value)
    except ValueError as exc:
        raise LaunchError(f"authorization {field} must be an ISO date (YYYY-MM-DD): {exc}") from exc


def build_engagement(
    target_url: str,
    objective: str,
    authorization: dict,
    intensity: str = "standard",
    max_run_seconds: int = 0,
    max_llm_tokens: int = 0,
    client: str = "",
    assessment_name: str = "",
) -> tuple[dict, dict]:
    """Build the engagement YAML mapping from validated operator input.

    `authorization` (fail-closed — every field below is required):
      confirmed: bool          — the explicit checkbox; False rejects the launch
      authorized_by: str       — the human/authority that approved testing
      ticket: str              — reference to the signed authorization document
      starts / ends: str       — ISO dates bounding the assessment window
      allow_private_ranges: bool — opt-in for loopback/RFC1918 lab targets
      excluded_hosts: [str]    — explicit carve-outs that always win

    Returns (engagement_mapping, normalized_summary). Raises LaunchError on any
    missing/invalid input. The mapping carries NO credentials.
    """
    if not authorization.get("confirmed"):
        raise LaunchError("authorization confirmation is required — the operator "
                          "must confirm in writing they are authorized to test this target")
    authorized_by = str(authorization.get("authorized_by") or "").strip()
    if not authorized_by:
        raise LaunchError("authorized_by is required — record who authorized this assessment")
    ticket = str(authorization.get("ticket") or "").strip()
    if not ticket:
        raise LaunchError("ticket is required — reference the signed authorization document (SOW, bounty scope URL, change request)")

    objective_text = str(objective or "").strip()
    if not objective_text:
        raise LaunchError("objective is required — describe what the assessment should accomplish")

    starts = _iso_date(str(authorization.get("starts") or ""), "start")
    ends = _iso_date(str(authorization.get("ends") or ""), "end")
    if ends < starts:
        raise LaunchError("authorization end date is before the start date")

    allow_private = bool(authorization.get("allow_private_ranges"))
    normalized = parse_target_url(target_url, allow_private_ranges=allow_private)

    preset = INTENSITY_PRESETS.get(str(intensity or "standard").strip().lower())
    if preset is None:
        raise LaunchError(f"unknown intensity '{intensity}' — choose one of {sorted(INTENSITY_PRESETS)}")
    rps, total_requests = preset

    excluded = [str(h).strip() for h in (authorization.get("excluded_hosts") or [])
                if str(h).strip()]

    name = (assessment_name or f"web-launch-{normalized['host']}").strip()
    data = {
        "name": name,
        "client": (client or normalized["host"]).strip(),
        "authorized_by": authorized_by,
        "ticket": ticket,
        "starts": starts.isoformat(),
        "ends": ends.isoformat(),
        "scope": {
            "allowed_hosts": [normalized["host"]],
            "excluded_hosts": excluded,
            "allowed_ports": [int(normalized["port"])],
            "allowed_schemes": [normalized["scheme"]],
            "allow_private_ranges": allow_private,
        },
        "limits": {
            "max_requests_per_second": rps,
            "max_total_requests": total_requests,
            "max_run_seconds": int(max_run_seconds or 0),
            "max_llm_tokens": int(max_llm_tokens or 0),
        },
        "objective": {
            "name": "Authorized web application assessment",
            "description": objective_text,
        },
    }
    summary = {
        "target_url": target_url.strip(),
        "scheme": normalized["scheme"],
        "host": normalized["host"],
        "port": normalized["port"],
        "authorized_by": authorized_by,
        "ticket": ticket,
        "starts": starts.isoformat(),
        "ends": ends.isoformat(),
        "intensity": intensity,
        "allow_private_ranges": allow_private,
        "excluded_hosts": excluded,
    }
    return data, summary


def write_launch_artifacts(out_dir: Path, engagement: dict, summary: dict) -> str:
    """Write engagement.yaml + authorization metadata into the run directory.

    authorization.json records WHO authorized WHAT and WHEN (audit trail, no
    secrets — model credentials never pass through the launch flow). Returns the
    engagement path for the existing launch pipeline. The generated engagement
    is validated by the existing loader by the CALLER (server) before arming.
    """
    import yaml
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    eng_path = out_dir / "engagement.yaml"
    eng_path.write_text(yaml.safe_dump(engagement, sort_keys=False), encoding="utf-8")
    record = dict(summary)
    record["confirmed"] = True
    record["created_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    record["generated_by"] = "redteam.launch.build_engagement"
    (out_dir / "authorization.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8")
    return str(eng_path)

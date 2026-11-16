"""Build an engagement from a dashboard form: client URL(s) + authorization -> scope.

The dashboard's "New engagement" form lets an operator type the client's URL instead of
hand-writing YAML. The scope this produces is deliberately the NARROWEST reading of what
was typed:

  - exactly the hosts in the URLs (no wildcard, no parent domain, no CIDR),
  - exactly their ports and schemes,
  - private/loopback ranges only when the operator ticks the box,
  - a window that starts today and ends on the date the operator gives.

Widening any of that (a *.client.com wildcard, an internal range) still needs a
hand-written engagement file. The authorization fields (who authorized it, the signed
reference) are required — the same fields load_engagement already refuses to run
without.

`preflight` is the form's "Check" button: it shows the scope that would be armed,
resolves each host, and — only once the authorization fields are filled — sends ONE
GET per URL (no redirects followed) through the same ScopeGuard the agent uses.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_MAX_TARGETS = 20
_MAX_WINDOW_DAYS = 90


class FormError(ValueError):
    """The form can't be turned into a safe engagement; message is operator-facing."""


@dataclass
class EngagementForm:
    client: str
    targets: list[str]
    authorized_by: str
    ticket: str
    ends: str                      # ISO date
    objective: str = ""
    allow_private_ranges: bool = False
    sandbox: bool = True
    max_requests_per_second: float = 3.0
    max_total_requests: int = 2000
    max_run_seconds: int = 3600
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ParsedUrl:
    url: str
    scheme: str
    host: str
    port: int


def parse_url(raw: str) -> ParsedUrl:
    text = (raw or "").strip()
    if not text:
        raise FormError("empty target")
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise FormError(f"{raw!r}: {exc}") from exc
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise FormError(f"{raw!r}: only http and https targets are supported")
    if parts.username or parts.password:
        raise FormError(f"{raw!r}: remove the user:password@ part; put credentials in the objective")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise FormError(f"{raw!r}: no host")
    if "*" in host:
        raise FormError(f"{raw!r}: wildcards need a hand-written engagement file")
    try:
        ipaddress.ip_network(host, strict=False)
        if "/" in host:
            raise FormError(f"{raw!r}: CIDR ranges need a hand-written engagement file")
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
            raise FormError(f"{raw!r}: {host!r} is not a valid host name")
    port = port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    shown_host = f"[{host}]" if ":" in host else host
    return ParsedUrl(url=f"{scheme}://{shown_host}:{port}{path}", scheme=scheme,
                     host=host, port=port)


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def validate(form: EngagementForm, today: _dt.date | None = None) -> list[ParsedUrl]:
    """Raise FormError listing every problem at once, else return the parsed targets."""
    today = today or _dt.date.today()
    errs: list[str] = []
    if not _clean(form.client):
        errs.append("client name is required")
    if not _clean(form.authorized_by):
        errs.append("authorized by is required (the person who signed the authorization)")
    if not _clean(form.ticket):
        errs.append("authorization reference is required (SOW / contract / bug-bounty URL)")
    try:
        ends = _dt.date.fromisoformat((form.ends or "").strip())
        if ends < today:
            errs.append("end date is in the past")
        elif (ends - today).days > _MAX_WINDOW_DAYS:
            errs.append(f"window longer than {_MAX_WINDOW_DAYS} days; use an engagement file")
    except ValueError:
        errs.append("end date must be YYYY-MM-DD")
    raw = [t for t in (form.targets or []) if (t or "").strip()]
    if not raw:
        errs.append("at least one target URL is required")
    if len(raw) > _MAX_TARGETS:
        errs.append(f"at most {_MAX_TARGETS} target URLs per engagement")
    parsed: list[ParsedUrl] = []
    for t in raw[:_MAX_TARGETS]:
        try:
            parsed.append(parse_url(t))
        except FormError as exc:
            errs.append(str(exc))
    if errs:
        raise FormError("; ".join(errs))
    return parsed


def build_engagement_doc(form: EngagementForm, today: _dt.date | None = None) -> dict:
    today = today or _dt.date.today()
    parsed = validate(form, today)
    hosts = sorted({p.host for p in parsed})
    ports = sorted({p.port for p in parsed})
    schemes = sorted({p.scheme for p in parsed})
    client = _clean(form.client)
    doc: dict = {
        "name": f"{client} web assessment",
        "client": client,
        "authorized_by": _clean(form.authorized_by),
        "ticket": _clean(form.ticket),
        "starts": today.isoformat(),
        "ends": form.ends.strip(),
        "scope": {
            "allowed_hosts": hosts,
            "excluded_hosts": [],
            "allowed_ports": ports,
            "allowed_schemes": schemes,
            "allow_private_ranges": bool(form.allow_private_ranges),
        },
        "limits": {
            "max_requests_per_second": max(0.5, min(float(form.max_requests_per_second), 20.0)),
            "max_total_requests": max(50, min(int(form.max_total_requests), 20000)),
            "max_run_seconds": max(60, min(int(form.max_run_seconds), 6 * 3600)),
        },
        "require_approval_for": ["destructive_command", "auth_bypass_attempt"],
        "sandbox": {"enable": bool(form.sandbox)},
        "targets": [p.url for p in parsed],
        "created_from": "dashboard-form",
    }
    return doc


def _is_internal(ip: ipaddress._BaseAddress) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified)


def preflight(form: EngagementForm, *, resolver=socket.getaddrinfo, fetch=None,
              control_plane: tuple[str, int] | None = None,
              today: _dt.date | None = None) -> dict:
    """The "Check" button. Never raises for a form problem — returns it in `errors`."""
    out: dict = {"ok": False, "errors": [], "warnings": [], "scope": None, "targets": []}
    try:
        doc = build_engagement_doc(form, today)
    except FormError as exc:
        out["errors"] = str(exc).split("; ")
        return out
    out["scope"] = doc["scope"]

    from .config import ConfigError
    if control_plane is not None:
        from .scope import check_control_plane_overlap
        try:
            check_control_plane_overlap(_engagement_from_doc(doc), *control_plane)
        except ConfigError as exc:
            out["errors"].append(str(exc))
            return out

    from .scope import ScopeGuard, ScopeViolation
    guard = ScopeGuard(_engagement_from_doc(doc), resolver=resolver)
    for url in doc["targets"]:
        row: dict = {"url": url, "ips": [], "in_scope": False, "reachable": None}
        host = urlsplit(url).hostname or ""
        try:
            infos = resolver(host, None)
            row["ips"] = sorted({i[4][0] for i in infos})
        except (socket.gaierror, OSError) as exc:
            row["error"] = f"DNS: {exc}"
            out["targets"].append(row)
            continue
        internal = [ip for ip in row["ips"] if _safe_internal(ip)]
        if internal and not form.allow_private_ranges:
            row["error"] = (f"resolves to internal address {internal[0]}; tick "
                            "'internal / private ranges' only if the RoE covers it")
            out["targets"].append(row)
            continue
        if internal and doc["sandbox"]["enable"] and host in ("localhost", "127.0.0.1", "::1"):
            out["warnings"].append(
                f"{url}: inside the Kali sandbox 'localhost' is the sandbox itself, so "
                "Kali tools can't reach this target. Browser and HTTP tools still can; "
                "run it in Docker on redteam-net (see bench runner) for full tooling.")
        try:
            guard.check(url)
            row["in_scope"] = True
        except ScopeViolation as exc:
            row["error"] = str(exc)
            out["targets"].append(row)
            continue
        if fetch is not None:
            try:
                row["reachable"] = fetch(url)
            except Exception as exc:  # noqa: BLE001 — operator-facing message only
                row["reachable"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
        out["targets"].append(row)

    out["ok"] = all(r.get("in_scope") for r in out["targets"]) and not out["errors"]
    return out


def _safe_internal(ip: str) -> bool:
    try:
        return _is_internal(ipaddress.ip_address(ip.split("%")[0]))
    except ValueError:
        return False


def _engagement_from_doc(doc: dict):
    """Same validation path as a hand-written file (load_engagement), minus the disk."""
    import tempfile
    from pathlib import Path

    import yaml

    from .config import load_engagement
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "engagement.yaml"
        p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        return load_engagement(p)


def http_probe(url: str, timeout: float = 6.0) -> dict:
    """One GET, no redirects followed, small read. Used only by the Check button."""
    import requests

    r = requests.get(url, timeout=(3, timeout), allow_redirects=False, stream=True,
                     headers={"User-Agent": "redteam-preflight/1"})
    try:
        body = r.raw.read(65536, decode_content=True) or b""
    finally:
        r.close()
    title = ""
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:120]
    return {"ok": True, "status": r.status_code, "server": r.headers.get("Server", ""),
            "location": r.headers.get("Location", ""), "title": title,
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000)}

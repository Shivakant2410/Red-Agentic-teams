"""TrafficRecorder — per-run HTTP traffic evidence, ARTEX-style, with our discipline.

ARTEX ("Traffic Recording and Execution Monitoring") records what its agents put on
the wire so an operator can watch/replay execution. We port the idea but keep the
Gen-2 secrets discipline: the traffic log is OPERATOR-FACING EVIDENCE, so held
credential material (Authorization/Cookie/API-key values, Set-Cookie) is masked in
BOTH directions before it ever touches disk — the same rule tools/probe.py applies
to the model transcript. Bodies are truncated (default 16 KB) and bodies can be
disabled entirely for the most sensitive RoE (--no-traffic-bodies).

Where it hooks: the single shared fetch path (tools/http.py) records every in-scope
request/response — probes, proofs, verify passes, workflow chains — plus the
scope-DENIED attempts (a blocked request is evidence that the boundary held, and the
audit log already treats it that way; now the operator can see the wire-level shape).

Storage contract mirrors events.py: append-only JSONL (traffic.jsonl in the run dir),
flush per record, tolerant reader with the same cursor semantics (after=last seq).
Emission must NEVER break a run — record() swallows sink failures (same design rule
as the EventBus), because a full disk or a read-only directory must not kill an
engagement that is mid-proof.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import weakref
import zlib
from pathlib import Path

# Header names whose VALUES are credential-adjacent. Applied to BOTH request and
# response headers. Names stay (shape is signal); values become a withheld marker.
MASKED_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authenticate",
})

DEFAULT_BODY_LIMIT = 16 * 1024
_TRUNCATED = " [truncated]"

# One process serves both the run engine and the browser-extension ingest API.
# Share recorder instances by path so both writers use the same lock + sequence.
_RECORDER_REGISTRY: weakref.WeakValueDictionary[str, "TrafficRecorder"] = weakref.WeakValueDictionary()
_REGISTRY_LOCK = threading.RLock()


def recorder_for(path: str | Path) -> "TrafficRecorder":
    key = str(Path(path).resolve())
    with _REGISTRY_LOCK:
        recorder = _RECORDER_REGISTRY.get(key)
        if recorder is not None:
            return recorder
        return TrafficRecorder(path)


def decode_content_body(raw: bytes, content_encoding: str = "",
                        max_output: int = 2 * 1024 * 1024) -> tuple[bytes, str]:
    """Decode gzip/deflate for evidence inspection without changing wire bytes.

    Returns (decoded_bytes, label). Unsupported, malformed, or expansion-capped
    bodies return (b"", explanatory_label); callers must not treat them as quotes.
    """
    data = raw or b""
    encodings = [x.strip().lower() for x in (content_encoding or "").split(",")
                 if x.strip()]
    if not encodings or encodings == ["identity"]:
        return data[:max_output], "identity"
    for encoding in reversed(encodings):
        if encoding not in ("gzip", "x-gzip", "deflate"):
            return b"", f"unsupported:{encoding}"
        wbits = (16 + zlib.MAX_WBITS) if encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
        try:
            decoder = zlib.decompressobj(wbits)
            decoded = decoder.decompress(data, max_output + 1)
            if len(decoded) > max_output or decoder.unconsumed_tail:
                return b"", "decoded_body_too_large"
            tail = decoder.flush(max_output + 1 - len(decoded))
            decoded += tail
            if len(decoded) > max_output or not decoder.eof:
                return b"", "invalid_or_truncated_compressed_body"
            data = decoded
        except zlib.error:
            if encoding == "deflate":
                try:
                    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                    decoded = decoder.decompress(data, max_output + 1)
                    if len(decoded) > max_output or decoder.unconsumed_tail:
                        return b"", "decoded_body_too_large"
                    decoded += decoder.flush(max_output + 1 - len(decoded))
                    if len(decoded) > max_output or not decoder.eof:
                        return b"", "invalid_or_truncated_compressed_body"
                    data = decoded
                    continue
                except zlib.error:
                    pass
            return b"", f"decode_failed:{encoding}"
    return data, "+".join(encodings) + ":decoded"


def redact_command(command: str) -> str:
    """Mask common inline secrets before Bash command telemetry reaches disk."""
    value = str(command or "")
    patterns = (
        r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s'\"]+",
        r"(?i)((?:--password|--token|--api[-_]?key|--secret)(?:=|\s+))[^\s'\"]+",
        r"(?i)((?:cookie|set-cookie)\s*:\s*)[^\r\n'\"]+",
    )
    for pattern in patterns:
        value = re.sub(pattern, r"\1<redacted>", value)

    assignment = re.compile(
        r"(?i)([\"']?)([a-z0-9_.-]+)([\"']?\s*[:=]\s*[\"']?)([^&,\s'\"]+)"
    )

    def mask_assignment(match):
        key = match.group(2)
        if _SENSITIVE_FIELD.search(key):
            return match.group(1) + key + match.group(3) + "<redacted>"
        return match.group(0)

    return assignment.sub(mask_assignment, value)[:4000]

def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _mask_headers(headers: dict | None) -> dict:
    out: dict = {}
    for k, v in (headers or {}).items():
        name = str(k)
        if name.lower() in MASKED_HEADERS:
            out[name] = f"<withheld:{len(str(v))} chars>"
        else:
            out[name] = str(v)
    return out


_SENSITIVE_FIELD = re.compile(
    r"(?i)(password|passwd|passphrase|otp|one[_-]?time[_-]?code|"
    r"verification[_-]?code|totp|mfa|captcha|recaptcha|hcaptcha|"
    r"turnstile|token|secret|api[_-]?key|access[_-]?key|session[_-]?id|"
    r"authorization|cookie|state|nonce|code[_-]?verifier|signature|sig)"
)


def _sanitize_url(url: str) -> str:
    """Remove userinfo, fragments and sensitive query values from evidence URLs."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    raw = str(url or "")
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.netloc:
            return raw.split("#", 1)[0].split("?", 1)[0][:2048]
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        netloc = f"{host}:{port}" if port is not None else host
        query = urlencode([
            (key, "<redacted>" if _SENSITIVE_FIELD.search(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))[:2048]
    except ValueError:
        return raw.split("#", 1)[0].split("?", 1)[0][:2048]


def _redact_nested(value):
    if isinstance(value, dict):
        return {
            key: ("<redacted>" if _SENSITIVE_FIELD.search(str(key))
                  else _redact_nested(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    return value


def _sanitize_body(body: str | None, headers: dict | None) -> str | None:
    """Remove common credential/challenge values before traffic reaches disk."""
    if body is None:
        return None
    from urllib.parse import parse_qsl, urlencode
    text = str(body)
    content_type = next(
        (str(v).lower() for k, v in (headers or {}).items()
         if str(k).lower() == "content-type"), "")
    if "multipart/form-data" in content_type:
        return "[multipart body withheld]"
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            return json.dumps(_redact_nested(json.loads(text)),
                              ensure_ascii=False, separators=(",", ":"))
        except (ValueError, TypeError):
            pass
    if "application/x-www-form-urlencoded" in content_type or (
            "=" in text and "&" in text and not text.lstrip().startswith("<")):
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
            if pairs:
                return urlencode([
                    (key, "<redacted>" if _SENSITIVE_FIELD.search(key) else value)
                    for key, value in pairs
                ])
        except Exception:
            pass
    # Conservative fallback for JSON-ish, form-ish and CLI-embedded payloads.
    patterns = (
        r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,'\"}]+",
        r"(?i)([\"']?(?:password|passwd|otp|one[_-]?time[_-]?code|"
        r"verification[_-]?code|totp|captcha|recaptcha|hcaptcha|"
        r"cf-turnstile-response|token|secret|api[_-]?key|session[_-]?id)"
        r"[\"']?\s*[:=]\s*[\"']?)[^&,\s'\"}]+",
    )
    for pattern in patterns:
        text = re.sub(pattern, r"\1<redacted>", text)
    return text


def _clip(body: str | None, limit: int, record_bodies: bool) -> str:
    if not record_bodies or body is None:
        return ""
    body = str(body)
    if len(body) <= limit:
        return body
    return body[:limit] + _TRUNCATED


class TrafficRecorder:
    """Append-only, thread-safe JSONL traffic log for one run."""

    def __init__(self, path: str | Path, max_body_bytes: int = DEFAULT_BODY_LIMIT,
                 record_bodies: bool = True):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._max_body = max(0, int(max_body_bytes))
        self._bodies = bool(record_bodies)
        self._seq = 0
        self.count = 0
        with _REGISTRY_LOCK:
            _RECORDER_REGISTRY[str(self._path.resolve())] = self
        # Best-effort: a read-only disk / weird parent must not prevent CONSTRUCTING
        # the recorder (record() swallows the later open failure — run survives).
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def record_http(self, *, method: str, url: str, status: int, elapsed_ms: int,
                    tool: str = "", session: str = "",
                    req_headers: dict | None = None, req_body: str | None = None,
                    resp_headers: dict | None = None, resp_body: str | None = None,
                    error: str = "", source: str = "") -> None:
        """Record one request/response exchange (or a failed/denied attempt).

        `source` marks where the exchange came from for the operator scanning the
        log: '' (unmarked, a real wire exchange), 'mock' (fulfilled locally by a
        stub — the SPA walkthrough's credential-free bootstrap — never touched
        the target), or any tool-chosen label. Mocked rows are evidence of what
        the CLIENT asked for, not of what the server said — keep them distinct."""
        rec = {
            "seq": None,  # assigned under lock
            "ts": _now(),
            "kind": "http",
            "source": str(source or ""),
            "tool": tool,
            "method": str(method or "GET").upper(),
            "url": _sanitize_url(url),
            "status": int(status),
            "elapsed_ms": int(elapsed_ms),
            "session": session or "",
            "error": error,
            "req_headers": _mask_headers(req_headers),
            "req_body": _clip(_sanitize_body(req_body, req_headers), self._max_body, self._bodies),
            "resp_headers": _mask_headers(resp_headers),
            "resp_body": _clip(_sanitize_body(resp_body, resp_headers), self._max_body, self._bodies),
        }
        # Telemetry must never break a run (EventBus design rule): a full disk, a
        # vanished directory, or any serialization surprise is swallowed here.
        try:
            with self._lock:
                self._seq += 1
                rec["seq"] = self._seq
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                self.count += 1   # only written records count — the operator briefs off this
        except Exception:
            pass

    def record_event(self, *, event_type: str, source: str,
                     url: str = "", session: str = "",
                     metadata: dict | None = None) -> None:
        """Append a bounded metadata-only event to the same traffic sequence."""
        safe_meta = {}
        for key, value in (metadata or {}).items():
            if key in {"challenge_kind", "field_count", "resource_type",
                       "tab_id", "frame_id", "command", "exit_code",
                       "timed_out", "duration_ms", "method", "status_code",
                       "request_id"}:
                if isinstance(value, (str, int, float, bool)) or value is None:
                    safe_meta[key] = value if not isinstance(value, str) else value[:4000]
        rec = {
            "seq": None, "ts": _now(), "kind": "event",
            "source": str(source or ""), "event_type": str(event_type or "")[:80],
            "tool": str(source or ""), "method": "EVENT", "url": _sanitize_url(url),
            "status": 0, "elapsed_ms": 0, "session": str(session or "")[:120],
            "error": "", "req_headers": {}, "req_body": "",
            "resp_headers": {}, "resp_body": "", "metadata": safe_meta,
        }
        try:
            with self._lock:
                self._seq += 1
                rec["seq"] = self._seq
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                self.count += 1
        except Exception:
            pass

    def summary(self) -> dict:
        return {"recorded": self.count, "path": str(self._path)}


def read_traffic(path: str | Path, after: int = 0, limit: int = 1000) -> list[dict]:
    """Replay traffic records with seq > after — the same cursor contract as
    events.read_events, so the API serves both the same way. Tolerant of a torn
    last line (a writer mid-flush)."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("seq", 0) > after:
                out.append(rec)
                if len(out) >= limit:
                    break
    return out

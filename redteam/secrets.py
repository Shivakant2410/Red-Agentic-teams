"""Secret harvesting from material we already obtained.

Deliberately NOT a scanner: nothing here goes looking for /.env or /config.json. It reads
what the operator already has — a response body, a file we retrieved, a token we hold —
and pulls out *candidates*. A candidate is worthless until it is actually used, so we
optimise for recall here and let the behavioural proof (`try_credential`) kill the junk.

The highest-value detector is the JWT decoder: in web engagements the role/scope claim is
very often the escalation path itself.
"""

from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass

JWT, KEYVALUE, CONNECTION_STRING, AWS_KEY, HIGH_ENTROPY, COOKIE = (
    "jwt", "keyvalue", "connection_string", "aws_key", "high_entropy", "cookie")


@dataclass
class Candidate:
    kind: str
    value: str
    context: str = ""          # what it was labelled as / where it came from
    confidence: str = "medium"  # low | medium | high
    claims: dict | None = None  # decoded JWT payload, when applicable

    @property
    def preview(self) -> str:
        """Masked form, safe to echo back to the model and into reports."""
        v = self.value
        return v if len(v) <= 8 else f"{v[:4]}...{v[-4:]} (len {len(v)})"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Decode a JWT's header and payload WITHOUT verifying it (we're the attacker)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    out = []
    for part in parts[:2]:
        pad = "=" * (-len(part) % 4)
        try:
            out.append(json.loads(base64.urlsafe_b64decode(part + pad)))
        except Exception:
            return None
    if not all(isinstance(o, dict) for o in out):
        return None
    return out[0], out[1]


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_KV_RE = re.compile(
    r"""(?i)\b(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|
        auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?token|
        password|passwd|pwd|secret|token|bearer)\b["']?\s*[:=]\s*["']?
        ([A-Za-z0-9_\-./+=]{8,})""",
    re.VERBOSE)
_CONN_RE = re.compile(
    r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|ftp)://[^\s'\"<>]{6,}", re.IGNORECASE)
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_COOKIE_RE = re.compile(r"(?i)\bset-cookie:\s*([A-Za-z0-9_\-]+)=([^;\s]{6,})")
_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{24,}\b")

# Words that show up in long base64-ish blobs but are never secrets.
_ENTROPY_STOP = re.compile(r"(?i)(image/|text/html|application/|charset|wwwwww|aaaaaa)")


def extract_candidates(text: str, context: str = "", max_items: int = 40) -> list[Candidate]:
    """Pull credential candidates out of material we already retrieved."""
    if not text:
        return []
    found: list[Candidate] = []
    seen: set[str] = set()

    def add(kind: str, value: str, ctx: str, confidence: str, claims=None):
        value = value.strip().strip("'\"")
        if not value or value in seen or len(value) > 4096:
            return
        seen.add(value)
        found.append(Candidate(kind=kind, value=value, context=ctx or context,
                               confidence=confidence, claims=claims))

    for tok in _JWT_RE.findall(text):
        decoded = decode_jwt(tok)
        claims = decoded[1] if decoded else None
        # A decodable JWT is high confidence; its claims often name the privilege to target.
        add(JWT, tok, "jwt", "high" if claims else "medium", claims)

    for label, value in _KV_RE.findall(text):
        add(KEYVALUE, value, label.lower(), "high")

    for conn in _CONN_RE.findall(text):
        add(CONNECTION_STRING, conn, "connection string", "high")

    for key in _AWS_RE.findall(text):
        add(AWS_KEY, key, "aws access key id", "high")

    for name, value in _COOKIE_RE.findall(text):
        add(COOKIE, value, f"cookie {name}", "medium")

    # Anything else that simply looks too random to be prose.
    for blob in _ENTROPY_RE.findall(text):
        if blob in seen or _ENTROPY_STOP.search(blob):
            continue
        if shannon_entropy(blob) >= 3.8:
            add(HIGH_ENTROPY, blob, "high-entropy string", "low")

    return found[:max_items]


def interesting_claims(claims: dict | None) -> dict:
    """Claims worth targeting for escalation (role/scope/admin/identity)."""
    if not claims:
        return {}
    keys = ("role", "roles", "scope", "scopes", "admin", "isAdmin", "is_admin",
            "group", "groups", "permissions", "sub", "email", "user", "username", "id")
    out = {}
    for k in keys:
        if k in claims:
            out[k] = claims[k]
    data = claims.get("data")
    if isinstance(data, dict):
        for k in keys:
            if k in data:
                out[f"data.{k}"] = data[k]
    return out

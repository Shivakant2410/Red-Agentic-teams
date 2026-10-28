"""jwt_inspect — deterministic JWT weakness analysis, zero LLM calls.

Token analysis is a solved problem: the weaknesses are structural facts (alg=none,
missing expiry, attacker-controlled key URLs, injection-prone kid fields), not
judgment calls. Burning an LLM turn to eyeball a JWT is waste — and models miss
things. This tool decodes the token and applies a fixed checklist, returning
structure + a severity-ranked lead list.

PROOF-FIRST: every entry is a LEAD with a `verify_hint` saying how a human-grade
proof would look (e.g. replay the token with the signature stripped). Nothing here
is a finding — the agent must attempt the proof (verify_vulnerability) and pass
independent verification (verify_finding_independently) before record_finding.

No network is touched: this is pure decoding, safe to call on any captured token.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json

from . import ToolContext

_LONG_LIFETIME_S = 7 * 24 * 3600  # tokens valid > 7 days get flagged
_PII_KEYS = ("email", "phone", "name", "address", "ssn", "dob")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _decode(token: str) -> tuple[dict, dict, str] | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2]


def _ts(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def analyze(token: str) -> dict:
    """Run the checklist. Returns {ok, header, payload, leads:[...]} or {ok: False, error}."""
    decoded = _decode(token)
    if decoded is None:
        return {"ok": False, "error": "not a decodable JWS (expected header.payload.signature)"}
    header, payload, signature = decoded
    leads: list[dict] = []

    def lead(severity: str, title: str, detail: str, verify_hint: str) -> None:
        leads.append({"severity": severity, "title": title, "detail": detail,
                      "verify_hint": verify_hint})

    alg = str(header.get("alg", "")).lower()
    if alg in ("", "none"):
        lead("critical", "unsigned token (alg=none)",
             "The header declares no signature algorithm. If the server accepts such "
             "tokens, anyone can mint arbitrary identities.",
             "Replay the token with the signature segment empty and a modified payload; "
             "if protected content returns, forge a privileged payload and replay.")
    elif alg.startswith("hs"):
        lead("low", f"symmetric algorithm ({header.get('alg')})",
             "HMAC-based tokens are only as strong as the server secret; if that secret "
             "is weak or leaked, tokens can be forged offline.",
             "Attempt offline cracking of the signature with a wordlist (hashcat mode "
             "16500); prove forgery by signing a crafted payload with the recovered key.")

    # Attacker-controlled key material — classic JWT attack surface.
    for key, sev in (("jku", "high"), ("x5u", "high"), ("jwk", "high"), ("x5c", "medium")):
        if key in header:
            lead(sev, f"attacker-influenced key header ({key})",
                 f"The header carries {key}; some libraries fetch/derive the verification "
                 "key from it instead of a trusted store.",
                 f"Host your own key material, point {key} at it (or at a URL you control), "
                 "re-sign the token, and see whether the server accepts it.")

    kid = header.get("kid")
    if kid is not None:
        lead("medium", "injection-prone kid header",
             "kid is often concatenated into a SQL query or a filesystem path when the "
             "server looks up the verification key.",
             "Probe kid with SQLi payloads (e.g. \"' OR '1'='1\") and path-traversal "
             "values (e.g. \"../../dev/null\" paired with a known-empty key).")

    # Time claims.
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    exp = _ts(payload.get("exp"))
    iat = _ts(payload.get("iat"))
    nbf = _ts(payload.get("nbf"))
    if exp is None:
        lead("medium", "no expiry (exp missing)",
             "The token never expires; a stolen token is valid forever unless the server "
             "has server-side revocation.",
             "Replay the token well past any plausible session lifetime and confirm it "
             "still authenticates.")
    elif exp < now:
        lead("info", "token is expired",
             "Operational note: this captured token's exp has passed. If the server "
             "still accepts it, that IS the vulnerability.",
             "Replay it against a protected endpoint; acceptance of an expired token "
             "is a critical finding.")
    if exp is not None and iat is not None and exp - iat > _LONG_LIFETIME_S:
        lead("low", f"long-lived token ({int((exp - iat) / 86400)} days)",
             "Long token lifetimes widen the window for replay after theft.",
             "Note as hygiene; pair with a replay demonstration for impact.")
    if nbf is not None and nbf > now:
        lead("info", "token not yet valid (nbf in the future)",
             "Operational note: the token claims it is not valid yet.")

    # Identity claims worth probing.
    sub = payload.get("sub")
    if isinstance(sub, str) and sub.isdigit():
        lead("medium", "sequential numeric subject (sub)",
             "Predictable subject identifiers invite cross-account substitution.",
             "Capture tokens for two accounts you control, swap the sub values "
             "(re-signing if the server checks signatures you can obtain keys for), and "
             "test horizontal access.")
    if "aud" not in payload or "iss" not in payload:
        lead("low", "missing audience/issuer binding",
             "Without aud/iss, a token minted for one service may be replayed against "
             "another that shares the key store.",
             "Replay this token against sibling services on the same infra.")

    pii = sorted({k for k in payload if any(p in str(k).lower() for p in _PII_KEYS)})
    if pii:
        lead("info", "personal data in payload",
             f"Claims ({', '.join(pii)}) are exposed to anyone who can read the token "
             "(JWT payloads are base64, not encrypted).",
             "Note for the report: sensitive claims in a readable token.")

    return {
        "ok": True,
        "header": header,
        "payload": payload,
        "signature_present": bool(signature),
        "leads": leads,
        "note": ("All entries are LEADS. Prove each (verify_vulnerability), pass "
                 "independent verification, then record_finding — never record this "
                 "output as a finding directly."),
    }


class JwtInspectTool:
    name = "jwt_inspect"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Decode a JWT and run a deterministic weakness checklist (alg=none, "
                "attacker-controlled jku/x5u/kid headers, missing/expired exp, long "
                "lifetimes, predictable sub, PII in payload). Offline — no network. "
                "Returns severity-ranked LEADS with proof hints; not findings."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "token": {"type": "string", "description": "The JWT (JWS compact form) to analyze."},
                },
                "required": ["token"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, token: str) -> str:
        result = analyze(token)
        ctx.audit.record("jwt_inspect", ok=result.get("ok", False),
                         leads=len(result.get("leads", [])))
        # Never echo the signature back into the transcript (it is a live credential).
        if result.get("ok"):
            result["token_preview"] = token[:24] + "…"
        return json.dumps(result, ensure_ascii=False)

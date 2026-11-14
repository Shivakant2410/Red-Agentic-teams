# Transport-Layer Hardening Gaps

**CWE-319** · 2 skill(s) · folder `categories/tls_hardening/`

## Skills in this shelf

- `web/Cleartext HTTP served without TLS redirect` (CWE-319)
- `web/Strict-Transport-Security header absent` (CWE-319)

## Technique

Cleartext served without redirect and missing HSTS — the two transport proofs an HTTP agent can make without TLS tooling (cipher work needs a separate toolchain).

## Proof design (why it is falsifiable)

Status/header facts, not opinions: 200-on-HTTP (vs 301/308) and header-absence conditions with present=False; the hardened twins falsify both skills.

## Bypass variants / escalation ("think more beats level")

- Mixed-content asset loading over http:// on TLS pages
- Cookie Secure-flag absence pairing (session_security shelf)
- Downgrade-story chaining: cleartext + session cookie + no HSTS = strip primitive
- TLS cipher/protocol analysis via sslscan sibling tooling

## Sources (copied & rewritten into our proof-first DSL)

- OWASP Transport Layer Protection Cheat Sheet
- Mozilla Web Security Guidelines (headers)

## False positives to rule out

Intentionally-HTTP local/health endpoints — scope the probe to user-facing hosts.

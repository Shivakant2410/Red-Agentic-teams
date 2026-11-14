# Session & Client-Layer Hardening Gaps

**CWE-1004, CWE-1021** · 2 skill(s) · folder `categories/session_security/`

## Skills in this shelf

- `web/Session cookie missing HttpOnly flag` (CWE-1004)
- `web/Frame-clickjacking protections absent` (CWE-1021)

## Technique

Cookie flag hygiene (HttpOnly absent = XSS-readivable session) and clickjacking (no X-Frame-Options/frame-ancestors) — low-noise config proofs feeding the chain story.

## Proof design (why it is falsifiable)

Response headers themselves are the evidence; the benign mock is the hardened twin, so the falsifier rejects hardened apps automatically.

## Bypass variants / escalation ("think more beats level")

- SameSite absence + CSRF chain story
- Secure-flag absence over mixed content
- frame-ancestors CSP bypass inventories
- Cookie-scope overbreadth (Domain=) for sibling-subdomain theft

## Sources (copied & rewritten into our proof-first DSL)

- OWASP Session Management Cheat Sheet
- HackTricks book — Clickjacking

## False positives to rule out

API-only endpoints without cookies — scope the probe to Set-Cookie responses.

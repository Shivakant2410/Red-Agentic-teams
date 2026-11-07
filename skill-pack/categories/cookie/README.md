# Cookie Layer Defects

**CWE-565, CWE-1004** · 1 skill(s) · folder `categories/cookie/`

## Skills in this shelf

- `web/Cookie Domain scope overbreadth` (CWE-565)

## Technique

Scope and flag proofs at the cookie layer: Domain-wildcard overbreadth (tenant-wide session exposure), pairing with session_security shelf's HttpOnly/clickjacking proofs.

## Proof design (why it is falsifiable)

Set-Cookie attribute regexes (Domain=. present) vs host-only twins that lack the attribute.

## Bypass variants / escalation ("think more beats level")

- __Host-/__Secure- prefix enforcement checks
- Cookie-tossing via subdomain + path confusion (needs takeover/XSS sibling)
- SameSite absence chains with csrf shelf
- Session-in-URL disclosure (referrer leakage)

## Sources (copied & rewritten into our proof-first DSL)

- OWASP Session Management Cheat Sheet
- Mozilla cookie prefixes documentation

## False positives to rule out

Single-tenant apps where Domain= is harmless by architecture — report with tenant context.

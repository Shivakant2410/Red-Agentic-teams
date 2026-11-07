# CORS Misconfiguration & Same-Origin-Policy Abuse

**CWE-942** · 3 skill(s) · folder `categories/cors/`

## Skills in this shelf

- `web/CORS origin reflection with credentials` (CWE-942)
- `web/CORS null-origin with credentials` (CWE-942)
- `web/JSONP callback reflection` (CWE-346)

## Technique

Arbitrary-origin reflection WITH credentials (attacker origin echoed into access-control-allow-origin while allow-credentials: true), the null-origin variant, and JSONP callback reflection as the pre-CORS sibling.

## Proof design (why it is falsifiable)

header_regex on BOTH headers — origin reflection without credentials is noise, and the benign control (no evil Origin) yields no ACAO header, so the condition set fails.

## Bypass variants / escalation ("think more beats level")

- Origin suffix/substring bypasses (`trusted.example.attacker.tld`, `attackertrusted.example`)
- Subdomain-scope ACAO combined with a takeover of any subdomain
- JSONP function-name abuse + charset tricks for data capture
- POST-message `*` with credentials in postMessage APIs

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — CORS Misconfiguration
- HackTricks book — CORS misconfig & JSONP

## False positives to rule out

Reflected Origin with allow-credentials absent — safe by spec; conditions require both headers.

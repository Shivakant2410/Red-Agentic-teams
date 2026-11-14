# Cross-Site Request Forgery

**CWE-352** · 1 skill(s) · folder `categories/csrf/`

## Skills in this shelf

- `web/CSRF token enforcement absent state-change` (CWE-352)

## Technique

Token enforcement absence: the state-changing POST succeeds with NO CSRF token/origin check, then a read-back request proves the change PERSISTED — the full forgery primitive, not just a missing header.

## Proof design (why it is falsifiable)

Two-request design: tokenless POST + independent GET confirming the new state. Hardened endpoints reject the tokenless POST (403) and fail both conditions.

## Bypass variants / escalation ("think more beats level")

- SameSite=Lax/Strict interaction story (modern browsers blunt GET-class CSRF)
- Login-CSRF and account-linking CSRF (OAuth shelf sibling)
- JSON CSRF via text/plain content-type confusion
- CSRF on cookie-based WS auth (websocket shelf sibling)
- Referer/Origin-check bypasses via subdomain takeover chain

## Sources (copied & rewritten into our proof-first DSL)

- OWASP CSRF Prevention Cheat Sheet
- HackTricks book — CSRF

## False positives to rule out

Anti-CSRF tokens embedded in cookies (double-submit) still passing — read-back distinguishes real state change from echo.

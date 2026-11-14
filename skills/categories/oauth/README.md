# OAuth 2.0 / OIDC Flaws

**CWE-352, CWE-601** · 1 skill(s) · folder `categories/oauth/`

## Skills in this shelf

- `web/OAuth state parameter not enforced` (CWE-352)

## Technique

Callback-layer proofs: state-parameter non-enforcement (code-injection CSRF) and the redirect_uri origin substitution (open_redirect shelf sibling) — the two highest-yield OAuth defects an HTTP agent can pin.

## Proof design (why it is falsifiable)

302-to-dashboard on the stateless callback vs 400 on a strict callback; the Location header is the oracle.

## Bypass variants / escalation ("think more beats level")

- code reuse/replay across clients (single-use code enforcement)
- scope escalation via repeated authorize with narrowed state
- PKCE-downgrade (S256->plain acceptance)
- id_token validation gaps (issuer/audience confusion) — JWT shelf sibling

## Sources (copied & rewritten into our proof-first DSL)

- OWASP OAuth 2.0 cheat sheet
- HackTricks book — OAuth flaws

## False positives to rule out

Client-side (SPA implicit-flow) stacks where stateless callback is by design — report with context.

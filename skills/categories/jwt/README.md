# JSON Web Token Defects

**CWE-347** · 2 skill(s) · folder `categories/jwt/`

## Skills in this shelf

- `elite/JWT forged-claim acceptance check` (CWE-345)
- `web/JWT kid path-traversal empty-key acceptance` (CWE-347)

## Technique

Signature-verification failures: forged-claim acceptance (tampered payload accepted without signature failure) and kid path traversal pointing key resolution at a known/empty file.

## Proof design (why it is falsifiable)

Differential on role: baseline token reads role:user while the forged token reads role:admin with 200 — an unforgeable state change, and the benign control keeps user.

## Bypass variants / escalation ("think more beats level")

- alg:none acceptance (unencoded payload siblings)
- RS256->HS256 confusion when the public key is fetchable
- jku/x5u header injection to a hosted key
- Expired-token acceptance and audience confusion
- kid SQLi/command-injection when key lookup is dynamic

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — JWT vulnerabilities
- swisskyrepo/PayloadsAllTheThings — JSON Web Token

## False positives to rule out

Tokens verified server-side where role comes from DB — differential role read excludes it.

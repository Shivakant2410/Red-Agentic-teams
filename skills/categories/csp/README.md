# Content-Security-Policy Posture

**CWE-693** · 2 skill(s) · folder `categories/csp/`

## Skills in this shelf

- `web/Content-Security-Policy header absent` (CWE-693)
- `web/CSP unsafe-inline script allowance` (CWE-693)

## Technique

CSP absence and CSP self-sabotage (unsafe-inline in script-src): the second line of defense for every injection defect, checked at the header layer.

## Proof design (why it is falsifiable)

Header presence (present=False) and directive-content regexes; strict-policy twins falsify.

## Bypass variants / escalation ("think more beats level")

- nonce/hash-based CSP quality review (manual depth)
- object-src/base-uri/directive gap inventory
- CSP report-only mode (policy declared but not enforced)
- JSONP-endpoint + CSP 'script-src *' combos for bypass chains

## Sources (copied & rewritten into our proof-first DSL)

- MDN CSP documentation
- Google CSP Evaluator methodology

## False positives to rule out

Meta-tag CSP (not header) — header check misses it; note in report rather than fake a fail.

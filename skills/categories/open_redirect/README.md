# Open Redirect

**CWE-601** · 2 skill(s) · folder `categories/open_redirect/`

## Skills in this shelf

- `web/Open redirect cross-origin Location` (CWE-601)
- `elite/OAuth redirect_uri origin substitution` (CWE-601)

## Technique

Cross-origin Location reflection on redirect parameters, plus OAuth redirect_uri origin substitution (code interception primitive).

## Proof design (why it is falsifiable)

header_regex pins the Location to the attacker origin AND status 302; benign same-origin next= params fail the origin match.

## Bypass variants / escalation ("think more beats level")

- Protocol-relative (`//evil.tld`), backslash, and triple-slash variants
- Allow-list confusion: `https://trusted@evil`, `https://trusted.evil`, `/.evil`
- Fragment/@-position tricks and URL-encoded hops
- Referer-based and post-login 'returnTo' sinks
- OAuth: redirect_uri allow-list bypass via subdomains + code leakage into Referer

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Open Redirect
- HackTricks book — OAuth redirect_uri

## False positives to rule out

Same-origin redirects — the cross-origin regex is the whole point.

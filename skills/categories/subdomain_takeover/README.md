# Subdomain Takeover Fingerprints

**CWE-350** · 4 skill(s) · folder `categories/subdomain_takeover/`

## Skills in this shelf

- `web/Subdomain takeover Shopify fingerprint` (CWE-350)
- `web/Subdomain takeover Fastly unknown-domain fingerprint` (CWE-350)
- `web/Subdomain takeover GitHub Pages fingerprint` (CWE-350)
- `web/Subdomain takeover S3 NoSuchBucket fingerprint` (CWE-350)

## Technique

Dangling DNS fingerprints: GitHub Pages 'There isn't a GitHub Pages site here.' and S3 NoSuchBucket XML with BucketName — the two highest-yield provider fingerprints.

## Proof design (why it is falsifiable)

Provider-specific unauthenticated error bodies that ONLY appear when the CNAME dangles; AccessDenied (bucket exists) and normal 404s fail by design.

## Bypass variants / escalation ("think more beats level")

- Extend the fingerprint table: Azure CDN, Heroku, Fastly, Shopify, Tilda, Ghost
- Verify CNAME chain with DNS sibling before reporting
- Claim-then-release proof protocol (only with written authorization)
- Wildcard-DNS + takeover combo stories

## Sources (copied & rewritten into our proof-first DSL)

- EdOverflow/can-i-take-over-xyz — fingerprint table
- projectdiscovery/nuclei-templates — http/takeovers/

## False positives to rule out

Fingerprint without dangling CNAME (hosted-but-404) — pair the HTTP hit with the DNS check before reporting; the skill's description says so.

# Web Cache Poisoning & Deception

**CWE-444** · 3 skill(s) · folder `categories/cache/`

## Skills in this shelf

- `web/Web cache poisoning unkeyed X-Forwarded-Host` (CWE-444)
- `web/Password reset poisoning X-Forwarded-Host` (CWE-640)
- `elite/Web cache deception authenticated leak` (CWE-441)

## Technique

Unkeyed input (X-Forwarded-Host) surfaces attacker content in a cached response; password-reset poisoning rides the same unkeyed host into email links; cache deception appends a static-extension suffix to a private path so the cache stores another user's data.

## Proof design (why it is falsifiable)

Differential: payload response carries the attacker host, baseline (no header) does not — the delta IS the injection, and the README warns about cache persistence across trials.

## Bypass variants / escalation ("think more beats level")

- Unkeyed headers ladder: X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL, X-Host
- Fat GET / header smuggling for cache key manipulation
- Cache-key normalization issues (dot-encoding, semicolons)
- Deception with path params (`/api/profile/noncacheable.js`)
- Vary-header confusion for victim-targeted poisoning

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Web Cache Poisoning
- swisskyrepo/PayloadsAllTheThings — Web Cache Poisoning/Deception

## False positives to rule out

Host header echoed but keyed (no poisoning) — baseline differential excludes it.

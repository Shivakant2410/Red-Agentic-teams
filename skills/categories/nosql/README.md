# NoSQL Injection

**CWE-943** · 1 skill(s) · folder `categories/nosql/`

## Skills in this shelf

- `web/NoSQL Mongo operator login bypass` (CWE-943)

## Technique

MongoDB operator injection over JSON bodies: `{$ne: ""}` login bypass where the driver treats operator keys as query operators.

## Proof design (why it is falsifiable)

Auth state flip: 200 + session-bearing JSON on the operator payload vs 401 on plain wrong credentials — an unforgeable differential.

## Bypass variants / escalation ("think more beats level")

- $regex incremental extraction for blind data pulls
- $where JS injection when enabled
- Operator injection via arrays (`user[]=`) on form endpoints
- Aggregation-stage injection in reporting APIs
- Redis/Riak/CouchDB query-shape siblings for other stores

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — NoSQL Injection
- HackTricks book — NoSQL injection

## False positives to rule out

Apps rejecting non-string passwords outright (still a defect, different skill) — regex pins session content.

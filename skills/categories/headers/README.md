# Routing Header Confusion

**CWE-436** · 1 skill(s) · folder `categories/headers/`

## Skills in this shelf

- `elite/X-Original-URL routing confusion` (CWE-288)

## Technique

X-Original-URL / X-Rewrite-URL style headers let an attacker choose the upstream route while the front-end enforces ACLs on the visible path.

## Proof design (why it is falsifiable)

403 on the direct request + 200 on the header-routed request = ACL enforced on the wrong input; benign (no header) stays 403.

## Bypass variants / escalation ("think more beats level")

- X-Rewrite-URL, X-HTTP-Method-Override, X-Forwarded-Path siblings
- ACL bypass to admin panels, then to pre-auth RCE endpoints
- Combined Host+path routing confusion
- CDN cache-key pollution via routing headers

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Routing/cache header bypasses
- swisskyrepo/PayloadsAllTheThings — HTTP Header Injection (bypass section)

## False positives to rule out

Proxies that strip unknown headers — the differential handles it (payload then equals baseline).

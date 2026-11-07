# Broken Access Control (IDOR / Mass Assignment)

**CWE-639, CWE-915** · 3 skill(s) · folder `categories/access_control/`

## Skills in this shelf

- `web/IDOR horizontal object-graph` (CWE-639)
- `web/Mass assignment role escalation` (CWE-915)
- `web/Admin function reachable without privilege (BFLA)` (CWE-285)

## Technique

Two proofs: horizontal IDOR — same object type fetched under two principals, both 200 with differing JSON identity (json_differs on `id`) — and mass assignment — server accepts and PERSISTS a privileged field (`role: admin`) verified by a second read.

## Proof design (why it is falsifiable)

json_differs fails on identical values (benign same-object fetch), and the mass-assignment check read proves persistence, not just echo — write-back is what makes it exploitable.

## Bypass variants / escalation ("think more beats level")

- Guid/uuid enumeration instead of sequential ids
- Method-switching (GET->PATCH->POST) and content-type switching for hidden params
- Non-id fields (json_path=owner, email, tenant_id)
- Role injection via nested/related objects (`address[country]`, `role_id`)
- Bulk endpoints (`?ids=1,2,3`) as one-shot IDOR amplifiers

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — IDOR & Mass Assignment
- swisskyrepo/PayloadsAllTheThings — Mass Assignment parameter names

## False positives to rule out

Public objects (status 200 by design) — the differing-id condition requires genuinely distinct objects.

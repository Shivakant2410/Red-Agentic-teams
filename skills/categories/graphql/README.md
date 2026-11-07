# GraphQL Abuse

**CWE-200** · 3 skill(s) · folder `categories/graphql/`

## Skills in this shelf

- `web/GraphQL introspection enabled` (CWE-200)
- `elite/GraphQL field suggestion enumeration` (CWE-200)
- `elite/GraphQL alias amplification primitive` (CWE-770)

## Technique

Introspection enabled (full schema disclosure), field-suggestion enumeration ('Did you mean' as a dictionary oracle), and alias amplification as a batching primitive for brute/race.

## Proof design (why it is falsifiable)

__schema query returning 200 with __schema in body; suggestion oracle must include the quoted field-name hint; alias primitive must return N aliased data keys.

## Bypass variants / escalation ("think more beats level")

- GET-query bypass when POST introspection is blocked
- Introspection via __type(name) singles when __schema is filtered
- Nested-query depth DoS via alias stacks
- Batch/array-of-queries JSON for amplification
- Field-level authz (BOLA over graph edges) once schema is known

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — GraphQL
- swisskyrepo/PayloadsAllTheThings — GraphQL Injection

## False positives to rule out

Blocked introspection with suggestions still on — that is itself the field-suggestion skill, not noise.

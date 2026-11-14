# PHP Type Juggling (Magic Hashes)

**CWE-288** · 1 skill(s) · folder `categories/type_juggling/`

## Skills in this shelf

- `web/PHP type-juggling magic hash bypass` (CWE-288)

## Technique

Loose-comparison bypass: `240610708` hashes (md5) to 0e462097431906509019562988736854 — a 0e-all-digit 'magic hash' that ==-collides with ANY stored 0e-hash.

## Proof design (why it is falsifiable)

Auth state flip (302 -> /dashboard) on the magic value; a non-magic sibling fails normally. PRECONDITION: the stored hash must be 0e-shaped (leaked hash or known seed) — the README says so and the agent should verify the precondition before firing.

## Bypass variants / escalation ("think more beats level")

- Full magic-hash tables (md5/sha1/sha256) from PayloadsAllTheThings
- JSON-body type confusion ("pass": true, 0, []) alongside 0e tricks
- String-vs-int juggling in switch/in_array paths
- Sibling languages: JS == coercion in auth middlewares

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Type Juggling (magic hashes)
- HackTricks book — PHP type juggling

## False positives to rule out

password_verify() (strict) stacks — they never collide; the control proves the stack is loose first.

# Race Conditions & Single-Use Enforcement

**CWE-362** · 1 skill(s) · folder `categories/race_condition/`

## Skills in this shelf

- `web/Single-use token reusable on replay` (CWE-362)

## Technique

Deterministic serial-replay core: a token/coupon credited ONCE must never succeed twice. True parallel races (double-spend) additionally need the platform's burst executor — this shelf pins the enforcement defect itself.

## Proof design (why it is falsifiable)

Two identical requests both 200 = enforcement absent; consumed-token 400 on replay falsifies.

## Bypass variants / escalation ("think more beats level")

- Parallel-burst double-spend with the burst executor (limits-withdrawal/transfer)
- Coupon/trial-limit races (single-use absent — business_logic sibling)
- Last-write-wins profile races for privilege flip
- Confirmation-of-funds TOCTOU in checkout flows

## Sources (copied & rewritten into our proof-first DSL)

- PortSwigger Research — race condition single-packet attack (Kettle)
- OWASP Race Condition notes

## False positives to rule out

Idempotency-key'd endpoints legitimately replay-succeed — read the response body for a fresh vs cached marker before reporting.

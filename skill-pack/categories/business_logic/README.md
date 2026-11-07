# Business Logic Abuse (OWASP A04)

**CWE-840** · 2 skill(s) · folder `categories/business_logic/`

## Skills in this shelf

- `web/Negative quantity accepted in cart totals` (CWE-840)
- `web/Single-use coupon accepted on replay` (CWE-840)

## Technique

Server-side constraint proofs: negative quantities producing negative totals, single-use coupons applying twice — logic defects that scanners cannot genericize but a proven differential can pin exactly.

## Proof design (why it is falsifiable)

Server-COMPUTED evidence: the total becomes negative / the discount applies twice — not echo, arithmetic. Validation-rejecting twins 400 and falsify.

## Bypass variants / escalation ("think more beats level")

- Currency/rounding manipulation (price precision, 0.005 tricks)
- Quantity-type confusion (float, string '1e9')
- Checkout flow skips (confirm-order endpoint callable directly)
- Refund/credit double-claim chains with race_condition shelf

## Sources (copied & rewritten into our proof-first DSL)

- OWASP Top 10 2021 — A04 Insecure Design
- HackTricks book — business logic abuse

## False positives to rule out

Test environments with seeded discounts — verify the arithmetic in the response, not the status.

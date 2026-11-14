# API Abuse & Rate-Limit Gaps

**CWE-770** · 1 skill(s) · folder `categories/api_abuse/`

## Skills in this shelf

- `web/Rate limiting absent burst acceptance` (CWE-770)

## Technique

Absence-of-control proofs: N-burst requests against sensitive endpoints (OTP verify, login, token check) with zero throttling responses — OWASP API4 resource consumption.

## Proof design (why it is falsifiable)

All conditions demand 200 across the burst; any honest rate limiter returns 429 mid-burst and falsifies. Negative control IS the rate limiter.

## Bypass variants / escalation ("think more beats level")

- OTP/2FA brute primitives (code-space sizing math in README)
- Coupon/gift-code enumeration sweeps
- Webhook/event flooding for resource exhaustion
- Pagination/amplification abuse (page_size=1000)

## Sources (copied & rewritten into our proof-first DSL)

- OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption
- HackTricks book — rate-limit bypass notes

## False positives to rule out

Distributed rate limits keyed per-IP+token — single-IP bursts are the correct conservative probe; document the limitation when reporting.

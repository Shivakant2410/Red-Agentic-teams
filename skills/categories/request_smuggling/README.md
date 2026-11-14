# HTTP Request Smuggling (Desync)

**CWE-444** · 2 skill(s) · folder `categories/request_smuggling/`

## Skills in this shelf

- `elite/Request smuggling CL.TE timing oracle` (CWE-444)
- `elite/Request smuggling TE.CL timing oracle` (CWE-444)

## Technique

CL.TE and TE.CL desync detection by timing: a body whose framing the front-end and back-end read differently makes the back-end wait for the remainder — a clean latency oracle without poisoning real users.

## Proof design (why it is falsifiable)

latency_delta with a structurally identical well-formed request as baseline; min_delta 3.5s cannot be network noise. Benign (framing-consistent) requests stay fast.

## Bypass variants / escalation ("think more beats level")

- Confirm with a two-burst self-smuggle that completes with a differential
- Header-smuggling variants (X-Forwarded injection into back-end requests)
- HTTP/2 downgrade desync (h2c and content-length+authority tricks)
- Client-side desync for browser-triggered attacks
- Response-queue poisoning only after timing confirms — never blind-fire at shared caches

## Sources (copied & rewritten into our proof-first DSL)

- PortSwigger Research — HTTP request smuggling (James Kettle)
- HackTricks book — Request Smuggling

## False positives to rule out

Idle-timeout latency — the paired baseline request absorbs server-wide latency drift.

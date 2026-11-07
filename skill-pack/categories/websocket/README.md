# WebSocket Security (HTTP-observable layer)

**CWE-1385** · 1 skill(s) · folder `categories/websocket/`

## Skills in this shelf

- `web/WebSocket cross-origin handshake acceptance` (CWE-1385)

## Technique

Cross-origin handshake acceptance (CSWSH prerequisite): the upgrade request carries an attacker Origin and the server still switches protocols — authenticated cookie-backed WS sessions are then hijackable.

## Proof design (why it is falsifiable)

status 101 on the attacker-Origin upgrade; origin-allowlisted endpoints 403 and falsify.

## Bypass variants / escalation ("think more beats level")

- Post-handshake message abuse needs the WS sibling tool (out of HTTP scope)
- ws->wss downgrade and mixed-origin page embedding stories
- Origin-allowlist substring bypasses (same family as CORS shelf)
- CSWSH -> live message exfil chain (browser tool sibling)

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — WebSocket pentesting
- Christian Schneider — Cross-Site WebSocket Hijacking (original research)

## False positives to rule out

Token-authenticated WS (Origin independent) — confirm cookie-session auth before reporting.

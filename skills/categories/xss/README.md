# Cross-Site Scripting

**CWE-79** · 2 skill(s) · folder `categories/xss/`

## Skills in this shelf

- `web/XSS reflected HTML-context` (CWE-79)
- `web/Stored XSS persisted marker` (CWE-79)

## Technique

HTML-context reflection proven by execution-relevant markup, not just echo: unique marker + attribute-closing + `<svg/onload>` reflected RAW (reflected_unescaped condition), plus second-request stored-XSS persistence proof.

## Proof design (why it is falsifiable)

reflected_unescaped checks the payload reaches the body un-entity-encoded — html.escape'd reflections (the 90% case) fail the condition. Stored variant requires a SECOND request to observe persistence, so self-XSS/echo is excluded.

## Bypass variants / escalation ("think more beats level")

- Attribute/JS-context breakout (`" onfocus= autofocus`, template literal escape)
- Filter evasion: `<svg/onload>`, `<details open ontoggle>`, case/encoding mixes
- DOM XSS via fragment and postMessage sinks (needs browser-context sibling)
- mXSS through innerHTML round-trips
- Cookie-less session fixation via XSS-mounted fetch

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — XSS Injection
- HackTricks book — XSS (context breakout cheat sheets)

## False positives to rule out

Entity-encoded reflections and JSON-escaped strings — both fail the unescaped condition by design.

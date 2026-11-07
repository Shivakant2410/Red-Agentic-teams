# HTTP Parameter Pollution

**CWE-235** · 1 skill(s) · folder `categories/hpp/`

## Skills in this shelf

- `web/HTTP parameter pollution parser differential` (CWE-235)

## Technique

Parser disagreement over duplicated parameters: WAF/filter validates the first occurrence while the application takes the LAST — payloads ride in past input validation.

## Proof design (why it is falsifiable)

reflected_unescaped on the sink: the second-occurrence payload reaches the body raw while the single-param control is sanitized — the differential IS the bypass.

## Bypass variants / escalation ("think more beats level")

- First-vs-last vs concatenation behaviors per stack (PHP/Rails/ASP.NET differ)
- HPP into SQLi/SSRF sinks (id=1&id=2 building arrays)
- QS delimiter confusion (; vs &) per server
- HPP in URL-encoded JSON bodies and nested query builders

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — HTTP Parameter Pollution
- swisskyrepo/PayloadsAllTheThings — parameter pollution notes

## False positives to rule out

Frameworks rejecting duplicate params outright (400) — honest negative result.

# Server-Side Template Injection (SSTI)

**CWE-1336** · 8 skill(s) · folder `categories/ssti/`

## Skills in this shelf

- `web/SSTI Jinja2 arith+repeat proof` (CWE-1336)
- `web/SSTI Freemarker arith proof` (CWE-1336)
- `web/SSTI Mako python-arithmetic proof` (CWE-1336)
- `web/SSTI Velocity set-interpolation proof` (CWE-1336)
- `web/SSTI ERB ruby-eval proof` (CWE-1336)
- `web/Twig SSTI RCE map-system gadget` (CWE-1336)
- `web/Freemarker SSTI RCE Execute gadget` (CWE-94)
- `elite/Jinja2 SSTI OS command execution` (CWE-1336)

## Technique

User input reaches a server-side template engine and is compiled, not printed. Each skill pins ONE engine and proves arithmetic/string-repeat first, RCE gadgets second: Jinja2 `{{7*7}}`->49 plus `{{7*'7'}}`->7777777 (string repetition is Python-specific), Freemarker `${7*7}`, Mako `${7*7}`, Velocity `#set`, ERB `<%= %>`, then engine-specific gadgets (Twig `|map('system')`, Freemarker `.new()`, Jinja2 `__class__` chains).

## Proof design (why it is falsifiable)

Dual proof: evaluated result present AND raw marker absent — rules out plain reflection. The repeat probe (7777777) discriminates Jinja2 from Twig/Django, so the follow-up gadget matches the confirmed engine.

## Bypass variants / escalation ("think more beats level")

- Engine fingerprint decision tree (Jinja2 -> Twig -> Freemarker -> Mako -> Velocity -> ERB)
- Blind SSTI via `{% set x=%s %}` error channels when output is not reflected
- WAF evasion: `{%25+... %}`, `{{7*7}}` split across parameters, `{7*7}` attr-based
- RCE ladder per engine: Jinja2 MRO chains, Twig map/filter, Freemarker Execute+ObjectConstructor
- Client-side SSTI (angular/pug in email/marketing templates) as a lower-noise sibling

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Server Side Template Injection
- HackTricks book — SSTI (engine detection tables)

## False positives to rule out

Numeric echoes like '49' in pricing UIs — the raw-marker-absent condition kills these.

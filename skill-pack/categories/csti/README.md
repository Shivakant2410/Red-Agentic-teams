# Client-Side Template Injection

**CWE-1336** · 1 skill(s) · folder `categories/csti/`

## Skills in this shelf

- `web/Angular client-side template injection reflection` (CWE-1336)

## Technique

The HTTP-observable CSTI precondition pair: template syntax reflected RAW into a page that bootstraps Angular (ng-version/ng-app) — the browser compiles the reflection. HTTP alone cannot evaluate the DOM, so this shelf proves the pair and defers final confirmation to a browser tool.

## Proof design (why it is falsifiable)

Raw reflection + framework marker BOTH present; sanitized reflection or framework-absent pages fail honestly.

## Bypass variants / escalation ("think more beats level")

- Angular sandbox escapes per version ({{constructor...}} ladders)
- Vue/pug client template variants
- Email/marketing-template CSTI (campaign editors)
- Chain to DOM-XSS evidence via browser sibling tool

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Angular/CSTI client-side template injection
- swisskyrepo/PayloadsAllTheThings — client-side template injection

## False positives to rule out

{{moustache}} on non-template stacks (plain text) — the framework marker condition is what keeps this honest.

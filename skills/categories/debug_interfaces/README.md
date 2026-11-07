# Interactive Debug Consoles

**CWE-489** · 1 skill(s) · folder `categories/debug_interfaces/`

## Skills in this shelf

- `redteam/Werkzeug debug console exposed` (CWE-489)

## Technique

Werkzeug debugger console (and siblings) exposed — an interactive code-execution console behind a frequently bypassable PIN.

## Proof design (why it is falsifiable)

__debugger__ resource embedded in the console page — Werkzeug-specific, SPA-invisible.

## Bypass variants / escalation ("think more beats level")

- PIN bypass via predictable machine-id inputs (leaked by traceback siblings)
- Sibling consoles: Rails web-console, Laravel Ignition, IPython
- Traceback -> console chaining (info_disclosure feeds this folder)
- Console -> T1505.003 webshell equivalence for the chain story

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Werkzeug debug console
- projectdiscovery/nuclei-templates — http/exposures/ (werkzeug)

## False positives to rule out

404-fallback pages — the __debugger__ marker is Werkzeug-internal.

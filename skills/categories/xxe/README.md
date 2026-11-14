# XML External Entity (XXE)

**CWE-611** · 2 skill(s) · folder `categories/xxe/`

## Skills in this shelf

- `web/XXE in-band external entity file read` (CWE-611)
- `web/XXE error-based file disclosure` (CWE-611)

## Technique

DOCTYPE entity injection against XML parsers: in-band file read (`&xxe;` resolves into the response), error-based read (file content rides a parser exception), and SSRF-via-entity for internal pivoting.

## Proof design (why it is falsifiable)

Passwd-structured marker (`root:x:0:0`) appears ONLY when the parser resolved the external entity; DTD-blocked or hardened parsers produce errors without file content.

## Bypass variants / escalation ("think more beats level")

- Parameter-entity error oracle (%f; inside SYSTEM URI)
- OOB exfiltration via external DTD + HTTP/DNS (needs collaborator)
- XXE in SVG/XLSX/DOCX uploads (archive-embedded XML)
- Encoding tricks (UTF-16, base64-in-DTD) past naive filters
- PHP expect:// and Java jar:// protocol escalation

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — XXE Injection
- HackTricks book — XXE (error-based payloads)

## False positives to rule out

Parse errors without file content — control mock covers exactly that case.

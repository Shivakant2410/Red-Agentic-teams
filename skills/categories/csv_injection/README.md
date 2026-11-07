# CSV / Formula Injection

**CWE-1236** · 1 skill(s) · folder `categories/csv_injection/`

## Skills in this shelf

- `web/CSV formula injection via export` (CWE-1236)

## Technique

Spreadsheet-formula characters (=, +, -, @) stored via profile/comment fields execute when an admin exports to CSV and opens it in Excel/Sheets.

## Proof design (why it is falsifiable)

Second-request read-back: the export contains =HYPERLINK(attacker,...) verbatim — persistence proven, not just echo.

## Bypass variants / escalation ("think more beats level")

- DDE (`=cmd|'/c calc'!A0`) and HYPERLINK variants
- Google Sheets IMPORTXML-based exfiltration
- Injection via every export surface (reports, invoices, user lists)
- Prefix-blacklist bypasses with tab/CR prefixes

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — CSV Injection
- OWASP — CSV Excel Macro Injection

## False positives to rule out

Sanitizers prefixing cells with ' — the read-back condition fails on those.

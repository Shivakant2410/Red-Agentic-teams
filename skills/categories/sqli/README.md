# SQL Injection

**CWE-89** · 9 skill(s) · folder `categories/sqli/`

## Skills in this shelf

- `web/SQLi time-based blind PostgreSQL` (CWE-89)
- `web/SQLi error-based PostgreSQL-family` (CWE-89)
- `web/SQLi boolean-blind response differential` (CWE-89)
- `elite/SQLi UNION reflection exfiltration primitive` (CWE-89)
- `web/SQLi error-based MySQL-family` (CWE-89)
- `web/SQLi error-based MSSQL-family` (CWE-89)
- `web/SQLi error-based Oracle-family` (CWE-89)
- `web/SQLi time-based blind MySQL-MariaDB` (CWE-89)
- `web/SQLi time-based blind MSSQL` (CWE-89)

## Technique

Dialect-pinned proofs: error-based families (psycopg/PG::/SQLSTATE[42 vs MySQL syntax vs MSSQL SqlException vs ORA-01756), time-based oracles (pg_sleep/sleep/WAITFOR DELAY with a structurally identical 0-second twin), boolean-blind differentials, and UNION reflection.

## Proof design (why it is falsifiable)

Time-based skills isolate DB execution from network noise: baseline and payload differ ONLY in the sleep argument (pg_sleep(0) vs pg_sleep(6)), so latency_delta >= 3.5s cannot be jitter. Error-based skills match driver-level exception strings — impossible to fake with app errors.

## Bypass variants / escalation ("think more beats level")

- Bool-blind byte-by-byte extraction with a boolean differential pair
- UNION column-count ladder (ORDER BY n) then marker exfiltration
- Second-order SQLi (stored payload executes on a later page)
- JSON/XML-aware injection when quote filtering is context-aware
- Out-of-band exfiltration via DNS (DNSExfiltrator pattern) when latency is throttled

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — SQL Injection
- HackTricks book — SQL Injection (error fingerprints per dialect)

## False positives to rule out

App-level validation errors that mimic driver text — regexes pin driver-namespace strings only.

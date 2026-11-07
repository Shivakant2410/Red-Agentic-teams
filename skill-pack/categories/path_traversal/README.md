# Path Traversal & Local File Inclusion

**CWE-22** · 4 skill(s) · folder `categories/path_traversal/`

## Skills in this shelf

- `web/Path traversal once-strip filter evasion` (CWE-22)
- `web/Nginx alias traversal off-by-slash` (CWE-22)
- `web/PHP filter wrapper LFI base64 read` (CWE-98)
- `redteam/Grafana plugin path traversal` (CWE-22)

## Technique

Filter-aware traversal: once-strip evasion (`....//`), Nginx alias off-by-slash, PHP filter wrapper (`php://filter/convert.base64-encode/resource=`) for source read, plus CVE-pinned product traversal (Grafana plugins).

## Proof design (why it is falsifiable)

Passwd-structured content in the response of the EVASION payload while a normal file request succeeds — proves the filter exists AND was beaten, not that the app is simply open.

## Bypass variants / escalation ("think more beats level")

- Encoding ladders: %2e%2e%2f, ..%252f, ..%c0%af, ..%ef%bc%8f
- Null-byte and truncation tricks on legacy stacks
- php://filter chains for source disclosure -> hardcoded secret harvesting
- Traversal in archive extraction (zip-slip) and upload filenames
- Windows variants: ..\, drive-absolute paths, ADS `file.php::$DATA`

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — File Inclusion / Path Traversal
- HackTricks book — File Inclusion/Path traversal (encoding tables)

## False positives to rule out

404-vs-403 noise — vuln mock demands actual passwd content, not error shapes.

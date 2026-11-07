# File Upload Abuse

**CWE-434, MITRE T1505.003** · 2 skill(s) · folder `categories/file_upload/`

## Skills in this shelf

- `web/Upload double-extension filter bypass` (CWE-434)
- `web/Upload phtml execution marker` (CWE-434)

## Technique

Filter-bypass and execution proofs on upload endpoints: double-extension handling (shell.php.jpg), .phtml polyglot upload with an execution marker, GIF-magic-prefixed PHP. Each skill pins ONE filter class and proves either storage or execution.

## Proof design (why it is falsifiable)

Execution proof: server OUTPUT contains our marker + php_uname() — the strongest possible confirmation (webshell-class). Storage proof: accepted path echoed back. Benign controls: rejected upload (415) or saved-but-served-static (no marker).

## Bypass variants / escalation ("think more beats level")

- Content-type/extension matrix (php5, phtml, phar, shtml, asa, cer)
- Magic-byte polyglots (GIF89a, \xFF\xD8 JPEG prefixes)
- Path manipulation in filename (../../, absolute paths)
- Metadata exif payload placement + LFI pairing
- Upload -> LFI/XXE/SSRF chain stories (phar://, archive XML)

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — Upload Insecure Files
- HackTricks book — File Upload (extension/filter tables)

## False positives to rule out

Uploads accepted but served from a static CDN without handlers — storage-only findings are reported at lower impact and the execution conditions honestly fail.

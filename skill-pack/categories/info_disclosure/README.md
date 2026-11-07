# Diagnostic & Information Disclosure

**CWE-200, CWE-489** · 4 skill(s) · folder `categories/info_disclosure/`

## Skills in this shelf

- `web/Directory listing autoindex exposed` (CWE-548)
- `web/phpinfo diagnostic page exposed` (CWE-200)
- `web/Framework debug traceback disclosure` (CWE-209)
- `web/OpenAPI-Swagger spec exposed` (CWE-200)

## Technique

Autoindex listings, phpinfo, framework tracebacks with paths/DEBUG state, and machine-readable API specs (OpenAPI) exposed to anonymous users.

## Proof design (why it is falsifiable)

Structure-anchored regexes (Index of /, PHP Version + php.ini path, Traceback + File lines, openapi/paths keys) — decorative 404/HTML fails.

## Bypass variants / escalation ("think more beats level")

- Swagger-UI paths -> hidden endpoint harvesting for the whole catalog
- Traceback -> source paths -> .map/.bak sweeps
- phpinfo -> env secrets + upload_tmp_dir for LFI chaining
- Autoindex -> backup/config file enumeration

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/exposures/, http/misconfiguration/
- danielmiessler/SecLists — discovery sweeps

## False positives to rule out

Custom 404/500 pages — none of the anchors appear on them.

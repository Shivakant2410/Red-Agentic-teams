# CMS Surfaces (WordPress)

**CWE-200, CWE-352** · 3 skill(s) · folder `categories/cms/`

## Skills in this shelf

- `web/WordPress REST users enumeration` (CWE-200)
- `web/WordPress debug.log exposure` (CWE-532)
- `web/WordPress xmlrpc method discovery` (CWE-200)

## Technique

WordPress REST user enumeration, debug.log exposure, and xmlrpc method discovery — the standard CMS recon triad feeding credential brute and pingback abuse.

## Proof design (why it is falsifiable)

WP-shaped JSON/HTML markers (id/slug arrays, PHP Notice with wp- paths, methodResponse arrays).

## Bypass variants / escalation ("think more beats level")

- REST user enum -> application-password brute
- xmlrpc system.multicall password amplification
- debug.log -> plugin paths -> known plugin CVE matching
- Sibling CMS: Drupal user/REST endpoints, Joomla com_users

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/cves/wordpress, http/exposures/
- HackTricks book — WordPress pentesting

## False positives to rule out

REST hardened with /?rest_route= blocked — xmlrpc sibling still probes independently.

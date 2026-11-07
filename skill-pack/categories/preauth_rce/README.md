# Pre-Auth RCE (Known CVEs & Gadgets)

**CWE-917, CWE-94** · 3 skill(s) · folder `categories/preauth_rce/`

## Skills in this shelf

- `web/ThinkPHP invokefunction controller RCE` (CWE-94)
- `web/Log4Shell JNDI lookup error probe` (CWE-917)
- `redteam/Spring Cloud Gateway SpEL RCE` (CWE-917)

## Technique

CVE-pinned remote code execution reachable without credentials: ThinkPHP invokefunction controller dispatch, Log4Shell JNDI lookup probes (error-channel confirmation), Spring Cloud Gateway SpEL route-filter injection.

## Proof design (why it is falsifiable)

Each proof rides the product's own error/echo channel: phpinfo rendered by the dispatched controller, NamingException naming our host, route args echoing SpEL evaluation output — no blind assumptions, no destructive payload.

## Bypass variants / escalation ("think more beats level")

- Log4Shell: full ${jndi:ldap://} chain with a private collaborator
- Spring Cloud Gateway: reverse-shell route (authorized ops only)
- ThinkPHP: write-webshell follow-up via file_put_contents dispatch
- Sibling CVE families: Confluence OGNL, WebLogic T3/IIOP, VMware vCenter

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/cves/ (thinkphp, log4j, spring)
- HackTricks book — JNDI exploit notes

## False positives to rule out

WAFs blocking the string — error-channel probes survive string-only filters on some stacks; keep the negative control.

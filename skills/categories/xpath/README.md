# XPath Injection

**CWE-643** · 1 skill(s) · folder `categories/xpath/`

## Skills in this shelf

- `web/XPath injection boolean wildcard probe` (CWE-643)

## Technique

XPath expression concatenation: boolean/wildcard payloads return the whole node set — the XML sibling of the LDAP shelf's wildcard enumeration.

## Proof design (why it is falsifiable)

Node markers (<user>) present on the injection and absent on the empty-control — differential identical in shape to ldap_injection.

## Bypass variants / escalation ("think more beats level")

- Boolean-blind XPath extraction (count()/substring() ladders)
- XPath 2.0 function abuse (doc() for file reads where supported)
- Auth-bypass filters (' or '1'='1 on login XPath)
- Siblings: JSONPath/YAML query injection on query-builder endpoints

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — XPath Injection
- HackTricks book — XPath injection

## False positives to rule out

Client-side XSLT rendering — probe only server-side evaluation endpoints.

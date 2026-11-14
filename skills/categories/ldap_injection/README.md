# LDAP Injection

**CWE-90, MITRE T1087.002** · 1 skill(s) · folder `categories/ldap_injection/`

## Skills in this shelf

- `web/LDAP wildcard filter enumeration` (CWE-90)

## Technique

Filter-string concatenation abuse: wildcard uid=* returns the whole directory; the same family covers auth-bypass filters `*)(uid=*))(|(uid=*`.

## Proof design (why it is falsifiable)

Directory-shaped fields (uid/cn/dn) present on the wildcard payload and ABSENT on the nonexistent-uid control — a clean differential.

## Bypass variants / escalation ("think more beats level")

- Attribute enumeration ladder (mail, memberOf, sAMAccountName)
- Filter auth-bypass (`*)(&)` variants) on bind flows
- BLIND LDAP via boolean errors (AND 1=1/1=0 shaped filters)
- AD-specific pivots: memberOf harvesting for privilege mapping
- Sibling: XPath/JSONPath injection when directory-shaped data rides XML

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — LDAP Injection
- HackTricks book — LDAP injection & AD enumeration

## False positives to rule out

Endpoints that pre-escape or bind with service accounts — empty control keeps it honest.

# Exposed Admin & Database Panels

**CWE-1188** · 6 skill(s) · folder `categories/admin_panels/`

## Skills in this shelf

- `redteam/Tomcat Manager exposed 401-probe` (CWE-1188)
- `redteam/H2 database console exposed` (CWE-284)
- `infra/phpMyAdmin panel exposed` (CWE-1188)
- `infra/Adminer db manager exposed` (CWE-1188)
- `infra/JBoss jmx-console exposed` (CWE-668)
- `infra/Alibaba Druid stat monitor exposed` (CWE-200)

## Technique

Title/realm-pinned detection of Tomcat Manager, H2 console, phpMyAdmin, Adminer, JBoss jmx-console, Druid monitor — each is a staging surface for the auth/default-credential and webshell follow-up skills.

## Proof design (why it is falsifiable)

Status code + title/realm anchors (Basic realm="Tomcat Manager", <title>H2 Console</title>) — proxied 404 pages cannot produce the realm header.

## Bypass variants / escalation ("think more beats level")

- Feed hits into auth/grafana_default_creds-style skills
- H2 console -> JDBC RCE (RUNSCRIPT/CREATE ALIAS) follow-ups
- Adminer -> file-read via load data/attach-db flows
- Manager -> WAR webshell deploy (T1505.003) once credentials land

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/technologies/, http/exposures/
- HackTricks book — admin panel default creds

## False positives to rule out

Vendor login pages with similar titles — realm/title anchors are vendor-specific strings.

# Authentication Flaws (Enumeration / Default Credentials / Bypass)

**CWE-204, CWE-288, CWE-1188** · 4 skill(s) · folder `categories/auth/`

## Skills in this shelf

- `web/Username enumeration login differential` (CWE-204)
- `redteam/Grafana default credential login` (CWE-798)
- `elite/Tomcat Manager default credential acceptance` (CWE-798)
- `infra/Nacos CVE-2021-29442 UA auth bypass` (CWE-288)

## Technique

Login differentials that leak account existence, default-credential acceptance on admin surfaces, and CVE-pinned auth bypasses (Nacos serverIdentity UA bypass).

## Proof design (why it is falsifiable)

Differential responses: known user gets a distinct message/status; default creds flip state (200 + session JSON); bypass header yields the protected listing.

## Bypass variants / escalation ("think more beats level")

- Timing-based enumeration when messages are normalized
- Response-body and response-size differentials on registration/reset flows
- Vendor default-credential dictionaries (tomcat/grafana/nacos families)
- Header-bypass ladders: X-Original-URL, X-Accel-Redirect, referer/trusted-host tricks
- JWT/session fixation follow-ups once auth lands

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Auth bypass & default credentials
- projectdiscovery/nuclei-templates — http/default-logins, http/cves (Nacos)

## False positives to rule out

Uniform 'invalid credentials' with no differential — then the skill honestly reports nothing.

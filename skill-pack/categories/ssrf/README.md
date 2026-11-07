# SSRF & Cloud Metadata (IMDS)

**CWE-918, MITRE T1552.005** · 5 skill(s) · folder `categories/ssrf/`

## Skills in this shelf

- `web/SSRF file-scheme local file read` (CWE-918)
- `web/SSRF AWS IMDSv1 role discovery` (CWE-918)
- `web/SSRF AWS IMDSv1 credential dump` (CWE-918)
- `web/SSRF GCP metadata instance zone read` (CWE-918)
- `web/SSRF Azure IMDS instance read` (CWE-918)

## Technique

Server-side fetch abuse: file:// local read, AWS IMDSv1 (no header required — role name then credential JSON), GCP metadata (requires Metadata-Flavor: Google), Azure IMDS (requires Metadata: true). Each cloud gets its own skill because the required headers differ.

## Proof design (why it is falsifiable)

Response content is cloud-shaped and unforgeable: role-name line, AccessKeyId JSON, projects/<n>/zones/<region>, vmId/subscriptionId. Egress-blocked errors fail the regexes.

## Bypass variants / escalation ("think more beats level")

- Redirect chain SSRF (302 to 169.254.169.254) past naive allow-lists
- DNS rebinding when targets are validated by hostname
- Cloud-native aliases: metadata.google.internal, 100.100.100.200 (Alibaba), 169.254.170.2 (ECS task)
- IMDSv2 hop-by-hop header restrictions (X-aws-ec2-metadata-token-token-ttl-seconds)
- Gopher:// and other exotic schemes where supported

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — SSRF / Cloud SSRF (metadata services)
- swisskyrepo/PayloadsAllTheThings — Server Side Request Forgery

## False positives to rule out

Outbound proxies returning their own error pages — cloud-shaped regexes exclude proxy HTML.

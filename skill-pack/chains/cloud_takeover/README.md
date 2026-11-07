# Attack chains — Blind Read -> Cloud Identity -> Resource Takeover

**Group `cloud_takeover`** · 3 chain(s) · folder `chains/cloud_takeover/`

One SSRF or XXE primitive is rarely the finding — it is the door. This group walks from an arbitrary-fetch/file-read primitive into the instance identity plane (AWS/GCP/Azure metadata), extracts live session credentials, and hands the operator a pivot into cloud resources.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `aws-imds-full-takeover` | AWS IMDS: SSRF -> role -> session keys -> takeover | 3 | CWE-918, CWE-798 |
| `multi-cloud-metadata-sweep` | Metadata sweep: GCP + Azure + AWS in one primitive | 3 | CWE-918, CWE-200 |
| `xxe-to-metadata` | XXE as SSRF: file proof -> error channel -> metadata creds | 3 | CWE-611, CWE-918 |

## Shared recon for this group (how to find candidates at all)

- **SSRF sink inventory** — Crawl + wayback, keep every endpoint whose name or parameter suggests fetching a URL (fetch, url, proxy, dest, img, render, import, webhook, callback, preview, html2pdf).
- **Unkeyed header hunt** — Inject candidate headers (X-Forwarded-Host, X-Original-URL, Referer-as-URL) at every mirror and cache; diff responses.
- **Canary egress check** — Send a collaborator-style canary domain through every candidate sink; DNS or HTTP callback proves server-side fetch before you waste probes on metadata IPs.
- **Error mining for internals** — Force errors at sinks and read stack traces / messages for internal hostnames, ports, VPC ranges and proxy config.
- **Sibling-stack clustering** — Shodan/FOFA favicon-hash and header clustering to find other apps on the same front-proxy stack — one SSRF pattern usually repeats fleet-wide.

## Chain playbooks

### AWS IMDS: SSRF -> role -> session keys -> takeover — `aws-imds-full-takeover`

**Goal.** Turn a same-origin SSRF into live AWS session credentials for the instance profile.
**Preconditions.** A parameter or header that makes the server issue HTTP requests (or read file:// paths); EC2 deployment without IMDSv2 hop limit enforcement.
**Impact.** Live AKIA/ASIA session keys for the instance role -> S3/EC2/STS actions in the role's scope; combined with public bucket listing this is direct data-plane takeover.
**CWE.** CWE-918, CWE-798 · **Fallbacks.** `multi-cloud-metadata-sweep`, `xxe-to-metadata`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/SSRF file-scheme local file read` | Prove the sink at the strongest primitive (file://) and fingerprint the host (cloud-init, /etc/passwd, hostname). | Record the sink; try http:// against 169.254.169.254 through the same sink. | file:// blocked but http:// works -> go straight to step 2; neither works -> pivot to chain multi-cloud-metadata-sweep for header-based providers. |
| 2 | `web/SSRF AWS IMDSv1 role discovery` | Read /latest/meta-data/iam/security-credentials/ to learn the attached role name. | Save the role name as the {{role_name}} input of step 3. | 401 on IMDS = IMDSv2 token required -> try X-aws-ec2-metadata-token header injection via web/CRLF response-header injection; GCP/Azure instead -> multi-cloud-metadata-sweep. |
| 3 | `web/SSRF AWS IMDSv1 credential dump` | Dump the role's AccessKeyId/SecretAccessKey/Token = live session credentials. | Validate scope with a cheap ListBuckets/GetCallerIdentity call; pivot to redteam/S3-GCS public bucket listing for the data plane. | Keys present but scoped-down -> keep them as evidence, sweep other SSRF sinks for other roles; redteam/.env dotenv secrets exposure may hold static keys. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- url/fetch/proxy/dest/img/render query params
- webhook configurators (Slack/Discord/Teams)
- import-from-URL (avatars, Google-Sheets style import, CMS media by URL)
- PDF/report generators (wkhtmltopdf, headless Chrome)
- link-preview unfurlers, oEmbed endpoints
- XML/DOCX/SVG import features (XXE-as-SSRF)

**Recon methods** — techniques beyond the skill itself:

- **Parameter wordlist fuzz on sinks** — FFUF the collected endpoint list with canary URL values in every candidate parameter. Tooling: ffuf + SecLists burp-parameter-names. Signal: Canary callback or response containing canary content..
- **Wayback parameter mining** — Pull historical URLs, grep for fetch-shaped parameters, replay them at the live host. Tooling: gau / waybackurls + grep -E 'url=|dest=|proxy='. Signal: Old endpoints still alive are untested by dev..
- **Internal port scan via latency** — Time requests to 127.0.0.1:N through the sink; open ports answer fast or differently. Tooling: Burp Intruder + response-time column. Signal: Latency deltas identify 80/8080/8000/9200/6379 neighbors..
- **IMDS address variants** — Try 169.254.169.254, 169.254.169.254.nip.io, decimal/hex/IPv6 encodings to slip past blocklists. Tooling: manual + Burp Repeater. Signal: Blocklist bypass when one encoding returns data others 403..
- **Header-based metadata triggers** — Inject Metadata-Flavor / Metadata / X-aws-ec2-metadata-token headers where the sink forwards client headers. Tooling: Burp + param-miner header brute. Signal: GCP/Azure metadata JSON in the response..

**Class variants** — other places the same weakness hides:

- SSRF in webhook signature validators
- SSRF in SAML IdP metadata fetch
- SSRF in Grafana/Prometheus datasource URLs
- SSRF in k8s admission webhooks
- SSRF in image/media processors via URL
- ImageMagick-style processors with file scheme

**Dorks**:

- github: "169.254.169.254" language:python (review hardcoded IMDS calls)
- github: "imds" "hop_limit"
- google: inurl:fetch?url= OR inurl:proxy?url=

**Pivot hints** — where to go after proof:

- Session keys -> assume-role across accounts in the org
- role name reveals workload -> enumerate sibling instances via same stack (favicon clustering)
- no cloud creds? file:// read of ~/.aws/credentials or /var/lib/kubelet/... configs

**Sources.** PayloadsAllTheThings — Server Side Request Forgery; HackTricks — Cloud SSRF & metadata; AWS docs — IMDSv2 session tokens; PortSwigger Web Security Academy — SSRF


### Metadata sweep: GCP + Azure + AWS in one primitive — `multi-cloud-metadata-sweep`

**Goal.** With one header-forwarding SSRF, sweep every major cloud's metadata service and harvest whichever identity plane the workload runs on.
**Preconditions.** SSRF sink that forwards or allows injected request headers (needed for GCP Metadata-Flavor and Azure Metadata:true).
**Impact.** GCP access tokens, Azure vmId/subscriptionId/IMDS tokens, or AWS credentials — whichever provider hosts the target.
**CWE.** CWE-918, CWE-200 · **Fallbacks.** `aws-imds-full-takeover`, `xxe-to-metadata`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/SSRF GCP metadata instance zone read` | GCP check: metadata.google.internal with Metadata-Flavor: Google; projects/\d+/zones/ proves the identity plane. | Token endpoints follow: /computeMetadata/v1/instance/service-accounts/default/token. | Not GCP -> step 2 (Azure). |
| 2 | `web/SSRF Azure IMDS instance read` | Azure check: 169.254.169.254/metadata/instance with Metadata:true header. | vmId/subscriptionId -> /metadata/identity/oauth2/token for managed identity token. | Not Azure -> step 3 (AWS). |
| 3 | `web/SSRF AWS IMDSv1 role discovery` | AWS check: plain GET, no special header needed. | Jump to chain aws-imds-full-takeover step 3 for the credential dump. | All three miss -> workload is on-prem or IMDSv2-only; sweep internal services via latency (see discovery.recon). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- any header-forwarding proxy or template renderer
- fetch sinks where attacker controls some headers
- CRLF-injectable parameters (inject Metadata-Flavor into the sub-request)

**Recon methods** — techniques beyond the skill itself:

- **Header passthrough test** — Send X-Test headers to your canary through the sink; if they arrive, metadata headers can be forged. Tooling: canary host + Burp. Signal: Attacker-chosen headers reach the sub-request..
- **CRLF header injection primer** — Probe parameters for %0d%0a to smuggle Metadata-Flavor into the internal request. Tooling: web/CRLF response-header injection skill. Signal: Injected header lands in internal request -> GCP/Azure metadata unlocks..
- **Provider banner triangulation** — Error pages, Server headers and timing patterns reveal the hosting provider before you burn probes. Tooling: manual recon. Signal: e.g. gstatic references, Azure App Service headers (x-ms-...), AWS ALB headers..
- **Metadata IP alternatives** — metadata.google.internal, 169.254.169.254, 100.100.100.200 (Alibaba), fd00:ec2::254 (IPv6 AWS). Tooling: manual list. Signal: Any hit identifies the provider directly..

**Class variants** — other places the same weakness hides:

- Alibaba 100.100.100.200
- DigitalOcean /lib/os-server-info style endpoints
- Oracle Cloud 192.0.0.192
- OpenStack 169.254.169.254 with X-Service-Token
- k8s env-injected credentials instead of IMDS

**Dorks**:

- github: "Metadata-Flavor" "computeMetadata"
- shodan: http.html:"x-ms-request-id"
- github: "169.254.169.254/metadata/instance"

**Pivot hints** — where to go after proof:

- GCP token -> impersonate service accounts via token scopes
- Azure IMDS -> managed-identity token -> ARM enumeration
- record which provider answered to shorten future sweeps fleet-wide

**Sources.** GCP metadata API docs; Azure IMDS protocol docs (version param required); HackTricks — Cloud metadata endpoints; PayloadsAllTheThings — SSRF URLs / cloud providers


### XXE as SSRF: file proof -> error channel -> metadata creds — `xxe-to-metadata`

**Goal.** Use XML entity expansion first as file-read proof, then as an HTTP client toward the cloud metadata service.
**Preconditions.** Any XML parser accepting external entities: XML/DOCX/XLSX/SVG uploads, SAML consumers, RSS parsers, XML-RPC, config importers.
**Impact.** Arbitrary local file read (configs, SSH keys) and, where the parser resolves http entities, cloud credentials via metadata.
**CWE.** CWE-611, CWE-918 · **Fallbacks.** `aws-imds-full-takeover`, `recon-secrets-to-cloud`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/XXE in-band external entity file read` | In-band proof: /etc/passwd rendered into the response confirms entity resolution. | Read app config files next (paths from file listing) for secrets. | No in-band output -> step 2, use the error channel. |
| 2 | `web/XXE error-based file disclosure` | Blind variant: exfiltrate file content through parser error messages. | Same evidence, different channel — keep for parsers that suppress output but leak errors. | Errors sanitized -> OOB via canary DTD (documented gap: needs collaborator endpoint); meanwhile try metadata via step 3. |
| 3 | `web/SSRF AWS IMDSv1 credential dump` | Repoint the entity at http://169.254.169.254/... through the same parser (XXE-as-SSRF). | Credentials JSON lands in-band or in error text; pivot to chain aws-imds-full-takeover. | Parser blocks http entities -> file:// read of ~/.aws/credentials, .env, /proc/self/environ instead. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- DOCX/XLSX/PPTX uploads (they are zip+XML)
- SVG uploads (image upload features!)
- SAML response consumption
- RSS/Atom feed importers
- WordPress xmlrpc, SOAP endpoints
- XML config import (nagios/zabbix-style)

**Recon methods** — techniques beyond the skill itself:

- **Content-Type probe** — Post the same entity payload with text/xml, application/xml, and inside an SVG; parsers differ by route. Tooling: Burp Repeater + body swap. Signal: Parser error mentioning XML = parse surface..
- **Office-file steganography** — Inject DTD into [Content_Types].xml of a real DOCX and upload. Tooling: manual zip edit. Signal: Upload accepted + entity resolved = stealth XXE on 'image/document only' endpoints..
- **Parser fingerprint** — Error text identifies library (libxml2, javax.xml, php xml_parse) -> pick encoding/parameter-entity tricks per parser. Tooling: error mining. Signal: Library tells you which XXE bypasses apply (e.g. PHP param entities, Java jar://)..
- **OOB-free blind detection** — Time or size differentials from huge entity counts (billion laughs) confirm expansion without callbacks. Tooling: timing probes. Signal: Latency spike proves entity processing..

**Class variants** — other places the same weakness hides:

- XInclude on fragment parsers
- DTD-in-PDF generators
- YAML deserialization surfaces (pyYAML)
- JSON-to-XML converters
- Office macro-free xlsx with external references

**Dorks**:

- github: "<!DOCTYPE" "<!ENTITY" inurl:upload
- github: "DocumentBuilderFactory" -"setFeature" (no hardening)
- shodan: http.html:"xmlrpc.php"

**Pivot hints** — where to go after proof:

- file read -> /etc/hostname + provider configs -> pick metadata variant
- read /proc/net/tcp for internal service map
- combine with path traversal skills once a file-read channel exists

**Sources.** PayloadsAllTheThings — XXE; HackTricks — XXE per-language tricks; PortSwigger — Blind XXE with OOB; Gosecure — PHP parameter-entity XXE research


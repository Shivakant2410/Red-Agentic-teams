# Attack chains — Exposed Artifacts -> Secrets -> Infra Takeover

**Group `exposure_to_takeover`** · 5 chain(s) · folder `chains/exposure_to_takeover/`

Belt-and-suspenders ops hygiene failures chain into infrastructure access: source maps into source history, source history into cloud keys, exposed management planes into CI and cluster control. This is the group where recon exhaust alone becomes a takeover story.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `recon-secrets-to-cloud` | Recon: sourcemap -> .env -> .git history -> bucket -> cloud keys | 4 | CWE-540, CWE-538, CWE-200 |
| `subdomain-takeover-sweep` | Takeover: fingerprint sweep -> claim -> cookie-scope abuse | 5 | CWE-350 |
| `spring-actuator-to-rce` | Spring: actuator env -> heapdump tokens -> gateway SpEL RCE | 4 | CWE-200, CWE-94 |
| `jenkins-to-cluster` | CI -> cluster: Jenkins enum -> Groovy RCE -> kubelet -> etcd | 4 | CWE-306, CWE-284 |
| `container-plane-sweep` | Container plane: registry catalog -> docker daemon -> portainer/consul/nomad | 5 | CWE-306, CWE-668 |

## Shared recon for this group (how to find candidates at all)

- **Artifact-path dictionary sweep** — Fixed dictionary of artifact paths (.git, .env, .svn, .DS_Store, backup.*, dump.*, *.sql, *.tar) against every live host.
- **Wayback archaeology** — Historical URLs reveal old artifact locations, dev hosts and removed endpoints that still answer.
- **Subdomain expansion** — CT logs + passive DNS + takeover-fingerprint sweep; dead CNAMEs are the takeover surface.
- **Management-plane dictionary** — Known management consoles (Tomcat/Jenkins/H2/phpMyAdmin/Adminer/Portainer/Consul/Nomad/Vault/Solr...) probed at canonical paths and ports.
- **Secret-pattern harvest** — From every exposed artifact: grep key patterns (AKIA, AIza, sk_live, xoxb, ghp_, pem headers, DSN strings) — each hit maps to a pivot chain.

## Chain playbooks

### Recon: sourcemap -> .env -> .git history -> bucket -> cloud keys — `recon-secrets-to-cloud`

**Goal.** Walk the artifact ladder from client-side source disclosure to usable cloud credentials and data buckets.
**Preconditions.** Any one exposed artifact class on any live host.
**Impact.** Application source, secrets in history, cloud keys -> resource access; public buckets -> data plane.
**CWE.** CWE-540, CWE-538, CWE-200 · **Fallbacks.** `spring-actuator-to-rce`, `aws-imds-full-takeover`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/JS source map disclosure` | Restore original source from .map files — endpoints, comments, and leftover keys. | Extract endpoint list + any embedded creds; feed endpoints into other chains. | No maps -> step 2 (.env) and step 3 (.git) directly. |
| 2 | `redteam/.env dotenv secrets exposure` | Live environment config: DB DSNs, mail creds, cloud keys. | Key triage: which creds are cloud vs app-internal. | No .env -> git history next; .DS_Store/.svn siblings for directory naming. |
| 3 | `redteam/.git source disclosure chain` | Full source history incl. deleted secrets (old keys often still valid). | Mine history for rotated-but-live keys. | No .git -> backup archives (web/Backup archive misplacement exposure) and phpinfo/actuator env as alternates. |
| 4 | `redteam/S3-GCS public bucket listing` | Use bucket names recovered from source/env to reach the data plane. | Public data + arns/policies -> severity lift. | Bucket names unknown -> brute from org naming conventions; note documented gap (needs wordlist tool). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- every live host's webroot
- staging/dev subdomains (wayback)
- API hosts (sourcemaps rare but gold)
- old product versions still deployed

**Recon methods** — techniques beyond the skill itself:

- **Artifact dictionary sweep** — Fixed path list per host; diff 404 vs 403 vs 200. Tooling: ffuf + artifact wordlist. Signal: Artifact served or directory-listing behavior..
- **Map-file probe** — For every .js: request .js.map; also check webpack devtool leaks in bundle comments. Tooling: manual + script. Signal: Map JSON with sourcesContent..
- **GitHub org mining** — GitHub code search on the org name and domains for leaked keys and configs. Tooling: github search + gitleaks/trufflehog on found repos. Signal: Key patterns in commit history..
- **Dir-name recovery from .DS_Store** — Recover hidden directory names from .DS_Store/.svn before brute-forcing paths. Tooling: web/.DS_Store mac resource exposure, web/.svn working-copy wc.db exposure. Signal: Directory names → targeted artifact sweep..
- **Diagnostics pages** — phpinfo/actuator env/heapdump print env vars including keys — alternate artifact class. Tooling: web/phpinfo diagnostic page exposed, redteam/Spring Boot actuator env leak. Signal: Env table with credentials..

**Class variants** — other places the same weakness hides:

- .DS_Store / .svn / .hg directory disclosure
- backup.zip / site.tar / dump.sql
- phpinfo env section
- actuator env + heapdump strings
- MinIO bootstrap env disclosure
- CI logs with masked-but-visible secrets

**Dorks**:

- github: filename:.env AWS_SECRET
- github: "DB_PASSWORD" org:<target-org>
- google: intitle:index.of .env
- shodan: http.html:"phpinfo()"

**Pivot hints** — where to go after proof:

- cloud keys -> aws-imds-full-takeover narrative for impact framing
- DB DSNs -> admin_panels shelf (phpMyAdmin/Adminer/H2)
- sourcemap endpoints -> param fuzzing on fresh surface

**Sources.** PayloadsAllTheThings — .git/.env disclosure; gitleaks patterns; can-i-take-over-xyz (adjacent fingerprints); HackerOne disclosure write-ups on artifact exposure


### Takeover: fingerprint sweep -> claim -> cookie-scope abuse — `subdomain-takeover-sweep`

**Goal.** Sweep abandoned service fingerprints across providers, claim the dangling origin, and abuse parent-scope cookies.
**Preconditions.** Subdomain DNS CNAME pointing at a removed service.
**Impact.** Attacker-controlled content on trusted origin; cookie injection into parent scope; OAuth allow-list capture.
**CWE.** CWE-350 · **Fallbacks.** `oauth-session-ato`, `cross-origin-action-suite`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/Subdomain takeover GitHub Pages fingerprint` | GitHub Pages dangle detection (404 + 'There isn't a GitHub Pages site here.'). | Claim via GH Pages repo -> trusted origin controlled. | Next fingerprint. |
| 2 | `web/Subdomain takeover S3 NoSuchBucket fingerprint` | S3 dangle detection (<Code>NoSuchBucket</Code> + BucketName). | Claim the bucket name -> origin controlled. | Next fingerprint. |
| 3 | `web/Subdomain takeover Shopify fingerprint` | Shopify dangle fingerprint. | Claim. | Next fingerprint. |
| 4 | `web/Subdomain takeover Fastly unknown-domain fingerprint` | Fastly dangle fingerprint ('Fastly error: unknown domain'). | Claim. | No fingerprint hit -> enumerate more providers via can-i-take-over-xyz list (documented extension path). |
| 5 | `web/Cookie Domain scope overbreadth` | Convert origin control into session attack: overbroad Domain cookies are injectable from your subdomain. | Cookie fixation/injection into the parent app. | Cookie scope tight -> content phishing + OAuth allow-list pivot (oauth-session-ato). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- CT logs (crt.sh) for subdomain census
- passive DNS (SecurityTrails/VirusTotal)
- NXDOMAIN-with-CNAME states
- wayback for dead-but-once-active subdomains

**Recon methods** — techniques beyond the skill itself:

- **CNAME census** — Resolve every subdomain; collect CNAME targets; flag NXDOMAIN/CNAME pairs and provider fingerprints. Tooling: dnsrecon/amass + httpx. Signal: CNAME to provider + provider 404 fingerprint..
- **Fingerprint library sweep** — Run the full can-i-take-over-xyz fingerprint list (Heroku, Azure, CloudFront, Tumblr, Zendesk, Tilda, Readme.io, Surge.sh, Pantheon, Unbounce, Short.io, ...). Tooling: nuclei takeover tags + manual. Signal: Any provider 404 body..
- **Wayback orphan hunt** — Subdomains that existed historically but resolve nowhere now = prime candidates. Tooling: wayback + DNS diff. Signal: Historical host, current dangle..
- **Wildcard exclusion** — Verify wildcard DNS records — wildcards mask takeovers; find and handle them. Tooling: manual. Signal: Everything resolves -> check wildcard suffix behavior..

**Class variants** — other places the same weakness hides:

- Heroku/Azure/CloudFront/Tumblr/Zendesk/Tilda/Readme.io/Surge/Pantheon/Intercom/Webflow/Greenhouse/FogBugz/Unbounce/Short.io fingerprints (extend shelf)
- vhost confusion takeovers
- MX/record-level takeovers (mail)
- CSR/brand abuse via custom domains

**Dorks**:

- shodan: hostname:*.target.tld http.status:404
- google: site:*.target.tld -www
- github: cname.target.tld

**Pivot hints** — where to go after proof:

- OAuth allow-list origins -> oauth-session-ato
- cookie scope -> cross-origin-action-suite
- phishing from trusted subdomain = separate severity narrative

**Sources.** can-i-take-over-xyz (EdOverflow et al.); nuclei-templates — takeover fingerprints; HackTricks — Subdomain takeover; service-provider custom-domain docs


### Spring: actuator env -> heapdump tokens -> gateway SpEL RCE — `spring-actuator-to-rce`

**Goal.** From exposed Spring Boot actuators to configuration secrets, in-memory session tokens, and a pre-auth SpEL RCE.
**Preconditions.** Spring Boot with exposed management endpoints (classic :8080 app or gateway).
**Impact.** Config secrets + session tokens + code execution on the gateway/app.
**CWE.** CWE-200, CWE-94 · **Fallbacks.** `jenkins-to-cluster`, `recon-secrets-to-cloud`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `redteam/Spring Boot actuator env leak` | Read /actuator/env: datasource creds, cloud keys, internal route map. | Triage secrets; step 2 for in-memory tokens. | env blocked -> mappings/heapdump may still be open. |
| 2 | `redteam/Spring Boot actuator heapdump` | Download heapdump; mine strings for active session IDs, tokens, cached credentials. | Session tokens -> immediate authenticated access; gadget libraries visible for step 3. | heapdump blocked -> work with env alone; try jolokia (documented variant). |
| 3 | `redteam/Spring Cloud Gateway SpEL RCE` | If a Spring Cloud Gateway is present: pre-auth SpEL injection -> RCE. | Step 4 closes the OS layer. | No gateway -> Log4Shell probe (web/Log4Shell JNDI lookup error probe) against Spring logging surfaces; spring4shell (documented variant). |
| 4 | `web/Command injection output echo marker` | Deterministic OS proof through the RCE channel. | Full chain narrative closed. | Blind -> time-based oracle skill. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- :8080 /actuator on app hosts
- gateway services (Spring Cloud Gateway)
- admin spring-boot-admin UIs
- eureka/consul service inventories

**Recon methods** — techniques beyond the skill itself:

- **Actuator census** — Probe /actuator, /env, /heapdump, /mappings, /jolokia directly and via one-hop proxies (headers confusion). Tooling: ffuf + actuator wordlist. Signal: JSON env or heap content..
- **Spring Boot Admin hash** — Shodan favicon hash 116323821 finds Spring Boot Admin UIs fleet-wide. Tooling: shodan/FOFA favicon search. Signal: Admin UI instances..
- **Heapdump mining** — strings + grep for 'session', 'token', 'AKIA', 'Bearer', class names for gadget libs. Tooling: strings/grep/VisualVM. Signal: Live tokens and gadget libs..
- **Error-page fingerprint** — Whitelabel error page confirms Spring Boot; status/date headers help version guess. Tooling: manual. Signal: Whitelabel page = actuator likely present..

**Class variants** — other places the same weakness hides:

- /jolokia -> MBean RCE
- eureka instance hijack
- configserver exposure
- spring cloud function SpEL (CVE-2022-22963)
- spring4shell (CVE-2022-22965)

**Dorks**:

- shodan: http.favicon.hash:116323821
- google: intitle:"Spring Boot Admin"
- github: management.endpoints.web.exposure.include=*

**Pivot hints** — where to go after proof:

- creds -> admin_panels shelf
- session tokens -> authenticated chains (idor, bfla)
- RCE -> cloud metadata via localhost (cloud_takeover)

**Sources.** Spring Boot Actuator docs + hardening guides; PortSwigger — Spring Actuator abuse; nuclei-templates — spring; CVE-2022-22963/22965 advisories


### CI -> cluster: Jenkins enum -> Groovy RCE -> kubelet -> etcd — `jenkins-to-cluster`

**Goal.** From unauthenticated Jenkins enumeration to script-console RCE and then into the Kubernetes control plane.
**Preconditions.** Jenkins (and ideally a k8s cluster) reachable.
**Impact.** CI code execution, cluster pod inventory with env secrets, etcd secrets read.
**CWE.** CWE-306, CWE-284 · **Fallbacks.** `container-plane-sweep`, `spring-actuator-to-rce`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `redteam/Jenkins unauth job enumeration` | Map jobs, build names, env hints — the recon layer for the console. | Job/agent naming informs privilege targeting. | Console blocked -> keep enum evidence; pivot to kubelet next. |
| 2 | `redteam/Jenkins script console unauth` | Groovy console execution = CI-plane RCE (build credentials, cloud keys in env). | Read Jenkins env + creds store paths -> often k8s SA tokens. | Console authed -> default creds (auth shelf) or CVE-era deser (documented variant); continue to cluster probes. |
| 3 | `redteam/Kubelet read-only PodList API` | Kubelet PodList exposes pod env vars — often includes secrets/tokens. | Harvest env secrets from pods. | 10250 blocked -> 10255 read-only (infra/Kubelet read-only 10255 metrics) or apiserver anon (infra/Kubernetes API anonymous version disclosure). |
| 4 | `redteam/etcd unauth key-value read` | Cluster store read: all secrets if exposed on :2379. | Cluster-level secret harvest = full infrastructure compromise narrative. | etcd secured -> document kubelet findings; try docker daemon (devops_infra shelf). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- :8080 Jenkins
- :2379 etcd
- :10250/:10255 kubelet
- CI agent nodes
- org-hosted dev clusters

**Recon methods** — techniques beyond the skill itself:

- **CI surface census** — Probe Jenkins paths (/people, /asynchPeople, /script, /securityRealm) and status pages. Tooling: ffuf + jenkins wordlist. Signal: Jenkins UI or API without auth..
- **Kubelet dual-port probe** — 10250 (authed API) vs 10255 (read-only) — often one is open. Tooling: manual/curl. Signal: PodList JSON..
- **etcd version probe** — GET /version on :2379 reveals exposure; keyspace read follows. Tooling: manual. Signal: etcd cluster version JSON..
- **Service inventory side-doors** — Consul/Nomad/Portainer/Docker APIs on adjacent hosts (devops_infra shelf) complete the CI->infra map. Tooling: devops_infra skills. Signal: Any unauth service API..

**Class variants** — other places the same weakness hides:

- Jenkins CVE-era deserialization (CLI)
- Groovy console with default creds
- kubelet exec via 10250 (needs POST auth — documented gap)
- apiserver anonymous pivots
- helm tiller (legacy)
- argo workflows unauth

**Dorks**:

- shodan: product:"Jenkins" port:8080
- shodan: port:2379 etcd
- google: intitle:"Dashboard [Jenkins]"

**Pivot hints** — where to go after proof:

- CI creds -> repo access -> source chain (recon-secrets-to-cloud)
- cluster secrets -> cloud_takeover chains
- docker daemon -> devops_infra shelf for container escape narrative

**Sources.** Jenkins security advisories; Kubernetes hardening guide (kubelet read-only port); HackTricks — Jenkins/K8s; etcd exposure advisories


### Container plane: registry catalog -> docker daemon -> portainer/consul/nomad — `container-plane-sweep`

**Goal.** Sweep the container management plane: image catalog disclosure, Docker API takeover, and orchestrator/SDN consoles.
**Preconditions.** Any container-infra API reachable (5000, 2375, 9000, 8500, 4646).
**Impact.** Image/source theft, container takeover via Docker API, orchestration control.
**CWE.** CWE-306, CWE-668 · **Fallbacks.** `jenkins-to-cluster`, `datastore-unauth-sweep`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `infra/Docker Registry v2 catalog unauth` | Registry catalog + tag enumeration = image names as org-source intel. | Image inventory; pull manifests for env-in-image secrets (documented follow-up). | Registry authed -> docker daemon next. |
| 2 | `redteam/Docker daemon API unauthenticated` | Exposed :2375 Docker API = host-level container control. | Container exec narrative (documented next step); highest infra impact. | Daemon closed -> Portainer/Consul/Nomad sweep. |
| 3 | `infra/Portainer API unauth status` | Portainer exposure signals and often management capabilities. | Version/status -> default-cred attempts (auth shelf pattern). | Next service. |
| 4 | `infra/Consul agent members unauth API` | Consul service catalog: internal service map for lateral moves. | Internal topology -> targeted SSRF/probes. | Next service. |
| 5 | `infra/Nomad API unauth jobs list` | Nomad job listing: workload names, drivers, groups — env and task intel. | Job specs often reveal env vars and image refs. | Next service; Vault health (infra/Vault sys/health unauth disclosure) completes the sweep. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- ports 5000/2375/9000/8500/4646/8200
- internal-hostname recon from other chains
- shodan banner search
- CI environments that self-host these services

**Recon methods** — techniques beyond the skill itself:

- **Banner triangulation** — Each service has a distinctive version/status JSON — probe all canonical ports in one sweep. Tooling: nmap-like manual list. Signal: Service JSON answers..
- **Catalog path probing** — /v2/_catalog (registry), /containers/json (daemon), /api/status (portainer), /v1/agent/members (consul), /v1/jobs (nomad). Tooling: manual curl list. Signal: Any 200 JSON..
- **Adjacent-host propagation** — Findings on one infra host imply sibling services on neighbors — sweep the subnet via latency techniques. Tooling: SSRF latency channel. Signal: Neighbor services answer..
- **CI-adjacency inference** — CI servers and build agents almost always run registries/daemons on the same host or subnet — start the sweep from every Jenkins/GitLab hit. Tooling: jenkins-to-cluster chain recon. Signal: Infra API answers on a CI-adjacent host..

**Class variants** — other places the same weakness hides:

- registry manifest pull for image secrets
- portainer default creds -> full mgmt
- consul KV read (documented variant)
- nomad job exec (documented)
- vault token reading via health exposure paths

**Dorks**:

- shodan: product:"Docker" port:2375
- shodan: port:8500 consul
- github: "2375" docker-compose.yml

**Pivot hints** — where to go after proof:

- docker API -> mount host filesystem narrative
- consul map -> internal SSRF targets (cloud_takeover)
- nomad/vault -> secrets plane

**Sources.** Docker Engine API docs (security note on 2375); HashiCorp hardening guides; nuclei-templates — infra; HackTricks — Docker security


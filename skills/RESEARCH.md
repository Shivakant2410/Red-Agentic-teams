# Skill Pack Research Dossier

This pack is built from published security research, not a generic technique checklist.
Every elite skill names its research lineage below. Sources were located and (for the
desync probes and the prototype-pollution gadget) read in full during authoring.

## Skill-by-skill lineage

### elite/Request smuggling CL.TE + TE.CL timing oracles
- **Source**: PortSwigger Web Security Academy — *Finding HTTP request smuggling
  vulnerabilities* — https://portswigger.net/web-security/request-smuggling/finding
  (read in full; the probes are the published byte-exact timing tests:
  CL.TE = `TE: chunked` + `CL: 4`, body `1\r\nA\r\nX`; TE.CL = `CL: 6`, body `0\r\nX`)
- **Foundational research**: James Kettle, *HTTP Desync Attacks: Request Smuggling
  Reborn* (Black Hat USA / DEF CON 27) — https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- **Research program**: https://portswigger.net/research/request-smuggling
  (HTTP/2: The Sequel is Always Worse; Browser-Powered Desync Attacks; HTTP/1.1 Must Die)
- **Engineering honesty**: the platform's `make_fetch` opens a fresh connection per
  request (`redteam/tools/http.py`), so Kettle's primary same-connection
  response-differential detection is NOT expressible in this DSL. The pack ships his
  differential-TIMING oracle instead, and the skill description records that a
  raw-socket (pipelined) fetch primitive is the missing platform capability.

### elite/Prototype pollution Node status gadget
- **Source**: Gareth Heyes, *Server-side prototype pollution: Black-box detection* —
  https://portswigger.net/research/server-side-prototype-pollution (read in full;
  exact gadget `{"__proto__":{"status":510}}` against Node's http-errors module;
  JSON-reflection and qs/Lodash/Express surfaces documented there)
- Control design mirrors the article's falsification logic: a benign direct-key
  `{"status":510}` must NOT change error codes.

### elite/GraphQL field suggestion enumeration
- **Sources**: Escape.tech — *When GraphQL field suggestions become a Security Issue* —
  https://escape.tech/blog/graphql-verbose-error-suggestions ; CyberAdvisors,
  *GraphQL APIs & Enumeration Basics* (the "Did you mean …?" oracle) —
  https://blog.cyberadvisors.com/technical-blog/blog/graphql-apis-enumeration-basics ;
  APISec guide example (`Cannot query field 'usr' … Did you mean 'user'?`) —
  https://www.apisec.ai/blog/graphql-security-testing-guide
- **Canonical tooling**: Clairvoyance (schema reconstruction from suggestions) and the
  SuiteCRM CVE-2023-47643 introspection default —
  https://www.stingrai.io/blog/graphql-api-vulnerabilities-and-common-attacks

### elite/GraphQL alias amplification primitive
- **Sources**: Apollo GraphOS security docs on batched requests ("clients could
  effectively enumerate through all nodes in a single request while slipping past
  brute-force protections") — https://www.apollographql.com/docs/graphos/platform/security/overview ;
  Checkmarx, *Didn't Notice Your Rate Limiting: GraphQL Batching Attack* —
  https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack ;
  OWASP GraphQL Cheat Sheet (batching attacks section) —
  https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

### elite/OAuth redirect_uri origin substitution
- **Sources**: PortSwigger Web Security Academy — *OAuth 2.0 authentication
  vulnerabilities* (leaking authorization codes) — https://portswigger.net/web-security/oauth
  and the lab *OAuth account hijacking via redirect_uri* —
  https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri ;
  RFC 6749 §10.6 (authorization-code redirection URI validation requirement).

### elite/JWT forged-claim acceptance check
- **Source**: PortSwigger Web Security Academy — *JWT attacks* (jku/x5u header
  injection, kid path injection, alg:none) — https://portswigger.net/web-security/jwt
- The skill proves server-side ACCEPTANCE of a forged token (privilege differential);
  forging itself is agent-supplied input by design (the DSL verifies, it does not
  run crypto).

### elite/Jinja2 SSTI OS command execution
- **Source**: PayloadsAllTheThings — Jinja2 SSTI section —
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
  (`cycler.__init__.__globals__` → `os`; cycler/joiner/namespace are Jinja2 ≥2.9
  template globals). Upgrades detection (`{{7*7}}`) to an impact proof (`uid=\d+(`).

### elite/SQLi UNION reflection exfiltration primitive
- **Lineage**: standard UNION-technique progression (column-count discovery → marker
  reflection → arbitrary exfiltration), as used across PortSwigger Academy SQLi
  modules; complements the pack's time-based and error-based detection skills by
  proving the exfiltration primitive itself.

### elite/Web cache deception authenticated leak
- **Source**: PortSwigger Web Security Academy — *Web cache deception* —
  https://portswigger.net/web-security/web-cache-deception, built on the Black Hat USA
  2024 whitepaper *Gotta cache 'em all: bending the rules of web cache exploitation*.
  The shipped skill is the static-extension variant with an anonymous-replay
  differential; path-mapping/delimiter/normalization variants are documented as
  copy-and-adapt in the description.

### elite/X-Original-URL routing confusion
- **Source**: PortSwigger Web Security Academy — *Access control vulnerabilities*
  (X-Original-URL / X-Rewrite-URL alternate-route header technique) —
  https://portswigger.net/web-security/access-control

### elite/Prometheus metrics endpoint exposure
- **Source**: Prometheus exposition format (`# HELP` / `# TYPE`) —
  https://prometheus.io/docs/instrumenting/exposition_formats/ ; exposure impact
  documented in the OWASP DevSecOps guideline and countless disclosed-recon reports.

### elite/Tomcat Manager default credential acceptance
- **Source**: Apache Tomcat 9 Manager HOW-TO (auth realm, WAR deploy surface) —
  https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html ; the `tomcat:tomcat`
  default is the canonical misconfiguration (T1505.003 web-shell path).

## Deliberately excluded (a god pentester knows what not to fake)

| Technique | Why excluded from this DSL pack |
| --- | --- |
| Same-connection desync response-differential test | `make_fetch` is connection-per-request; needs a raw-socket/pipelined fetch primitive (repo recommendation) |
| HTTP/2 desync (H2.TE, H2.CL) | curl/requests paths are HTTP/1.1-only |
| SSRF to cloud metadata (169.254.169.254) | scope guard is fail-closed on private ranges — by design; needs an approved-SSRF lab mode |
| Blind XXE / OOB callbacks | beacon lands on the collaborator host, invisible to in-target response conditions; needs OOB-listener integration |
| DOM clobbering / mXSS / client-side desync | requires the Playwright surface; future pack via browser tools |
| Second-order (store-then-trigger) injections | k-of-n re-verification mutates state; needs idempotency-aware trials |

---

# v3 additions — the basic → god ladder (28 new skills)

The ladder the product needs: every tier is a *precise, single technique* with its own
falsification design — the small ones are differential-oracle skills, not vague "check
for X" recipes. DSL notes used across this batch: `body_regex`/`header_regex` support
`present: false` (used for negative halves of differentials); `json_differs` requires
BOTH json paths present AND values differing (boolean-blind oracle); `latency_delta`
is `elapsed(request_b) - elapsed(request_a)` (slow request goes in `request_b`).

## Tier: basic — small vulnerabilities, sharp differentials

| Skill | Technique / source |
| --- | --- |
| web/Directory listing autoindex exposed | CWE-548 — https://cwe.mitre.org/data/definitions/548.html ; PortSwigger KB "Directory listing" — https://portswigger.net/kb/issues/00600100_directory-listing ; ctrl: sibling dir must 404 |
| web/Path traversal once-strip filter evasion | PayloadsAllTheThings Directory Traversal (once-strip `....//`, encodings) — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md ; PortSwigger file path traversal — https://portswigger.net/web-security/file-path-traversal |
| web/Username enumeration login differential | OWASP WSTG-IDM-004 (known vs unknown response differential) — https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account |
| web/Framework debug traceback disclosure | Django "How to manage error reporting" (DEBUG=True → full traceback) — https://docs.djangoproject.com/en/6.1/howto/error-reporting/ ; CWE-209 |
| web/phpinfo diagnostic page exposed | Invicti "PHPinfo pages" — https://www.invicti.com/web-application-vulnerabilities/phpinfo-pages/ ; CWE-200 |
| web/Open redirect cross-origin Location | OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html ; CWE-601; ctrl: internal `next` must stay same-origin |

## Tier: mid — real exploit primitives, still single-surface

| Skill | Technique / source |
| --- | --- |
| web/XXE in-band external entity file read | PayloadsAllTheThings XXE — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md ; PortSwigger XXE — https://portswigger.net/web-security/xxe ; OWASP/CWE-611 — https://community.owasp.org/vulnerabilities/XML_External_Entity_(XXE)_Processing |
| web/Stored XSS persisted marker | PortSwigger stored XSS (persistence across requests, not reflection) — https://portswigger.net/web-security/cross-site-scripting/stored |
| web/SQLi boolean-blind response differential | OWASP WSTG SQL injection (true/false response differential oracle) + PAT SQLi; implemented as the repo's `json_differs` so a hardened target returns equal counts → falsified |
| web/Mass assignment role escalation | OWASP API6:2019 Mass Assignment — https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/ (role field binding → privilege flip proven on /me) |
| web/CSV formula injection via export | OWASP CSV Injection (`=`, `+`, `-`, `@` formula chars, =HYPERLINK exfil) — https://community.owasp.org/attacks/CSV_Injection ; CWE-1236 |
| web/Password reset poisoning X-Forwarded-Host | PortSwigger password reset poisoning — https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning ; real-world X-Forwarded-Host case GHSA-cgj8-7m5q-x5gv — https://github.com/coollabsio/coolify/security/advisories/GHSA-cgj8-7m5q-x5gv |
| web/CORS null-origin with credentials | PortSwigger CORS (null-origin + credentials variant, distinct from the v1 reflected-origin skill) — https://portswigger.net/web-security/cors ; CWE-942 |

## Tier: god — research-grade misconfigs, gadget chains, CVE precision

| Skill | Technique / source |
| --- | --- |
| web/Nginx alias traversal off-by-slash | Orange Tsai, Black Hat 2018 "Breaking Parser Logic" (write-up: https://blog.devsecopsguides.com/p/nginx-path-configuration-pitfalls) ; Invicti alias_traversal — https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/ ; bayotop/off-by-slash tool — https://github.com/bayotop/off-by-slash ; real-world: HackerOne nodejs.org — https://hackerone.com/reports/1650273 |
| web/PHP filter wrapper LFI base64 read | Synacktiv "PHP filters chain: what is it and how to use it" — https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it + php_filter_chain_generator — https://github.com/synacktiv/php_filter_chain_generator + error-oracle follow-up — https://synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle ; skill ships the base64-encode read oracle, copy skill for the iconv LFI→RCE chain |
| web/Twig SSTI RCE map-system gadget | PayloadsAllTheThings SSTI (Twig ≥1.41 filter/map callable gadgets `{{['id']\|map('system')}}`) — https://gitlab.com/pentest-tools/PayloadsAllTheThings/-/tree/master/Server%20Side%20Template%20Injection |
| web/Freemarker SSTI RCE Execute gadget | PayloadsAllTheThings Java SSTI (`freemarker.template.utility.Execute"?new()`) — same mirror; the pattern behind recent CVEs (e.g. CVE-2025-70830 Datart) |
| redteam/Apache mod_status server-status exposed | Tenable Nessus 10677 — https://www.tenable.com/plugins/nessus/10677 ; Apache mod_status docs — https://httpd.apache.org/docs/2.4/mod/mod_status.html ; Mobb "still real in 2026" — https://www.mobb.ai/blog/apache-server-status-exposure-is-still-real-in-2026 |
| redteam/Elasticsearch unauth data exposure | PentestPad port 9200 (unauth version JSON → _cat/indices → document dump) — https://www.pentestpad.com/port-exploit/port-9200-elasticsearch ; hackviser ES pentesting — https://hackviser.com/tactics/pentesting/services/elasticsearch ; CWE-306 |
| redteam/Docker daemon API unauthenticated | PentestPad port 2375 ("unauthenticated root on the host") — https://www.pentestpad.com/port-exploit/port-2375-docker-engine-api ; Unit42 attacker TTPs on unsecured daemons — https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/ ; Akamai Hunt malware targeting exposed Docker APIs — https://www.akamai.com/blog/security-research/new-malware-targeting-docker-apis-akamai-hunt |
| redteam/etcd unauth key-value read | PentestPad port 2379 (all K8s Secrets base64 at rest) — https://www.pentestpad.com/port-exploit/port-2379-etcd ; hackviser etcd — https://hackviser.com/tactics/pentesting/services/etcd ; CWE-306 |
| redteam/H2 database console exposed | JFrog research, CVE-2021-42392 (console accepts arbitrary JDBC URLs → JNDI RCE) — https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console ; NVD — https://nvd.nist.gov/vuln/detail/cve-2021-42392 |
| redteam/Jenkins script console unauth | Jenkins official docs (Administer permission, sub-processes, credential decryption) — https://www.jenkins.io/doc/book/managing/script-console/ ; cobalt.io impact note — https://www.cobalt.io/vulnerability-wiki/inf1/network-jenkins-script-console-access |
| redteam/Grafana default credential login | Grafana docs (default admin:admin + forced change) — https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/ ; proof = POST /login then /api/user shows the admin principal |
| redteam/Spring Boot actuator heapdump | Wiz "Exploring Spring Boot Actuator Misconfigurations" — https://www.wiz.io/blog/spring-boot-actuator-misconfigurations ; HPROF `JAVA PROFILE` magic as the in-band oracle |
| redteam/MinIO bootstrap verify env disclosure | CVE-2023-28432 — NVD — https://nvd.nist.gov/vuln/detail/cve-2023-28432 ; Rapid7 module (returns env incl. MINIO_ROOT_PASSWORD) — https://www.rapid7.com/db/modules/auxiliary/gather/minio_bootstrap_verify_info_disc/ ; vulhub PoC — https://github.com/vulhub/vulhub/blob/master/minio/CVE-2023-28432/README.md |
| redteam/Grafana plugin path traversal | CVE-2021-43798 — GHSA-8pjx-jj86-j47p — https://github.com/advisories/GHSA-8pjx-jj86-j47p ; Grafana security release — https://grafana.com/blog/grafana-8-3-1-8-2-7-8-1-8-and-8-0-7-released-with-high-severity-security-fix/ (vulnerable URL shape /public/plugins/<id>/) |
| redteam/Spring Cloud Gateway SpEL RCE | CVE-2022-22947 — NVD — https://nvd.nist.gov/vuln/detail/cve-2022-22947 ; spring.io advisory — https://spring.io/security/cve-2022-22947 ; vulhub PoC (AddResponseHeader route with #{SpEL} → read route back → command output) — https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22947 |

---

# v4 additions — horizontal marketplace expansion (43 new skills, 2 new packs)

Strategy: Flipkart/Amazon-style horizontal breadth — new CATEGORIES the earlier packs
did not carry — while every entry stays a single precise technique with its own
falsification design. New packs: `horizon_web_pack.json` (29), `horizon_infra_pack.json` (14).

Exclusion-table update: *SSRF to cloud metadata* IS expressible in this DSL when the
vector endpoint is the public target and the private URL rides inside a parameter —
the platform's scope guard only sees the public fetch, so `web/SSRF AWS IMDSv1 role
discovery` + `web/SSRF AWS IMDSv1 credential dump` are legitimate in-scope proofs.

| Skill | Technique / source |
| --- | --- |
| web/SSTI Mako / Velocity / ERB proofs | PayloadsAllTheThings SSTI engine matrix (Mako `${}`, Velocity `#set`, ERB `<%= %>`; engine differentiation by language semantics: `${7*'7'}` → 7777777 is Python-family, errors on Java/Freemarker) — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md |
| web/SQLi error-based MySQL / MSSQL / Oracle families | Dialect fingerprints (`You have an error in your SQL syntax`/MariaDB, `Unclosed quotation mark`/SqlClient, `ORA-#####`) — PortSwigger SQL injection — https://portswigger.net/web-security/sql-injection |
| web/SQLi time-based blind MySQL + MSSQL | `SLEEP(n)` / `WAITFOR DELAY` differential timing oracles — same chapter + PayloadsAllTheThings SQLi — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md |
| web/NoSQL Mongo operator login bypass | PayloadsAllTheThings NoSQL injection (`$ne` bracket params, Express qs extended) — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md |
| web/Java / PHP / Python-pickle deserialization probes | Java: ysoserial readObject sink (`java.io.StreamCorruptedException` oracle) — https://github.com/frohoff/ysoserial ; PHP: `unserialize(): Error at offset` POP-chain recon — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/README.md ; Python: `_pickle.UnpicklingError` / `invalid load key` |
| web/SSRF file-scheme read + IMDSv1 chain | appsecco breaking-and-pwning-apps-and-servers-aws-azure-training (metadata service exploitation) — https://github.com/appsecco/breaking-and-pwning-apps-and-servers-aws-azure-training ; AWS IMDS docs — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html ; MITRE T1552.005 (cloud instance metadata API) |
| web/Session cookie missing HttpOnly | OWASP Session Management Cheat Sheet (cookie flags) — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html ; CWE-1004 |
| web/Frame-clickjacking protections absent | OWASP Clickjacking Defense Cheat Sheet (X-Frame-Options / frame-ancestors) — https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html ; CWE-1021 |
| web/JWT kid path-traversal empty-key acceptance | PortSwigger JWT attacks (kid path injection → /dev/null → empty HMAC key; token forged with REAL empty-key HMAC in the pack) — https://portswigger.net/web-security/jwt |
| web/JSONP callback reflection | OWASP AJAX/JSONP resource: https://www.owasp.org/index.php/ AJAX ; CWE-346 (origin-validation error) |
| web/OpenAPI-Swagger spec exposed | OWASP API Security Top 10 (API disclosure); CWE-200 |
| web/WordPress REST users / debug.log / xmlrpc trio | nuclei-templates wordpress fingerprints (`/wp-json/wp/v2/users` slug enumeration, `/wp-content/debug.log`, xmlrpc `system.listMethods`) — https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures/files ; WP REST API docs — https://developer.wordpress.org/rest-api/ |
| web/.DS_Store / .svn wc.db / backup.zip / source map artifacts | nuclei-templates exposures (`.DS_Store` Bud1 magic, `.svn/wc.db` SQLite magic, archive content-types, `.js.map` sources) — https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures ; CWE-538/540 |
| web/ThinkPHP invokefunction controller RCE | CVE-2018-25270 (ThinkPHP 5.0.23/5.1.31 invokefunction → `call_user_func_array`), ExploitDB 45978, actively exploited (SonicWave/ SonicWall analysis) — https://www.sonicwall.com/blog/thinkphp-remote-code-execution-rce-bug-is-actively-being-exploited ; https://www.exploit-db.com/exploits/45978 |
| web/Log4Shell JNDI error probe | CVE-2021-44228 Log4Shell — NVD https://nvd.nist.gov/vuln/detail/cve-2021-44228 — shipped as an ERROR-BASED recon probe only; definitive confirmation requires an OOB collaborator (documented in the skill description, honest per the exclusion table) |
| infra/Kubernetes API anonymous /version | K8s API access control docs (anonymous requests) — https://kubernetes.io/docs/reference/access-authn-authz/authentication/ ; CWE-306 |
| infra/Kubelet read-only 10255 /metrics | Kubelet read-only port (readOnlyPort) docs + nuclei fingerprints — https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/ |
| infra/Consul /v1/agent/members | Consul HTTP API (members/serf LAN map) — https://developer.hashicorp.com/consul/api-docs/agent ; CWE-306 |
| infra/Nomad /v1/jobs + X-Nomad-Index | Nomad HTTP API (blocking-query headers X-Nomad-Index/KnownLeader/LastContact) — https://developer.hashicorp.com/nomad/api-docs |
| infra/Vault /v1/sys/health | Vault health endpoint (intentionally unauthenticated; leaks version/seal state) — https://developer.hashicorp.com/vault/api-docs/system/health |
| infra/Apache Solr admin/cores | Solr cores API (`responseHeader` fingerprint) — https://solr.apache.org/guide/solr/latest/configuration-guide/cores-and-collections.html |
| infra/CouchDB _all_dbs + Server header | CouchDB HTTP server config (`Server: CouchDB/x` mochiweb fingerprint) — https://docs.couchdb.org/en/stable/config/http.html |
| infra/Portainer /api/status | Portainer CE API (status/version) — https://docs.portainer.io/api/introduction |
| infra/Nacos CVE-2021-29442 UA bypass | NVD — https://nvd.nist.gov/vuln/detail/CVE-2021-29442 ; nuclei template nacos-auth-bypass.yaml (User-Agent: Nacos-Server on /v1/auth/users) — https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/other/nacos-auth-bypass.yaml |
| infra/Druid stat monitor | Alibaba Druid StatViewServlet (loginUsername unset → anonymous /druid/index.html) — https://github.com/alibaba/druid/wiki/ |
| infra/phpMyAdmin / Adminer exposure | nuclei-templates default-panel fingerprints; Adminer CVE-2021-21317 SSRF family — https://nvd.nist.gov/vuln/detail/CVE-2021-21317 |
| infra/JBoss jmx-console | JBoss JMX MainDeployer WAR-deploy RCE chain (legacy经典) — nuclei + hacktricks Java consoles — https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/jboss |
| infra/Docker Registry v2 catalog | Registry HTTP API v2 (`GET /v2/_catalog`) — https://distribution.github.io/distribution/spec/api/ |

Deliberately NOT shipped in v4 (a god pentester knows what not to fake):
same-connection desync (needs raw-socket fetch), HTTP/2 desync (HTTP/1.1-only
fetchers), OOB callbacks (no collaborator listener), second-order stateful
injections (k-of-n trials mutate state), client-side gadgets (needs the browser
surface). The Log4Shell probe is marked non-definitive for exactly this reason.

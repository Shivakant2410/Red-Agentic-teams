# DISCOVERY_PLAYBOOK — how to find what the skills prove

Skills prove; this playbook finds. A skill is a falsifiable HTTP experiment — it
needs a suspect. Discovery is the discipline that generates suspects at scale:
more surface, more differentials, more oracles, more places the same bug class
hides. Every chain in `chains/` carries its own discovery block; this document is
the pack-wide methodology that feeds all of them.

## 1. The universal discovery loop

Run this loop against every target. Each phase feeds the next; findings fall out
of phase 4 more often than out of any single probe.

| Phase | What you do | Output | Feeds |
|---|---|---|---|
| 1. Expand assets | Subdomains (CT logs, passive DNS), wayback URLs, sibling apps via favicon-hash clustering, ASN/adjacent hosts | host + URL universe | 2 |
| 2. Map the live surface | Crawl, JS bundle recon, sourcemaps, API docs, mobile builds | endpoint + parameter universe | 3 |
| 3. Mine structured intel | OpenAPI/GraphQL schemas, actuator mappings, verbose errors, comments | data model + sink taxonomy | 4 |
| 4. Differential testing | Two accounts, two roles, two encodings, two HTTP versions, front vs origin | behavior deltas = suspects | 5 |
| 5. Oracle confirmation | Canary callbacks, latency twins, deterministic markers | proof-shaped findings | skills |
| 6. Convert to skill | Winner becomes a `Skill` via AUTHORING.md loop (COPY→NORMALIZE→PROVE→CONTROL→FILE) | new shelf entry | pack |

**Doctrine: differentials beat wordlists.** Most elite findings come from
observing how behavior *changes* (between two requests that differ in exactly one
way), not from spraying payloads. Wordlists find low-hanging surface; differentials
find logic.

## 2. Class-by-class discovery matrix

One row per class cluster. "Fastest signal" is what usually confirms in one
request; "more ways" is how you find the same class when the obvious probe fails.

| Class (shelves / chains) | Fastest signal | More ways to find it |
|---|---|---|
| SSRF & metadata (`ssrf`, cloud_takeover) | Canaries + `169.254.169.254` variants in every fetch-shaped param | wayback param grep (`url=|dest=|fetch=|proxy=`), webhook/PDF/import sinks, unkeyed-header proxies, XXE-as-SSRF via office/XML uploads, latency port scan, DNS rebinding when IP-filtered |
| Injection family (`sqli/ssti/xss/xxe/nosql/ldap/xpath/cmd`, injection_to_rce) | Engine fingerprint from forced errors + polyglot canaries (`{{7*7}} ${7*7} <%= 7*7 %>`) | ORDER BY/LIMIT contexts, stored fields as second-order sinks, template editors in product UI, filenames/headers as injection surfaces, JSON-path args, GraphQL resolver args |
| Auth & authz (`auth/access_control/jwt/nosql`, auth_to_admin) | Two-account replay matrix (Auth Analyzer pattern) | register-response schema echo, JWT header-param sweep (kid/jku/x5u), mobile API diff (older builds skip checks), role vocabulary via field-suggestion oracles, verb/encoding switch on protected functions |
| Cache & edge (`cache/request_smuggling/headers/crlf`, edge_cache_smuggling) | Cache headers (Age/X-Cache/CF-Cache-Status) + unkeyed header reflection | CL.TE/TE.CL timing pairs, path-normalization diffs (`//`, `/..;/`, `;params`), param-miner unkeyed hunt, front/back 404-body diff, duplicate-header acceptance probes |
| Secrets & artifacts (`secrets_exposure/info_disclosure`, recon-secrets-to-cloud) | Artifact-path dictionary (.git/.env/.svn/.DS_Store/backup.*) + `.js.map` probes | wayback archaeology for old paths, GitHub org code search + gitleaks, phpinfo/actuator env tables, heapdump string mining, sourcemap endpoint recovery |
| Exposed panels & services (`admin_panels/devops_infra/data_stores/monitoring/debug_interfaces`, exposure groups) | Canonical paths/ports per product + version JSON banners | favicon-hash fleet clustering, shodan/FOFA product banners, CI-adjacency inference (Jenkins host ⇒ registry/daemon nearby), actuator/mappings and eureka inventories |
| Takeover (`subdomain_takeover`) | CNAME census + provider 404 fingerprints | CT-log census, wayback orphan hosts, wildcard-record exclusion logic, full provider list sweep (can-i-take-over-xyz) |
| OAuth/session (`oauth/session_security/csrf/cookie`, cross-origin-action-suite) | Flow walkthrough: state/PKCE presence, redirect_uri allow-list probing | redirect error-message diffing to map the allow-list, SameSite/HttpOnly/Domain cookie audit, `new WebSocket(` grep for CSWSH, login-CSRF and account-linking probes |
| Business logic (`business_logic/race_condition/api_abuse`, checkout-abuse-race) | Replay every one-time interaction; numeric fuzz on quantities | totals-diff matrix, flow-state skipping (call confirm directly), type-confusion in parsers, currency/rounding edges |
| File upload & traversal (`file_upload/path_traversal`, upload-to-shell) | Upload + fetch the stored path; `../` matrix on file params | filename reflection, validator recovery via sourcemaps, zip-slip via importers, alias off-by-slash probes, wrapper acceptance (`php://filter`, `file://`) |
| Deserialization (`deserialization`) | Blob census: base64 prefixes (`rO0AB`/`O:`/`gASV`/`/wEy`) | heapdump library mining, remember-me cookie probes, import-feature inventory, phar:// pairing with file ops |
| Kubernetes & cluster (`kubernetes`) | 10250/10255 kubelet + :2379 etcd + apiserver anon paths | `/var/run/secrets` paths via SSRF, service-account token reuse, pod env var harvest, CI→cluster adjacency |
| GraphQL (`graphql`) | Endpoint matrix + introspection probe | suggestion-oracle schema rebuild, IDE asset fingerprints (GraphiQL/Altair), tracing/debug extensions, GET-based query endpoints |
| CMS (`cms`) | wp-json/wp-login/xmlrpc fingerprints | author archive pivots (`?author=N`), plugin readme versions, debug.log/backup artifacts |
| AI/LLM (`ai_prompt_injection`, `ai_jailbreak`, `ai_system_prompt_exfil`, `ai_agentic_tools`, `ai_rag_vector`, `ai_output_handling`, ai_agent_hijack) | Ask capability-revealing questions + plant a canary, then diff compliant-vs-bare-ask twins | tool/MCP metadata census + hash diff (rug pull), document/email ingestion surfaces as injection canals, refusal-phrasing fingerprinting per guardrail layer, citation interrogation for corpus layout, renderer census for output sinks, two-account memory probes |

## 3. Dork boxes (curated operator lists)

**Google/Bing** — surface discovery:
`site:*.target.tld inurl:admin`, `intitle:index.of`, `intitle:"Dashboard [Jenkins]"`,
`intitle:"Spring Boot Admin"`, `inurl:graphql`, `inurl:redirect_uri=`,
`inurl:fetch?url=`, `inurl:wp-content/debug.log`, `inurl:/api/v1/users`.

**GitHub** — code & secrets (run against org + domain + product name):
`filename:.env AWS_SECRET`, `org:<org> "DB_PASSWORD"`, `"169.254.169.254" language:python`,
`jwt.verify( { algorithms`, `render_template_string(`, `move_uploaded_file(`,
`csrf_exempt`, `location /static { alias`, `yaml.load(`, `serialize($_`.
Sweep found repos with gitleaks/trufflehog for the *history*, not just HEAD.

**Shodan/FOFA/Censys** — fleet clustering:
`http.favicon.hash:<hash>` (same stack, same bugs), `product:"Elasticsearch" port:9200`,
`port:2379 etcd`, `product:"Jenkins" port:8080`, `http.favicon.hash:116323821`
(Spring Boot Admin), `http.html:"GraphiQL"`, `http.html:"phpinfo()"`,
`hostname:*.target.tld http.status:404` (takeover candidates).

## 4. Client-side recon (the JS is the map)

1. Pull every `.js` from the surface; run endpoint extraction (fetch/axios URLs,
   string literals with `/api`, template hosts).
2. Probe `<script>.js.map` for every bundle; `sourcesContent` gives you original
   code with comments and leftover keys.
3. Grep bundles for key patterns: `AKIA|AIza|sk_live|xoxb|ghp_|BEGIN (RSA )?PRIVATE`,
   `api[_-]?key`, `Bearer `, `new WebSocket(`, `redirect_uri`.
4. Decode every token/blob the app sets (JWT, base64 blobs) — serializer prefixes
   and role claims fall out immediately.
5. Mobile builds: decompile (apktool/jadx), grep the same patterns plus API paths;
   older API versions found there usually skip newer authz checks.

## 5. Differential doctrine (how to force behavior deltas)

- **Two identities, one request**: replay every authenticated request of account A
  under account B. Any 200 = IDOR/BFLA suspect.
- **Two encodings, one parameter**: JSON vs form, `%2e%2e` vs `..`, `;` params,
  duplicate params (HPP) — parser disagreement is the suspect.
- **Two headers, one route**: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`
  vs the real route — front/back disagreement is the suspect.
- **Two framings, one body**: CL/TE permutations — desync is the suspect.
- **Two times, one request**: latency twin against any sink — internal reachability
  is the signal.
- Keep a Comparer discipline: diff *everything* (body, headers, status, timing);
  findings hide in the noise you didn't compare.

## 6. Canary & OOB doctrine (and what to do without OOB)

- Any external-fetch suspect gets a canary (collaborator/webhook.site/self-hosted
  listener) **before** metadata IPs — cheap, safe, and it proves egress.
- Blind classes without in-band reflection: use deterministic *timing twins* and
  *size* differentials as the oracle (see `latency_delta` condition type), or
  error-channel exfil (XXE error-based, SQL error-based).
- Honest gap: pure OOB confirmation (DNS-callback-only SSRF/XXE) and true parallel
  races need platform capabilities the pure-HTTP skill format cannot fake — these
  stay documented as gaps in the root README rather than being faked.

## 7. From finding to skill, from skill to chain

1. A confirmed differential becomes a **skill** through the AUTHORING.md loop:
   copy the proven payload family → normalize to the platform schema → prove on a
   vulnerable mock → falsify with a negative control → file into a shelf folder.
2. Skills that reliably co-occur become **chains**: write `scripts/chain_data_*.py`
   with steps pinned to installed skill names, a discovery block (entry points,
   recon, variants, dorks, pivots) and fallbacks; `build_chains.py` validates and
   regenerates the tree.
3. Chains that reveal a missing capability become the next shelf — the pack grows
   outward from evidence, the same horizontal-expansion rule that built it.

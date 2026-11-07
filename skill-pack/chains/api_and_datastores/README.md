# Attack chains — API Plane & Data Stores: Schema -> Extraction

**Group `api_and_datastores`** · 3 chain(s) · folder `chains/api_and_datastores/`

Modern apps hand out their schema (GraphQL/OpenAPI) and leave data stores exposed. Chains here convert schema visibility into object-level extraction and sweep unauth data planes (Elasticsearch/CouchDB/Solr) plus CMS surfaces.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `graphql-recon-to-exfil` | GraphQL: introspection -> suggestions -> alias amplification -> IDOR | 4 | CWE-200, CWE-639 |
| `datastore-unauth-sweep` | Data stores: Elasticsearch -> CouchDB -> Solr (+ admin panels fallback) | 4 | CWE-200, CWE-306 |
| `wordpress-footprint-to-auth` | CMS: WP users -> xmlrpc surface -> debug log -> credentials | 3 | CWE-200, CWE-532 |

## Shared recon for this group (how to find candidates at all)

- **API doc hunt** — /swagger.json, /api-docs, /v2/api-docs, /openapi.json, graphql endpoints, OpenAPI in sourcemaps.
- **Schema-first extraction** — From any schema: enumerate writable fields (mass assignment surface) and object-id patterns (IDOR surface) before testing.
- **Datastore banner sweep** — 9200/5984/8983/27017/2379 canonical endpoints; wayback for /_cat/indices or /_all_dbs hits.
- **CMS fingerprint pivot** — WP/Drupal/Joomla fingerprints -> the cms shelf (REST users, xmlrpc, debug logs) — CMSes chain into auth via xmlrpc brute (documented variant).
- **Mobile-first API diff** — Mobile builds often hit API versions with weaker authz — diff mobile endpoints vs web.

## Chain playbooks

### GraphQL: introspection -> suggestions -> alias amplification -> IDOR — `graphql-recon-to-exfil`

**Goal.** Full schema recovery and object-level extraction on GraphQL surfaces.
**Preconditions.** A GraphQL endpoint (introspection may be off — suggestions still leak).
**Impact.** Complete data-model visibility, then bulk object extraction.
**CWE.** CWE-200, CWE-639 · **Fallbacks.** `idor-mass-extraction`, `auth-bypass-to-admin`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/GraphQL introspection enabled` | Dump the schema when introspection is on — every type, field, and relation. | Build the field/ID map; step 3 for scale. | Introspection disabled -> step 2 (suggestion oracle). |
| 2 | `elite/GraphQL field suggestion enumeration` | Did-you-mean messages leak field names when introspection is disabled. | Reconstruct partial schema; step 3. | Suggestions off too -> GET/POST/v2 endpoint variants + graphiql UI strings (documented variants). |
| 3 | `elite/GraphQL alias amplification primitive` | One request, hundreds of aliased object fetches — the scale primitive. | Bulk extraction of any readable type. | Batching limited -> persisted-query abuse or query-cost gaps (documented). |
| 4 | `web/IDOR horizontal object-graph` | Object-level authz on nodes: swap ids inside node(id:) wrappers. | Cross-tenant extraction narrative. | Authz solid -> document schema exposure alone; check mutations for CSRF (csrf shelf). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- /graphql /graphiql /api/graphql /v2/graphql
- ?query= GET endpoints
- GraphiQL/Altair/Playground UI strings in JS
- apollo client config in sourcemaps

**Recon methods** — techniques beyond the skill itself:

- **Endpoint matrix** — Probe method (POST/GET) and path variants; some frameworks expose multiple. Tooling: manual + ffuf. Signal: GraphQL error JSON shape..
- **IDE fingerprint** — graphiql/playground/altair UI assets confirm endpoint and let you browse interactively. Tooling: JS asset review. Signal: IDE bundle present..
- **Suggestion oracle mining** — Feed nonsense fields, parse 'Did you mean' lists recursively to rebuild schema. Tooling: clairvoyance-style manual loop. Signal: Field name leakage..
- **Tracing/debug flags** — apollo-tracing, debug extensions, error paths leak resolver internals. Tooling: manual. Signal: Tracing JSON in responses..

**Class variants** — other places the same weakness hides:

- query batching amplification
- field-level authz gaps
- subscriptions (ws) — pair with websocket skill
- persisted-query bypass
- mutation CSRF (csrf shelf)

**Dorks**:

- google: inurl:graphql site:target.tld
- shodan: http.html:"GraphiQL"
- github: createApolloServer(

**Pivot hints** — where to go after proof:

- schema -> idor-mass-extraction
- auth token reuse -> jwt-to-privilege
- subscriptions -> websocket skill pairing

**Sources.** GraphQL security best practices (graphql.org); PayloadsAllTheThings — GraphQL; PortSwigger — GraphQL labs; clairvoyance research notes


### Data stores: Elasticsearch -> CouchDB -> Solr (+ admin panels fallback) — `datastore-unauth-sweep`

**Goal.** Sweep unauthenticated data-plane stores for direct database reads.
**Preconditions.** Data stores reachable (HTTP APIs: ES/CouchDB/Solr; TCP-only stores documented as gaps).
**Impact.** Direct read of application data: indices, documents, DB lists.
**CWE.** CWE-200, CWE-306 · **Fallbacks.** `container-plane-sweep`, `recon-secrets-to-cloud`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `redteam/Elasticsearch unauth data exposure` | ES cluster/indices read via /_cat/indices + search endpoints. | Document-level extraction; look for user/password indices. | No ES -> step 2. |
| 2 | `infra/CouchDB unauth _all_dbs` | CouchDB db list via /_all_dbs. | DB names -> document reads (documented follow-up). | No CouchDB -> step 3. |
| 3 | `infra/Apache Solr admin cores unauth` | Solr admin cores listing; query endpoints follow. | Cores -> query extraction; velocity RCE (documented variant) as escalation. | None reachable -> TCP-only stores (Mongo/Redis/postgres) are documented gaps (need TCP tooling); pivot to admin panels shelf. |
| 4 | `infra/phpMyAdmin panel exposed` | Fallback: exposed DB consoles often yield the same data plane with creds found elsewhere (recon-secrets-to-cloud). | Panel + creds -> full DB read. | Try Adminer (infra/Adminer db manager exposed), H2 console (redteam/H2 database console exposed). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- ports 9200/5984/8983/8081
- wayback hits for /_cat/indices, /_all_dbs, /solr
- internal service names from recon chains
- cloud-hosted search endpoints misconfigured public

**Recon methods** — techniques beyond the skill itself:

- **Canonical endpoint sweep** — One curl list across all datastore ports/paths per host. Tooling: manual script. Signal: Store banner JSON..
- **Banner version triage** — Version strings select CVE-era escalations (Solr velocity, CouchDB 12635). Tooling: manual. Signal: Version in banner..
- **Kibana/monitoring adjacency** — Kibana/monitoring panels often sit beside ES and leak index names. Tooling: manual. Signal: Kibana UI accessible..
- **Backup dump pairing** — Dump.sql/backup artifacts (secrets_exposure shelf) pair with store findings for full datasets. Tooling: recon-secrets-to-cloud chain. Signal: Artifact + live store = same dataset twice..

**Class variants** — other places the same weakness hides:

- ES script_fields injection (RCE-ish)
- CouchDB config endpoint auth bypass (CVE-2017-12635)
- Solr velocity template RCE (CVE-2019-17558)
- Mongo/Redis unauth (documented TCP gap)
- kibana SSRF through exporters

**Dorks**:

- shodan: product:"Elastic" port:9200
- shodan: product:"CouchDB"
- google: inurl:/_cat/indices

**Pivot hints** — where to go after proof:

- found creds -> admin_panels shelf
- PII scale -> severity framing
- store creds -> datastore reuse across services

**Sources.** Elasticsearch/CouchDB/Solr security docs; nuclei-templates — datastore exposures; HackTricks — Elasticsearch; CVE-2017-12635 / CVE-2019-17558 advisories


### CMS: WP users -> xmlrpc surface -> debug log -> credentials — `wordpress-footprint-to-auth`

**Goal.** Chain WordPress recon skills into a credentials story: enumerate users, map xmlrpc methods, recover leaked logs.
**Preconditions.** WordPress fingerprint on any host.
**Impact.** User list, xmlrpc brute surface, log-recovered secrets — feeds auth chains.
**CWE.** CWE-200, CWE-532 · **Fallbacks.** `auth-bypass-to-admin`, `recon-secrets-to-cloud`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/WordPress REST users enumeration` | REST users endpoint leaks the author/admin namespace. | Username list for auth chains. | REST blocked -> sitemap author archives, ?author=N redirects (documented variants). |
| 2 | `web/WordPress xmlrpc method discovery` | xmlrpc exposes system.listMethods + wp.getUsersBlogs — the brute surface. | xmlrpc available -> password brute is the documented follow-up (needs burst tooling). | xmlrpc disabled -> REST auth attempts with username list. |
| 3 | `web/WordPress debug.log exposure` | wp-content/debug.log leaks errors incl. paths, SQL fragments, plugin internals. | Log-derived secrets/paths -> targeted attacks; also proves poor ops hygiene for the report. | No log -> other secrets_exposure artifacts (.env/backup) on the same host. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- wp-login/wp-json fingerprints
- multisite networks
- xmlrpc on old installs
- plugin/theme paths from JS

**Recon methods** — techniques beyond the skill itself:

- **WP fingerprint sweep** — /wp-json, /wp-login.php, /xmlrpc.php, /wp-content paths per host. Tooling: ffuf + wp wordlist. Signal: WP markers in responses..
- **Plugin/version census** — readme.txt and ?v= style versions map plugin CVEs (per-product — extend on demand). Tooling: manual + wpscan-style logic. Signal: Outdated plugin versions..
- **Author archive pivots** — ?author=N and sitemap author lists when REST users is blocked. Tooling: manual. Signal: Usernames from archives..
- **Config-artifact pairing** — wp-config backups, .env files, and SQL dump artifacts (secrets_exposure shelf) recover DB creds and salts that pair with the user list. Tooling: recon-secrets-to-cloud chain. Signal: Credentials or table prefixes from artifacts..

**Class variants** — other places the same weakness hides:

- xmlrpc user enumeration + brute
- REST /users context=edit tricks
- plugin-specific CVEs (extend per target)
- theme editor abuse when admin reached
- db debug constants left on

**Dorks**:

- google: inurl:wp-content/debug.log
- shodan: http.html:"wp-content"
- google: inurl:wp-json/wp/v2/users

**Pivot hints** — where to go after proof:

- user list -> auth chains (username enumeration)
- xmlrpc brute (documented: needs burst tool)
- admin reach -> theme editor = SSTI/RCE-like impact (documented variant)

**Sources.** WordPress REST API docs; WPScan methodologies; HackTricks — WordPress; xmlrpc security write-ups


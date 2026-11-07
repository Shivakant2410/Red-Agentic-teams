# Data Stores & Search Engines

**CWE-668** · 3 skill(s) · folder `categories/data_stores/`

## Skills in this shelf

- `redteam/Elasticsearch unauth data exposure` (CWE-306)
- `infra/Apache Solr admin cores unauth` (CWE-200)
- `infra/CouchDB unauth _all_dbs` (CWE-200)

## Technique

Elasticsearch cluster/index exposure, Solr admin cores, CouchDB _all_dbs — data-layer discovery and direct read confirmation.

## Proof design (why it is falsifiable)

Engine-shaped responses (cat tables, responseHeader JSON, Server: CouchDB headers) with ACL errors as the benign twin.

## Bypass variants / escalation ("think more beats level")

- ES _cat/indices -> document _source pulls
- Solr admin -> Streaming Expressions / JNDI gadget CVEs
- CouchDB _all_dbs -> _replicator abuse
- Sibling stores: MongoDB Atlas HTTP, Redis INFO over HTTP proxies

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/misconfiguration/ (elasticsearch, solr, couchdb)
- HackTricks book — Elasticsearch/Solr/CouchDB

## False positives to rule out

Proxy 401s with engine Server headers — status conditions require the data body, not the header.

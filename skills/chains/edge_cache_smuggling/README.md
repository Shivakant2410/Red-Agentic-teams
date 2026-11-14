# Attack chains — Front-Edge Abuse: Smuggling -> Poisoning -> Victim-Scale Impact

**Group `edge_cache_smuggling`** · 3 chain(s) · folder `chains/edge_cache_smuggling/`

The edge (proxies, CDNs, caches, routers) is where a small parse differential becomes impact at scale: one desync poisons every cached response; one deception leaks every user's profile. Chains here convert single-request primitives into victim-side payloads.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `smuggling-to-poisoned-reset` | Smuggling: desync detect -> cache poison -> reset capture | 4 | CWE-444, CWE-640 |
| `cache-deception-pii` | Deception: path trick -> victim-cached profile -> PII harvest | 3 | CWE-640, CWE-524 |
| `routing-confusion-lfi` | Routing confusion -> alias traversal -> LFI source read | 4 | CWE-22, CWE-288 |

## Shared recon for this group (how to find candidates at all)

- **Cache behavior probe** — Collect X-Cache/X-Varnish/Age/CF-Cache-Status headers on every mirror; map which paths and methods are cached.
- **Unkeyed header matrix** — Candidate unkeyed headers (X-Forwarded-Host, X-Forwarded-Proto, X-Original-URL, X-Rewrite-URL) sent with cache-buster params; watch for reflection into responses.
- **Front/back fingerprint** — Server, Via, and error-page triangulation to guess the front/back pair (nginx->gunicorn, cloudflare->?); pairs suggest which desync class applies.
- **Path normalization diffs** — //, /..;/, /%2e%2e, ;params, %-encoding depth — edge and origin disagree; disagreements are exploits.
- **Timing desync probes** — CL.TE/TE.CL timing oracles before any payload — prove the differential before exploiting it.

## Chain playbooks

### Smuggling: desync detect -> cache poison -> reset capture — `smuggling-to-poisoned-reset`

**Goal.** Prove front/back desync, convert it into cache poisoning, and land poisoned password-reset links to capture victim tokens.
**Preconditions.** A front proxy paired with a backend that disagrees on CL/TE framing.
**Impact.** Cache-wide content injection and account takeover of arbitrary reset recipients.
**CWE.** CWE-444, CWE-640 · **Fallbacks.** `cache-deception-pii`, `routing-confusion-lfi`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `elite/Request smuggling CL.TE timing oracle` | Prove the CL.TE desync differential with a deterministic timing oracle. | Craft poison-prefix requests; step 3 scales it. | No CL.TE -> step 2 (TE.CL). |
| 2 | `elite/Request smuggling TE.CL timing oracle` | The reverse differential — one of the two usually fires. | Same pivot as step 1. | Both silent -> H2 desync / client-side desync are documented gaps (need h2/browser tooling); fall back to header-based poisoning (step 3 without desync). |
| 3 | `web/Web cache poisoning unkeyed X-Forwarded-Host` | Scale: poison cacheable responses with attacker content via unkeyed headers (works with or without desync). | Poisoned cache serves payload to every visitor of that path. | Header filtered -> find other unkeyed inputs via param-miner; CRLF (web/CRLF response-header injection) to inject whole headers. |
| 4 | `web/Password reset poisoning X-Forwarded-Host` | Victim-targeted capture: reset emails carry attacker-host links when the Host header is unkeyed. | Capture reset tokens -> account takeover; pair with cache poison for self-reset via admin page (PortSwigger combo). | Host pinned -> X-Forwarded-Host alternates (X-HTTP-Host-Override etc.), or poisoning path for stored variant. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- any cacheable path behind a proxy
- password-reset/email-sending features
- health/status endpoints (desync probes hide here)
- CDN-fronted APIs

**Recon methods** — techniques beyond the skill itself:

- **Framing differential timing** — CL.TE and TE.CL timing pairs on likely-cached and likely-uncached paths. Tooling: Turbo Intruder / manual pairs. Signal: Consistent delay on one framing = desync direction..
- **Duplicate-header acceptance** — Send duplicate Content-Length and Transfer-Encoding mixes; error messages and 400/501 responses fingerprint the front. Tooling: manual. Signal: Front rejects one shape, origin accepts another..
- **Cache-key mapping** — Cache-buster param + candidate unkeyed headers; diff cached vs uncached responses. Tooling: param-miner. Signal: Reflection into cached body..
- **Reset-link host audit** — Trigger a reset and read the link's host; then vary X-Forwarded-Host shapes. Tooling: manual. Signal: Email link host changes with header..
- **Peer stack clustering** — Favicon hash + header clustering finds sibling apps on the same edge — one desync often repeats across the fleet. Tooling: shodan/FOFA favicon search. Signal: Same stack, same exploit surface..

**Class variants** — other places the same weakness hides:

- H2.CL / H2.TE desync (needs h2 tooling — documented gap)
- client-side desync (browser-based)
- 0.CL (POST-body desync)
- smuggling into gRPC/HTTP2 gateways
- desync + CORS combos

**Dorks**:

- shodan: favicon-hash + Via/Server clustering to find identical front/back stacks
- github: "Transfer-Encoding: chunked" proxy
- google: inurl:/reset? token

**Pivot hints** — where to go after proof:

- poisoned admin cache + reset combo (PortSwigger classic)
- pair with cache-deception-pii for data theft
- document desync alone — it is critical by itself

**Sources.** PortSwigger Research — HTTP Desync Attacks (Kettle); PortSwigger — Web cache poisoning; HackTricks — Smuggling; RFC 7230/9112 framing rules


### Deception: path trick -> victim-cached profile -> PII harvest — `cache-deception-pii`

**Goal.** Make authenticated victims cache their own profile data to public URLs, then harvest at scale.
**Preconditions.** A cache that keys on the path but caches extension-looking requests, plus an authenticated profile endpoint.
**Impact.** PII/tokens of many users extracted from public cache entries.
**CWE.** CWE-640, CWE-524 · **Fallbacks.** `smuggling-to-poisoned-reset`, `idor-mass-extraction`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `elite/Web cache deception authenticated leak` | Prove the deception: victim profile cached to a public path (/profile/nonexistent.css). | Identify which data lands in cache; step 3 scales harvest. | Cache ignores extensions -> try ;/.jpg trailing tricks, path params, or two-layer (CDN+app) variants. |
| 2 | `web/IDOR horizontal object-graph` | Correlate: if profile endpoints take IDs, deception + IDOR multiplies victims per cached entry. | Broader blast radius documented. | Skip — deception alone stands. |
| 3 | `web/Rate limiting absent burst acceptance` | Confirm no throttle on cache reads -> unbounded PII extraction. | Blast radius = every user who visits the poisoned link pattern. | Throttled -> slow-extract within budget; document rate-limit separately. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- profile/settings endpoints
- X-Cache/Age-bearing responses
- CDN-fronted authenticated apps
- banking/dashboard style apps with static-asset caching

**Recon methods** — techniques beyond the skill itself:

- **Cache extension matrix** — Request authenticated pages with .css/.js/.ico/.json suffixes and path tricks; diff response headers for cache status. Tooling: manual + Intruder. Signal: Cached entry appears for an authenticated body..
- **Two-layer audit** — Check CDN layer and app layer separately; one may cache what the other would not. Tooling: header diffing. Signal: CF-Cache-Status vs app cache disagree..
- **Vary analysis** — Audit Vary headers — missing Vary: Cookie/Authorization is the deception enabler. Tooling: manual. Signal: No vary on auth headers..
- **Cache key simplification** — param-miner finds unkeyed params; simplification (ignoring query, case, port) widens deception surface. Tooling: param-miner. Signal: Unexpected cache hits..

**Class variants** — other places the same weakness hides:

- deception via ;.js path params
- case/encoding tricks
- CloudFront cache policies
- Varnish vcl behavior
- app-level caches (django cache_page)

**Dorks**:

- google: inurl:profile site:target.tld
- shodan: http.html:"varnish"
- github: cache_page( django

**Pivot hints** — where to go after proof:

- pair with smuggling chain for poison+deception combo
- harvested tokens feed auth chains
- document cache behavior map for the client

**Sources.** PortSwigger — Web cache deception; snyk/original deception research (Filipov); HackTricks — Cache deception; CDN cache-policy docs


### Routing confusion -> alias traversal -> LFI source read — `routing-confusion-lfi`

**Goal.** Exploit front/back routing disagreement to reach hidden paths, then walk into filesystem reads and PHP source/config disclosure.
**Preconditions.** Front proxy with rewrite/header routing + origin app; or nginx static alias config.
**Impact.** Access to hidden/admin paths and arbitrary file/source read (DB creds from config).
**CWE.** CWE-22, CWE-288 · **Fallbacks.** `smuggling-to-poisoned-reset`, `recon-secrets-to-cloud`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `elite/X-Original-URL routing confusion` | Reach paths the front blocks (admin, debug) via alternate routing headers. | Note which paths are reachable; hunt for filesystem-touching endpoints. | Headers stripped -> nginx alias traversal next; also try X-Rewrite-URL variants. |
| 2 | `web/Nginx alias traversal off-by-slash` | Static alias misconfiguration lets /static../ escape into arbitrary directory reads. | Directory-level reads -> step 3 for filter-bypassed file reads. | No alias -> generic traversal filters next. |
| 3 | `web/Path traversal once-strip filter evasion` | Beat naive traversal filters (single-strip normalization). | File reads confirmed -> step 4 for source/config. | Filter stronger -> encoding matrix (%2e%2e%2f, ....//, unicode), or PHP wrappers next. |
| 4 | `web/PHP filter wrapper LFI base64 read` | php://filter base64 read of application/config source — DB creds and secrets land in-band. | Creds feed admin panels shelf (phpMyAdmin/Adminer/H2) for the pivot. | Not PHP -> pure traversal reads of .env/.git targets (recon-secrets-to-cloud chain). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- nginx location /static style aliases (off-by-slash)
- front proxies with rewrite rules
- apps with download/preview file params
- WAF-blocked paths worth re-testing via confusion

**Recon methods** — techniques beyond the skill itself:

- **Routing header sweep** — X-Original-URL / X-Rewrite-URL / X-Forwarded-Host at every mirror; diff status/bodies. Tooling: Burp + header list. Signal: Front honors an attacker-chosen path..
- **Alias misconfig probe** — /static../, /static%2e%2e/, /static..%2f against known static prefixes. Tooling: manual. Signal: Directory listing or file content of parent..
- **404-source differential** — Compare 404 bodies across paths to infer which layer produced them (front vs origin). Tooling: manual. Signal: Different 404 = two layers = confusion surface..
- **Wrapper acceptance** — php://filter, file://, data:// acceptance on any file-parameter endpoint. Tooling: manual. Signal: Wrapper executed = wrapper-level read..

**Class variants** — other places the same weakness hides:

- X-Accel-Redirect internal file access
- /..;/ on Tomcat/Jetty (RFC violations)
- Spring matrix variables
- WAF-bypass via path confusion
- LFI->RCE via log poisoning/session files (documented variant)

**Dorks**:

- github: location /static { alias
- github: X-Original-URL
- google: inurl:download?file= site:target.tld

**Pivot hints** — where to go after proof:

- read configs -> creds -> admin_panels shelf
- read .git targets -> recon-secrets-to-cloud
- pair with xxe for parser-level reads

**Sources.** nginx docs — location/alias pitfalls; PortSwigger — X-Original-URL routing; PayloadsAllTheThings — Path traversal / LFI; HackTricks — nginx misconfigurations


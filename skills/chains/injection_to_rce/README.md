# Attack chains — Injection Proofs -> Code Execution -> OS Layer

**Group `injection_to_rce`** · 4 chain(s) · folder `chains/injection_to_rce/`

Injection skills prove the parser; chains prove the impact. This group ladders template/injection/serialization proofs into OS command execution, using the command-injection skills as the universal final mile.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `ssti-escalation-ladder` | SSTI: arith proof -> engine RCE gadget -> OS echo | 3 | CWE-1336, CWE-94 |
| `upload-to-shell` | Upload: locate -> bypass -> execute -> OS proof | 4 | CWE-434, CWE-78 |
| `sqli-blind-to-exfil` | SQLi: boolean differential -> engine errors -> UNION exfil | 3 | CWE-89 |
| `deserialization-ladder` | Deserialization: Java/PHP/Python probes -> gadget RCE | 4 | CWE-502 |

## Shared recon for this group (how to find candidates at all)

- **Engine fingerprint sweep** — Polyglot canaries ({{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, {php}) into every reflected surface incl. filenames, headers, error contexts.
- **Sink taxonomy** — Map user data into these server contexts: templates, SQL, XML, serializers, OS strings, LDAP/XPath filters — each maps to a shelf.
- **Second-order inventory** — Stored inputs (profile fields, filenames, headers logged to DB) may reach parsers in background jobs — mark them for delayed probes.
- **Error-verbosity mining** — Force 500s and read tracebacks: engine names, paths, library versions — each is a skill selector.
- **Upload + execute pairing** — Wherever uploads exist, pair the upload shelf with execution shelves (PHP/webconfig/htaccess) — upload alone is rarely the ceiling.

## Chain playbooks

### SSTI: arith proof -> engine RCE gadget -> OS echo — `ssti-escalation-ladder`

**Goal.** Escalate template-injection proofs to OS command execution on the detected engine, with a full engine-coverage ladder.
**Preconditions.** Reflected user input rendered by a server-side template engine (including email/PDF template editors).
**Impact.** Arbitrary code/OS command execution as the app user.
**CWE.** CWE-1336, CWE-94 · **Fallbacks.** `upload-to-shell`, `sqli-blind-to-exfil`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/SSTI Jinja2 arith+repeat proof` | Deterministic engine + eval proof (343 marker) for Jinja2. | Step 2 for RCE; other engines detected -> swap the sibling proof (Freemarker/Mako/Velocity/ERB). | No eval -> client-side reflection -> web/Angular client-side template injection reflection (CSTI). |
| 2 | `elite/Jinja2 SSTI OS command execution` | Jinja2 gadget chain to OS command. | Step 3 confirms the OS layer; alternative engines -> web/Twig SSTI RCE map-system gadget, web/Freemarker SSTI RCE Execute gadget. | Sandboxed Jinja -> Twig/Freemarker/Mako/ERB siblings; sandbox survives -> document eval-only impact. |
| 3 | `web/Command injection output echo marker` | Deterministic uid() marker through the OS layer — converges every engine chain onto one proof shape. | Full RCE narrative: probe -> gadget -> OS marker. | Output blind -> web/Command injection time-based sleep oracle as the blind channel. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- user-editable email/subject templates (god-tier sink)
- PDF/invoice generators
- CMS template/theme editors
- i18n message keys
- webhook payload templating
- error-page interpolation

**Recon methods** — techniques beyond the skill itself:

- **Polyglot canary injection** — Inject {{7*7}} ${7*7} <%= 7*7 %> #{7*7} into every reflected parameter, header (UA), and filename. Tooling: Burp Intruder + canary list. Signal: 49/343 rendered — engine identified by which syntax fires..
- **Template-editor hunt** — Search the product surface for template/notification/signature editors — these are intended user-facing template sinks. Tooling: product UI walkthrough. Signal: Editor UI = direct SSTI if server-rendered..
- **Traceback engine reveal** — Force errors; Jinja/Mako/Freemarker/Twig names in tracebacks tell you which proof to run. Tooling: web/Framework debug traceback disclosure. Signal: Engine name = exact skill match..
- **Filename reflection** — Upload/name files with canaries — filenames often pass through templates (attachment names, export titles). Tooling: manual. Signal: Rendered arithmetic in file-derived output..

**Class variants** — other places the same weakness hides:

- email subject/body template injection
- PDF invoice generators
- i18n key injection
- Flask error handlers rendering user input
-  Velocity/Freemarker in Java admin consoles
- Twig in abandoned CMS plugins

**Dorks**:

- github: render_template_string(
- github: Template(source).render(
- github: new Template( velocity

**Pivot hints** — where to go after proof:

- RCE -> internal network recon via latency channel
- pair with upload-to-shell for persistence
- read config for cloud creds (recon-secrets-to-cloud)

**Sources.** PayloadsAllTheThings — SSTI; HackTricks — SSTI per-engine; PortSwigger — Template injection; community engine-specific gadget sheets (Jinja2/Twig/Freemarker)


### Upload: locate -> bypass -> execute -> OS proof — `upload-to-shell`

**Goal.** From discovering the upload directory to executing uploaded code and proving the OS layer.
**Preconditions.** Any file upload feature (avatar, ticket attachment, import).
**Impact.** Remote code execution via uploaded script; full host compromise as the web user.
**CWE.** CWE-434, CWE-78 · **Fallbacks.** `ssti-escalation-ladder`, `deserialization-ladder`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/Directory listing autoindex exposed` | Locate the upload directory and naming scheme (where files land, whether names are kept). | Direct URL for the payload in step 2/3. | No listing -> derive paths from page source, JS, or error messages. |
| 2 | `web/Upload double-extension filter bypass` | Get a PHP-family payload past extension filtering (shell.php.jpg shape). | Payload stored; step 3 proves execution. | Validation stricter -> phtml/phar/phps/php5 variants, .htaccess/.user.ini drop, or content-type/filename normalization quirks. |
| 3 | `web/Upload phtml execution marker` | Prove the payload executes (php_uname marker) — upload becomes RCE. | Step 4 for OS-layer proof; also try web/Stored XSS persisted marker for the XSS-flavored upload impact. | No execution -> pivot placement via web/Path traversal once-strip filter evasion (write outside upload dir). |
| 4 | `web/Command injection output echo marker` | Converge on the deterministic uid() OS proof through the shell. | Full chain narrative; proceed to internal recon. | Blind -> web/Command injection time-based sleep oracle. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- avatar/profile images
- ticket attachments
- bulk import (CSV/zip)
- theme/plugin installers
- API upload endpoints from OpenAPI specs

**Recon methods** — techniques beyond the skill itself:

- **Upload-path reflection** — Check whether the response or subsequent pages echo the stored path/name — path knowledge is half the exploit. Tooling: manual. Signal: Filename echoed in HTML/JSON..
- **Extension acceptance matrix** — Probe the validator with a matrix (php3/phtml/phar/phps/jpg;php; .jpg/.php hybrids; case tricks; null byte legacy). Tooling: Burp Intruder + wordlist. Signal: One variant stored where others rejected..
- **Validation-code recovery** — Sourcemaps/source disclosure reveal the server-side validator; read before fuzzing. Tooling: web/JS source map disclosure. Signal: Client-side-only checks = trivial bypass..
- **Archive upload angle** — Zip uploads with traversal names (zip slip) place files outside the upload root. Tooling: manual crafted zips. Signal: Files appearing in unexpected directories..
- **Cloud upload diff** — Distinguish local storage vs S3/presigned — cloud storage changes the execution story to bucket takeover/public ACL. Tooling: redteam/S3-GCS public bucket listing. Signal: Storage URLs on cloud domains..

**Class variants** — other places the same weakness hides:

- SVG upload -> stored XSS
- .htaccess/.user.ini placement
- polyglot GIF+PHP
- zip slip via importers
- race upload-vs-scanner
- web.config for IIS deployments

**Dorks**:

- github: move_uploaded_file(
- google: inurl:uploads site:target.tld
- github: "content-type" "image/" upload allowlist

**Pivot hints** — where to go after proof:

- shell -> internal creds/configs -> cloud_takeover chains
- pair with directory listing for fleet-wide uploaded payloads
- combine with deserialization-ladder via phar:// for PHP

**Sources.** PayloadsAllTheThings — Upload insecure files; HackTricks — File upload; OWASP File Upload Cheat Sheet; commix/phantom shell methodologies


### SQLi: boolean differential -> engine errors -> UNION exfil — `sqli-blind-to-exfil`

**Goal.** From a boolean-blind confirmation to engine-fingerprinted error extraction to UNION-based bulk exfiltration.
**Preconditions.** An injectable parameter (string, numeric, ORDER BY, JSON path).
**Impact.** Full database read (and credential harvest feeding auth chains); potential file read depending on engine config.
**CWE.** CWE-89 · **Fallbacks.** `ssti-escalation-ladder`, `auth-bypass-to-admin`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/SQLi boolean-blind response differential` | Confirm injection with a deterministic differential (AND 1=1 vs 1=2). | Step 2 to fingerprint the engine. | Boolean filtered -> time-based siblings (MySQL/PostgreSQL/MSSQL). |
| 2 | `web/SQLi error-based MySQL-family` | Engine fingerprint + version + fast extraction through error messages; swap to PostgreSQL/MSSQL/Oracle siblings per fingerprint. | Engine confirmed -> step 3 for bulk. | Errors suppressed -> stay time-based and enumerate with the sibling time-based skill. |
| 3 | `elite/SQLi UNION reflection exfiltration primitive` | Column-count-matched UNION reflection for bulk table dumps. | Harvest users table -> credentials feed chain auth-bypass-to-admin. | Column mismatch resists -> error-based char-by-char extraction; MSSQL -> xp_cmdshell (documented variant, needs privilege). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- search/filter/sort parameters
- ORDER BY / LIMIT / OFFSET parameters (classic blind spot)
- JSON-path arguments
- cookie/Referer/User-Agent values logged to DB
- GraphQL argument strings
- report/export query builders

**Recon methods** — techniques beyond the skill itself:

- **Param classification** — Test numeric vs string vs ORDER BY contexts with minimal toggles (' vs " vs ') before any payload. Tooling: manual. Signal: Syntax error text = context identified..
- **Error fragment mining** — Tracebacks with SQL fragments give engine, table and even the query — selects the right skill instantly. Tooling: web/Framework debug traceback disclosure. Signal: Engine name in error..
- **Second-order candidate list** — Mark stored fields (profile, filenames) as delayed injection surfaces — they hit SQL in background jobs. Tooling: manual + patience. Signal: Stored value later reflected in SQL-driven error..
- **Encoding quirks** — URL-encoding vs raw, unicode tricks, comment variants (--, #, /**/) change filter behavior. Tooling: manual matrix. Signal: One encoding passes where others fail..
- **GraphQL argument injection** — GraphQL resolvers often build SQL from string args — inject inside query strings. Tooling: introspection + manual. Signal: Error fragments inside GraphQL errors..

**Class variants** — other places the same weakness hides:

- ORDER BY injection (no quote needed)
- LIMIT/OFFSET injection
- INSERT/UPDATE contexts (verbose errors)
- JSON_extract() injection
- second-order via stored values
- NoSQL regex/data-type alternatives

**Dorks**:

- github: executeQuery( + concat
- github: db.query(` + variable (template literal SQL)
- google: inurl:id= "mysqli_fetch

**Pivot hints** — where to go after proof:

- users table -> auth-bypass-to-admin
- MySQL FILE privilege -> secure_file_priv file read
- database names -> data_stores shelf sweep for direct connections

**Sources.** PayloadsAllTheThings — SQL injection; PortSwigger — SQLi cheat sheet; OWASP SQLi Prevention + blind techniques; sqlmap methodology notes (manual equivalents)


### Deserialization: Java/PHP/Python probes -> gadget RCE — `deserialization-ladder`

**Goal.** Fingerprint which native deserializer the app feeds, then converge on a gadget-driven RCE.
**Preconditions.** Native-encoded data in cookies, bodies, viewstate-like blobs, or import features.
**Impact.** Code execution via gadget chains (Java CommonsCollections etc.), object injection (PHP), arbitrary Python execution (pickle).
**CWE.** CWE-502 · **Fallbacks.** `upload-to-shell`, `ssti-escalation-ladder`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/Java deserialization object-graph probe` | Detect Java native deserialization (rO0AB surfaces) and object-graph handling. | Gadget selection (heapdump helps: redteam/Spring Boot actuator heapdump) -> step 4. | No Java surface -> step 2/3 for PHP/Python. |
| 2 | `web/PHP unserialize offset probe` | PHP object-injection surface detection (O:N:... shapes). | PHP route: gadget via phar:// or ThinkPHP -> step 4. | No PHP -> step 3. |
| 3 | `web/Python pickle invalid-load-key probe` | Pickle surface detection (gASV blobs, invalid-load-key oracle). | Pickle RCE payloads via __reduce__ (documented next step) -> step 4. | None of three -> YAML deserialization or .NET ViewState (documented gaps; note them honestly). |
| 4 | `web/Command injection output echo marker` | Converge: OS-layer proof once a gadget executes. | Chain narrative closed with deterministic marker. | Blind -> time-based oracle skill. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- remember-me cookies (Java Shiro, PHP, Django)
- session blobs / viewstate-like parameters
- import features (JMX, RPC, native formats)
- queue/job payloads
- API bodies with base64 blobs (base64 starts rO0AB / gASV / Tzo)

**Recon methods** — techniques beyond the skill itself:

- **Blob census** — Collect every base64/hex blob the app sets; prefix-match against native serializers (rO0AB=Java, O:=PHP, gASV=pickle, /wEy=.NET). Tooling: manual + decode. Signal: Native serializer identified..
- **Library census via heapdump** — Actuator heapdump strings reveal gadget libraries (commons-collections versions) before payload crafting. Tooling: redteam/Spring Boot actuator heapdump + strings. Signal: Gadget library present..
- **phar angle** — PHP file operations on phar streams unserialize metadata — pair any file-read/upload with phar probes. Tooling: manual. Signal: phar:// acceptance..
- **Import-format inventory** — Native-format imports (Java native RPC, PHP session upload progress, Python job queues) are the classic sinks. Tooling: product docs + probing. Signal: Serializer errors on malformed input..

**Class variants** — other places the same weakness hides:

- Shiro rememberMe AES with leaked key
- commons-collections gadget chains (ysoserial)
- php phar metadata deserialization
- pyYAML unsafe load
- .NET ViewState (needs machineKey — documented gap)

**Dorks**:

- github: ObjectInputStream
- github: yaml.load( -safe_load
- github: unserialize($_

**Pivot hints** — where to go after proof:

- RCE -> internal network + config -> cloud_takeover chains
- gadget lib versions -> matching public gadget lists
- pair upload-to-shell for payload delivery

**Sources.** Java Deserialization Cheat Sheet; ysoserial gadget notes; PayloadsAllTheThings — Insecure Deserialization; php phar deserialization research (S.Pate)


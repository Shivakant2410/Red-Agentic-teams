# Hands and skills — what every agent holds and may execute

> Rendering of `redteam/hands.py` (regenerate: `python3 scripts/gen_hands_doc.py`).
Trust classes are the crosscheck layer's own vocabulary (`redteam/tools/crosscheck.py`); a hand may not claim a discipline the trust matrix does not enforce — `tests/test_hands.py` locks this.

| Agent | Role | Hands | Skills |
|---|---|---|---|
| `recon` | surface mapping (orchestrator round) | 16 | 3 |
| `exploit` | prove vulnerabilities (orchestrator round / swarm) | 13 | 3 |
| `access` | press a confirmed foothold (orchestrator round) | 10 | 1 |
| `logic` | business-logic workflows (orchestrator round) | 6 | 1 |
| `verify` | independent pass over pending findings | 1 | 1 |
| `a01-access` | OWASP A01 Broken Access Control (swarm class expert) | 9 | 1 |
| `a03-injection` | OWASP A03 Injection (swarm class expert) | 13 | 2 |
| `a05-misconfig` | OWASP A05 Security Misconfiguration & Sensitive Data Exposure (swarm class expert) | 13 | 1 |
| `a07-auth` | OWASP A07 Identification & Authentication Failures (swarm class expert) | 10 | 1 |
| `a10-ssrf` | OWASP A10 Server-Side Request Forgery (swarm class expert) | 7 | 1 |

Trust classes: `deterministic-honest`, `first-party-observation`, `ground-truth`, `lead-crosschecked`, `offline-parse`, `peer-read`, `proof-trial`


## recon — surface mapping (orchestrator round)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `surface_scan` | step | ground-truth | knock on every host/port the RoE allows, once, and fill the asset inventory — the alive-map every later step aims at | one call, no arguments, first thing in a mapping round; a host it did not answer for is dead to this run — never spend a step on it |
| `host_probe` | step | lead-crosschecked | binary-assisted liveness + technology fingerprint of discovered URLs (httpx/nmap class leads) | its endpoint/service claims are LEADS: crosscheck_lead them first-party (GET / raw TCP) before any probe aims at one |
| `port_scan` | step | lead-crosschecked | RoE-bounded port scan of in-scope hosts (nmap class) | every open-port claim must survive a raw first-party TCP connect via crosscheck_lead before it goes in the graph |
| `content_discovery` | step | lead-crosschecked | wordlist-driven path discovery on a live host (ffuf class) — backups, dotfiles, admin paths, API roots | a claimed path is not a path until a first-party GET reaches it (crosscheck_lead); 404/410 on the re-fetch kills the lead |
| `crawl` | step | lead-crosschecked | link/JS crawl of a live host (katana class) — the app's own map of itself | crawled URLs are leads until a first-party GET reaches them (crosscheck_lead) |
| `param_discovery` | step | lead-crosschecked | hidden-parameter discovery on an endpoint (arjun class) | a claimed param is not real until a first-party WITH/WITHOUT pair actually differs (crosscheck_lead); identical response kills it |
| `spa_recon` | step | lead-crosschecked | walk a SPA's bundle to infer its API routes | inferred routes are leads: a first-party GET (or a 405 on a POST-able route) corroborates, 404 kills |
| `crosscheck_lead` | step | first-party-observation | run the registered second method against a tool's lead claim (corroborated / contradicted / unverifiable) — the trust ladder's gate | never skip it on a lead you want to be true; unknown (tool, claim) pairs fail closed by design — unverifiable means drop it |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `browser_click` | step | first-party-observation | click a page element by role/name — drive multi-step flows | observations only |
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `kali_exec` | step | first-party-observation | run an allowlisted binary in the sandbox (scope-guarded) | the wrapped BINARY's claims (ffuf/katana/arjun/nuclei/httpx/nmap class) are lead classes — each obeys its TRUST_MATRIX entry via the wrapping tool or crosscheck_lead, never direct belief |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**alive-before-aiming** — WHEN a mapping round starts (nothing alive known yet)

1. surface_scan once, no arguments
2. read the asset inventory it filled
3. aim host_probe/content_discovery/crawl ONLY at hosts/ports that answered

- EXIT: no step spent on a host the RoE allows but the scan did not answer
- PROOF: n/a — mapping produces inventory, not findings

**lead-then-first-party** — WHEN any binary/crawler tool returns leads (paths, params, ports, routes)

1. collect the leads with their (tool, claim) class
2. crosscheck_lead each class — first-party GET / WITH-WITHOUT pair / raw TCP
3. corroborated leads go forward; contradicted leads are dropped, not retried
4. unverifiable leads are dropped — the matrix fails closed on purpose

- EXIT: every lead you ACT on carries a corroborated verdict
- PROOF: crosscheck verdict 'corroborated' recorded per lead

**auth-wall-passthrough** — WHEN a login wall blocks mapping, or the brief supplies a token/cookie

1. authenticate with the seeded/brief credentials (multi-step login aware)
2. or set_session the brief-supplied token under a name
3. continue mapping what is behind the wall

- EXIT: authenticated surface mapped; the held session is registered for downstream specialists
- PROOF: n/a — mapping


## exploit — prove vulnerabilities (orchestrator round / swarm)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `find_techniques` | step | ground-truth | pull the first-party playbook card for a technique (differential shape, false-positive traps, accepted proof) | read the card BEFORE designing checks — do not re-derive what the playbook already encodes |
| `crosscheck_lead` | step | first-party-observation | run the registered second method against a tool's lead claim (corroborated / contradicted / unverifiable) — the trust ladder's gate | never skip it on a lead you want to be true; unknown (tool, claim) pairs fail closed by design — unverifiable means drop it |
| `apply_skill` | verification-trial | proof-trial | fill in a PROVEN skill's parameters and re-run its exact proof (the skill library's whole point: fill two params, not redesign a proof) | use the skill verbatim; if the skill's shape doesn't fit, design a check with verify_vulnerability instead |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `browser_fill` | step | first-party-observation | type into a form field (payloads included) — the stored-XSS submission path | observations only; the rendering surface still needs proof |
| `kali_exec` | step | first-party-observation | run an allowlisted binary in the sandbox (scope-guarded) | the wrapped BINARY's claims (ffuf/katana/arjun/nuclei/httpx/nmap class) are lead classes — each obeys its TRUST_MATRIX entry via the wrapping tool or crosscheck_lead, never direct belief |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**playbook-first** — WHEN a technique/target pair is claimed from the attack tree

1. find_techniques(technique) and read the card
2. use the card's differential shape and its false-positive traps
3. design the check against THAT shape, not from memory

- EXIT: the check's conditions use the card's differential shape
- PROOF: the proof shape the card names

**ready-spec-consume** — WHEN the claimed node carries a synthesis draft (evidence + check_spec)

1. read the draft's evidence refs — they record WHY the node looked attackable
2. fire the draft's check_spec through verify_vulnerability 1:1, unmodified
3. a refuted draft is a closed node, not a redesigned one

- EXIT: pending_verification reached, or the draft is refuted and the node closed
- PROOF: the draft's own conditions, verbatim

**look-then-prove** — WHEN holding a hypothesis worth a trial (no draft, no ready spec)

1. http_probe to shape it — contexts, response shapes, session reach
2. ONE verify_vulnerability with differential conditions (status AND body/content), never status alone

- EXIT: check recorded pending_verification — then keep proving, never self-promote
- PROOF: differential conditions


## access — press a confirmed foothold (orchestrator round)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `extract_secrets` | step | offline-parse | regex sweep over material you already hold (bodies, files) for credential shapes (AKIA…, ghp_…, eyJ…) | a regex hit is a lead until the resource is Fetched and its content verified |
| `try_credential` | step | first-party-observation | bounded credential attempts against an in-scope login | SMALL burst, then stop — RoE-minimal; a lockout message is an enumeration finding, not a bypass |
| `prove_privilege` | verification-trial | proof-trial | differential privilege-boundary proof for a held session | never label access yourself — the check lands pending_verification like every other proof |
| `record_access` | step | first-party-observation | note a discovered lead/edge (not self-granted access) into the ledger | records leads and edges, never labels held access |
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `kali_exec` | step | first-party-observation | run an allowlisted binary in the sandbox (scope-guarded) | the wrapped BINARY's claims (ffuf/katana/arjun/nuclei/httpx/nmap class) are lead classes — each obeys its TRUST_MATRIX entry via the wrapping tool or crosscheck_lead, never direct belief |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |

### Skills

**harvest-try-prove** — WHEN a confirmed foothold exists and the kill chain names the stage to press

1. extract_secrets over material already held
2. try_credential the candidates — SMALL bounded burst, in-scope only
3. prove_privilege the boundary differentially with the held session
4. record_access for leads/edges discovered — never label access yourself

- EXIT: every pressed stage ends in a proof-trial verdict or an explicit 'nothing presses further'
- PROOF: prove_privilege's differential check


## logic — business-logic workflows (orchestrator round)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `verify_workflow_abuse` | verification-trial | proof-trial | ordered attack_steps vs honest control_steps with a stated invariant — the business-logic proof | one-shot: business logic cannot be re-run k-of-n — sequence it right the first time |
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `browser_fill` | step | first-party-observation | type into a form field (payloads included) — the stored-XSS submission path | observations only; the rendering surface still needs proof |
| `browser_click` | step | first-party-observation | click a page element by role/name — drive multi-step flows | observations only |

### Skills

**ordered-attack-vs-control** — WHEN a workflow-shaped endpoint (cart/checkout/coupon/order/transfer) is claimed

1. state the domain assumption the app makes (coupon once, price server-side, no step skipping, no repeats)
2. verify_workflow_abuse: attack_steps breaking it, control_steps doing the SAME workflow honestly (fresh identifier), the invariant that separates them
3. authenticate first if the workflow needs a session

- EXIT: one correct sequence — no spraying; one-shot proofs are not re-run
- PROOF: the invariant that the attack broke and the control did not


## verify — independent pass over pending findings

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `verify_finding_independently` | verification-trial | proof-trial | reproduce a finding's check in a FRESH context with a forced negative control — the independent verdict | accept the verdict; do not argue with it |

### Skills

**run-all-pending** — WHEN any finding is pending_verification

1. verify_finding_independently(finding_id) for EACH pending finding
2. accept the verdict — reproduce + forced negative control decided, not you

- EXIT: zero pending findings
- PROOF: the independent verdict (confirmed/refuted)


## a01-access — OWASP A01 Broken Access Control (swarm class expert)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `crosscheck_lead` | step | first-party-observation | run the registered second method against a tool's lead claim (corroborated / contradicted / unverifiable) — the trust ladder's gate | never skip it on a lead you want to be true; unknown (tool, claim) pairs fail closed by design — unverifiable means drop it |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**two-principal-differential** — WHEN a horizontal/vertical boundary is claimed (IDOR, missing function auth)

1. authenticate YOUR own user; register a second identity if the brief has one
2. http_probe YOUR object as baseline, then the same shape with THEIR identifier
3. verify_vulnerability: status==200 on payload AND json_differs on the owner path
4. control: re-run YOUR id through the identical modified path — if yours fails too, the path shape is wrong, not the boundary

- EXIT: differential recorded with the self-control; a lone 403/404 is not a pass
- PROOF: status AND body-carrying-the-OTHER-principal's-content


## a03-injection — OWASP A03 Injection (swarm class expert)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `xss_reflect_probe` | step | lead-crosschecked | deterministic reflection map: one unique marker per param, context classification, READY check_spec when specials survive | READY means the check_spec is proven-shaped — still fire it through verify_vulnerability; escaped reflections produce NO idea |
| `graphql_inspect` | step | deterministic-honest | 4-request deterministic checklist over a GraphQL endpoint (introspection, validation echo, error shape) | honestly registered unverifiable in the trust matrix: it maps SURFACE, it claims nothing — what it finds still needs a proof tool |
| `crosscheck_lead` | step | first-party-observation | run the registered second method against a tool's lead claim (corroborated / contradicted / unverifiable) — the trust ladder's gate | never skip it on a lead you want to be true; unknown (tool, claim) pairs fail closed by design — unverifiable means drop it |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `browser_fill` | step | first-party-observation | type into a form field (payloads included) — the stored-XSS submission path | observations only; the rendering surface still needs proof |
| `browser_click` | step | first-party-observation | click a page element by role/name — drive multi-step flows | observations only |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**reflect-map-prove** — WHEN xss_reflect_probe reports a READY check_spec (or an escaped reflection)

1. READY: fire its check_spec through verify_vulnerability 1:1, unmodified
2. escaped reflection: produce NO idea — do not spend budget on a dead oracle
3. classify the context (element/attribute/JS string/href) — the context picks the breakout, not a payload list

- EXIT: reflected_unescaped proof on YOUR marker in the claimed context
- PROOF: reflected_unescaped

**differential-pairs-only** — WHEN a SQLi or command-injection hypothesis exists

1. probe with SAFE differential pairs (quote-then-boolean, arithmetic identity, time pairs) — never destructive payloads
2. confirm only via differential response pairs or latency_delta
3. error text alone is plantable — it does not count

- EXIT: differential recorded; error-based 'confirmation' never recorded
- PROOF: differential pair or latency_delta


## a05-misconfig — OWASP A05 Security Misconfiguration & Sensitive Data Exposure (swarm class expert)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `surface_scan` | step | ground-truth | knock on every host/port the RoE allows, once, and fill the asset inventory — the alive-map every later step aims at | one call, no arguments, first thing in a mapping round; a host it did not answer for is dead to this run — never spend a step on it |
| `content_discovery` | step | lead-crosschecked | wordlist-driven path discovery on a live host (ffuf class) — backups, dotfiles, admin paths, API roots | a claimed path is not a path until a first-party GET reaches it (crosscheck_lead); 404/410 on the re-fetch kills the lead |
| `nuclei_scan` | step | lead-crosschecked | template-driven known-vuln sweep of a live host | a template match is a lead until the first-party re-fetch shows the marker (crosscheck_lead) |
| `crosscheck_lead` | step | first-party-observation | run the registered second method against a tool's lead claim (corroborated / contradicted / unverifiable) — the trust ladder's gate | never skip it on a lead you want to be true; unknown (tool, claim) pairs fail closed by design — unverifiable means drop it |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `extract_secrets` | step | offline-parse | regex sweep over material you already hold (bodies, files) for credential shapes (AKIA…, ghp_…, eyJ…) | a regex hit is a lead until the resource is Fetched and its content verified |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `find_attack_templates` | step | ground-truth | recall known-tech template sets matching a fingerprint | templates aim probes; they do not prove |
| `apply_template` | step | first-party-observation | run a recalled template's checks | its hits are leads — proof tools still decide |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**fetch-the-secret** — WHEN a regex-shaped lead exists (AKIA…, ghp_…, eyJ…) or a juicy path is claimed

1. http_probe the exact resource — a lead that never fetched is not a finding
2. crosscheck_lead any content_discovery/nuclei claim first (first-party GET)
3. verify_vulnerability: status==200 AND body_regex matching the secret/resource shape
4. kill decoys: coherent content, not just presence; placeholder values

- EXIT: the EXPOSURE proven — one request, body carrying the resource
- PROOF: status==200 AND body_regex


## a07-auth — OWASP A07 Identification & Authentication Failures (swarm class expert)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `authenticate` | step | first-party-observation | log in through the app's own flow (seeded/brief creds, multi-step aware) and hold the session | logging in is bootstrap, not proof; a session you hold is input to proofs, never a finding |
| `set_session` | step | first-party-observation | register a brief-supplied token/cookie as a named session instead of hand-writing headers | register what the brief gave you; never invent tokens |
| `jwt_inspect` | step | offline-parse | deterministic offline parse of a held token: algorithm, claims, expiry | its output is a LEAD about the token — prove consequences THROUGH the app; the parse alone never proves anything |
| `try_credential` | step | first-party-observation | bounded credential attempts against an in-scope login | SMALL burst, then stop — RoE-minimal; a lockout message is an enumeration finding, not a bypass |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**token-then-app** — WHEN jwt_inspect flags a token (alg none, symmetric key in claims, odd expiry)

1. jwt_inspect every held token — deterministic, offline
2. prove the consequence THROUGH the app: forge/resend via authenticate/set_session + verify_vulnerability
3. the parse alone never proves anything

- EXIT: app-level proof (the crafted token WORKS or the control fails)
- PROOF: differential with and without the tampered field


## a10-ssrf — OWASP A10 Server-Side Request Forgery (swarm class expert)

### Hands

| Tool | Cost | Trust | Purpose | Obligation |
|---|---|---|---|---|
| `surface_scan` | step | ground-truth | knock on every host/port the RoE allows, once, and fill the asset inventory — the alive-map every later step aims at | one call, no arguments, first thing in a mapping round; a host it did not answer for is dead to this run — never spend a step on it |
| `http_probe` | step | first-party-observation | raw first-party HTTP fetch — the second method the crosscheck layer itself trusts; read responses, classify contexts, shape hypotheses | an observation aims the next step; it NEVER records a finding — proving is verify_vulnerability/confirm_finding's job |
| `verify_vulnerability` | verification-trial | proof-trial | fire a full reproducing check (requests + conditions) — the main proof hand; a synthesis draft's check_spec goes in 1:1, unmodified | fire only with a hypothesis worth proving; conditions must be the differential shape (status AND body/content), never status alone |
| `confirm_finding` | verification-trial | proof-trial | record a simple single/differential HTTP proof as a finding check | same discipline: differential shape or nothing |
| `browser_navigate` | step | first-party-observation | drive the real browser to a URL — JS-rendered surfaces the probe cannot see | what you SEE is an observation; pair with browser_content to read it |
| `browser_content` | step | first-party-observation | read the live DOM/text of the page the browser is on | observations only — stored-payload rendering here still needs a proof tool to count |
| `search_peer_traces` | step | peer-read | read sibling workers' observations (identifiers, tokens, paths they saw) | a peer observation is a hint to re-derive YOURSELF, not evidence |

### Skills

**two-shape-ssrf** — WHEN a parameter takes a URL/host/path (webhook, fetcher, importer, avatar/PDF)

1. surface_scan first — the RoE grid IS your target list, alive hosts only
2. learn the app's two response shapes: known-good external URL vs refused/invalid
3. swap the parameter to an in-scope INTERNAL target; read which shape returns
4. body_regex for internal-only content landing in YOUR response is the strongest proof; blind = timing/size differential + the word 'blind'

- EXIT: internal content reflected (proven) or an honest 'blind' differential
- PROOF: body_regex on internal-only content


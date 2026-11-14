# Attack chains — Identity Abuse -> Privilege Escalation -> Admin Plane

**Group `auth_to_admin`** · 4 chain(s) · folder `chains/auth_to_admin/`

Authentication and authorization defects compound: an operator bypass plus a forged claim plus an unprivileged admin function is a full account takeover of the administrative plane. Each chain here starts from a low-signal flaw and escalates it into the admin data plane.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `auth-bypass-to-admin` | NoSQL bypass -> mass assignment -> BFLA -> IDOR | 4 | CWE-943, CWE-915, CWE-285 |
| `jwt-to-privilege` | JWT: kid traversal -> forged claims -> object access | 3 | CWE-347, CWE-345 |
| `idor-mass-extraction` | Enumeration seed -> IDOR -> alias amplification -> bulk exfil | 4 | CWE-639, CWE-770 |
| `oauth-session-ato` | OAuth: redirect capture -> state abuse -> token theft | 4 | CWE-601, CWE-352 |

## Shared recon for this group (how to find candidates at all)

- **Two-account differential** — Register two low-privilege accounts; replay every request of account A with B's session and vice versa; diff objects, IDs, role fields.
- **JWT/cookie anatomy** — Decode every token: algorithm, role claims, kid/jku headers, path scoping of cookies, Domain attribute width.
- **Admin-route discovery** — JS bundle grep for admin/manage/backoffice strings, OpenAPI specs, field-suggestion oracles, /api/v1/admin style guessing.
- **Register-response diff** — Compare registration/profile-update request schema against response echo; the server often leaks the full role model it accepts.
- **Legacy client fallback** — Older API versions (v1 vs v3, mobile builds) frequently skip newer authorization checks.

## Chain playbooks

### NoSQL bypass -> mass assignment -> BFLA -> IDOR — `auth-bypass-to-admin`

**Goal.** Walk from an authentication bypass into the admin data plane through privilege-model abuse.
**Preconditions.** A JSON login endpoint backed by Mongo-style documents, plus a role-bearing user model.
**Impact.** Unauthenticated or self-registered user reaches administrative functions and other tenants' objects.
**CWE.** CWE-943, CWE-915, CWE-285 · **Fallbacks.** `jwt-to-privilege`, `idor-mass-extraction`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/NoSQL Mongo operator login bypass` | Enter as an existing (or synthetic) user without a password via $ne/$regex operators. | Note the session shape; test which fields drive authorization. | Not Mongo or not JSON -> web/PHP type-juggling magic hash bypass; need usernames first -> web/Username enumeration login differential. |
| 2 | `web/Mass assignment role escalation` | Push role/isAdmin/permissions fields through register/profile-update to self-escalate. | Decode the new session and diff privileges before/after. | Fields filtered on update -> try registration-time injection, PATCH vs PUT, or JSON vs form encoding (parser differential). |
| 3 | `web/Admin function reachable without privilege (BFLA)` | With the escalated identity, hit admin-only functions directly to prove function-level authz is broken. | Enumerate admin capabilities; pick the highest-value function (export, user management). | Function blocked -> header routing confusion elite/X-Original-URL routing confusion; endpoint unknown -> web/OpenAPI-Swagger spec exposed or field-suggestion enumeration. |
| 4 | `web/IDOR horizontal object-graph` | With any privileged identity, enumerate the object graph across tenants. | Bulk-extract via elite/GraphQL alias amplification primitive if the API is GraphQL. | Sequential IDs blocked -> GUID leakage in exports/emails; document depth instead. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- JSON login bodies (grep JS for fetch(...login))
- register/profile update payloads
- API docs and mobile builds revealing role fields
- admin UIs reachable at non-obvious paths

**Recon methods** — techniques beyond the skill itself:

- **Schema echo diff** — Send unknown fields (role, isAdmin, tenant_id) and watch which echo back in responses or tokens. Tooling: Burp + manual. Signal: Echoed unknown field = model accepts it somewhere..
- **Operator probe matrix** — Try $ne, $regex, $where, $gt on login and search endpoints in JSON and URL-encoded forms. Tooling: Burp Intruder + mongo wordlist. Signal: Login succeeds without password..
- **Role-model recovery** — Field-suggestion oracles and verbose errors reveal the role vocabulary (admin, staff, superuser). Tooling: elite/GraphQL field suggestion enumeration or error mining. Signal: Role names you did not guess..
- **Mobile API teardown** — Decompile the APK/IPA and grep API paths and role checks — older endpoints and hidden admin routes live here. Tooling: apktool + strings. Signal: Hidden /admin/api routes, hardcoded role checks..
- **Token audience check** — Decode tokens across services; tokens issued for one service often validate on siblings. Tooling: jwt.io / jwt_tool. Signal: Same secret family across services..

**Class variants** — other places the same weakness hides:

- role stored in cookie vs JWT vs server session
- register-time vs profile-update mass assignment
- PATCH/PUT/JSON-merge quirks
- case-sensitivity tricks (Role vs role)
- mass assignment via GraphQL mutations

**Dorks**:

- github: db.users.find({"password": {"$ne"
- github: "is_admin" "request.json"
- google: inurl:/api/v1/admin

**Pivot hints** — where to go after proof:

- admin function list -> pick export/report (bulk data)
- combine with business-logic chain for monetary impact
- session fixation check after takeover

**Sources.** PayloadsAllTheThings — NoSQL injection; OWASP API Top 10 — API3/BOPLA & API6; HackTricks — Mongo injection; PortSwigger — Mass assignment labs


### JWT: kid traversal -> forged claims -> object access — `jwt-to-privilege`

**Goal.** Break token integrity (empty-key signing, claim forgery) and ride the forged identity into object-level access.
**Preconditions.** JWT in Authorization header or cookie; a kid parameter and role claims present.
**Impact.** Attacker-signed tokens accepted as any user/role; horizontal and vertical privilege escalation.
**CWE.** CWE-347, CWE-345 · **Fallbacks.** `auth-bypass-to-admin`, `cross-origin-action-suite`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/JWT kid path-traversal empty-key acceptance` | Prove verification weakness: kid-controlled key lookup accepting an attacker-chosen (empty) key. | Sign tokens as anyone; jump straight to step 3 if role claims are attacker-writable. | kid rejected -> try alg:none, RS256->HS256 confusion (public key from /jwks), jku/x5u injection (documented variants). |
| 2 | `elite/JWT forged-claim acceptance check` | Prove the verifier accepts re-signed claims (role/user/sub) — the escalation primitive. | Forge admin token -> step 3. | Claims verified against server state -> fall back to session-layer chains (cross-origin-action-suite). |
| 3 | `web/IDOR horizontal object-graph` | Use the forged identity to enumerate other tenants' objects. | Bulk extraction like chain idor-mass-extraction. | Object authz intact server-side -> document token forgery alone (still critical). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- Authorization: Bearer ...
- access_token/refresh cookies
- localStorage tokens (grep JS)
- SAML/OAuth id_token reuse

**Recon methods** — techniques beyond the skill itself:

- **Token census** — Collect every token shape the app issues (login, refresh, email confirm) and diff their claims and algorithms. Tooling: manual + jwt_tool. Signal: Different verification per token type; weaker one is the way in..
- **Header param sweep** — Test kid path traversal, jku/x5u remote JWKS, and duplicate JSON keys in the header. Tooling: jwt_tool -X. Signal: Verifier behavior changes with header content..
- **JWKS endpoint probe** — Find /jwks /keys /.well-known/jwks.json; public keys enable HS256 confusion attempts. Tooling: manual. Signal: RS256->HS256 confusion accepts when key cache misbehaves..
- **Expiry/audience laxness** — Replay expired tokens, swap aud/iss across services, drop exp entirely. Tooling: manual. Signal: Verifier checks signature but not context..
- **Cookie scope pairing** — Pair JWT cookies with web/Cookie Domain scope overbreadth — a forged cookie on any subdomain lands on the app. Tooling: web/Cookie Domain scope overbreadth skill. Signal: Domain=.target.tld on a session cookie..

**Class variants** — other places the same weakness hides:

- alg:none acceptance
- RS256->HS256 confusion
- kid SQLi in key lookup
- jku/x5u attacker JWKS
- signature-stripping on custom refresh flows
- JWT in query string (referrer leakage)

**Dorks**:

- github: jwt.verify( { algorithms
- github: "kid" "fs.readFileSync" jwt
- google: inurl:id_token= site:target.tld

**Pivot hints** — where to go after proof:

- forged admin -> BFLA chain for function-level proof
- refresh-token theft -> persistent access
- pair with oauth chain when login is OAuth-backed

**Sources.** PortSwigger — JWT attacks; PayloadsAllTheThings — JWT; OWASP JWT Cheat Sheet; jwt_tool repository notes


### Enumeration seed -> IDOR -> alias amplification -> bulk exfil — `idor-mass-extraction`

**Goal.** From a valid-user list to bulk extraction of tenant data via object-level authorization gaps, amplified by GraphQL aliases and absent throttling.
**Preconditions.** Two accounts and an object-ID scheme reachable cross-tenant.
**Impact.** Mass PII/document extraction with one weak-ID pivot and no rate-limiting resistance.
**CWE.** CWE-639, CWE-770 · **Fallbacks.** `graphql-recon-to-exfil`, `auth-bypass-to-admin`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/Username enumeration login differential` | Seed the object-owner namespace: valid usernames/emails make IDOR targets concrete. | Target list for step 2. | Uniform responses -> use public sign-up lists, org directory pages, or WordPress-style REST users enumeration on CMSs. |
| 2 | `web/IDOR horizontal object-graph` | Find the ID scheme that crosses tenants (sequential, weakly-encoded, role-skipped). | Document the scheme, then scale via step 3/4. | IDs are GUIDs -> harvest them from exports, emails, API responses, or graphql node(id:) base64 wrappers. |
| 3 | `elite/GraphQL alias amplification primitive` | One request, hundreds of objects — the scale multiplier when the API is GraphQL. | Bulk dump; pair with introspection for the field list. | No GraphQL -> export/report functions or batch endpoints serve the same role. |
| 4 | `web/Rate limiting absent burst acceptance` | Prove no throttling: burst acceptance turns a finding into an unlimited extraction. | Rate the extraction as unbounded; document blast radius. | Throttled -> rotate sessions/identities (documented variant) or slow-extract within limits. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- invoice/order/document download URLs
- export & report generators
- profile/message view endpoints
- unsubscribe/confirmation token URLs
- GraphQL node(id:) wrappers

**Recon methods** — techniques beyond the skill itself:

- **Auth Matrix replay** — Record every object request for account A, replay with B; any 200 on foreign objects is IDOR. Tooling: Burp Auth Analyzer / manual match-replace. Signal: 200 with A's ID under B's session..
- **ID scheme archaeology** — Collect object IDs from links, emails, exports; look for base64/uuid-encoder wrappers (f_LE rather than uuid). Tooling: manual + base64 decode. Signal: Decodable wrappers exposing raw integers..
- **Response-body diff** — Swap IDs and diff bodies; some endpoints hide objects in UI but still serve data. Tooling: Burp Comparer. Signal: Same shape, different object = authz on client only..
- **Verb/encoding switch** — GET->PATCH->DELETE, JSON vs form, trailing dots/semicolons on the path — authorization sometimes keyed to one shape. Tooling: manual. Signal: One verb/shape bypasses the check..
- **Export-feature audit** — Exports, invoices, webhook configs, and admin previews are the highest-yield IDOR sinks. Tooling: manual enumeration. Signal: Bulk objects in one response..

**Class variants** — other places the same weakness hides:

- IDOR in file download endpoints
- IDOR via predictable tokens (sequential reset codes)
- IDOR on HTTP methods (GET allowed, POST blocked)
- GraphQL object-level authz gaps
- IDOR behind admin previews (second-order)

**Dorks**:

- google: inurl:invoice?id= site:target.tld
- github: request.args.get("user_id")
- github: "export" "@app.route" admin

**Pivot hints** — where to go after proof:

- paired with jwt-to-privilege for vertical escalation
- exfil via absent throttling unbounded
- PII scale drives severity rating upward

**Sources.** OWASP API Top 10 — API1 BOLA; PortSwigger — IDOR labs; HackTricks — IDOR; GraphQL alias amplification research (Escobar)


### OAuth: redirect capture -> state abuse -> token theft — `oauth-session-ato`

**Goal.** Turn OAuth flow weaknesses (redirect_uri scope, missing state, open redirectors) into full account takeover of victim sessions.
**Preconditions.** OAuth login or account-linking flow present.
**Impact.** Authorization codes/tokens delivered to attacker-controlled origins; victims' accounts linked to attacker identities.
**CWE.** CWE-601, CWE-352 · **Fallbacks.** `jwt-to-privilege`, `subdomain-takeover-sweep`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `elite/OAuth redirect_uri origin substitution` | Prove the provider accepts attacker-controlled origins in redirect_uri (suffix/path/@ tricks). | Codes/tokens can be steered; combine step 3 for a legit-looking hop. | Exact-match enforced -> subdomain takeover of an allow-listed origin (chain subdomain-takeover-sweep) is the premium bypass. |
| 2 | `web/OAuth state parameter not enforced` | CSRF on the flow: bind victims to attacker codes (login CSRF / account linking takeover). | Victim completes flow -> attacker account linkage. | State present but reusable -> replay within TTL; PKCE absent -> code interception becomes viable. |
| 3 | `web/Open redirect cross-origin Location` | Use the site's own redirector as redirect_uri to make a wildcard allow-list exploitable. | Chained redirect keeps provenance legit while landing codes on your origin. | No open redirect -> postMessage/referer-leak variants (documented) or implicit-flow token leakage. |
| 4 | `web/Session cookie missing HttpOnly flag` | Finalization: tokens/cookies exposed to JS make the takeover persistent in browser context. | Script-side capture completes the ATO story. | HttpOnly set -> XSS-based capture (web/XSS reflected HTML-context) is the alternative collector. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- login-with-X buttons
- account linking / connect pages
- mobile deep links (app redirect schemes)
- id_token in fragment responses

**Recon methods** — techniques beyond the skill itself:

- **Allow-list cartography** — Enumerate every accepted redirect_uri value by error-message diffing; collect wildcards and legacy entries. Tooling: manual + error mining. Signal: Suffix/path matching or wildcard domains..
- **Bypass pattern sweep** — Try /path traversal, %2f, @attacker, sub-suffix (evil-target.tld), dot- inserting encodings. Tooling: manual list. Signal: Any accepted non-canonical origin..
- **State & PKCE audit** — Strip/replay state, check code_challenge binding, try re-used codes. Tooling: manual. Signal: Flow completes without unguessable binding..
- **Implicit/fragment audit** — response_type=token flows leak fragments to referers/analytics scripts. Tooling: manual + JS review. Signal: Token in location.hash handled by third-party JS..
- **Takeover pairing** — Check allow-listed origins for dead CNAMEs — takeover converts an exact-match allow-list into attacker origin. Tooling: subdomain-takeover skills. Signal: Provider fingerprint on abandoned origin..

**Class variants** — other places the same weakness hides:

- redirect_uri path traversal
- open redirector as intermediate hop
- state in cookie vs session
- PKCE downgrade (plain)
- account-linking CSRF (the higher-impact OAuth CSRF)
- id_token aud confusion across clients

**Dorks**:

- google: inurl:redirect_uri= site:target.tld
- github: redirect_uri allowlist
- github: "response_type=token"

**Pivot hints** — where to go after proof:

- subdomain-takeover-sweep for allow-list origins
- jwt-to-privilege if provider and app share token verification
- session fixation after linking

**Sources.** OWASP OAuth 2.0 Cheat Sheet; PortSwigger — OAuth labs; PayloadsAllTheThings — OAuth; OAuth 2.0 for Browser-Based Apps (IETF draft)


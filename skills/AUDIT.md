# AUDIT.md — Re-audit: distance to god level

**Batch A deliverable · audited 2026-11-07 · snapshot: 50 shelves / 131 skills / 24 chains / 7 chain groups / 77 skills chained / validators G1–G3 + C1–C4 green**

Method: this audit was computed, not remembered. A ground-truth inventory script
walked every `categories/` JSON and every `chains/` file; a scoring script maps
each shelf family onto OWASP Top 10 2021 and WSTG v4.2 with quarter-step scores,
each justified by named shelves and skills. Numbers below are reproducible
(`scripts/audit_inventory.py`, `scripts/audit_coverage.py`). Where a capability
needs a platform feature this pack cannot fake, it says so instead of inflating
the score — same doctrine the validators enforce.

---

## 1. Where the product actually is

| Layer | State | Evidence |
|---|---|---|
| Skills (single techniques) | **50 shelves, 131 skills**, prefix census: `web/` 85, `redteam/` 19, `infra/` 14, `elite/` 13 | inventory census |
| Proof discipline | **Best-in-class for HTTP**: every skill is falsifiable — vulnerable mock passes all conditions, benign control fails ≥1 (G3, repo's own `run_negative_control`) | `validation_report.txt`: 131 passed |
| Chains (campaign layer) | 24 chains / 7 groups, each step has success+failure pivots, per-chain discovery playbook, fallback graph closed (C1–C4) | `chains_validation_report.txt`: PASS |
| Discovery (meta-methodology) | Per-chain discovery blocks + pack-wide `DISCOVERY_PLAYBOOK.md` (differentials-over-wordlists doctrine, dork boxes, finding→skill→chain growth loop) | landed with chains |
| Executors | **One agent class: HTTP client.** Everything above it is skill knowledge; everything below it is missing | this audit, §3 |
| Domains | Web ~60–65% (§2). AI 0%, network 0%, mobile/iOS 0%, EDR 0%, API ~25% (only GraphQL + access-control reuse) | §2, §5 |

The one-line verdict: **this is a web-exploit knowledge engine with god-tier proof
discipline, carried by a single HTTP executor, with no AI/network/mobile surface
and no operations layer.** That is the gap to god level.

## 2. Honest web completion: ~60–65%

### 2.1 Scorecard (computed)

**OWASP Top 10 2021 — weighted 65.0%**

| Category | Score | Named coverage | Missing for 1.0 |
|---|---|---|---|
| A01 Broken Access Control | 0.90 | access_control(3: IDOR, BFLA, mass assignment), headers/X-Original-URL, path_traversal(4), kubernetes(4) | workflow-level authz breadth |
| A02 Cryptographic Failures | 0.40 | tls_hardening(2, header-level), jwt(2), cookie scope, HttpOnly | cipher/protocol analysis, padding oracle, entropy |
| A03 Injection | 0.90 | 15 injection shelves, 40+ skills (sqli 9, ssti 8, xss, xxe, cmdi, nosql, ldap, xpath, hpp, csv, crlf, upload, deserialization, preauth_rce 3) | mail/IMAP-SMTP injection, XSLT, format string |
| A04 Insecure Design | 0.50 | business_logic(2), race(1), api_abuse(1), oauth state + checkout-abuse-race chain | workflow-abuse breadth (reserve/refund/rounding) |
| A05 Security Misconfiguration | 1.00 | admin_panels(6), devops_infra(6), kubernetes(4), data_stores(3), debug_interfaces, monitoring, cms, cors, csp, secrets_exposure(9) | — |
| A06 Vulnerable & Outdated Components | 0.75 | preauth_rce(3 CVE families), auth/nacos CVE-2021-29442, grafana plugin traversal, thinkphp, spring-gateway SpEL | generic fingerprint→CVE sweep family |
| A07 Identification & Authn Failures | 0.70 | auth(4), jwt(2), type_juggling, nosql operator bypass, oauth state | MFA bypass, reset-flow breadth, lockout/throttle differential |
| A08 Software & Data Integrity | 0.60 | deserialization(3), request_smuggling(2), file_upload(2), prototype_pollution | CI/CD pipeline integrity, signed-update checks, SAML wrapping |
| A09 Logging & Monitoring Failures | **0.00** | nothing | entire class absent — see §4 P2 |
| A10 SSRF | 0.75 | ssrf(5: AWS IMDS×2, Azure, GCP, file://), xxe-to-metadata chain | OOB-blind confirmation (no collaborator) |

**WSTG v4.2 — weighted 60.4%**

| Family | Score | Named coverage / missing |
|---|---|---|
| INFO Information Gathering | 1.00 | deepest family: secrets_exposure(9), info_disclosure(4), monitoring, cms, cloud_storage |
| CFG Configuration & Deployment | 1.00 | full exposed-control-plane sweep, all prove-capable |
| IDNT Identity Management | 0.50 | user enum only; no registration abuse / role-matrix / lockout policy |
| ATHN Authentication | 0.75 | default creds, UA bypass, JWT forgery+kid, magic hash, NoSQL bypass, OAuth state; missing MFA/reset/lockout |
| ATHZ Authorization | 0.75 | BFLA, IDOR object-graph, mass assignment, routing confusion, JWT claims; missing vertical matrix breadth |
| SESS Session Management | 0.50 | HttpOnly, clickjacking, CSRF, cookie scope, token replay; missing fixation/logout/timeout/concurrency/entropy |
| INPV Input Validation | 0.75 | 40+ falsifiable injection skills; missing mail/XSLT/format-string |
| ERRH Error Handling | 0.25 | traceback disclosure only |
| CRYP Cryptography | 0.25 | HSTS + redirect + JWT-alg adjacency; no real crypto analysis |
| BUSL Business Logic | 0.50 | coupon replay, negative qty, token replay, burst + one chain |
| CLNT Client-Side | 0.50 | CSP(2), CORS(3), CSTI reflection, JSONP, open redirect; missing DOM execution (browser agent) |
| APIT API Testing | 0.50 | GraphQL(3), BFLA/IDOR reuse, burst; missing API2/API9/API10 families |

**Headline: the web domain is ~60–65% complete.** Read honestly:

- Against *what a pure-HTTP agent can even test*, the pack is near its ceiling:
  ~75–80% of the HTTP-testable surface has a find+prove skill. The remaining
  HTTP-layer work (A04/A06/A07 breadth, API families, mail/XSLT injections) is
  worth maybe **+10 points** of pure skill-building.
- The other **~25 points are executor work, not skill work**: OOB confirmation,
  DOM execution, race sync, HTTP/2, TLS crypto, raw TCP. No number of new JSON
  files closes those; they need the agents in §3.
- **A09 is a true zero** — and it is the one OWASP class where being "attacker
  platform only" is not an excuse; a red team validates detections.

### 2.2 The 8 families that are find-only today (executor-gated)

| Family | Current proof | Blocked by |
|---|---|---|
| csti | `{{` reflection only | DOM engine (sandbox-escape eval) |
| race_condition | sequential replay proxy | burst executor (last-byte sync) |
| request_smuggling | CL.TE / TE.CL h1 timing | HTTP/2 client (h2 desync class) |
| xxe | in-band + error-based | OOB collaborator (blind XXE) |
| ssrf | metadata + file:// reads | OOB collaborator (blind callback) |
| preauth_rce/log4shell | error-delta probe | OOB collaborator (confirmed callback) |
| tls_hardening | header checks only | TLS client (ciphers, cert chain, padding) |
| websocket | handshake acceptance | frame fuzzer (post-handshake CSWSH abuse) |

## 3. Agents still required (the real answer to "what's missing")

Twelve executor agents close the find-only gap and open the new domains.
Priority: **P0 = blocks the user's stated priority domain or a P0 doctrine hole;
P1 = unlocks a full batch; P2 = unlocks a later batch or polish.**

| # | Agent | Minimum capability | Unlocks (existing skills upgraded) | Unlocks (new domains/batches) | Pri |
|---|---|---|---|---|---|
| 1 | **LLM/AI harness** | transport for chat-completions endpoints, multi-turn state, per-turn scorer hooks, deterministic `llm_mock` fixture for CI | — (whole domain is new) | **Batch B: entire AI red teaming domain** (prompt injection, jailbreak, system-prompt exfil, agentic tool abuse, RAG) | **P0** |
| 2 | **OOB collaborator** | per-test canary hostname + DNS/HTTP callback listener; interaction log queryable by correlation id | xxe, ssrf, log4shell → blind-confirm; also any `ctrl:` hint marked OOB | honest blind RCE/SSRF doctrine; Batch C webhook tests | **P0** |
| 3 | **Burst/race executor** | N parallel connections, last-byte sync, socket-level control | race_condition (replay→true race), business_logic coupon race, checkout-abuse-race chain proof, api_abuse throttle differential | Batch C sensitive-flow abuse | P1 |
| 4 | **DOM/browser engine** | headless Chromium + CDP: eval, event dispatch, storage/postMessage hooks, screenshot | csti (reflection→execution), xss (marker→execution), clickjacking (render PoC) | Batch B output-handling→client-XSS chain; DOM-XSS family | P1 |
| 5 | **HTTP/2 + protocol client** | h2 streams/frames/settings, h2c upgrade, connection pool control | request_smuggling (h1 timing→h2 desync, 0-length CL), websocket frame abuse | edge/smuggling shelf v2 | P1 |
| 6 | **Raw TCP datastore clients** | redis, mongo wire, postgres, memcached, FTP, SMTP minimal protocol speakers | data_stores: HTTP-fronted (ES/Couch/Solr) → TCP-protocol stores | Batch D network shelves | P1 |
| 7 | **Identity/credential agent** | stateful multi-session, token rotation, flow walker (multi-redirect OAuth), lockout-differential | auth/session families (SESS 0.50→0.75, ATHN→0.9), oauth chain depth | Batch C API2 broken-auth matrix | P1 |
| 8 | **Network recon orchestrator** | port/service scan → fingerprint → skill routing table | new A06 sweep family (fingerprint→CVE routing upgrades 0.75→0.90) | Batch D; feeds chains across domains | P1 |
| 9 | **TLS/crypto client** | cipher/protocol enumeration, cert parsing, JA3, padding-oracle harness | tls_hardening (headers→crypto posture), CRYP 0.25→0.75 | jwt key-confusion breadth | P2 |
| 10 | **Mobile kit** | static: apktool/jadx/ipa plist parsing; dynamic: frida hooks | — | Batch E mobile/iOS (MASTG) | P2 |
| 11 | **Detonation sandbox** | isolated env + telemetry capture + control/benign diffing | — | Batch F EDR/defense-evasion (ATT&CK technique validation); also closes A09 honestly | P2 |
| 12 | **Render-diff vision agent** | screenshot + pixel/layout diff | clickjacking PoC quality, defacement checks | polish | P2 |

Platform-level (not agents, but god-level blockers anyway) — see §4.

## 4. God-level blockers, ranked

**P0 — blocks the stated priority (AI red teaming) or a doctrine hole**
1. No LLM harness agent → the #1 requested domain is structurally unreachable. Batch B is designed and waiting (ROADMAP §B).
2. No OOB collaborator → the pack's own honest-coverage doctrine is violated in 3 families (blind XXE/SSRF/Log4Shell stay "find-only" forever without it).
3. Upstream `SkillLibrary` bugs (dedup signature asymmetric: register by name vs load by cwe; `register()` forces uuid4, discarding caller ids) — documented in the installer header, still unfixed upstream. Every future batch pays this tax on merge; a PR should go upstream.

**P1 — blocks full batches**
4. No fingerprint/inventory routing layer (A06 sweep; also the natural feed for chain planning — banner → known-CVE shelf → chain).
5. No evidence/findings export schema: proof lives in condition results today; god level requires a finding record (skill, chain context, request/response evidence, matched conditions, mock-vs-live flag) that leaves the platform.
6. No stateful identity/burst/h2 execution (agents 3/5/7) → 4 of 12 WSTG families stuck at 0.25–0.5.

**P2 — later batches, polish, and honesty items**
7. A09 logging/monitoring family: absent. Honest path is agent 11 (detonation sandbox with benign-vs-malicious telemetry diffing) — detection testing without telemetry feedback would be fake.
8. Regression corpus: benign mock set must grow ≥2× as shelves grow, or G3's falsifiability budget thins per-family.
9. No CI cadence: garak-style scheduled self-validation + re-scan discipline (the pack already has validators; it needs a runner contract).
10. Mobile/iOS/EDR have zero foothold (agents 10/11 prerequisite).

## 5. God-level definition and the current scorecard

God level for an agentic red team platform = all seven pillars ≥4/5 AND at least
four domains covered. Current:

| Pillar | Score | Basis |
|---|---|---|
| Find (recon breadth) | web 4/5, other domains 0/5 | discovery playbook + 20+ recon skills; zero cross-domain |
| Prove (falsifiable, negative controls) | web 5/5 | G1–G3 gates are genuinely ahead of typical open-source packs |
| Chain (campaign composition) | 3/5 | 24 chains landed; no cross-domain chains, no dynamic replanning mid-campaign |
| Discover (meta-methodology) | 3/5 | DISCOVERY_PLAYBOOK is web-only doctrine |
| Execute (executor breadth) | 2/5 | one HTTP agent; 12 gaps in §3 |
| Operate (evidence, dedup, regression, CI) | 1/5 | validators only |
| Cover (domain matrix) | 1/5 | web 60–65%; AI/API/network/mobile/iOS/EDR ≈ 0–25% |

**Overall ≈ 2.9/5.** Trajectory to god level is deliberately sequenced in
`ROADMAP.md`: Batch B (AI) attacks the Cover pillar where the user ranked it
highest; agents 1–2 (P0) unblock it; Batches C–F fill domain matrix rows;
Batch H hardens Operate so proof quality survives the scale-up.

## 6. What this audit commits to next

- Batch B (AI red teaming, 6 shelves / ~30 skills + `ai_agent_hijack` chains) is
  fully specified in `ROADMAP.md` §B with sources, proof strategy, and the
  `llm_mock` extension — no further research needed to start.
- **Batch B delivered 2026-11-07**: 30 skills / 6 shelves / 4 chains, G1–G3 +
  C1–C4 green. Cover pillar 1→2.5 (first non-web domain live); pack now
  56 shelves / 161 skills / 28 chains / 8 groups. WSTG/OWASP web percentages
  in §2 are unchanged (web-only scorecard, computed before the AI batch).
- Every claim in this file is either computed from pack files or attributed to a
  named public source (OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026,
  garak/PyRIT/promptfoo docs, Simon Willison's lethal trifecta, MCP
  tool-poisoning research, OWASP API Top 10 2023, MASTG/MASVS, MITRE ATT&CK).

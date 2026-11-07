# Red-Agentic-teams Skill Catalog — Marketplace Edition

**161 proven skills · 56 category shelves · one folder per vulnerability/methodology.**

Every skill is a single falsifiable HTTP experiment written to the platform's exact
`Skill` schema (`redteam/skills.py`), validated through three gates against the
repo's own machinery (strict `SkillLibrary` load, structural coherence, and
proof-vs-negative-control falsifiability). Payloads are copied from proven public
sources — PayloadsAllTheThings, HackTricks, nuclei-templates, can-i-take-over-xyz,
commix, PortSwigger research — and rewritten into our proof-first DSL.

## Layout

```
skills/
├── categories/access_control/  (3 skills)
├── categories/admin_panels/  (6 skills)
├── categories/ai_agentic_tools/  (7 skills)
├── categories/ai_jailbreak/  (5 skills)
├── categories/ai_output_handling/  (4 skills)
├── categories/ai_prompt_injection/  (6 skills)
├── categories/ai_rag_vector/  (4 skills)
├── categories/ai_system_prompt_exfil/  (4 skills)
├── categories/api_abuse/  (1 skills)
├── categories/auth/  (4 skills)
├── categories/business_logic/  (2 skills)
├── categories/cache/  (3 skills)
├── categories/ci_cd/  (2 skills)
├── categories/cloud_storage/  (1 skills)
├── categories/cms/  (3 skills)
├── categories/command_injection/  (2 skills)
├── categories/cookie/  (1 skills)
├── categories/cors/  (3 skills)
├── categories/crlf/  (1 skills)
├── categories/csp/  (2 skills)
├── categories/csrf/  (1 skills)
├── categories/csti/  (1 skills)
├── categories/csv_injection/  (1 skills)
├── categories/data_stores/  (3 skills)
├── categories/debug_interfaces/  (1 skills)
├── categories/deserialization/  (3 skills)
├── categories/devops_infra/  (6 skills)
├── categories/file_upload/  (2 skills)
├── categories/graphql/  (3 skills)
├── categories/headers/  (1 skills)
├── categories/hpp/  (1 skills)
├── categories/info_disclosure/  (4 skills)
├── categories/jwt/  (2 skills)
├── categories/kubernetes/  (4 skills)
├── categories/ldap_injection/  (1 skills)
├── categories/monitoring/  (2 skills)
├── categories/nosql/  (1 skills)
├── categories/oauth/  (1 skills)
├── categories/open_redirect/  (2 skills)
├── categories/path_traversal/  (4 skills)
├── categories/preauth_rce/  (3 skills)
├── categories/prototype_pollution/  (1 skills)
├── categories/race_condition/  (1 skills)
├── categories/request_smuggling/  (2 skills)
├── categories/secrets_exposure/  (9 skills)
├── categories/session_security/  (2 skills)
├── categories/sqli/  (9 skills)
├── categories/ssrf/  (5 skills)
├── categories/ssti/  (8 skills)
├── categories/subdomain_takeover/  (4 skills)
├── categories/tls_hardening/  (2 skills)
├── categories/type_juggling/  (1 skills)
├── categories/websocket/  (1 skills)
├── categories/xpath/  (1 skills)
├── categories/xss/  (2 skills)
├── categories/xxe/  (2 skills)
├── chains/<group>/          (attack chains + discovery playbooks)
├── install_skill_pack.py   # walks categories/ -> memory_dir/skills.json (idempotent)
├── validate_skill_pack.py  # three gates + G3 mock fixtures (mocks.json)
├── validate_chains.py      # C1-C4 chain gates -> chains_validation_report.txt
├── mocks.json              # vulnerable/benign response sets per skill
├── AUDIT.md                # re-audit: distance to god level, agent gaps, web %
├── ROADMAP.md              # batched expansion (AI red teaming first)
└── AUTHORING.md            # how new skills get made efficiently
```

## Shelf index

| Folder | Methodology | Skills | CWEs |
|---|---|---|---|
| `access_control` | Broken Access Control (IDOR / Mass Assignment) | 3 | CWE-285, CWE-639, CWE-915 |
| `admin_panels` | Exposed Admin & Database Panels | 6 | CWE-1188, CWE-200, CWE-284, CWE-668 |
| `ai_agentic_tools` | AI Agentic Tool Abuse (ASI01-ASI10 · MCP) | 7 | CWE-1427, CWE-269, CWE-345, CWE-348 |
| `ai_jailbreak` | AI Safety-Boundary Bypass (Jailbreaks) | 5 | CWE-1427 |
| `ai_output_handling` | AI Improper Output Handling (LLM05/LLM10) | 4 | CWE-400, CWE-79, CWE-918, CWE-94 |
| `ai_prompt_injection` | AI Prompt Injection (LLM01/ASI01) | 6 | CWE-1427 |
| `ai_rag_vector` | AI RAG & Vector-Store Abuse (LLM08/LLM04) | 4 | CWE-1427, CWE-200, CWE-863 |
| `ai_system_prompt_exfil` | AI System Prompt Leakage & Exfiltration (LLM07/LLM02) | 4 | CWE-200 |
| `api_abuse` | API Abuse & Rate-Limit Gaps | 1 | CWE-770 |
| `auth` | Authentication Flaws (Enumeration / Default Credentials / Bypass) | 4 | CWE-204, CWE-288, CWE-798 |
| `business_logic` | Business Logic Abuse (OWASP A04) | 2 | CWE-840 |
| `cache` | Web Cache Poisoning & Deception | 3 | CWE-441, CWE-444, CWE-640 |
| `ci_cd` | CI/CD (Jenkins) | 2 | CWE-306, CWE-668 |
| `cloud_storage` | Cloud Object-Store Misconfiguration | 1 | CWE-732 |
| `cms` | CMS Surfaces (WordPress) | 3 | CWE-200, CWE-532 |
| `command_injection` | OS Command Injection | 2 | CWE-78 |
| `cookie` | Cookie Layer Defects | 1 | CWE-565 |
| `cors` | CORS Misconfiguration & Same-Origin-Policy Abuse | 3 | CWE-346, CWE-942 |
| `crlf` | CRLF / HTTP Response Header Injection | 1 | CWE-113 |
| `csp` | Content-Security-Policy Posture | 2 | CWE-693 |
| `csrf` | Cross-Site Request Forgery | 1 | CWE-352 |
| `csti` | Client-Side Template Injection | 1 | CWE-1336 |
| `csv_injection` | CSV / Formula Injection | 1 | CWE-1236 |
| `data_stores` | Data Stores & Search Engines | 3 | CWE-200, CWE-306 |
| `debug_interfaces` | Interactive Debug Consoles | 1 | CWE-489 |
| `deserialization` | Insecure Deserialization Probes | 3 | CWE-502 |
| `devops_infra` | DevOps & Service APIs (Docker/HashiCorp/Registry) | 6 | CWE-200, CWE-306, CWE-668 |
| `file_upload` | File Upload Abuse | 2 | CWE-434 |
| `graphql` | GraphQL Abuse | 3 | CWE-200, CWE-770 |
| `headers` | Routing Header Confusion | 1 | CWE-288 |
| `hpp` | HTTP Parameter Pollution | 1 | CWE-235 |
| `info_disclosure` | Diagnostic & Information Disclosure | 4 | CWE-200, CWE-209, CWE-548 |
| `jwt` | JSON Web Token Defects | 2 | CWE-345, CWE-347 |
| `kubernetes` | Kubernetes & Cluster Components | 4 | CWE-284, CWE-306 |
| `ldap_injection` | LDAP Injection | 1 | CWE-90 |
| `monitoring` | Monitoring Endpoints | 2 | CWE-200 |
| `nosql` | NoSQL Injection | 1 | CWE-943 |
| `oauth` | OAuth 2.0 / OIDC Flaws | 1 | CWE-352 |
| `open_redirect` | Open Redirect | 2 | CWE-601 |
| `path_traversal` | Path Traversal & Local File Inclusion | 4 | CWE-22, CWE-98 |
| `preauth_rce` | Pre-Auth RCE (Known CVEs & Gadgets) | 3 | CWE-917, CWE-94 |
| `prototype_pollution` | Prototype Pollution | 1 | CWE-1321 |
| `race_condition` | Race Conditions & Single-Use Enforcement | 1 | CWE-362 |
| `request_smuggling` | HTTP Request Smuggling (Desync) | 2 | CWE-444 |
| `secrets_exposure` | Source, Config & Secret Exposure | 9 | CWE-200, CWE-538, CWE-540 |
| `session_security` | Session & Client-Layer Hardening Gaps | 2 | CWE-1004, CWE-1021 |
| `sqli` | SQL Injection | 9 | CWE-89 |
| `ssrf` | SSRF & Cloud Metadata (IMDS) | 5 | CWE-918 |
| `ssti` | Server-Side Template Injection (SSTI) | 8 | CWE-1336, CWE-94 |
| `subdomain_takeover` | Subdomain Takeover Fingerprints | 4 | CWE-350 |
| `tls_hardening` | Transport-Layer Hardening Gaps | 2 | CWE-319 |
| `type_juggling` | PHP Type Juggling (Magic Hashes) | 1 | CWE-288 |
| `websocket` | WebSocket Security (HTTP-observable layer) | 1 | CWE-1385 |
| `xpath` | XPath Injection | 1 | CWE-643 |
| `xss` | Cross-Site Scripting | 2 | CWE-79 |
| `xxe` | XML External Entity (XXE) | 2 | CWE-611 |

## Attack chains (28 chains · 8 groups)

Chains are multi-skill kill sequences the planner composes: each step names an
installed skill, its purpose, the success pivot and the failure pivot. Every
chain file also carries a **discovery** block — the "other ways to find similar
things" playbook (entry points, recon methods with tooling and signals, class
variants, dorks, pivot hints).

| Group | Mission | Chains | Skills touched |
|---|---|---|---|
| `cloud_takeover` | Blind Read -> Cloud Identity -> Resource Takeover | 3 | 7 |
| `auth_to_admin` | Identity Abuse -> Privilege Escalation -> Admin Plane | 4 | 13 |
| `injection_to_rce` | Injection Proofs -> Code Execution -> OS Layer | 4 | 12 |
| `edge_cache_smuggling` | Front-Edge Abuse: Smuggling -> Poisoning -> Victim-Scale Impact | 3 | 11 |
| `exposure_to_takeover` | Exposed Artifacts -> Secrets -> Infra Takeover | 5 | 22 |
| `api_and_datastores` | API Plane & Data Stores: Schema -> Extraction | 3 | 11 |
| `business_logic_abuse` | Business-Layer Abuse & Cross-Origin Action Suites | 2 | 8 |
| `ai_agent_hijack` | Prompt Injection -> Agent Action -> Exfiltration | 4 | 16 |

Playbooks: `chains/<group>/README.md` · methodology: `DISCOVERY_PLAYBOOK.md`.

## Install

```bash
python3 install_skill_pack.py <memory_dir>            # installs ALL shelves
python3 install_skill_pack.py <memory_dir> --only ssti,ssrf   # selected shelves
python3 install_skill_pack.py <memory_dir> --list     # dry-run listing
```

The installer also exports the attack chains as a single
`<memory_dir>/chains.json` (planner artifact, not Skill objects); `--no-chains`
skips it.

Idempotent: a second run adds 0 (name-level dedup; see installer notes on the two
upstream quirks in `SkillLibrary` dedupe/id handling).

## Validate

```bash
RATEAMS_REPO=/path/to/Red-Agentic-teams python3 validate_skill_pack.py
```

Gates: **G1** schema (repo's strict `Skill(**row)` loader), **G2** structure
(params/placeholders/condition refs/payload naming), **G3** falsifiability (proof
holds on vulnerable mocks; benign control fails ≥1 condition via the repo's own
`run_negative_control`).

## Progressive disclosure map (agent context economy)

- **Level 1 (always loaded):** `name` + `description` (retrieval keywords + `ctrl:` hint) —
  this is what `SkillLibrary.briefing()` puts into `[PROVEN SKILLS]`.
- **Level 2 (on skill fire):** `categories/<folder>/README.md` — technique depth,
  bypass variants, false-positive notes.
- **Level 2.5 (planning):** `chains/<group>/<slug>.json` — multi-step kill sequences
  with per-step success/failure pivots plus the per-chain discovery playbook;
  read when composing campaigns, not during single-skill execution.
- **Level 3 (governance):** this README, `AUTHORING.md`, `DISCOVERY_PLAYBOOK.md`,
  `AUDIT.md` (re-audit: web ~60-65%, 12 executor-agent gaps, P0/P1/P2 blockers),
  `ROADMAP.md` (batched expansion; Batch B = AI red teaming, fully specified),
  `mocks.json`.

Read `AUTHORING.md` before adding a new shelf.

## Honest coverage vs OWASP Top-10 2021 (web-app view)

Computed scorecard (OWASP weighted 65.0%, WSTG v4.2 weighted 60.4%, A09 at 0.00,
8 executor-gated find-only families) with per-category justification lives in
`AUDIT.md` §2 — the table below is the quick view.

| OWASP category | Status | Shelves |
|---|---|---|
| A01 Broken Access Control | **strong** | access_control (IDOR, mass assignment, BFLA), cors, headers, auth, headers-routing |
| A02 Cryptographic Failures | **partial** | jwt, tls_hardening, session_security, cookie |
| A03 Injection | **strong** | sqli (9), ssti (8), xss, xxe, nosql, ldap_injection, xpath, command_injection, csv_injection, deserialization, hpp, csti |
| A04 Insecure Design | **started** | business_logic (negative qty, coupon reuse), race_condition, api_abuse — needs per-app flows |
| A05 Security Misconfiguration | **strong** | info_disclosure, secrets_exposure, admin_panels, cloud_storage, debug_interfaces, csp, monitoring, cms |
| A06 Vulnerable Components | **partial** | preauth_rce (3 CVE families), kubernetes, devops_infra, data_stores — CVE matrix is per-product, widen on demand |
| A07 Identification & Auth Failures | **partial** | auth, type_juggling, jwt, cookie, oauth, csrf |
| A08 Software & Data Integrity | **partial** | deserialization, jwt, subdomain_takeover — SAML wrapping not yet covered |
| A09 Logging & Monitoring Failures | n/a | detection-side, not an exploit-skill class |
| A10 Server-Side Request Forgery | **strong** | ssrf (5: file://, AWS×2, GCP, Azure) |

**Classes needing platform capabilities beyond pure HTTP** (documented, not faked):
out-of-band callback proofs (blind SSRF/XXE OOB — needs a DNS/HTTP collaborator
endpoint), DOM/browser-context findings (DOM XSS, CSTI confirmation — needs a
browser tool), true parallel races (needs a burst executor), TLS cipher analysis
(needs a TLS client tool). Chain recipes live in the dedicated `chains/` tree
(group playbooks + per-chain discovery) — see `DISCOVERY_PLAYBOOK.md` for how
to find candidates for every shelf.

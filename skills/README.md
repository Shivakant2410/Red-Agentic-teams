# Red-Agentic-teams — Skill Catalog

This directory contains the skill catalog for the Red-Agentic-teams platform:
161 skills organised into 56 category shelves, plus 28 multi-step attack chains
across 8 groups. Each skill is a single, self-contained experiment written to
the platform's exact `Skill` schema (`redteam/skills.py`), and each carries the
evidence fixtures required to demonstrate that it fires on a vulnerable target
and stays silent on a correctly configured one.

The catalog is maintained as data rather than code. Skills are JSON documents
installed into the platform's skill library through the platform's own
registration path, so no conversion or adapter layer is involved.

## Requirements

- Python >= 3.10
- A checkout of this repository. The validation tooling imports the platform's
  own `redteam` package and resolves it relative to the checkout, so run the
  commands below from the repository root.

## Layout

```
skills/
├── categories/            56 shelves — one folder per vulnerability class
│   └── <shelf>/           skill JSONs plus a README with class-level depth
├── chains/                8 groups — multi-step chains with discovery playbooks
│   └── <group>/           one JSON per chain plus a group README
├── mocks.json             per-skill vulnerable/benign response fixtures (gate G3)
├── install_skill_pack.py  installs categories/ into a platform memory_dir
├── validate_skill_pack.py skill gates G1–G3
├── validate_chains.py     chain gates C1–C4
├── AUTHORING.md           how new skills and shelves are authored
├── RESEARCH.md            source research behind the catalog
├── DISCOVERY_PLAYBOOK.md  how candidates are enumerated for every shelf
├── AUDIT.md               computed coverage scorecard and gap analysis
└── ROADMAP.md             expansion plan, sequenced by batch
```

## Shelf index

| Folder | Coverage area | Skills | CWE references |
|---|---|---|---|
| `access_control` | Access control (IDOR, mass assignment, function-level) | 3 | CWE-285, CWE-639, CWE-915 |
| `admin_panels` | Exposed administrative and database panels | 6 | CWE-1188, CWE-200, CWE-284, CWE-668 |
| `ai_agentic_tools` | AI agent tooling and MCP surfaces (ASI01–ASI10, LLM06) | 7 | CWE-1427, CWE-269, CWE-345, CWE-348 |
| `ai_jailbreak` | AI safety-boundary bypass | 5 | CWE-1427 |
| `ai_output_handling` | AI output handling (LLM05, LLM10) | 4 | CWE-400, CWE-79, CWE-918, CWE-94 |
| `ai_prompt_injection` | AI prompt injection (LLM01, ASI01) | 6 | CWE-1427 |
| `ai_rag_vector` | AI retrieval and vector-store weaknesses (LLM08, LLM04) | 4 | CWE-1427, CWE-200, CWE-863 |
| `ai_system_prompt_exfil` | AI system-prompt leakage (LLM07, LLM02) | 4 | CWE-200 |
| `api_abuse` | API throttling and consumption limits | 1 | CWE-770 |
| `auth` | Authentication flaws (enumeration, default credentials, bypass) | 4 | CWE-204, CWE-288, CWE-798 |
| `business_logic` | Business-logic enforcement (OWASP A04) | 2 | CWE-840 |
| `cache` | Web cache poisoning and deception | 3 | CWE-441, CWE-444, CWE-640 |
| `ci_cd` | CI/CD surfaces (Jenkins) | 2 | CWE-306, CWE-668 |
| `cloud_storage` | Cloud object-store misconfiguration | 1 | CWE-732 |
| `cms` | CMS surfaces (WordPress) | 3 | CWE-200, CWE-532 |
| `command_injection` | OS command injection | 2 | CWE-78 |
| `cookie` | Cookie attribute scope | 1 | CWE-565 |
| `cors` | Cross-origin resource sharing misconfiguration | 3 | CWE-346, CWE-942 |
| `crlf` | Response-header injection | 1 | CWE-113 |
| `csp` | Content-Security-Policy posture | 2 | CWE-693 |
| `csrf` | Cross-site request forgery | 1 | CWE-352 |
| `csti` | Client-side template injection | 1 | CWE-1336 |
| `csv_injection` | CSV formula injection | 1 | CWE-1236 |
| `data_stores` | Data stores and search engines | 3 | CWE-200, CWE-306 |
| `debug_interfaces` | Interactive debug consoles | 1 | CWE-489 |
| `deserialization` | Insecure deserialization | 3 | CWE-502 |
| `devops_infra` | DevOps and service APIs (Docker, HashiCorp, registries) | 6 | CWE-200, CWE-306, CWE-668 |
| `file_upload` | File upload handling | 2 | CWE-434 |
| `graphql` | GraphQL API weaknesses | 3 | CWE-200, CWE-770 |
| `headers` | Routing header confusion | 1 | CWE-288 |
| `hpp` | HTTP parameter pollution | 1 | CWE-235 |
| `info_disclosure` | Diagnostic and information disclosure | 4 | CWE-200, CWE-209, CWE-548 |
| `jwt` | JSON Web Token defects | 2 | CWE-345, CWE-347 |
| `kubernetes` | Kubernetes and cluster components | 4 | CWE-284, CWE-306 |
| `ldap_injection` | LDAP injection | 1 | CWE-90 |
| `monitoring` | Monitoring endpoints | 2 | CWE-200 |
| `nosql` | NoSQL injection | 1 | CWE-943 |
| `oauth` | OAuth 2.0 / OIDC flows | 1 | CWE-352 |
| `open_redirect` | Open redirects | 2 | CWE-601 |
| `path_traversal` | Path traversal and local file inclusion | 4 | CWE-22, CWE-98 |
| `preauth_rce` | Pre-authentication RCE via known CVEs | 3 | CWE-917, CWE-94 |
| `prototype_pollution` | Prototype pollution | 1 | CWE-1321 |
| `race_condition` | Race conditions and single-use enforcement | 1 | CWE-362 |
| `request_smuggling` | HTTP request smuggling (desync) | 2 | CWE-444 |
| `secrets_exposure` | Source, configuration and secret exposure | 9 | CWE-200, CWE-538, CWE-540 |
| `session_security` | Session and client-layer hardening gaps | 2 | CWE-1004, CWE-1021 |
| `sqli` | SQL injection | 9 | CWE-89 |
| `ssrf` | Server-side request forgery and cloud metadata | 5 | CWE-918 |
| `ssti` | Server-side template injection | 8 | CWE-1336, CWE-94 |
| `subdomain_takeover` | Subdomain takeover fingerprints | 4 | CWE-350 |
| `tls_hardening` | Transport-layer hardening gaps | 2 | CWE-319 |
| `type_juggling` | PHP type juggling | 1 | CWE-288 |
| `websocket` | WebSocket security (HTTP-observable layer) | 1 | CWE-1385 |
| `xpath` | XPath injection | 1 | CWE-643 |
| `xss` | Cross-site scripting | 2 | CWE-79 |
| `xxe` | XML external entity | 2 | CWE-611 |

## Attack chains

Chains compose individual skills into multi-step operations. Each chain file
records its steps with per-step success and failure pivots, and carries a
discovery playbook covering entry points, reconnaissance methods with tooling
and signals, class variants, and pivot hints. Payload detail is intentionally
kept out of this README; it lives in the chain and skill definitions and in the
per-group READMEs.

| Group | Chains | Skills referenced |
|---|---|---|
| `ai_agent_hijack` | 4 | 16 |
| `api_and_datastores` | 3 | 11 |
| `auth_to_admin` | 4 | 13 |
| `business_logic_abuse` | 2 | 8 |
| `cloud_takeover` | 3 | 7 |
| `edge_cache_smuggling` | 3 | 11 |
| `exposure_to_takeover` | 5 | 22 |
| `injection_to_rce` | 4 | 12 |

Methodology for the discovery playbooks: `DISCOVERY_PLAYBOOK.md`.

## Installation

From the repository root:

```bash
python3 skills/install_skill_pack.py <memory_dir>                  # all shelves
python3 skills/install_skill_pack.py <memory_dir> --only=ssti,ssrf  # selected shelves
python3 skills/install_skill_pack.py --list                        # inventory only
```

A full run writes `<memory_dir>/skills.json` and exports the chain tree as
`<memory_dir>/chains.json`:

```
skills.json: 0 existing -> 161 added, 0 already known, 161 total (catalog: 161 skills / 56 shelves)
chains.json: 28 attack chains exported (planner artifact; groups: ai_agent_hijack, api_and_datastores, …)
```

The installer is idempotent. A second run adds nothing:

```
skills.json: 161 existing -> 0 added, 161 already known, 161 total
```

Use `--no-chains` to skip the chain export, and `--list` to print the catalog
without installing.

## Validation

Two self-checks ship with the catalog. Both resolve the platform package from
the checkout automatically:

```bash
python3 skills/validate_skill_pack.py   # skill gates G1–G3
python3 skills/validate_chains.py       # chain gates C1–C4
```

- **G1 — schema.** Every skill loads through the platform's strict `Skill(**row)`
  constructor; a missing, extra or mistyped field fails the load.
- **G2 — structure.** Request parameters, condition references and placeholder
  substitution must be internally consistent, and each skill's primary request
  is named so the negative-control hook can address it.
- **G3 — falsifiability.** Every skill must satisfy its conditions against the
  vulnerable fixture set in `mocks.json`, and the platform's own
  `run_negative_control` must confirm that the corresponding benign fixture set
  fails at least one condition. A skill that cannot distinguish vulnerable from
  correctly configured behaviour is rejected.
- **C1–C4 — chains.** Schema and unique slugs, step references against
  installed skills, discovery-playbook completeness, and fallback-graph
  integrity.

Expected output:

```
catalog: 161 skills across 56 shelves
ALL GATES PASS — schema exact · structure coherent · proofs hold · benign controls falsify-proof

chains validated: 28 files, 28 slugs, 8 groups, 93 distinct skills referenced
RESULT: PASS — all chain gates (C1-C4) clean
```

## Platform integration

The installer writes the exact on-disk format the platform reads at run time:
`redteam/run.py` constructs `SkillLibrary(<memory_dir>/skills.json)`, so an
installed catalog is immediately usable without any import step. Skill names
and descriptions surface through `SkillLibrary.briefing()`; the per-shelf
`README.md` files carry the class-level operational detail and are intended to
be read on demand rather than held in working context. `chains.json` is a
planner artifact consumed when composing campaigns, not during single-skill
execution.

## Documentation map

- `AUTHORING.md` — authoring workflow and gate requirements for new skills.
- `RESEARCH.md` — the public sources each shelf was derived from.
- `DISCOVERY_PLAYBOOK.md` — how candidates are enumerated per shelf.
- `AUDIT.md` — computed coverage scorecard and the current gap analysis.
- `ROADMAP.md` — the batched expansion plan.

Read `AUTHORING.md` before adding a new shelf.

## Coverage posture

Coverage is measured rather than asserted. `AUDIT.md` §2 contains a computed
scorecard against the OWASP Top 10 (web application view) and the WSTG v4.2
families, with per-category justification, and an explicit list of finding
classes that require platform capabilities beyond plain HTTP — out-of-band
confirmation, browser-context execution, controlled parallelism, and
protocol-level clients. Those classes are recorded as gaps rather than
approximated, and `ROADMAP.md` sequences the work that closes them.

## Provenance

Technique classes are adapted from mature public sources and rewritten into the
platform's schema and proof format: PayloadsAllTheThings, HackTricks,
nuclei-templates, can-i-take-over-xyz, commix, and PortSwigger research for the
web shelves; the OWASP GenAI LLM Top 10 (2025), the OWASP Agentic Top 10
(2026), NVIDIA garak, microsoft PyRIT, promptfoo, and published MCP security
research for the AI shelves. Individual shelf READMEs cite the applicable
source material. Concrete payloads and proof fixtures are not reproduced in
this document; they live in the skill definitions and in `mocks.json`.

## Intended use

This catalog supports authorised security assessment and defensive validation
of systems you own or are explicitly engaged to test. Use it within the bounds
of applicable law, your rules of engagement, and the target's written consent.

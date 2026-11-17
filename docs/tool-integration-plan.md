# Tool integration plan — the capability ladder

Status: planning document for the tooling phases after C1. Complements the ROADMAP
(R1–R4 are evaluation/platform phases; this document is the *attack-capability*
ladder that feeds them) and ADR-001 (the collective-intelligence loop the tools
feed into). Sequencing decision, per operator direction: **web first, basic →
advanced, then red teaming.** Nothing in here replaces the verification pipeline;
everything in here feeds it.

## 0. The no-toy rule

A tool row in this document is not "done" when a wrapper exists. An integration is
done when ALL of the following ship together:

1. **Wrapper** — fixed-allowlist command builder (`shlex.quote`, numeric caps), no
   free-form agent-supplied arguments, single deterministic invocation.
2. **Parser** — JSON/JSONL → typed lead dicts, junk-tolerant, hard lead cap,
   golden-file unit tests against recorded/representative output fixtures.
3. **Guards** — `ctx.scope.check()` before anything leaves the host; risk-class
   approval mapping (§2); budget/rate caps wired to `RateLimiter`.
4. **Leads-only discipline** — output is `lead` + `verify_hint`, never a finding,
   never objective credit. The only writer to `FindingStore.promote()` stays
   `verify_finding_independently`.
5. **Provenance** — every lead carries `origin: agent|target`, source tool name,
   raw artifact reference (traffic record / file), and audit event.
6. **OPSEC cost tag** — a per-tool noise annotation (§3) so the B3 belief filter
   and the B4 OPSEC harness can measure each tool's detection cost empirically.
7. **Lab target** — an offline, deterministic lab target exercising the technique
   (`lab/` extension or a compose service), so CI never needs the internet.
8. **Failure shape** — degradation to `research.error`/audit record on missing
   binary, timeout, or parse failure. A tool never fails a run.

If any of the eight is missing, the tool stays unregistered. This is what separates
an orchestration platform from a shell alias.

## 1. What already exists (do not rebuild)

The Kali image ships `kali-linux-headless` (nmap, ffuf, sqlmap, nikto, gobuster,
impacket, ... are **on disk**). The gap is orchestration, not installation:
`kali_exec` exposes raw shell with none of the contract above. Existing structured
tools: `http_probe`, `surface_scan`, `spa_recon`, `nuclei_scan`, `jwt_inspect`,
`authenticate`/`set_session`, `verify_vulnerability`, `verify_workflow_abuse`,
`verify_finding_independently`, postex trio, browser tools, `search_peer_traces`.

## 2. Risk classes → approval mapping

Every tool declares ONE class. The class is enforced in the wrapper, not left to
the model's judgment.

| Class | Meaning | Examples | Gate |
|---|---|---|---|
| 0 | Passive / read-only against in-scope | parsers, jwt analysis, graph queries | auto |
| 1 | Active but conventional enum, rate-capped | ffuf, katana, arjun, httpx, nxc enum, kerbrute | auto + rate/budget caps |
| 2 | Credentialed operations, could lock accounts | password spray, kerberoast, cloud cred use | operator approval |
| 3 | Mutating / evidence-creating on target | canary ACE change, certificate request, sqlmap data-touching flags | per-action approval + canary discipline |
| 4 | Network-position or service-degrading | Responder/mitm6 poisoning, DoS anything | **excluded — not registered as agent tools** |

## 3. OPSEC cost tags

Each tool carries `noise: none|low|medium|high` plus the telemetry it generates
(e.g. ffuf: "burst of 404s from one IP"; kerbrute: "Kerberos user_enum failures";
nxc enum: "SMB session setups per host"). The B3 scheduler reads the tag to
throttle; the B4 harness validates the tag against the simulated defender, and
live-fire results update it. A tag that was never measured is marked `unmeasured`
— tags may be optimistic, measurements may not.

## 4. Kill-chain tool matrix — specific tools, recon → postex

Operator direction: name the actual tools per phase, not categories. `OWN` = the
platform's first-party tool (exists or ships in this plan); `R1`/`W2`/`W3` = planned
in this document; runs-in tells you where the binary lives (sandbox = the Kali
container under the egress firewall; host = the operator's machine; operator =
third-party source, delivered by hand — the sandbox cannot and should not reach it).

| Phase | Specific tools | Runs in | Class | First-party integration |
|---|---|---|---|---|
| **Recon** (passive) | crt.sh CT logs, wayback via gau/waymore, passive DNS (amass passive), leak-corpus lookups (dehashed/HIBP via operator) | operator | 0 | exports → `importers/assets.py` INTERSECTION; `http_probe`/`surface_scan` on what survives |
| **Surface** | `surface_scan` (OWN), httpx (`-tech-detect`), naabu, `spa_recon` (OWN, ARTEX port) | sandbox | 1 | inventory + knowledge graph; spa runtime surface |
| **Enum / discovery** | katana (`-fs rdn`), ffuf, feroxbuster, arjun, swagger/openapi hunting via `http_probe` (OWN), gau (in-scope historical only), kerbrute, nxc `--shares`/ldap enum, ldapdomaindump, GitDorker + gitleaks (client-supplied repos) | sandbox | 1 | `content_discovery`/`crawl`/`param_discovery` (OWN, W1 ✓); AD wrappers R1 |
| **Vuln detection (leads)** | nuclei (OWN), `jwt_inspect` (OWN), Certipy `find`, nxc coerce/zerosafety modules (check-only), smuggler, graphw00f, dalfox (candidate XSS), semgrep (client code, operator import) | sandbox | 0–1 | every match = lead + verify_hint; nothing records; every lead second-methoded via `crosscheck_lead` (§5b) |
| **Exploitation (gated)** | the verify pipeline (OWN): `verify_vulnerability`, `verify_workflow_abuse`, `verify_finding_independently`; sqlmap (fixed flags), jwt_tool, ysoserial/phpggc (proof payloads only), Certipy `auth` (canary SAN), impacket psexec/wmiexec (post-approval), evil-winrm (held creds) | sandbox | 2–3 | proofs only ever written by `verify_finding_independently`; canary objects mandatory |
| **Credential access** | impacket `GetUserSPNs` (kerberoast), `GetNPUsers` (AS-REP), `secretsdump` (class 3), lsassy via nxc module (class 3), hashcat + john (host, offline), `set_session` for operator tokens, Responder/mitm6 (**class 4 — excluded, never an agent tool**) | sandbox + host | 2–3 | secrets redactor masks at capture; cracking NEVER in-sandbox |
| **Post-exploitation** | `extract_secrets`/`prove_privilege` (OWN), the creditor (OWN), BloodHound CE + Cypher pathfinding (R2), chisel/ligolo-ng tunneling (operator infra), `record_access` + kill chain (OWN) | sandbox + compose | 2–3 | canary discipline; access graph is the state of record |
| **Lateral movement** | nxc sweeps (auth-only modules), impacket PTH, RDP/WinRM with held creds, AzureHound + GraphRunner (Entra) | sandbox | 2 | per-batch approval; every hop proven via creditor before credit |
| **Reporting** | `report.py`, `retest.py` (OWN), deterministic PoC bundles, B4 detection appendix | host | 0 | retest bundle = the remediation contract |

## 5. The techniques layer — agents look it up, they don't search

`redteam/tools/playbooks.py` + `data/playbooks/*.yaml` (ships **in the repo**,
offline by construction): first-party technique playbooks indexed by kill-chain
phase, surface, and tech tags. `find_techniques(kill_chain, surface, query)` returns
the FULL body: concrete steps naming the platform's tools, a `verify_hint` that
feeds the proof pipeline, the playbook's risk class, prerequisites, and an honest
`detection_risk` tag (default `unmeasured` until B4 measures it). When nothing
matches, it returns the corpus index and an explicit "design your own probe via
verify_vulnerability; do not search the web from the sandbox" — the egress firewall
would refuse third-party sources anyway, and the playbook says who fetches what
(`data_source: operator`).

Layered with what exists, the research stack is now:

1. `find_techniques` — how do I attack this CLASS of thing? (first-party, offline ✓)
2. `find_attack_templates` — what's known about this exact PRODUCT? (cloned nuclei corpus)
3. `apply_skill` — what already worked HERE? (earned skills, promoted only on proof)
4. the swarm forum — what did my siblings just learn? (C1)

Corpus discipline: `load_playbooks()` doubles as the CI linter (schema, ids,
kill-chain/surface enums, ≥80-char technique bodies, tool names valid). A playbook
stub can never ship. Proven approaches graduate: playbook → verified on target →
earned skill — the corpus stays curated, the skill DB stays earned.

### 5b. Cross-verification — never believe a tool's direct output (`tools/crosscheck.py`)

Operator rule, made operational: **a tool's direct output is never believed on its
own.** `crosscheck_lead(tool, claim, url/param/host/port, marker)` re-derives any
lead by a *structurally different* second method — sandbox-binary claims (ffuf,
katana, arjun, nuclei, httpx, nmap) get first-party checks (plain HTTP through the
shared fetch path, a WITH/without param differential, a raw TCP socket); first-party
inspector claims (xss_reflect_probe) get FRESH inputs (a marker the probe never
generated). Verdicts: `corroborated` (still a lead — it has earned proof budget, not
confidence), `contradicted` (drop it), `unverifiable` (no cheap second method or thin
inputs — never believed by default; the proof pipeline decides). The trust matrix is
introspectable (`python -m redteam.tools.crosscheck --matrix`), unknown `(tool,
claim)` pairs fail closed, exempt classes are documented rather than silent
(`surface_scan` = RoE ground truth; `jwt_inspect` = offline deterministic parse), and
nothing here touches the finding pipeline — promotion still runs the full ladder
(`docs/tool-inventory.md`, "The trust ladder").

---

## Track W — Web, basic → advanced

### W1 — Discovery & surface (ships with this document's first slice)

| Tool | Binary | Class | Notes |
|---|---|---|---|
| `content_discovery` | ffuf (`-json`) | 1 | Wordlist from a fixed in-image allowlist (`/usr/share/seclists/...`); auto-calibrate on; leads = new URLs → ENDPOINT graph. **Implemented in `tools/webdiscover.py`.** |
| `crawl` | katana (`-jsonl -fs rdn`) | 1 | JS-aware crawl, domain-field-scoped so it cannot wander off-target; endpoints + methods + status into the graph. **Implemented.** |
| `param_discovery` | arjun (`-oJ`) | 1 | Hidden-parameter candidates; feeds verify hints (authz-matrix and reflection checks). **Implemented.** |
| `host_probe` | httpx (projectdiscovery) | 1 | Title/status/tech JSON per live host; complements `surface_scan` (which knocks on allowed ports) with content-level probes of found HTTP services. **Implemented in `tools/hostprobe.py` — folds ENDPOINT + TECHNOLOGY nodes.** |
| `port_scan` | nmap (`-oX -`) | 1 | Structured parse of what Kali already has; `surface_scan` stays the RoE-driven inventory, this is the agent-directed deep probe of ONE allowed host (`-sV --version-light -T3`, top-ports or an RoE-validated explicit list — fail closed like scope.check). **Implemented in `tools/hostprobe.py` — folds HOST + SERVICE nodes, web-ish services get an ENDPOINT stub.** |

Exit criteria W1: three+ tools live with full contract, graph-visible surface
growth on the lab target, B4 noise measurement recorded for each.

### W2 — Vulnerability classes as deterministic checklists (the `jwt_inspect` pattern)

THE SMART WIRING that makes this track more than a checklist pile — the
**inspect → spec → prove chain**: a W2 inspector does not stop at "might be
vulnerable"; it answers the question a prover needs (WHERE did the marker land,
did the specials survive) and, when the sink is live, emits the exact
`requests`+`conditions` payload `verify_vulnerability` consumes 1:1 — k-of-n
reproducibility and the negative-control discipline come free from the existing
pipeline. Discovery output IS the proof input; the agent forwards, it does not
redesign. Tests pin this semantically: the generated spec must PASS through
`proof.eval_condition` against a live-sink response and FAIL against an
entity-encoded one.

| Tool | Class | Notes |
|---|---|---|
| `oauth_inspect` | 0–1 | Deterministic OAuth/OIDC checklist: state, PKCE, redirect_uri validation, token storage, implicit-flow use. Leads + verify hints. |
| `graphql_inspect` | 1 | graphw00f fingerprint + introspection probe + clairvoyance-style schema reconstruction lead. Pairs with R2.4's GraphQL check types. **Implemented in `tools/webinspect.py` (first-party HTTP, exactly 4 benign requests: introspection POST, query-over-GET, field-suggestion oracle, JSON-array batching; every check reports BOTH outcomes with a verify_hint naming the next first-party move).** |
| `smuggle_probe` | 1 | HTTP request-smuggling detection probes (CL.TE/TE.CL variants with benign timing control); leads only, exploitation stays in verify. |
| `header_inject_check` | 1 | Host-header injection, CRLF, cache-deception candidates — deterministic request variants via the existing proxy. |
| `xss_reflect_probe` | 1 | Reflection mapping (parameter → sink context) so the verifier designs context-correct proofs; **no** payload blasting. **Implemented in `tools/webinspect.py` (unique benign marker per call; <=2 requests per param, <=5 params; context = html_body/attribute/tag_name/js/json/response_header; `specials_survive` leads carry a READY check_spec for verify_vulnerability; escaped reflections are documented so proof budget is not wasted).** |
| `ssti_probe` | 1 | Benign math-marker template injection candidates per parameter; verify pipeline confirms with the standard k-of-n. |
| `sqli_exploit` | 2 | sqlmap wrapper, **fixed flags** (`--batch --level<=2 --risk<=1 --threads=1`), one vector at a time, per-action approval; boolean/time-based only; results are leads. |

Exit criteria W2: each checklist ships with its lab app variant (see §6), and its
verify_hint chains into an existing or new `check_type` (R2.4 list: CSRF
double-submit, race, cache poisoning, GraphQL authz).

### W3 — Advanced web

| Tool | Class | Notes |
|---|---|---|
| `oob_watch` | 0 + 2 | Self-hosted **interactsh** collaborator (compose service, never the public oast.fun): registers OOB domains, polls callbacks; a callback is *evidence with provenance* (target→our OOB server) and feeds blind-SSRF/RCE verifications. |
| `jwt_forge` | 3 | jwt_tool-style proof forging (alg confusion, kid path) — used ONLY inside verify to demonstrate impact; operator approval. |
| `deser_poc` | 3 | ysoserial/phpggc payload generation as *proof material* for a verify step; never fired outside a gated verification. |
| `ws_probe` | 1 | WebSocket/SSE handshake + message-frame recording through the proxy; cross-site WebSocket hijacking leads. |
| DOM observation | 0 | Playwright sink instrumentation (postMessage handlers, `eval`/`innerHTML` reachability from URL params) — extends the existing browser tools, no new binary. |

Exit criteria W3: OOB evidence accepted by the verification pipeline end-to-end in
CI (compose: app + interactsh server), DOM observations produce graph edges.

---

## Track R — Red teaming (identity → graph → cloud → C2)

### R1 — Identity primitives (AD/local)

| Tool | Binary | Class | Notes |
|---|---|---|---|
| `kerbrute_enum` | kerbrute | 1 | Quiet user enumeration; B4 measures it. |
| `kerberoast` | impacket GetUserSPNs | 2 | Service-ticket requests for accounts with SPNs; hash material handled like the secrets redactor (mask both directions). |
| `asreproast` | impacket GetNPUsers | 2 | Same handling as kerberoast. |
| `nxc_sweep` | netexec | 1–2 | Protocol enum (SMB/LDAP/WinRM/MSSQL/SSH) = class 1; credentialed checks/spray = class 2 per-action. JSON where supported, else fixed-format parsers. NetExec is the maintained CrackMapExec successor (CME archived 12/2023). |
| `adcs_inspect` | certipy | 0–1 | Deterministic ESC1–ESC17 misconfig enumeration; the `jwt_inspect` of certificates. Pure-Python, JSON out. |
| `secrets_dump` | impacket secretsdump | 3 | Operator-approved postex; output redacted at capture; canary discipline. |

Lab: Samba AD DC container seeded with a deterministic domain (users/groups/SPNs/
delegations/ADCS template misconfigs) — CI-runnable, no Windows licensing.

### R2 — Attack-path graph (the BloodHound lesson)

**Design principle:** paths are first-class objects, and every edge of a proposed
path becomes a *hypothesis* in the C1 registry — pathfinding proposes, the proof
pipeline disposes. Edge hypotheses are verified safely (e.g. "GenericAll over
Domain Admins" → canary-object test, never a real DA change).

| Component | Class | Notes |
|---|---|---|
| `ad_collect` | 1 | bloodhound-ce-python collector in-sandbox → ZIP artifact with provenance. |
| BloodHound CE service | 0 | docker compose profile (`--profile ad`): app + postgres + neo4j; ingest via API; never co-tenant with the target network. |
| `ad_paths_from` | 0 | Cypher tool: shortest path(s) from an owned node; returns JSON paths; each edge → hypothesis with `proposed_test`. |
| `ad_path_critic` | 0 | Cross-examines a path against the registry: already-refuted edges, stale leases, unverified preconditions — feeds the forum as a challenge. |
| AzureHound | 1 | Same pattern for Entra ID when R3 lands. |

Exit criteria R2: on the seeded lab domain, `ad_paths_from` proposes ≥3 paths,
≥1 survives edge-by-edge verification, and refuted edges demonstrably suppress
their branches on replay (C1 journal proves it).

### R3 — Cloud identity & posture

| Tool | Binary | Class | Notes |
|---|---|---|---|
| `cloud_enum` | cloudfox | 1 | Read-only AWS situational awareness; JSON out; ideal agent default. |
| `aws_privesc_scan` | pacu (module) | 2 | IAM enum/privesc-vector scan; credential use operator-approved; no CloudTrail tampering (class 4). |
| `cloud_posture` | scoutsuite/prowler | 1 | Read-only multi-cloud misconfig audit → leads. |
| `entra_walk` | graphrunner ideas | 2 | Entra ID postex enumeration via Graph API with owned tokens; apps/consent/service-principal leads. |

Lab: **LocalStack** for AWS (offline CI), recorded-fixture mode for Entra.

### R4 — Kubernetes & C2 (optional, last)

- `k8s_paths` — KubeHound against a kind cluster profile; same path→hypothesis
  loop as R2. Only if K8s engagements become a demand signal.
- C2 realism (Sliver adapter) — every interaction class-3 gated, B4-scored; the
  C2-less postex path (access graph + creditor) remains the default and the
  differentiator. Build only when a live engagement requires beacons.

---

## 6. Lab & test strategy (offline-first, per the no-toy rule)

1. **Fixtures**: every parser gets golden files from recorded real output
   (happy + junk + adversarial shapes) — no network in unit tests, ever.
2. **Web labs**: extend `lab/` per W2/W3 technique (reflected params, SSTI,
   GraphQL, smuggling-pair, OOB-capable app). Each lab module doubles as a
   benchmark scenario and a verify-pipeline regression.
3. **AD lab**: Samba AD DC + deterministic seed script (badblood-style but
   deterministic — fixed seed, fixed object set) for R1/R2.
4. **Cloud lab**: LocalStack profile for R3.
5. **Compose profiles**: `--profile ad`, `--profile oob`, `--profile cloud` keep
   the default `docker compose up` unchanged.

## 7. Sequencing & exit gates

W1 (done) → W1b (httpx/nmap slices) → W2 → W3 → R1 → R2 → R3 → R4.
A phase starts only when the previous phase's exit criteria are met and measured.
Every phase lands as its own stacked branch/PR with the full suite green and the
B4 OPSEC harness extended to score the new tools' tags.

## 8. Non-goals (unchanged)

Public-target mode; model-decided scope; findings from tool output; class-4 tools
as agent tools; autonomous exploit deployment without approval; benchmark-chasing
on saturated suites. The verification pipeline remains the only path to "confirmed";
tools make the pipeline's to-do list longer and smarter, nothing more.

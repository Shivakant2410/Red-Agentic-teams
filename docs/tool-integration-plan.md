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

---

## Track W — Web, basic → advanced

### W1 — Discovery & surface (ships with this document's first slice)

| Tool | Binary | Class | Notes |
|---|---|---|---|
| `content_discovery` | ffuf (`-json`) | 1 | Wordlist from a fixed in-image allowlist (`/usr/share/seclists/...`); auto-calibrate on; leads = new URLs → ENDPOINT graph. **Implemented in `tools/webdiscover.py`.** |
| `crawl` | katana (`-jsonl -fs rdn`) | 1 | JS-aware crawl, domain-field-scoped so it cannot wander off-target; endpoints + methods + status into the graph. **Implemented.** |
| `param_discovery` | arjun (`-oJ`) | 1 | Hidden-parameter candidates; feeds verify hints (authz-matrix and reflection checks). **Implemented.** |
| `host_probe` | httpx (projectdiscovery) | 1 | Title/status/tech JSON per live host; complements `surface_scan` (which knocks on allowed ports) with content-level probes of found HTTP services. Next slice. |
| `port_scan` | nmap (`-oX/-oJ`) | 1 | Structured parse of what Kali already has; `surface_scan` stays the RoE-driven inventory, this is the agent-directed deep probe of ONE allowed host. Next slice. |

Exit criteria W1: three+ tools live with full contract, graph-visible surface
growth on the lab target, B4 noise measurement recorded for each.

### W2 — Vulnerability classes as deterministic checklists (the `jwt_inspect` pattern)

| Tool | Class | Notes |
|---|---|---|
| `oauth_inspect` | 0–1 | Deterministic OAuth/OIDC checklist: state, PKCE, redirect_uri validation, token storage, implicit-flow use. Leads + verify hints. |
| `graphql_inspect` | 1 | graphw00f fingerprint + introspection probe + clairvoyance-style schema reconstruction lead. Pairs with R2.4's GraphQL check types. |
| `smuggle_probe` | 1 | HTTP request-smuggling detection probes (CL.TE/TE.CL variants with benign timing control); leads only, exploitation stays in verify. |
| `header_inject_check` | 1 | Host-header injection, CRLF, cache-deception candidates — deterministic request variants via the existing proxy. |
| `xss_reflect_probe` | 1 | Reflection mapping (parameter → sink context) so the verifier designs context-correct proofs; **no** payload blasting. |
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

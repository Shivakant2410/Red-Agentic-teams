# Operator tooling research — what top red teamers actually carry (2025–2026)

Companion to `docs/tool-integration-plan.md` (the capability ladder) and
`docs/hands-and-skills.md` (the agent hands). This is the "keep researching"
track: named, in-use operator tooling per kill-chain stage, each mapped to
(a) what our first-party surface already covers, and (b) which FUTURE hand it
would become. Nothing here is installed by this phase — per the ladder's rule,
a tool enters when a phase consumes its output, and every binary claim obeys
the trust matrix (crosscheck) regardless of origin.

Sources: Bishop Fox's 2025 red team tools survey (bishopfox.com/blog/
2025-red-team-tools-c2-frameworks-active-directory-network-exploitation),
ProjectDiscovery's published toolchain, and the 2025–2026 operator literature.
Cited tool names are as-published; our mapping is ours.

## 1. The external/web recon chain — WE ALREADY REIMPLEMENT IT FIRST-PARTY

The canonical operator chain is ProjectDiscovery's:
`subfinder → httpx → naabu → katana → nuclei` (+ `dnsx`, `interactsh`), with
`ffuf` for content discovery and `arjun` for hidden parameters.

| Operator tool | Our first-party hand | Trust class | Second method (crosscheck) |
|---|---|---|---|
| ffuf | `content_discovery` | lead-crosschecked | first-party GET (`http_get`) |
| katana | `crawl` | lead-crosschecked | first-party GET |
| httpx | `host_probe` | lead-crosschecked | first-party GET |
| nmap | `port_scan` | lead-crosschecked | raw TCP connect |
| arjun | `param_discovery` | lead-crosschecked | WITH/WITHOUT differential |
| SPA bundle walk | `spa_recon` | lead-crosschecked | GET / 405 probe |
| nuclei | `nuclei_scan` | lead-crosschecked | marker re-fetch (`http_marker`) |

The lesson we operationalized: operators don't trust these tools either — they
re-verify hits in the browser/proxy before reporting. Our crosscheck layer is
that discipline, made mechanical.

## 2. Identity / Active Directory — the tier our web-first ladder defers (Tier 1→2)

Bishop Fox's 2025 AD/network set, verbatim: **SharpHound, BloodHound.py,
NetExec (ex-CrackMapExec), Certipy, Impacket, msldap, GhostPack, Octopwn**.

- **NetExec** — the credential-spray/enum swiss knife (SMB/WinRM/LDAP/MSSQL).
  Maps to our `try_credential` hand (bounded, RoE-minimal) and `prove_privilege`
  semantics. Future hand: `netexec_enum` under the ACCESS specialist, with the
  same "SMALL burst, then stop" obligation.
- **Certipy** — AD CS enumeration/abuse (ESC1–ESC8). No web-surface analog;
  a future identity-tier phase would need a `adcs_enum` hand + technique cards
  before any agent may hold it (technique + proof condition first — the same
  order specialists.py documents for new OWASP classes).
- **SharpHound / BloodHound.py** — graph collectors feeding **BloodHound**.
  Our knowledge graph is the same shape (nodes/edges the reasoning reads); a
  future `graph_collect` hand would feed OUR graph, not a foreign one.
- **Impacket / GhostPack** — protocol suites and C# post-ex; sandbox-tier
  (Tier 5, deferred) rather than agent hands.

## 3. Post-exploitation / credential access — Tier 5 (deferred, named for completeness)

**lsassy, DonPAPI, nanodump, pypykatz, mimikatz, HandleKatz** (LSASS reading
family), plus **LaZagne** for Lazy credentials. These are the ACCESS
specialist's real-world cousins of `extract_secrets` — but they require
footholds our black-box web scope doesn't produce yet. Deferred, not forgotten;
the ladder's Tier 5 notes apply.

## 4. C2 / infrastructure — out of agent scope, in architecture scope

2025 C2 set: **Sliver, Mythic, Cobalt Strike, Nighthawk, PoshC2, Merlin,
Empire** (+ Havoc in community use). Infrastructure pattern: redirectors,
domain fronting, HTTPS certs between implant and teamserver. For THIS project
the relevant takeaway is architectural, not operational: our orchestrator's
worker model (claim → work → verify, telemetry identity per worker) is the
same separation Mythic gives operators between payload, agent, and operator
UI — we already have the shape, minus the implant layer, which the RoE for a
web-app agentic pentest doesn't need.

## 5. Cloud — Tier 3, mapped but deferred

Operator set: **Pacu** (AWS exploitation), **ScoutSuite** (multi-cloud
audit-as-attack-surface), **CloudFox** (cloud enum), **ROADtools/AzureHound**
(Azure). Maps to future `cloud_enum` hands under a cloud specialist; the
proof discipline would be identical (cloud API responses are first-party
observations; tool verdicts are leads).

## 6. AI red teaming — the adjacent discipline (batch-b direction)

**Garak** (LLM vulnerability scanner), **PyRIT** (Microsoft's AI red-teaming
framework), **Promptfoo** (test-case/eval harness). Relevant because THIS
repo is an agentic red team: when the target is an LLM app, these become the
Tier-4 web-toolset analog. Our probe/proof/trust architecture is designed to
host them: an `llm_probe` hand would be lead-crosschecked like any other
(first-party conversation = the observation; scanner verdicts = leads).

## 7. What this research CHANGES in our plan

1. **Nothing gets installed for its own sake.** Every tool above enters the
   ladder only when a phase consumes its output type (the D0 rule).
2. **The identity tier (NetExec/Certipy/BloodHound-ingest class) is the
   highest-value NEXT capability surface** — it maps onto hands our agents
   already have semantics for (`try_credential`, `prove_privilege`,
   `record_access`) and onto the ACCESS specialist's existing skills.
3. **Binary outputs are leads, always.** Whatever the tool's pedigree
   (Cobalt Strike or a Python script), the trust matrix is the gate: a claim
   without a registered second method fails closed.
4. **Hands before tools.** The E1 lesson generalizes: a new tool without a
   Hand (purpose/cost/trust/obligation) bound to a named agent is shelfware.
   The ladder's next entries should be drafted as Hand+Skill+Technique-card
   triples, not as installs.

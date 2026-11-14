# Agentic security assessment: competitor notes

Research checked on 2026-09-26. This is a product/architecture comparison from
public project documentation, not a security audit of the projects. Statements
about product behavior are vendor/repository claims; risks and gaps below are
our analysis, not confirmed vulnerabilities.

## Projects reviewed

| Project | What its public documentation says | Useful pattern to adopt | Tradeoffs or gaps to validate |
|---|---|---|---|
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | Its README describes staged CTF/pentest workflows, saved sessions, Claude Code/Codex backends, and a legacy interactive multi-provider mode. It advertises target-based CLI usage and Docker flows. | Stage work, persist/resume sessions, and keep provider integration behind an interface. | The README's general target CLI is broader than our desired local-first scope. Its current architecture document says both model roles use full access and relies on deployment isolation rather than a second tool/filesystem sandbox. That increases the consequences of an isolation mistake. |
| [KeygraphHQ/PentestGPT](https://github.com/KeygraphHQ/PentestGPT) | Its README describes white-box web/API testing: static/source analysis followed by dynamic validation; claims only findings with a working PoC are reported. Lite is described as local/AGPL-3.0, while Pro adds a commercial integrated AppSec platform. | Correlate static evidence with dynamic confirmation, and attach reproducible evidence to reports. | Its documented Lite scope is source-available web applications and several named vulnerability classes; that is narrower than general black-box red teaming. Actual exploitation also raises impact and authorization risks; claims are vendor-authored and need independent validation. |
| [lordx64/pentestkit](https://github.com/lordx64/pentestkit) | Its README describes a Claude Agent SDK orchestrator, specialist agents, a shared knowledge base, proof-oriented reports, scope-guarded egress, and claims 104/104 on XBOW. | Centralize egress/scope checks, share structured evidence, and keep a proof requirement for findings. | The 104/104 result is not a useful model discriminator now: the official [XBOW benchmark README](https://github.com/xbow-engineering/validation-benchmarks) calls the suite outdated and saturated as of mid-2026. More agents and a persistent shared knowledge base also add cost, coordination, and stale-context risks. The README's performance result remains a project claim. |

## Product direction for this project

Adopt **phase boundaries, durable evidence, and a centralized policy chokepoint**.
Do not copy unrestricted tool execution, automatically following redirects,
or a broad public-target mode. The initial posture workflow makes only fixed
GET requests to a confirmed loopback fixture. The API authorization slice adds
a separate capability limited to a fixed 2x2 matrix of seeded principals and
synthetic records; it cannot target arbitrary APIs or mutate data. Neither
workflow follows redirects, executes a general shell, or transmits response
bodies to a model.

The eventual differentiation to test with design partners:

- measurable, reproducible evidence and safety behavior rather than one
  saturated benchmark score;
- explicit authorization/scope before each run, with deterministic enforcement
  independent of the model;
- useful local deployment and provider choice without making unsupported
  availability or detection claims;
- phase-level cost and quality measurements, with qualified models only.
- a narrow local-first object-level authorization check with reproducible
  evidence, to be validated against a larger held-out API benchmark before
  positioning it as product differentiation.

## Benchmark implications

Use the XBOW project only as a local harness smoke test or historical
comparison, not as the main model leaderboard. It is a CTF-style set of 104
challenges, not a representative measure of false positives, scope compliance,
report quality, or safe behavior. Build held-out, permissioned tasks with
known outcomes and refusal cases. Never run intentionally vulnerable
challenges on a public network.

## Sources

- GreyDGL PentestGPT README and architecture: repository links above
  (`README.md` and `docs/architecture.md`, accessed 2026-09-26).
- Keygraph PentestGPT README: repository link above (accessed 2026-09-26).
- pentestkit README: repository link above (accessed 2026-09-26).
- XBOW benchmark README: repository link above (accessed 2026-09-26).

---

## 2026-09-30 — Architecture pivot recorded (supersedes the constraints above)

This document was written as the design charter for `src/agentic_setup/`: a read-only,
loopback-only assessor whose governing principle was *"the model is a selector, never an
actuator."* The project has since deliberately pivoted to `redteam/`, an authorized red team
agent. The pivot is intentional, and this note exists so the charter is not read as current
policy.

**What the charter forbade that `redteam/` now does, on purpose:**

| Charter constraint | Current reality in `redteam/` |
|---|---|
| "Do not copy unrestricted tool execution" | `kali_exec` gives the model a general shell, and `run_exploit` executes model-authored Python |
| "Neither workflow … transmits response bodies to a model" | Response bodies are returned to the model as evidence (now capped at 256 KB) |
| Loopback-only targets | Targets are whatever the signed Rules of Engagement authorize |
| Findings are `severity: info`; "no exploit actions ran" | Findings are exploited and proven; severity is real |

**The charter's criticism now partly applies to us.** It faulted GreyDGL for relying "on
deployment isolation rather than a second tool/filesystem sandbox" — and `redteam/` does rely on
container isolation (egress firewall, non-root, dropped capabilities, resource limits) rather than
a second sandbox. That is an accepted trade, not an oversight.

**What carried over, because it was right:** deterministic enforcement independent of the model
(`redteam/scope.py`, the egress firewall), durable evidence for every claim (`redteam/verify.py`,
`redteam/falsify.py`, the hash-chained audit log), bounded capabilities (response caps, call
budgets, audited denials), and free-model cost control — now enforced server-side with
`provider.max_price = 0` rather than client-side filtering alone.

**What the charter demanded and we still owe:** *"held-out, permissioned tasks with known outcomes
**and refusal cases**."* `redteam/bench` has no refusal cases and no safe-fixture negative control,
so its false-positive number is not yet trustworthy. The paired `lab/` profiles
(`LAB_AUTHZ_PROFILE=safe|broken-owner-check`) exist precisely to fix this and are the next
validation gate.

---

## AI red teaming vendors: teardown that shaped `redteam/llmred/`

Research checked 2026-11-05. Same honesty rule as above: everything in the
"what their documentation says" column is a VENDOR claim, not an independently
verified measurement. The prior sections of this document covered web-pentest
competitors (PentestGPT line, pentestkit); this section covers the LLM
red-teaming category, because llmred (`redteam/llmred/`) was designed against
it.

### What the market looks like

Eleven providers were compared in Pillar Security's buyer's guide (Sept 2026),
which applies the OWASP GenAI Security Project's *Vendor Evaluation Criteria
for AI Red Teaming Providers and Tooling* (January 2026: 13 dimensions, six
green flags, six red flags). The open-source trio evaluated alongside them is
Microsoft PyRIT, NVIDIA garak, and promptfoo. Condensed:

| Vendor | What its documentation says | Pattern llmred took | Pattern llmred rejected |
|---|---|---|---|
| Pillar Red Graph Suite | Attacks through the application's real interface; renders an agent/tool/data graph; ships video + action-log evidence; claims ASRs are version-controlled per release with stable/new/hardened/regressed labels; findings flow into its own runtime guardrails | **Version-aware posture labels** (regression.py) and **proof-of-execution evidence** (hash-addressed transcripts) | Attacking via app UI/browser — llmred targets LLM endpoints; app flows stay in `redteam/` |
| Lakera Red (Check Point) | Targets/Scans/Results architecture; stateless (OpenAI-compatible) or stateful (session-id) targets; 23 default objectives across security/safety/responsible; risk score = share of harmful evals; Gandalf-fed intel corpus; 100+ languages | **Stateful session targets** (SessionTarget, configurable session header) | Risk-as-a-single-number (a bare rate with no interval is exactly what stats.py exists to prevent) |
| Microsoft PyRIT (+ Foundry agent) | Seeds/scenarios/attack-techniques/converters/targets/scorers; branching must happen on scorer results, never raw responses; "undetermined" is a first-class outcome; their own docs admit agentic categories are single-turn, English-only, mock tools | **Scorer discipline** (detectors.py: branch on verdicts; UNDETERMINED ≠ false) and the **skip-loudly** rule | Making the judge an oracle — ours may only UPGRADE undetermined (W8 judge-miscalibration discipline from the paper) |
| promptfoo | Plugins (objectives) × strategies (transforms + multi-turn) matrix; `layer` composition; CI/CD integration; regression `retry` strategy; default config recommends agentic jailbreak strategies; docs still cite the 2025 OWASP numbering | **Objective × strategy matrix**, **layer composition**, **CI gate exit codes** (regression.gate_exit_code, `--gate`) | Flat "n tests per plugin" grids — the budget goes where Thompson sampling says it pays |
| Palo Alto Prisma AIRS (Protect AI) | Attack library refreshed bi-weekly from Unit 42 + huntr (claimed 500+ vectors/50+ techniques); three scan types; OWASP/ATLAS/NIST/DASF mapping; connectors to OpenAI/Bedrock/REST/Copilot Studio | **Multiple scan types** maps to our strategies spread (static / adaptive) | License-credit pricing and US-region traffic inspection — n/a, we are local-first |
| Zscaler AI Red Teaming (SplxAI) | 12-framework compliance reporting; no-code connectors; multi-shot/delayed multi-turn; **automated system-prompt hardening** with diffs; policy generation for runtime guards; docs cite the 2025 OWASP edition | **Multi-shot escalation ladder** (multishot) and framework-mapped reporting (we cite 2026 numbering) | Guardrail-policy generation — out of scope; findings are data, consumers decide |
| HiddenLayer | AutoRT red teaming as one module of a model/supply-chain platform; model-file scanning; "OWASP-aligned" without itemized mapping | Nothing direct — confirms red teaming is a platform feature, not a standalone moat | Bundling posture; llmred stays a focused module |
| Noma | "Red team is itself an agent, adapting attacks to the application"; production SSO testing; posture findings trigger tests; findings → runtime signatures | The **adaptive attack loop** (pair-lite behind the AttackLLM port) | Posture-triggered coupling — our campaigns are explicit, authorized runs |
| Straiker Ascend | 24/7 paired attack/defense agents; claims 1,700+ exploits, 36% of coding-agent attacks → RCE (vendor figures, no released methodology) | Nothing direct | Continuous-always testing — our runs are budgeted, rate-limited, audited |
| Mindgard | Lancaster spin-out; attacker-style reconnaissance; CI/CD + Burp deployment; 150+ disclosed vulns | Reconnaissance-before-attacking maps to our deterministic recon philosophy | Managed-service remediation loop |
| Dreadnode | Open SDK + platform; 45+ strategies, 450+ transforms across 38 modules, 130+ scorers; auto-tagging to OWASP/ASI/ATLAS/NIST/SAIF; publishes benchmarks and a scope study of 4,897 agent tool calls | **Auto-tagged framework mapping** (objectives carry OWASP codes; report rolls up by class) | Their breadth (450+ transforms) — we ship 8 transforms + 4 turn flows, chosen by evidence |
| Synack (Sara + SRT) | Autonomous red agent + 1,500 human researchers, FedRAMP | Nothing direct | Managed human layer |

Open-source cross-check: garak (probes/detectors/generators/buffs) and PyRIT
confirm the same decomposition llmred uses — targets, transformations,
scorers, orchestration as independent pieces. promptfoo's strategy catalog
(base64/rot13/leetspeak/homoglyph encodings, crescendo-style escalation,
math/encoding jailbreaks) is the closest public analog to our
`strategies.py`, and PyRIT's orchestrator layer is the analog of
`campaign.py`.

### The differentiators llmred ships that NO vendor documents

1. **Bandit-allocated probe budgets.** Every vendor runs the objective ×
   strategy grid (or sells managed scans). llmred allocates each attempt with
   the Thompson-sampling bandit from `bandit.py`, priced at real turn cost —
   leaks found per request, with cross-campaign persistence
   (`llmred_bandit.json`). This is the paper's sec. 7.8 ("the statistical
   layer is ahead of the evaluation layer") turned into code.
2. **Honest intervals on every rate.** ASRs ship with Wilson 95% intervals
   (`stats.wilson_ci`); UNDETERMINED and errors are reported buckets, never
   laundered (PyRIT's `success_rate_decided` convention). Lakera's
   "risk score" and vendor ASR claims have no intervals anywhere in their
   public documentation.
3. **Fail-closed attribution at the module level.** No campaign starts without
   `authorized_by` + `ticket` + an explicit host allowlist re-checked before
   every HTTP call — because the sandbox egress firewall that protects
   `redteam/` cannot see an HTTPS chat endpoint.

### Acceptance checklist we took from the OWASP vendor criteria

Distilled from the buyer's guide's seven questions; each maps to a shipped
mechanism:

| Question | Our answer |
|---|---|
| Where does it attack from? | The configured LLM endpoint (stateless or session-bound) — not just a model CLI |
| Multi-turn and stateful? | plant-then-ask, cross-session, multishot, pair-lite; stateful targets get session ids |
| Data-exposure tests specifically? | Planted-canary secret-echo (same-session and cross-session) with encoding-aware detection |
| Continuous and version-aware? | summary.json → diff_summaries → stable/new/hardened/regressed; `--gate` fails CI on regression |
| Evidence with findings? | Full bounded transcript per attempt, sha256-addressed in campaign.jsonl and the hash-chained audit log |
| Which frameworks, which version? | OWASP LLM Top 10 **2026** numbering on every objective; rollup in the report |
| Closes into runtime? | Deliberately not in-module; findings are JSON + report for the consumer (documented non-goal) |

### Sources (accessed 2026-11-05)

- Pillar Security, "Best AI Red Teaming Providers for Enterprise AI Agents and
  GenAI Apps (2026): A Buyer's Comparison" — pillar.security/blog (the 11-vendor
  table, OWASP criteria distillation, Lakera/Noma/Straiker/Dreadnode details).
- promptfoo docs: LLM red teaming overview, Red Team Plugins, Red team
  Configuration, OWASP LLM Top 10 mapping — promptfoo.dev/docs/red-team*.
- PyRIT framework documentation (architecture: seeds, scenarios, attack
  techniques, executors/attacks, converters, targets, scorers, memory,
  analytics) — microsoft.github.io/PyRIT/latest/code/framework.
- Neural Trust, "10 Best AI Red Teaming Platforms (2026)" — Lakera Red
  (Check Point), SPLX (Zscaler), HiddenLayer AutoRT details —
  neuraltrust.ai/blog/best-ai-red-teaming-platforms.
- Giskard, "Mindgard alternatives for AI red teaming (2026)" — Mindgard
  capabilities and gaps — giskard.ai/knowledge/mindgard-alternatives-ai-red-teaming.

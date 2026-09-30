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

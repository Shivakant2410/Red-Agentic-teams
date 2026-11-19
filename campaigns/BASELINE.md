# Builder 04 — Phase 0 baseline: architecture, gaps, model configuration, campaign matrix

- **Base commit:** `052c83d8dda4c9ab9d8d047069bf5c6dab9e6c93` (`main`, = merge of PR #24
  `builder-04/unified-llm-mission-selection`, which added unified LLM selection, Ollama
  preflight, run-scoped credentials and mission lifecycle correctness).
- **CI status on that commit:** the repo declares one workflow (`.github/workflows/ci.yml`,
  "tests": push + pull_request, `pip install -e ".[dev]"`, `python -m pytest -q`). At the
  time of writing the repo has **zero recorded workflow runs** (`/actions/runs` returns an
  empty list), so CI has never produced a result to cite. The local test suite is therefore
  the verification authority for this work; every campaign report records the exact pytest
  command and counts instead.
- **Real model in use:** GLM-4.6 served through a local OpenAI-compatible bridge
  (`scripts/zai_bridge.js`, bun + `z-ai-web-dev-sdk`) on `http://127.0.0.1:9825/v1`.
  Platform preflight at `052c83d` reports 4/4 PASS against the bridge: `reachable`,
  `model_found`, `tool_call_ok` (synthetic `report_preflight_ok` call), `args_parsed`.
  The bridge implements the tool-call contract at the prompt layer (the SDK chat API does
  not expose OpenAI `tools` natively) and parses replies back into `message.tool_calls`.

## 1. Confirmed execution paths (traced at `052c83d`)

### Classic: `execute_run()` → Orchestrator / RedTeamAgent
`execute_run(opts)` (`redteam/run.py:275`) assembles, in order: engagement load
(`config.py:206`), control-plane overlap check (`scope.py:191`), `AuditLog`/`AuditBridge`,
`FindingStore` (`findings.py:77`), `RateLimiter`, `ScopeGuard` (`scope.py:70`; frozen to
`out/scope.json`, `run.py:316`), `KnowledgeGraph` (`run.py:331`), cross-run `BanditStore`,
EPSS/KEV priors, `AttackTree` (`run.py:353`), `AccessGraph` + `KillChain` (`run.py:365`),
`TrafficRecorder`/`AssetInventory`, `build_llm_client` (`gateway.py:203`; unconfigured →
honest `UnconfiguredClient`), deterministic recon (`recon/__init__.py:11`), `EvidenceProxy`
(`proxy.py:762`), optional `KaliSandbox` with default-DROP egress + canary
(`sandbox/docker_kali.py:149,231`), `ToolContext` + `build_registry` (~30 tools,
`tools/__init__.py:69`), `BudgetTracker` + `RunManifest`. Driver fork at `run.py:530`:
`multi_agent=True` → `Orchestrator.run` (`orchestrator.py:1383`: recon profile → up to 12
exploit swarm rounds with `run_verify_pass` after each → access loop → LLM strategist
reflection → gated LOGIC round → creditor sweep); else single-agent `RedTeamAgent.run`
(`agent.py:190`, per-turn state briefing, stall detection). Shared finalization
(`run.py:615-738`): verify pass (single-agent mode), memory credit/reflect, report.md/html,
objective.json, `run.finish`.

### Mission: `execute_run()` → MissionSpecialistExecutor → mission driver
`run.py:536-593` builds the mission Orchestrator with `terminal_manifest_writes=False`
(a specialist cannot flip run status), wraps it in `MissionSpecialistExecutor`
(`mission/specialist_executor.py:45`; diffs FindingStore+audit before/after each task), and
starts `run_mission_driver` (`mission/driver.py:126`) with the mission-scoped hypothesis
bundle and access gate. The driver (`driver.py:212-388`) creates one bounded RECON task,
then per round: objective/budget checks → VERIFY task when pending findings exist →
ACCESS task from access state → ONE ranked node from
`Orchestrator.mission_attack_frontier` (`orchestrator.py:1532`, which re-ranks
`AttackTree.actionable()`) → LOGIC fallback → `frontier_exhausted` stop. Claiming is the
scheduler "claim trio" (`mission/scheduler.py:126`): journaled CAS `reserve_task`
(`commander.py:177`) + `AttackTree.claim` (`attack_tree.py:443`) +
`hypotheses.claim_or_register` (duplicate suppression, `swarm/__init__.py:122`), then
fenced `mark_running` → executor → fenced completion; `abort_claim` rolls back.

### Tool dispatch, scope, egress
LLM tool calls go through `RedTeamAgent._dispatch` (`agent.py:443`): unknown tool →
corrective error + `agent.unknown_tool`; exceptions → `tool.exception` audit, loop
survives. Scope authority is `ScopeGuard.check` (`scope.py:123-155`): fail-closed — window
→ scheme → port → exclusions → host allowlist → every resolved IP; private/loopback only
with `allow_private_ranges`. Denials are audited (`tool.denied` in the shared HTTP path
`tools/http.py:111`, per-tool `.blocked` events) and mirrored into `traffic.jsonl`.
Sandbox egress: `build_egress_plan` (`sandbox/egress.py:32`) → default-DROP OUTPUT +
canary in `KaliSandbox` (requires Docker).

### Selection, hypotheses, state, verification
- **AttackTree** owns selection: `actionable()` ranks by technique priority + chain boost
  + bandit Thompson sample + strategist boosts (`attack_tree.py:383-411`); ownership via
  claim/lease; `sync()` completes nodes **only** on independent confirmation and unlocks
  chained techniques (`attack_tree.py:265-380`).
- **Hypotheses**: `HypothesisRegistry` (`swarm/hypotheses.py:253`), PROPOSED→ACTIVE→
  AWAITING_VERIFICATION→CONFIRMED/REFUTED, identity-keyed duplicate suppression, evidence
  and counter-evidence attachment (`orchestrator.py:1230`, `:1583`).
- **Stores**: KnowledgeGraph (`knowledge.py:236`), AccessGraph (`access.py:91`; holds with
  finding-id provenance, `revoked_nodes()` drives the fail-closed ACCESS gate), KillChain,
  AssetInventory; cross-run BanditStore/SkillLibrary/ExperienceStore.
- **Findings + verification**: `FindingStore.add` dedups; `promote(finding_id, verdict)`
  (`findings.py:154`) is the only path setting `confirmed`/`falsified`. The independent
  verifier `verify_finding_independently` (`tools/independent_verify.py:51`) rebuilds the
  stored `check_spec` (not the finder's narration), re-runs k-of-n trials (`verify.py:46`,
  5 trials / need 4) plus a **mandatory negative control** (`:158-254`); verdicts
  confirmed | falsified | not_reproducible. VERIFY tasks run in a restricted specialist
  context (`orchestrator.py:302`: plan role, one tool) via `run_verify_pass`
  (`orchestrator.py:330`), which also deterministically credits confirmed findings.

### Events / artifacts per run
`events.jsonl`, hash-chained `audit.log.jsonl`, `manifest.json`, `scope.json`,
`graph.json`, `attack_tree.json`, `access.json`, `killchain.json`, `inventory.json`,
`traffic.jsonl`, `findings.json`, `report.md/html`, `objective.json`; missions add
`mission.json`, `mission_journal.jsonl`, `research_journal.jsonl`, `research_forum.jsonl`.

## 2. Model configuration requirements (how a real campaign is configured)

Engagement YAML `llm.providers` block (e.g. `kind: openai_compat`,
`base_url: http://127.0.0.1:9825/v1`, `models_allow: ["glm-4.6"]`, `prefer_free: false`)
→ `LLMGateway` role-routing with rotation and cooldowns; or per-launch `LlmOverride`
(`server.py:149`, `_prepare_llm`: effective engagement without key material +
run-scoped credentials on `RunOptions.llm_credentials`, never persisted/logged).
`require_tool_support` makes discovery reject models that do not advertise tool support.
Preflight (`POST /api/llm/preflight`, `redteam/llm/preflight.py:106`) must pass
(4/4 for the bridge). Budgets: `max_run_seconds`, `max_llm_tokens`, rate limits,
`max_total_requests` — recorded per run in the manifest.

## 3. Known gaps and loop-breakdown risks (verified against source at `052c83d`)

| ID | Gap | Evidence (file:line) | Severity |
| --- | --- | --- | --- |
| G1 | **Self-confirmation bypass**: the specialist-facing `record_finding` tool accepts `confidence: "confirmed"` and stores it verbatim; `credit_confirmed_findings` acts on `confidence == "confirmed"` with no `independent_verdict` check — a model asserting success could credit an objective and inflate "confirmed" counters without independent verification. | `redteam/tools/workflow.py:35,44-48`; `redteam/credit.py:100-102`; contract violated vs `findings.py:155-156` | High (evidence-integrity) |
| G2 | **Mission replanning is static-list shaped**: `seen_nodes` permanently excludes a failed `(technique,target)` from re-attempt within a mission — new evidence (fresh endpoints, new access holds, refuted preconditions) never re-opens a failed path; classic mode has per-round `retry_failed` (`attack_tree.py:357`), the mission driver does not (the `TASK_REARMED` event type exists in `mission/events.py` but the driver never emits it). | `redteam/mission/driver.py:191,289-291,342` | High (replanning) |
| G3 | **Recon-failure dead-ends the mission**: exploit/access/logic tasks are only created after the recon task succeeds (`driver.py:259-264`); a failed recon yields no frontier work and the mission ends without retry. | `redteam/mission/driver.py:259-333` | Medium |
| G4 | **Specialist instructions may under-deliver evidence**: task instruction is a concise per-node brief (`orchestrator.py:829`); how much discovered endpoint/parameter/identity/response evidence reaches the specialist is measured in Phase 2 campaigns before any change. | `redteam/orchestrator.py:829-851` | To measure |
| G5 | **Single-agent verification is deferred** to one post-run pass (`run.py:615-629`); budget exhaustion mid-pass leaves findings `pending_verification` while the manifest still reports `completed`. Mission mode creates VERIFY tasks per round (correct shape). | `redteam/run.py:615-629` | Medium |
| G6 | **Chaining depends on the CWE→technique map** in `AttackTree.sync` (`attack_tree.py:265-305`); whether the campaign chain's prerequisites (e.g. file-read → admin takeover) unlock correctly is measured in Phase 2. | `redteam/attack_tree.py:265-380` | To measure |
| G7 | **Mission semantics**: post-PR-#24 behavior already distinguishes task success vs objective achievement vs unresolved verification (`mission/driver.py:93-123`); Phase 2 verifies on live runs. | `redteam/mission/driver.py:93-123` | To verify |
| G8 | **Research errors degrade silently**: hypothesis registration failure → unresearched execution, duplicate suppression lost for that claim (`scheduler.py:193-198`). | `redteam/mission/scheduler.py:193-198` | Low |
| G9 | Pre-existing parallel subsystems (`redteam/brain/`, `redteam/llmred/`, `redteam/offensive.py`, `src/agentic_setup/`) are NOT wired into the campaign paths above; they are left untouched (no-broad-refactor constraint; they are not used to fake autonomy). | — | Note |

## 4. Campaign test matrix (scenarios for the Phase 1 lab)

One deterministic, resettable lab app (`lab/campaign_lab.py`, localhost-only) hosts five
scenario families on distinct route groups; ground truth lives in the lab's fixed seed and
is checked by an independent scorer (never by the agent's own claims).

| ID | Route group | Vulnerability class (CWE) | Ground truth that must be demonstrated | Loop property exercised |
| --- | --- | --- | --- | --- |
| S-INJ | `/api/orders` search | SQL injection, SQLite (CWE-89) | Differential response proves injection; injection retrieves a stored `backup_code` value the UI never exposes; verifier differential reproduces k-of-n with negative control | Observe→hypothesize→execute→verify on a classic web vuln |
| S-AUTHZ | `/api/notes`, sessions | Broken authorization / IDOR (CWE-639) | bob's session retrieves alice's private note body; unauthenticated control denied; verifier differential confirms cross-principal read | Authenticated cross-account testing |
| S-BIZ | `/api/checkout` | Business-logic / workflow abuse (CWE-840 family) | Coupon `LAUNCH-25` applied twice in one order (per-user limit bypass) → order total drops below the legal floor; verifier re-runs the flow with fresh identifiers | Workflow state-transition abuse |
| S-CHAIN | `/api/files`, `/api/admin` | Path traversal → credential exposure → authz bypass chain (CWE-22 → CWE-284) | Step 1 traversal reads `/etc/campaign-lab/admin_token` content; step 2 token resets admin password; step 3 admin endpoint returns the objective flag. Chained access must be attempted only after step 1 evidence exists | Multi-step chain with demonstrated prerequisite access |
| S-REPLAN | `/api/admin/login`, `/api/profiles` | Forced-browsing dead end vs evidence-revealed reset path (CWE-640) | `/api/admin/login` cannot be brute-forced (fixed high-entropy password, deterministic); profile endpoint leaks a reset question answer; answering it enables password reset → admin login. Campaign must abandon the failed path after evidence and switch | Failed-path replanning driven by new evidence |

Driver × scenario coverage (Phase 2): each scenario runs under the **mission** driver;
S-INJ and S-AUTHZ additionally run under the **classic** driver for the comparison
report. Out-of-scope destinations (`example.com:80`, `127.0.0.1:9999`) are probed during
campaigns and MUST produce audited denials (`tool.denied`), never traffic. Egress proofs
are repeated with the same ScopeGuard stack outside the agent (control probes).

Success definition per the brief: task completion ≠ objective achievement; only the
independent verifier (k-of-n + negative control) can produce a confirmed finding; pending
findings are never reported as confirmed; stop reasons and budgets are reported per run.

## 5. Baseline campaign (pre-repair measurement)

Before any implementation change, at least one real-model mission (GLM-4.6 via the bridge)
runs against the existing `lab/tinyvault.py` IDOR lab to measure the current loop
end-to-end (discovery, hypotheses, task transitions, verification, stop reason). Its
measured weaknesses join G1-G9 as Phase 3 repair inputs.

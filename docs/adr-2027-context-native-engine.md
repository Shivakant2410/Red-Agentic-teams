# ADR-2027: Context-native browser and offensive reasoning engine

- **Status:** Proposed
- **Date:** 2026-11-25
- **Branch:** `feat/2027-context-native-engine-rfc`
- **Scope:** Architecture for the next evolution of the existing web + agentic red-team engine

## Decision

Evolve the current observe → hypothesize → prioritize → execute → verify loop into a **continuous, evidence-backed world-model loop**. The browser becomes a semantic application instrument; the reasoning engine maintains a typed model of actors, business objects, workflow transitions, services, and trust boundaries; the planner proposes counterfactuals against that model and updates its beliefs from deterministic evidence.

This is an additive evolution of the current architecture, not a replacement framework:

- `BrowserController` remains the Playwright boundary and the only browser execution surface.
- `KnowledgeGraph` remains the canonical graph; typed world-model records are graph node kinds/relations, not a second graph.
- `ObservationLog` and RECON V2 `EvidenceStore` remain the provenance and evidence planes.
- `AttackThesis` remains the human-auditable hypothesis artifact, extended with references to world-model facts and explicit falsifiers.
- `AttackTree` and `MissionScheduler` remain scheduling authorities. The world model may enrich and rank candidate work, but cannot authorize or widen scope.
- `VerifyFindingIndependentlyTool` remains the only authority that can promote a finding to confirmed.
- The existing `redteam/pi/` engine and `pi_oracle` independent-verification path are reused for web-to-AI cases; no parallel PI verifier is introduced.

## Current baseline (verified against main)

The repository already has more of this foundation than a greenfield design would suggest:

1. `redteam/tools/browser.py` captures bounded request/response and console rings, integrates traffic evidence, enforces ScopeGuard on routed requests, and refreshes live-view screenshots. It still exposes a single active page/context and `browser_content` is a bounded body-text view; click/fill are selector-oriented.
2. `redteam/knowledge.py` is a persistent, thread-safe, provenance-aware graph with typed nodes, relations, lifecycle, canonical identities, and evidence references. It does not yet have first-class business entities, principals/ownership, workflow states/transitions, or architecture layers/boundaries.
3. `redteam/observations.py` and `redteam/recon_v2/` provide evidence provenance, validation, shared observations, assets, and structured handoff.
4. `redteam/thesis.py` already creates falsifiable, scored `AttackThesis` records from an evidence digest. `redteam/synthesis.py` joins observations into evidence-backed ideas. The gap is the absence of a durable typed application model between observations and thesis generation.
5. `redteam/tools/independent_verify.py` supports independent re-derivation, including workflow and `pi_oracle` checks. The PI engine is therefore partially integrated at the verification layer, even though a unified web↔PI planner is not present.
6. `redteam/orchestrator.py` already describes a phased browser/API workflow and a LOGIC specialist. The next step is to make the model it reasons over explicit and incrementally updated.

## Target architecture

```text
Browser / API / PI observations
          |
          v
Evidence plane (traffic, observations, artifacts, provenance)
          |
          v
Typed World Model (inside KnowledgeGraph)
  principals | business entities | ownership
  workflow states/transitions | services | layers
  trust boundaries | temporal validity | confidence
          |
          v
Causal Thesis Engine
  invariant -> counterfactual -> expected behavior
  evidence refs -> kill condition -> confidence update
          |
          v
Constrained Planner / Posture Controller
  semantic browser | differential personas | API/schema
  web↔AI cross-boundary | passive-only / human handoff
          |
          v
Scoped execution -> independent verifier -> belief update
```

### 1. Typed World Model

Extend the existing KnowledgeGraph vocabulary with typed, evidence-backed records:

| Concept | Suggested graph representation | Required facts |
|---|---|---|
| Principal | `principal` | stable run-local identity, role claims, session reference (never raw secret) |
| Business entity | `business_entity` | entity type, opaque test-owned reference, tenant/owner relation |
| Workflow state | `workflow_state` | entity type, state label, observed source |
| Transition | `workflow_transition` | actor, entity, from/to states, triggering action, outcome |
| Service/component | `app_component` | component type, observed host/path, evidence |
| Architecture layer | `architecture_layer` | edge, gateway, authz, service, worker, storage, or unknown |
| Trust boundary | `trust_boundary` | source/destination layer, observed control, evidence |

Every inferred edge must carry evidence references, source, confidence, first/last seen, and freshness. Distinguish **observed**, **inferred**, and **operator-supplied** facts. LLM output alone cannot create a corroborated fact. Model-generated relations remain hypotheses until grounded by independent observations or operator input.

The graph must never store raw cookies, bearer tokens, passwords, private keys, DPoP proofs, or unredacted browser storage. Principal/session references point to the existing secret-safe session store.

### 2. Context-native browser

Keep Playwright's route handler and shared request budget as the enforcement boundary. Add capabilities in layers:

- **Semantic surface:** capture an accessibility snapshot and expose role/name/label-grounded controls. Prefer `get_by_role`, labels, and exact text over generated CSS selectors. Return stable, short-lived element references tied to the current page revision; invalidate them after navigation or DOM mutation.
- **Visual grounding:** optionally emit a screenshot with numbered, visible control annotations and matching element metadata. Vision is a locator aid, never proof of an action's effect. A screenshot is evidence only when linked to its URL, timestamp, page revision, and artifact reference.
- **Runtime metadata observer:** use a bounded, opt-in init script to inventory framework/route metadata and observe network API *metadata* (method, URL, operation name, content type, response class). Allowlist known public framework manifests and route declarations. Redact credential-shaped fields before persistence.
- **No private heap scraping:** do not recursively dump React Fiber internals, Redux/Zustand/Apollo caches, IndexedDB, localStorage, sessionStorage, crypto key material, or arbitrary globals. These are unstable implementation details and may contain secrets or other users' data. A future adapter may inspect a specific store only when the operator explicitly enables it and the data contract is documented.
- **No hidden transport replay:** observe the application's fetch/XHR/WebSocket/EventSource behavior; do not invoke captured closures or re-sign mutated requests inside the app runtime by default. Any replay is a distinct, approval-gated operation using a captured, redacted request template, a named test principal, a fresh test-owned object, a scope re-check, and a negative control.
- **Complete egress accounting:** verify WebSocket and service-worker traffic is covered by the same ScopeGuard and request budget. If a transport cannot be intercepted and accounted for, disable it or require an explicit operator decision; do not silently bypass the proxy.
- **Human-auth flow:** retain the current human-warmed session pattern. Do not automate CAPTCHA/2FA or conceal automation to defeat an interactive challenge.

### 3. Twin-context differential testing

Introduce a run-scoped browser context pool with explicitly configured aliases (for example `anon`, `user_a`, `user_b`, `org_admin`). Each alias maps to an operator-provisioned test identity and isolated browser context.

A workflow capture records a **redacted request template**, semantic action, object ownership reference, state before/after, and evidence refs. A differential test may replay only against a fresh object owned by the configured test principals. It compares semantic outcomes (object identity/owner, state transition, response class, and visible UI state), not status code alone.

Race tests use only dedicated disposable fixtures and bounded concurrency already covered by the engagement limits. Never race real payments, messages, user records, or production business objects. Cross-account tests must never enumerate or access arbitrary third-party identifiers.

### 4. Causal thesis and belief updates

Extend `AttackThesis` additively with:

- `world_model_refs`: graph fact IDs that support the thesis;
- `preconditions`: principal, object, and workflow state required;
- `counterfactual`: one state/ownership/transition assumption being challenged;
- `expected_control`: expected result for a benign or authorized control;
- `observed_outcome_refs`: evidence IDs from execution;
- `belief_status`: proposed, supported, contradicted, stale, or inconclusive.

Generate theses from a compact, evidence-cited world-model projection rather than a flat page-text digest. Prefer counterfactuals such as ownership mismatch, skipped state transition, stale authorization after role change, and async state/time-of-check mismatch. Each thesis must name a falsifier and a safe test fixture. A thesis with no supporting graph facts remains a low-confidence proposal and cannot seed active work.

Belief updates are deterministic folds over evidence and verifier verdicts. A successful task or HTTP 200 is not confirmation. The independent verifier still owns final finding status.

### 5. Web ↔ AI cross-boundary planner

Add a typed `CrossBoundaryCase` joining a browser-observed stored-input surface to a PI test case:

- source field and storage location;
- canary ID and propagation evidence;
- AI consumer / agent boundary;
- observed retrieval or invocation trace;
- tool capability and authorization policy;
- benign control and independent `pi_oracle` evidence.

The first version should run only in local labs or explicitly authorized test tenants, use non-exfiltrating canaries, and require approval before any side-effectful tool invocation. Feed newly discovered API/schema facts back to the World Model as untrusted observations until independently corroborated.

### 6. Context-adaptive posture controller

Choose a posture from observed application context, but treat posture as a **constraint reducer**, never a way to raise permissions or budgets:

- `semantic_browser`: WAF/interactive edge detected; reduce raw HTTP activity and use ordinary, human-paced UI navigation. Do not bypass challenges.
- `schema_differential`: API/GraphQL-heavy surface; favor schema evidence and low-volume differential checks on test-owned objects.
- `cross_boundary_lab`: AI/RAG/MCP surface detected; use canary-only PI tests in an authorized lab/tenant.
- `passive_only`: uncertainty, missing authorization, unsupported transport, or exhausted budget; collect local evidence or stop.

Every posture decision records its signals, selected mode, limits, and reason. It may lower request rate/concurrency but must never exceed the RoE's rate, total-request, time, or approval constraints.

## Implementation sequence

Ship as small, testable vertical slices. Do not attempt the whole architecture in one PR.

### Phase 0 — contract and fixtures
- Add typed World Model schemas and serialization over the existing KnowledgeGraph.
- Add synthetic fixture apps with two test principals, a tenant-owned object, a small workflow, a GraphQL endpoint, and a local mock AI consumer.
- Pin evidence provenance, secret redaction, and stale-state behavior.

### Phase 1 — semantic browser + read-only runtime metadata
- Add accessibility snapshot and semantic locator tools.
- Add screenshot/Set-of-Mark output linked to page revision and evidence refs.
- Add opt-in bounded route/network metadata observer (no heap/store scraping and no request replay).
- Test SPA, shadow DOM, iframe, stale element refs, and scope/budget denial.

### Phase 2 — live business model + causal theses
- Derive principal/entity/state/transition facts from observed forms, API schemas, UI labels, and captured workflows.
- Add evidence-cited world-model projection to thesis generation.
- Add deterministic belief updates and graph-to-thesis traceability.

### Phase 3 — twin-context differential verification
- Add named isolated browser contexts bound to test identities.
- Capture and replay safe request templates only against fresh test-owned fixtures.
- Reuse independent verifier with workflow-specific negative controls; add bounded race tests.

### Phase 4 — web↔PI cross-boundary
- Bridge browser stored-input evidence into the existing PI runner and `pi_oracle` verifier.
- Add local mock AI app and canary-tracked end-to-end tests.
- Keep tool side effects approval-gated.

### Phase 5 — adaptive posture
- Add context signal classifier and posture controller.
- Prove by tests that posture changes cannot expand ScopeGuard, budgets, concurrency, or approval policy.

## Non-goals / explicit exclusions

- No automatic attack against unowned production accounts or objects.
- No extraction of secrets from arbitrary browser memory/storage.
- No CAPTCHA/2FA bypass, stealth escalation, or evasion of bot controls.
- No hidden replay of application closures or client-side signing routines.
- No automatic GraphQL alias amplification, batching floods, or high-volume race bursts.
- No model-only promotion of observations, hypotheses, or findings to verified facts.
- No change to the existing ScopeGuard, egress, request-budget, approval, or independent-verification authorities.

## Acceptance criteria

1. Old graph files load unchanged; all new records are additive and schema-versioned.
2. Every World Model fact has provenance, confidence, and freshness; inferred facts cannot become corroborated from one LLM response.
3. Browser semantic actions are grounded in current accessibility/visual evidence and fail closed on stale element references.
4. Runtime observation is bounded, opt-in, redacted, and read-only.
5. All browser transports are either scope/budget-accounted or explicitly disabled.
6. Twin-context tests use only named test identities and test-owned fixtures.
7. Every active counterfactual has a control, a falsifier, and a stored evidence recipe.
8. Only independent verification can confirm a finding.
9. PI cases reuse the existing `pi_oracle` evidence contract.
10. Posture adaptation can reduce activity but cannot increase authorization or resource ceilings.
11. Unit, integration, fixture-app, and regression tests pass; no live third-party target is needed for CI.

## First implementation PR

The first code PR should implement **Phase 0 only**: schema-versioned typed World Model records that live in the existing KnowledgeGraph, with secret-safe serialization and tests proving old graph compatibility. This creates the stable contract that browser, thesis, twin-context, and PI work can share without prematurely coupling their execution paths.


## Operational integrity workstream (added from the repository audit)

The context-native engine depends on reliable concurrent execution and visible evidence. Treat these as platform prerequisites, not later cleanup. The following items are prioritized by failure impact.

### O0 — isolate each run's execution resources

- **Docker identity:** `SandboxConfig.container_name` currently defaults to the shared name `redteam-kali-run`; `execute_run()` constructs `KaliSandbox(engagement, audit=audit)` without a run-specific name; sandbox startup force-removes any existing container with that configured name before starting. Concurrent run launches can therefore interfere with one another. Derive the container name from a validated run ID (or inject a run-scoped sandbox config), enforce Docker's name-length/character constraints, and test two overlapping runs plus cleanup isolation.
- **Shared learning stores:** audit all run-scoped paths for bandit, skill, and experience stores. Per-instance Python locks do not coordinate separate run instances or processes. Use a common persistence primitive with an inter-process lock, atomic same-filesystem temp write + replace, and a defined read/modify/write transaction boundary. Atomic replacement prevents torn reads; it does not by itself prevent lost updates. Preserve HMAC verification semantics and test concurrent writers, crash-before-replace, and reload integrity.
- **Resource lifecycle:** every run must own and clean up only its own container, browser contexts, proxy, and temporary artifacts. A run's stop/failure path must not tear down another run's resources.

### O1 — make installation and CI reflect the shipped product

- Replace manually maintained package lists with package discovery that includes intended `redteam.*` packages while explicitly excluding tests, fixtures, and non-package directories. Preserve the intentional `src/agentic_setup` mapping only if that legacy package remains a supported distribution surface.
- Add a wheel-install smoke test in a clean environment (build wheel, install wheel, import supported entrypoints and subpackages). Editable-install tests alone do not validate wheel contents.
- Extend CI with dashboard dependency install + lint/typecheck/test/build, Rust formatting/check/test where the kernel is supported, and a Dockerfile build/lint smoke test where runner capabilities permit. Keep deterministic Python tests as a separate required job.

### O2 — expose existing product capabilities

Inventory backend routes against typed dashboard API methods and actual UI consumers. The audit identifies candidate gaps: deterministic retest, attack graph, traffic, proxy, coverage, inventory, and live recon. Confirm each route's current contract and authorization before adding typed client methods and run-detail panels. A route is not product functionality until the UI can discover, invoke, and render its result with honest loading/error/empty states.

### O3 — make failures observable

Replace silent exception swallowing in critical browser, proxy, orchestration, recon, and persistence paths with structured, redacted error events. Each event should include a stable error code, subsystem, operation, recoverability, run ID, and correlation/evidence reference; never include credentials, raw request bodies, or sensitive exception payloads. Expected best-effort failures may remain non-fatal, but must be counted and visible. Add tests that assert both the safe fallback and the emitted diagnostic.

### O4 — verify reachability before pruning or promoting subsystems

The audit's module reachability totals, orphan classifications, and swallowed-exception counts are useful hypotheses, not yet architecture facts. Recompute them with:
- explicit supported entrypoints (CLI, server, dashboard-triggered routes, worker processes, plugin/optional paths);
- static imports plus dynamic import/string-based registration and packaging metadata;
- a distinction between runtime unreachable, optional/lab-only, test/benchmark-only, and intentionally library-exported code;
- an AST rule definition that distinguishes `except: pass`, `except Exception: continue`, logging-only handlers, and deliberate best-effort cleanup.

Do not delete or archive code from a static import graph alone. Record ownership, intended support level, tests, and a migration/deprecation decision for each subsystem.

### Sequencing and gates

1. Fix run isolation and persistence correctness before enabling more concurrent or twin-context execution.
2. Prove wheel contents and clean-install imports before treating packaging as production-ready.
3. Surface existing API capabilities with contract tests before adding new engines.
4. Add structured error telemetry before broad refactors, so regressions remain diagnosable.
5. Use measured reachability and product usage to decide which subsystems to integrate, support as optional, or retire.

These work items do not weaken ScopeGuard, engagement budgets, approval gates, or independent verification. They are reliability requirements for those controls to remain trustworthy under concurrency and failure.

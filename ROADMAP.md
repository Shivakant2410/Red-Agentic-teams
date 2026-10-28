# ROADMAP — Gen-2 → world-class autonomous red teamer

Status as of Gen-2. This document is honest about where the project stands against the
best public systems, what Gen-2 fixed, and what actually matters next. It complements
`docs/competitor-landscape.md` (earlier research) and `GEN2-ARCHITECTURE.md` (what
Gen-2 built).

## Where the project already leads

Most public "autonomous pentest" projects are prompt scaffolds around a single model.
This project's differentiators, built in Gen-1 and preserved in Gen-2, remain rare:

1. **Deterministic scope enforcement at the network layer.** The Kali egress firewall
   (default-DROP, RoE-derived allowlist, self-test that tears the sandbox down if a
   probe escapes) does not depend on the model behaving. Few systems have anything
   stronger than prompt-level "stay in scope".
2. **Proof-first finding pipeline.** `pending_verification` → independent re-check in a
   fresh context → confirmed. Nothing credits the objective from a scanner match or a
   model's claim. False-positive discipline is the #1 credibility problem for
   autonomous pentesters; this architecture treats it as a first-class constraint.
3. **Cross-run learning that compounds.** Bandit-selected techniques per endpoint-shape,
   distilled tradecraft lessons, app-shape patterns, and a persistent skill library —
   the system gets better per target class, not just per run.
4. **Fail-safe degradation everywhere.** Reflection, semantic memory, telemetry, and
   gateway failover are amplifiers: each one returns to deterministic Gen-1 behavior on
   failure. Nothing new is load-bearing.
5. **Auditability.** Append-only hash-chained audit log, per-run event stream, reproducible
   reports. An operator can reconstruct every action and every decision.

## Gen-2: what this release added (shipped)

- **Multi-provider LLM gateway** — role-routed, cross-provider round-robin failover with
  429 cooldowns; Anthropic native; OpenAI-compatible endpoints (OpenAI/Z.ai/Groq/
  Ollama/vLLM); zero-config fallback to Gen-1 OpenRouter behavior. *(Removes the
  single-vendor availability ceiling that made long runs fragile.)*
- **Live mission control** — event bus → `events.jsonl` → FastAPI (replay + SSE) →
  Next.js dashboard with phase stepper, live event feed, findings, kill chain,
  reflections, and one-click approvals. The operator watches the attack as it happens
  instead of tailing files.
- **Headless control plane** — one `execute_run()` shared by CLI and API; REST launches,
  STOP, reports; approvals resolved over HTTP without a terminal.
- **LLM strategist reflection** — per-round self-critique from a deterministic digest,
  allowed only to re-rank the attack tree (never to create targets or authorize actions).
- **`jwt_inspect`** — deterministic JWT checklist (alg=none, jku/x5u/kid, expiry,
  lifetime, sequential sub, PII) feeding proof-hints, not findings.
- **`nuclei_scan`** — sandbox-routed, scope-guarded scanning whose matches are leads
  into the existing proof pipeline.
- **Local semantic memory** — zero-dependency backend (JSON + hashing/on-device
  embeddings); HelixDB stays optional for deep-semantic recall.
- **Attack-surface evidence (ARTEX port)** — three capabilities adapted from ARTEX
  (mhtsec/ARTEX), kept authorization-first: `traffic.py` (per-run wire evidence with
  credential headers masked both directions, droppable bodies, scope-denied attempts
  recorded, cursor-served at `/api/runs/{id}/traffic`), `inventory.py` + `surface_scan`
  (a host→port→service map built passively from every response and actively by a
  sweep that can only ever touch the RoE allowlist — capped, rate-limited, honest
  about dead pairs and budget exhaustion, never records findings), and
  `importers/assets.py` (ScopeSentry-style CSV/JSON/JSONL feed sync that is an
  INTERSECTION with the RoE, never a merge — out-of-scope entries are dropped and
  counted, scope.check still refuses them afterwards; validated 400 at launch).
- **Live-fire hardening round** — five capability gaps found by running the platform
  against a real LLM backend under adversarial fault injection were closed and
  live-validated: `http_probe` (cheap session-aware exploration that never touches the
  finding pipeline — the agent no longer burns confirm_finding verification budget to
  look around), `set_session` (operator-handed static tokens register as sessions with
  honest `operator_token` sourcing), unknown-tool dispatch recovery (a hallucinated
  tool name now returns the real tool list instead of a dead step), the **creditor**
  (deterministic post-verify sweep converts confirmed findings into objective credit —
  proven live on the IDOR lab with claiming forbidden; last round's uncollected
  OBJECTIVE ACHIEVED cannot reproduce), and the **scope self-targeting guard** (a
  launch whose scope includes the control plane's own host:port — including the
  localhost/127.0.0.1 alias case — is refused 400 before any run is armed).

## Gap analysis vs. the reference systems

Honest comparison against the systems people benchmark against: **CAI** (Cybersecurity
AI framework, alias0r), **PentestGPT** (GreyDGL), and **Nebula** (beryl-so). Claims
about those projects come from their public docs and should be re-validated; the gaps
below are what to build regardless of their current state.

### Where they are ahead today

| Gap | Who does it better | What it means here |
|---|---|---|
| **Benchmark scores & harness** | CAI publishes leaderboard results (CyBench, XBOW-style suites) and runs a model-comparison harness. Nebula ships CTF-oriented task suites. | We have no public, reproducible score. Gen-1's local benchmark exists but isn't a comparable suite. Without numbers, "proof-first" is an unproven claim. |
| **Community & model coverage** | CAI supports 20+ providers and a large contributor base; PentestGPT has years of CTF community usage. | Our provider coverage is now solid (Gen-2) but the ecosystem — integrations, docs, example engagements — is thin. |
| **Breadth of attack surface** | Nebula is CTF/web/pwn/crypto/forensics broad; CAI's agents span many challenge classes. | We are deliberately web-app/API focused (whitebox + blackbox). Depth over breadth is a defensible product choice, but it caps the audience. |
| **Agent execution sandboxing ergonomics** | CAI/Nebula run agents as swappable Docker images with one-command setup. | Our Kali image is a build-from-source first run (large, slow). Setup friction is real. |

### Where we are ahead (and must keep)

- **Safety architecture**: network-layer scope, approval gates, kill switch, engagement
  windows, self-unlocking prevention. None of the three reference systems document
  anything equivalent at this rigor.
- **False-positive control**: independent verification in a fresh context is our core
  loop; scanners-as-leads (Gen-2) extends it instead of bypassing it.
- **Operator experience for real engagements**: live mission control with approvals
  matches how a red-team lead actually supervises a junior tester; the reference
  systems are closer to benchmark runners.
- **Cost discipline**: free-model routing + role-based model pinning means an engagement
  can run at $0 or concentrate spend exactly where reasoning pays.

## Roadmap to close the gaps (priority order)

### Phase R1 — Prove it: reproducible evaluation (highest leverage)
1. **Held-out task suite.** 30–50 permissioned web/API tasks with known outcomes,
   machine-checkable success criteria (the objective system already scores runs this
   way), and refusal cases (out-of-scope targets the agent MUST NOT touch). Publish the
   harness, not vulnerable apps.
2. **Metrics beyond success rate**: false-positive rate (falsified/pending ratios are
   already tracked), scope-violation count (must be 0 by construction — assert it in
   the harness), cost per confirmed finding, wall-clock per phase (events make this
   computable from `events.jsonl`).
3. **Head-to-head runs** of the same suite across: Gen-1 OpenRouter-only vs. Gen-2
   gateway with role pinning, reflection on/off, semantic memory on/off. This turns the
   Gen-2 features from plausible into measured.

### Phase R2 — Deepen the loop
4. **Verifier expansion.** The independent verifier replays five check types (http,
   differential, proof, privilege, workflow). Add: CSRF double-submit, race-condition
   (send-N-prove-1-wins), cache poisoning (variant + benign control), and
   GraphQL-specific introspection/authorization proofs. Each becomes a `check_type`
   with its own negative-control recipe.
5. **PoC synthesis from proofs.** Every confirmed finding already stores replayable
   check steps; generate a standalone, deterministic PoC script + curl transcript per
   finding (no LLM in the loop) for the report.
6. **Strategy memory upgrade.** Replace the flat reflection note with a per-engagement
   strategy object the orchestrator can carry across rounds (what to abandon, what to
   double, budget reallocation), still constrained to re-ranking.

### Phase R3 — Breadth where it pays
7. **Cloud/container posture checks** behind the same approval gates (read-only
   metadata endpoints, public S3/Blob misconfig probes) — high client value, low risk.
8. **API-first mode**: OpenAPI/Postman ingestion into the knowledge graph (the
   whitebox route-seeding path already exists), parameter-level authorization matrix
   testing (the local assessment slice, generalized).
9. **Post-exploitation depth**: the access graph already models credentials →
   privileges → pivots; add credential-reuse across hosts and session-cookie replay
   across services as first-class techniques.

### Phase R4 — Platform
10. **One-command deployment** (`docker compose up` → server + prebuilt Kali image +
    dashboard) to kill the setup-friction gap.
11. **Multi-run operator view**: the dashboard already lists runs; add cross-run
    dashboards over the memory store (which techniques are winning on which shapes)
    and bandit visualizations.
12. **Resume/pause**: runs are already crash-resumable at the artifact level; add an
    explicit API to pause (soft STOP) and resume a run with its budget intact.

## Non-goals (keep saying no)

- Public-target / "scan anything" mode. Authorization artifacts are the product.
- Model-decided scope. Scope is enforced by the network and the ScopeGuard, never by
  prompt adherence.
- Benchmark chasing on saturated suites (XBOW's own maintainers call it saturated).
  The held-out suite in R1 is the honest version of this.
- Autonomous exploit deployment against production without per-action approval. The
  gated stages (persistence, defense evasion) stay gated.

## Success criteria for "world best"

1. A red-team lead can launch a scoped engagement from the dashboard, watch it live,
   approve dangerous steps from a phone, and hand the report to a client — without
   opening a terminal.
2. On the held-out suite: ≥90% task success with **zero scope violations** and a
   false-positive rate lower than any published baseline, at a documented cost per
   confirmed finding.
3. Every Gen-2 capability is measured to help (or is removed): reflection, semantic
   memory, gateway failover, and the new tools each carry a number from R1.
4. A new contributor can go from clone to first run in under five minutes.

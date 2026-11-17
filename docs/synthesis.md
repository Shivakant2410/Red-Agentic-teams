# Synthesis — the evidence-join layer (why the system wasn't thinking, and what now does)

## 1. The audit: following one claim through the loop

Before writing any code, this question was answered against the live loop:
**where, exactly, does reasoning enter the system, and where is it thrown away?**

Trace a real claim. Recon maps `http://t/api/orders/1042`. `AttackTree.sync()` calls
`seed_endpoint(ep)`, which loops `ENTRY_TECHNIQUES` — the SAME eight entry techniques
get seeded on EVERY endpoint, so the tree now contains `access.idor@http://t/api/orders/1042`
alongside `access.idor@http://t/blog/posts`, with identical status, identical bucket
logic, identical everything. A tree node is four fields: `(technique, target, status, bucket)`.
The scheduler (B3) may reorder this frontier by learned yield-per-cost — a real
improvement, but it reorders *labels*, it does not deepen them. When a swarm worker
claims the node, the handoff it receives is:

```
YOUR ASSIGNED TARGET THIS TURN: access.idor on http://t/api/orders/1042 —
"Use `authenticate`, then `verify_vulnerability` with two requests (your own object
as baseline, another id as payload)..."
```

That description is a **class** description. It is byte-identical for every endpoint
the tree will ever seed. Everything that made THIS endpoint attackable — that it has a
numeric path id, that the run holds two session identities, that a param node exists —
lives in the graph, the session store, the access graph, and the finding store…
and **no module reads them together**. Four gaps, all code-verified:

- **G1 — the tree is class-based, not evidence-based.** Every endpoint gets the same
  technique set; nodes carry no observations.
- **G2 — observations never compose.** PARAMETER nodes (with reflection attrs from
  `webinspect`), session identities, held access, credential findings — nothing joins
  "identifier + two identities" into "two-request differential with concrete requests".
  The join is the human red teamer's actual skill, and it was left to the LLM's chance
  notice inside a bounded briefing.
- **G3 — proof specs are invented at proof time.** `xss_reflect_probe` already emits
  READY check_specs that `verify_vulnerability` consumes 1:1 — for one class. For
  IDOR/authz the worker hand-invents requests from a blank page, every claim, every
  round, every worker.
- **G4 — the hypothesis registry stores but never generates.** C1 built
  registration, dedup, evidence, leases — a great *memory*. Nothing *proposes* into
  it deterministically; `claim_text` is still just "technique on target".

Generic tooling was never the bottleneck — the toolset already outruns the reasoning
that aims it.

## 2. What was built: `redteam/synthesis.py`

A deterministic **evidence-join layer**: pure functions over run state
(graph + sessions + findings), no network, no sandbox, **not registered in
build_registry** — the agents do not call it; the orchestrator feeds it. This is
deliberately NOT a tool. It is the connective tissue that makes the existing 31 tools'
outputs talk to each other.

Each run before an exploit swarm: `synthesize(ctx)` executes four rules; each rule IS
an evidence pattern, and **an idea without evidence is refused by construction**:

| Rule | Fires when | Produces |
| --- | --- | --- |
| R1 `identity_differential` | identifier-shaped path segment or param node **and** ≥2 held identities | `access.idor` idea: baseline request as identity A, payload as identity B, `status(payload)==200 AND body differs` |
| R2 `unauth_baseline` | protection-shaped path (`/admin`, `/profile`, …) mapped while holding a session | `access.control` idea: unauthenticated replay; body_regex pulled from the sessioned response |
| R3 `reflection_ready` | a PARAMETER node with `reflected=True specials_survive=True` | `xss.reflected` idea carrying the inspector's sink context forward. **Escaped reflections produce no idea** — proof budget is never spent on dead oracles |
| R4 `credential_reuse` | credential-shaped finding **and** auth-shaped endpoint | `auth.test` idea: `try_credential` plan with the finding id traced |

Ideas are deduped per `(technique, target)`, ranked by evidence count + technique
priority, capped, and — the point — injected at the exact handoff where reasoning used
to die. A worker that claims an enriched node now receives:

```
SYNTHESIZED EVIDENCE (…a DRAFT for you to verify/adapt, not a proof):
WHY: http://t/api/orders/1042 exposes numeric/UUID path id and we hold two distinct
     identities ('sess-admin', 'sess-user') — request the SAME object as both…
EVIDENCE:
  - [sessions/identity] held identity: session 'sess-admin' (ref: sess-admin)
  - [graph/endpoint] numeric/UUID path id observed on target (ref: http://t/api/orders/1042)
EXPECTED (if NOT vulnerable): identity B gets 403/404 or an object that is not A's
DRAFT CHECK: verify_vulnerability(check_type='proof'): requests = {baseline: GET
  http://t/api/orders/1042 as session 'sess-admin', payload: GET … as session
  'sess-user'}; conditions = status(payload)==200 AND body(payload) differs …
```

The draft rides `claim_or_register`'s existing `expected_behavior`/`proposed_test`
slots (no C1 schema change), and each evidence observation attaches as an
`EvidenceRef(kind="observation", source_agent="synthesis")` — the hypothesis now
records **why** the node looked attackable, not just what came of it. The rationale
chain survives the run.

## 3. The contract (what synthesis is NOT allowed to do)

Honoring the C1 governance rules verbatim:

1. **Never selects.** The tree's `actionable()`/`claim()` order is untouched; ideas
   only enrich nodes that already exist on the frontier. A synthesized idea cannot
   create, authorize, or widen work.
2. **Never proves.** Every draft is labeled a draft in the briefing text itself;
   proofs still run k-of-n + negative control; only `verify_finding_independently`
   says "confirmed".
3. **Degrades, never crashes.** `synthesize` wraps every read and every rule;
   a broken component yields fewer ideas, never an exception; a registry failure
   yields an audit record and a Gen-1-identical swarm.
4. **Evidence or silence.** Rules are patterns; no matching observations, no idea —
   the module cannot hallucinate a rationale, because rationales are composed from
   refs, not written.

## 4. Verification

- 15 unit tests (`tests/test_synthesis.py`): each rule fires only on its pattern
  (and its negative: one identity, escaped reflection, missing half of R4), ranking,
  dedupe, cap, per-section bounded briefing, degraded inputs yield empty not raise.
- Full suite: **1050 passed / 0 failed**.
- The orchestrator path is covered by the existing swarm tests: synthesis failures
  degrade to `synthesis.error` audit records with zero behavior change.

## 5. What this is not (scope honesty)

Not a scanner, not a new tool, not auto-exploitation, not a planner replacement.
The planner's static priority table, the bandit, the scheduler, and the tree remain
the selector; synthesis is the *memory-to-context converter* between them and the
workers. The next deepening candidates (in priority order, none started):
chained-idea rules (a confirmed foothold feeds R1/R2 with NEW principals — today only
held sessions are evidence), and a reflection-style pre-dead check for R2's
body_regex (one cheap in-scope fetch at synthesis time would turn "fill in from the
sessioned response" into a concrete regex — deliberately deferred: it is the first
network touch this module would make, and it deserves its own review).

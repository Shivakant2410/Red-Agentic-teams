# ADR-002: Unified Attack Intelligence Graph (Phase E2)

Status: Accepted (Phase E2 scope)
Supersedes: nothing. Extends ADR-001 (collective intelligence foundation) and the
Phase 1 audit (`docs/builder02-phase1-architecture-audit.md`) that pinned the gaps
this ADR closes. Complements Builder 01's D1 (`redteam/states.py`,
`docs/state-machines.md`) — the two new lifecycle machines live there.

## 1. Context

The Phase 1 audit verified that the platform has seven internally-consistent
authorities (KnowledgeGraph, AccessGraph, AttackTree, KillChain, AssetInventory,
FindingStore, HypothesisRegistry+EventJournal) coordinated procedurally by the
orchestrator, joined only at read time. It also verified four missing capabilities
and two robustness bugs:

- **F1** — three divergent URL normalizers; no canonical cross-store identity.
- **F2** — the inventory receives host/service observations that never reach the
  KnowledgeGraph (its host/service layer was populated only by `kali_exec`
  output parsing).
- **F3** — graph edges are bare tuples; no evidence/provenance anywhere on
  relationships.
- **F4** — no invalidation lifecycle anywhere: revoked credentials, remediated
  findings and vanished services left every derived structure intact.
- **F5** — falsified findings never reached the AttackTree (`sync()` skipped
  everything non-confirmed), so the bandit never learned the loss.
- **F6/F7** — KnowledgeGraph persistence was non-atomic and crashed on corrupt
  files; KillChain had no lock and never wrote the `achieved_at` its consumers read.

## 2. Decision

**Extend the existing stores. No second graph engine, no graph database, no new
event system, no re-keying of existing data.** Each authority keeps its role:

| Authority | Responsibility (unchanged) | Phase E2 addition |
|---|---|---|
| KnowledgeGraph | discovered surface intelligence | canonical identity layer, evidence refs, edge metadata, lifecycle (active/stale/remediated), atomic persistence |
| AccessGraph | demonstrated access and holdings | `last_seen`, evidence refs, `revoke()` (held→revoked), revocation history |
| AttackTree | work selection + execution state | `sync()` also fails the matching node on an independently FALSIFIED finding |
| KillChain | campaign progression | lock + `achieved_at` written honestly |
| AssetInventory | host/service inventory | read-only `iter_services()` feeder for the bridge |
| FindingStore | confidence + confirmation | untouched (two structured `finding_id` markers added at hold time in the creditor/privilege paths) |
| HypothesisRegistry | hypothesis lifecycle | untouched |
| EventBus | telemetry only | untouched |
| AuditLog | action history | untouched (receives `retest.invalidated` records) |

### 2.1 Why the KnowledgeGraph is extended, not replaced

It already had the dedup/correlation core (`observe()` merge, corroboration), the
per-endpoint coverage model, thread safety, and every producer already writes to
it. The audit priced a replacement at: re-wiring every producer, re-testing every
artifact consumer (server, graph_view, planner, reports), and re-keying every
persisted run — with no capability gain the extensions don't provide.

### 2.2 Why no second graph engine

The platform's actual workload is: one process, ≤3 worker threads, run-scoped
stores, file-served projections. Dict/set stores with O(1) upserts and full-JSON
persistence meet that. A graph DB would add infrastructure the concurrency model
can't even use (no multi-process access), and the audit's performance targets
(§14) remain unmeasured-against — no optimization without measurement.

### 2.3 Canonicalization policy (owned by `redteam/knowledge.py`)

`canonical_host(host)`: trim, lowercase, strip one trailing dot; IP literals
validated but unchanged; `www.` is NOT stripped (distinct surfaces stay distinct).
Pure string work — no DNS, no network.

`canonical_url(url)`: lowercase scheme+host; drop fragment; drop the port when it
equals the scheme default; path kept EXACTLY (no trailing-slash folding — path
distinctions are real resources); **query string DROPPED**.

The query trade-off (audit O1, resolved): query strings describe *behavior*, not
*resource identity*; keeping them is what produced the duplicate-endpoint problem
(spa_recon strips queries, passive recon and ffuf keep them). Parameter NAMES and
observations remain available through the existing PARAMETER nodes and through
`attrs["url_raw"]` (bounded, written once on first canonical observation when it
differs). What this merges: the same path under different/absent queries. What it
never merges: different paths.

**Existing IDs are never re-keyed.** `observe()` keeps byte-identical behavior for
existing callers; `observe_canonical()` is the canonical-entry path (used for
endpoint keys and the inventory bridge's host keys); `_find_locked()` performs
canonical lookup so lifecycle and join operations find an entity recorded under a
different spelling. Legacy run data needs no migration; old-code-reads-new-files
remains the documented one-way gate (unknown dataclass fields).

### 2.4 Evidence-reference contract

The swarm's `EvidenceRef` shape IS the contract — one vocabulary, no dialect:

```python
{"evidence_id", "kind" (observation|tool_result|finding|attempt|...),
 "origin" ("agent"|"target"), "source" (tool label), "source_agent",
 "artifact_ref" (traffic.jsonl line | events.jsonl seq | finding:<id> |
                 inventory.json:hosts[...].services[...] | node:<id>),
 "summary", "ts"}
```

Applied additively: `Node.evidence_refs`, `AccessNode.evidence_refs`, KG
`edge_attrs` (parallel map keyed by the existing triple, serialized as rows —
never separator-joined), and AccessGraph edge provenance recorded node-adjacent.
Rules: append-only; no fabrication (absent refs stay empty — "no provenance
recorded" is never rendered as "provenance disproven"); bounded strings; refs
point at real artifacts; secrets stay redacted upstream (traffic recorder).

### 2.5 Stale / revoked lifecycle (registered in `states.py`)

- `kg_node_lifecycle` (active → stale|remediated; stale → active on
  re-observation; remediated → active only on a future independent re-proof).
  Re-observation clears STALE but deliberately NOT REMEDIATED — an endpoint
  answering again says nothing about whether the vulnerability is back.
- `access_hold` (held → revoked via `revoke()`; revoked → held ONLY via a fresh
  `hold()` demonstration — the REQUIRED_SOURCE gate still decides what any hold,
  resurrected or not, may credit).

Both are currency decorations with append-only history. Nothing is deleted;
marking cannot authorize, execute, or confirm anything. Automatic round-based
staleness (the audit's configurable-K proposal) is **deferred**: no reliable
"quiet for N rounds" signal exists in the current run model, and a wall-clock
decay would mark quiet-but-live targets dead. `mark_stale()` is explicit-only in
this phase.

### 2.6 Synchronization strategy

The repo's proven pattern — pull-based sync at existing chokepoints — is widened,
not replaced:

1. **Inventory→KG bridge** (`orchestrator.sync_inventory_into_graph`): called at
   the two orchestrator post-verify sync sites and the single-agent turn sync
   (`agent.py`). Eligibility policy: only services that ANSWERED
   (`status_last` truthy) bridge; declared/failed probes stay inventory-only.
   Idempotent by construction (observe() merges).
2. **Falsified→tree** (inside `AttackTree.sync`): only `falsified` findings (an
   independent-verify verdict), only an EXISTING matching node (canonical target
   match, same CWE→technique mapping as confirmation), only that node — siblings
   untouched; FAILED remains once-per-round retryable.
3. **Retest→revocation** (`retest.invalidate_after_fix`, gated in
   `retest_run` on verdict == FIXED): revokes exactly the holdings carrying the
   finding's structured `finding_id` reference; marks the matching KG endpoint
   remediated. `blocked`/`cannot_confirm`/`reproducible` never invalidate — a
   transport failure or scope block is not evidence of a fix.

EventBus stays telemetry (ADR-001 §2.3 verdict unchanged); EventJournal stays the
hypothesis lifecycle authority; replay/recovery contracts are unchanged (per-store
load-on-init; the KG now survives a torn file with a reported warning).

### 2.7 Read-time attack-path projection

`graph_view.build_exploration_graph` gains an additive `attack_paths` section
assembled ONLY from records that actually join (inventory host/service → KG
endpoint → AttackTree technique → finding (+ confidence/independent verdict/retest
state) → access holding (held OR revoked, with status) → objective criterion).
Unmatched findings are listed under `unresolved` rather than guessed into a chain.
No nodes are created, no stores are written, no tools run, nothing is authorized;
the existing response shape is preserved for clients.

### 2.8 Backward compatibility

- All new dataclass fields default (`evidence_refs=[]`, `lifecycle={}`,
  `last_seen=""`, `invalidated_at=""`, `achieved_at=""`, …) — pre-E2 files load
  unchanged (tested).
- New optional keyword parameters only (`observe(..., evidence_refs=...)`,
  `hold(..., evidence_refs=...)`, `retest_run(..., access=None, graph=None)`) —
  existing call sites compile and behave identically.
- `observe_canonical` is new API; `observe` untouched.
- JSON gains keys (`edge_attrs`, lifecycle fields) that old readers ignore and
  new readers tolerate absence of.
- `states.EXPORT_VERSION` bumped 2→3 per D1's documented drift procedure.

## 3. Files touched (and the two documented exceptions)

Extensions: `knowledge.py`, `access.py`, `attack_tree.py`, `killchain.py`,
`orchestrator.py`, `agent.py`, `graph_view.py`, `retest.py`, `states.py`,
`tests/*`.

Documented exceptions to the Phase 1 "untouched" list (assignment §19 allows
minimal, justified changes):
- `inventory.py` — added the read-only `iter_services()` accessor (the bridge
  needs the full map; `summary()` is deliberately bounded at 64 for briefings).
- `credit.py`, `tools/independent_verify.py` — added the structured
  `finding_id` marker + evidence ref at the two hold sites, per the audit's own
  recommendation ("prefer exact finding IDs and structured provenance… added at
  the appropriate existing write path") — this is what makes retest-driven
  revocation exact instead of a free-text parser.

## 4. Deferred decisions

- Automatic round-based staleness (§2.5) — needs a reliable quiet-round signal.
- Cross-run/engagement graph enrichment (audit O5) — historical facts would
  import `origin="historical"`, never `held`, and require re-verification.
- A `knowledge.py` read-helper for "holds sourced from finding X" (audit O7) —
  the attrs marker made the string-free join possible without touching
  FindingStore.
- Strict lifecycle enforcement (rejecting illegal transitions at write time) —
  D1's tolerance policy applies to the new machines too.

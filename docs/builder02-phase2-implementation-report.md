# Builder 02 — Phase 2 Implementation Report: Unified Attack Intelligence Graph

Branch: `phase-e2-unified-intelligence-graph` (from `main` @ `ed199f7`)
Pull request: [#13 — Phase E2: Unified Attack Intelligence Graph](https://github.com/Shivakant2410/Red-Agentic-teams/pull/13)
Design basis: [Phase 1 audit](builder02-phase1-architecture-audit.md) · [ADR-002](adr-002-unified-intelligence-graph.md)

## 1. What was implemented

All ten stages of the approved design, as extensions of the existing stores:

| Stage | Delivered |
|---|---|
| 1A | KnowledgeGraph atomic persistence (tmp+replace, inventory.py pattern) + corrupt/torn-file tolerant load with a reported `last_load_warning` (never silent, never a crash) |
| 1B | KillChain `RLock` on mark/status/achieved/recommend-adjacent reads; `achieved_at` stamped on first ACHIEVED, cleared on an operator revert; `server.py`/`graph_view.py` now read a real timestamp (no code change needed there — they already `.get()` the field) |
| 2 | `canonical_url()` / `canonical_host()` in `knowledge.py` — the one identity layer; existing keys never re-keyed; `observe_canonical()` for new observations; canonical lookup in `_find_locked()` |
| 3 | KG extensions: `DOMAIN` kind; `Node.evidence_refs` (swarm `EvidenceRef` dict shape); `Node.lifecycle`; `edge_attrs` parallel map (tuple representation preserved); `mark_stale()`/`mark_remediated()`; optional `evidence_refs`/`edge_evidence` params on `observe()`; lifecycle rollup in `summary()` |
| 4 | AccessGraph: `last_seen`, `evidence_refs`, `invalidated_at`/`invalidation_reason`, `revoke()` (held→revoked), `revoked_nodes()`, re-hold via a fresh demonstration with append-only revocation history, revoked holdings excluded from `held()/reached()/frontier()` and surfaced honestly in `briefing()`/`summary()` |
| 5 | `orchestrator.sync_inventory_into_graph()` — inventory→KG bridge (answering services only; declared/failed probes stay inventory-only); read-only `AssetInventory.iter_services()` feeder; called at both orchestrator post-verify sync sites and the single-agent turn sync |
| 6 | `AttackTree.sync()` falsified branch — an independently FALSIFIED finding fails the matching existing node (canonical target match, same CWE map, siblings untouched, no new rows); `FAILED` retry behavior unchanged |
| 7 | `retest.invalidate_after_fix()` gated on verdict==FIXED in `retest_run(..., access, graph)`; `build_ctx_for_run` loads the run's own `graph.json`/`access.json`; structured `finding_id` markers added at the two hold sites (creditor + privilege credit); CLI passes the stores through |
| 8 | Evidence refs on nodes/edges/holds (Stage 3+4 fields) + `tests/test_graph_evidence_refs.py` proving persistence, append behavior, legacy tolerance, the shared vocabulary |
| 9 | `graph_view` additive `attack_paths` projection (inventory → KG endpoint → tree technique → finding + verification + retest state → access holding held/revoked → objective criterion) + `unresolved` list for unjoinable findings; existing response shape preserved; served automatically by the existing `/api/runs/{id}/graph` route |
| 10 | Cross-cutting verification: every bridge idempotent (tested), no bridge makes network calls or touches scope/approval/verification, states.py machines registered (`kg_node_lifecycle`, `access_hold`, `EXPORT_VERSION` 2→3 per D1's documented drift procedure) |

## 2. Architecture before and after

Before: seven authorities joined only at read time; host/service layer of the KG
dormant; three divergent URL normalizers; no edge provenance; no invalidation;
falsified findings invisible to the tree/bandit; KG flush non-atomic and
crash-on-corrupt; kill chain unlocked with a phantom `achieved_at`.

After: the same seven authorities with the same responsibilities, plus one shared
identity layer, one evidence vocabulary, an append-only currency lifecycle, three
idempotent bridges at existing chokepoints, and a read-time attack-path view.
**No second graph engine, no new event system, no re-keying, no authority moved.**

## 3. Authority boundaries preserved (verified by tests)

- Finding confirmation: `FindingStore.promote()` remains the only `confirmed`
  writer, called only by `verify_finding_independently` (`tests/test_temporal_staleness.py`,
  `test_retest.py` assert `confidence == "confirmed"` survives a fixed retest).
- Objective crediting: `REQUIRED_SOURCE` untouched; a REVOKED hold cannot credit
  (`test_access_invalidation.py::test_revoked_access_cannot_satisfy_objective_criteria`).
- Work selection: the bridge never seeds the tree
  (`test_inventory_kg_bridge.py::test_scope_and_authority_not_touched`); the
  falsified branch only fails nodes that already exist.
- Demonstrated access: only `hold()` re-activates a revoked holding; a bare
  `observe()` cannot (`test_access_invalidation.py::test_re_hold_requires_new_demonstration_via_hold`).
- EventBus: telemetry only; EventJournal: untouched; AuditLog: receives
  `retest.invalidated` records.
- Scope: no bridge makes network calls (pure in-memory state work); the retest
  RoE gate is unchanged (`test_temporal_staleness.py::test_out_of_scope_retest_stays_blocked`).

## 4. Canonical identity policy

Scheme+host lowercased; fragment dropped; default port dropped (non-default kept
— a distinct service); path kept EXACTLY (no trailing-slash folding); **query
string dropped** — documented trade-off (ADR-002 §2.3): query = behavior, not
resource identity; parameter names/values remain in the PARAMETER model and
`attrs["url_raw"]`; different paths never merge. `www.` never stripped; IP
literals validated but unchanged. Canonicalization is pure string work — no DNS,
no network.

## 5. Evidence model

The swarm `EvidenceRef` dict shape is THE contract (origin agent|target, source,
source_agent, artifact_ref, kind, ts) — applied to KG nodes, KG edges
(`edge_attrs` keyed by the existing triple, serialized as rows), and access
nodes. Append-only; legacy data loads with empty refs (never fabricated);
bounded strings; refs point at real persisted artifacts (traffic.jsonl lines,
finding ids, inventory rows).

## 6. Lifecycle and invalidation behavior

- KG: `mark_stale` / `mark_remediated` — append-only history (capped), idempotent,
  re-observation clears STALE but not REMEDIATED (policy: an endpoint answering
  again says nothing about the vulnerability returning).
- Access: `revoke` stamps when/why, keeps evidence/source/refs, drops the node
  from every current-holding consumer; re-hold requires a fresh demonstration and
  keeps the revocation record.
- Retest: ONLY `fixed` invalidates (never `blocked`/`cannot_confirm`/`reproducible`);
  revocation is exact (structured `finding_id` match — no free-text parsing);
  historical confirmation is never erased.

## 7. Synchronization bridges

1. `sync_inventory_into_graph` (orchestrator, called at post-verify sync + agent
   turn sync) — answering services only; idempotent merges; foreign-reference
   metadata (`inventory_host`, `inventory_key`) + an inventory-row evidence ref
   per observation.
2. `AttackTree.sync` falsified branch — canonical matching, existing nodes only,
   same-status re-marks refused (bandit loss recorded once).
3. `retest_run` FIXED gate → `invalidate_after_fix` — revocations + KG
   remediation, audited.

Builder 01's mission layer is untouched: the claim trio, leases, fencing,
scheduler, commander, and journal are exactly as merged in PR #11; the bridges
ride the same sync chokepoints the classic path already used, so both execution
paths get them.

## 8. Attack-path projection

Additive `attack_paths` (+ `unresolved`) in `build_exploration_graph`. Joins:
canonical URL match (endpoint ↔ finding target ↔ tree target), structured
finding→hold marker, criterion.target ↔ hold key. Never invents edges; never
presents revoked holdings or stale/remediated assets as current; never creates
tree nodes; read-only over persisted files; existing response shape unchanged
(`test_graph_view.py::test_existing_graph_response_shape_unchanged`).

## 9. Files changed

Extensions (13): `redteam/knowledge.py` (+342/−), `redteam/access.py` (+122),
`redteam/attack_tree.py` (+59), `redteam/killchain.py` (+68), `redteam/orchestrator.py`
(+102), `redteam/graph_view.py` (+221), `redteam/retest.py` (+94), `redteam/states.py`
(+93), `redteam/agent.py` (+10), `redteam/inventory.py` (+18), `redteam/credit.py` (+22),
`redteam/tools/independent_verify.py` (+20), `redteam/server.py` (untouched — the
existing route serves the additive keys).

Docs (3 + 2 new): `GEN2-ARCHITECTURE.md`, `AGENTS.md`, `ROADMAP.md`;
new `docs/adr-002-unified-intelligence-graph.md`; Phase 1 audit committed as the
design basis.

Tests (8 new + 3 extended): `test_identity_normalization.py` (13),
`test_knowledge_persistence.py` (9), `test_access_invalidation.py` (13),
`test_inventory_kg_bridge.py` (9), `test_tree_falsified_sync.py` (9),
`test_graph_evidence_refs.py` (9), `test_temporal_staleness.py` (13),
`test_killchain_lifecycle.py` (7), plus `test_graph_view.py` (+5 attack-path),
`test_retest.py` (+2), `test_states.py` (drift procedure: KNOWN_MACHINES +
reversible-machine reachability rule).

**Documented exceptions to the Phase 1 untouched list** (assignment §19 allows
minimal justified changes): `inventory.py` (`iter_services()` — the bridge needs
the unbounded map; `summary()` is deliberately capped at 64), `credit.py` and
`tools/independent_verify.py` (structured `finding_id` marker + evidence ref at
the two hold sites — the audit's own "prefer structured provenance at the
existing write path" recommendation; without it, revocation would require a
fragile free-text parser).

## 10. Tests and exact results

**Baseline (current main `ed199f7`, before any change):** `python -m pytest -q` →
**1 failed, 1897 passed, 16 skipped** in 52.28 s. The single failure
(`tests/test_mission_api.py::test_post_launches_mission_with_identity_triple`) is
a pre-existing full-suite ordering flake: it passes standalone and in pairs
(verified); it is unrelated to this branch and also passed in the full suite
below.

**Focused (new/extended) tests, actually executed:**
- 8 new files + `test_states.py`: **88 + N passed** (`88 passed in 0.51s` for the
  eight new files; states included in the 46 below)
- Extended files (`test_graph_view.py`, `test_retest.py`, `test_states.py`,
  `test_knowledge.py`): **46 passed in 1.27s**
- All new + affected existing (29 files): **279 passed in 8.30s**

**Full regression suite (this branch, all changes):** `python -m pytest -q` →
**1995 passed, 16 skipped, 3 warnings, 0 failed in 49.50 s**
(warnings: pre-existing sklearn SVD numerics in `test_template_search.py`).

Test counts: baseline 1914 collected on main → 1995 passed + 16 skipped here
(+98 net new tests, including the states drift-procedure additions and
parametrized machine checks).

## 11. Controlled demonstration

`python scripts/demo_unified_intelligence.py` → **ALL 10 STEPS ASSERTED**.
Local, deterministic, no network, no LLM: real persisted stores in a temp run dir
(KnowledgeGraph/AccessGraph/AttackTree/AssetInventory/FindingStore on disk),
deterministic doubles for the verifier (`HttpCheck` over a canned fetch with the
mandated negative-control shape) and the retest transport. The trace proves the
assignment's required sequence 1→10, including the persisted-on-disk assertions
(`access.json` shows `held:false` + revocation reason; `graph.json` shows
`lifecycle.status:"remediated"`; the finding stays `confirmed` with its retest
history — history preserved, currency corrected).

No claim is made that a real vulnerability was discovered or confirmed; the demo
is a fixture exercise of the plumbing.

## 12. Performance observations

No material overhead introduced. Structural notes: `observe()` gained two
optional list appends; `_flush()` writes one extra small JSON list (`edge_attrs`)
and uses tmp+rename (same syscall count as inventory.py, which shipped that
pattern from the start); the bridge is O(inventory services) per call at the two
existing sync points; the projection is O(records) per request, read-only. No
benchmarks were run beyond the suite (49.5 s full suite, same order as the
pre-change baseline 52.3 s — the suite itself got ~98 new tests while getting
faster, which bounds any per-test overhead).

## 13. Known limitations and deferred decisions

- Automatic round-based staleness (the audit's configurable-K proposal) is
  deliberately deferred (ADR-002 §2.5): no reliable quiet-round signal exists in
  the current run model; `mark_stale()` is explicit-only this phase. Wall-clock
  decay would mark quiet-but-live targets dead.
- Cross-run/engagement graph enrichment deferred (per-run stores remain the
  isolation contract; historical facts would need `origin="historical"` + re-
  verification semantics).
- Old-code-reads-new-files remains a one-way gate (new dataclass fields) —
  documented in ADR-002 §2.8.
- The creditor can re-hold from a still-confirmed finding after a revocation
  (`test_creditor_does_not_double_credit_after_revocation` documents the exact
  semantics); full remediation-aware crediting is a finding-store-policy decision
  explicitly left for review (the retest bridge, not the creditor, owns revocation).
- `trust_region` of the falsified→tree bridge is the CWE map: a falsified finding
  whose CWE has no mapping still fails no node (documented in the sync docstring).

# Cross-round strategy memory — the engagement gets one strategy, not twelve amnesiac ones

Phase B5 (roadmap R2.6). `redteam/strategy.py` gives the orchestrator a single,
structured strategy object that lives across the engagement's exploit rounds —
and fixes two opposite failure modes the Gen-2 reflection loop had.

## The problem it fixes

Gen-2's strategist (reflection.py) stopped the orchestrator being blind *between*
rounds — but each strategist call was still stateless. Its only memory was three
raw text notes, and its tree nudges had no release path. Two failure modes
followed, and they were opposites:

- **Amnesia.** Round N's reflection could contradict round N−1's — re-pressing a
  technique it had already written off, with nothing but prose to notice.
- **Stickiness.** `apply_strategy`'s nudges (+25 boost / −25 penalty) were write-
  only. A technique deprioritized once stayed suppressed for the whole run — even
  after it started producing confirmed findings. **Evidence could never beat a
  stale opinion.**

## The design: three rules, all deterministic

1. **Directives have TTLs.** A `press` (prioritize) lives 2 rounds; an `avoid`
   (deprioritize) lives 3 — writing off a technique is a stronger claim than
   pressing one, so it outlives it, but neither is forever.
2. **Evidence beats opinion, both ways.** A technique that lands a CONFIRMED tree
   node releases its `avoid` immediately (the write-off was wrong) *and* its
   `press` (it worked — stop distorting the tree). Evidence comes from the run
   itself: the orchestrator's own claim loop (what the swarm actually claimed)
   and the tree's confirmed chain (only newly completed nodes — repeats are
   deduped).
3. **No LLM is needed to forget.** If reflection fails — model error, budget,
   JSON garbage — the state still ticks, still releases on evidence, and the
   surviving directives stay applied. The worst case is always "back to the pure
   tree order", exactly the pre-B5 behavior, never something worse.

The strategist now *amends* a living state instead of restarting: its digest
carries an `ACTIVE STRATEGY STATE` block (live directives + a per-technique
evidence ledger, `claims`/`confirms`), and its system prompt says amend-don't-
restart. Re-deciding the same thing refreshes the directive's TTL; deciding
differently replaces it (per technique@target key).

## What changed, file by file

| File | Change |
|---|---|
| `redteam/strategy.py` | **new** — `EngagementStrategy` (amend / tick / observe_round / brief / persist) + `reset_tree_nudges` |
| `redteam/reflection.py` | digest gains the strategy block; system prompt gains the amend rule; reflection JSON shape unchanged |
| `redteam/orchestrator.py` | owns the state; feeds claims + newly-confirmed nodes each round; `_apply_strategy_state()` is now the only writer of tree nudges; emits `strategy.state`; persists `strategy.json` next to `reflections.json` |

The one trade-off worth flagging for review: `apply_strategy` is write-only, so
`reset_tree_nudges` clears exactly the two dicts it writes (`_strategy_boost`,
`_technique_penalty`) before each re-apply — otherwise a released directive could
not genuinely release. The tree **file** is untouched (core selection, chaining,
and the bandit's cross-run learning are all separate layers and untouched); a
frozen or oddly-shaped tree degrades to the old sticky behavior, never a crash.

## Safety envelope (unchanged by B5)

Directives reorder already-in-scope work through the tree's existing public
`apply_strategy` — the same constraint reflection has always had. Nothing can be
created, authorized, unlocked, or widened. The ledger reads outcomes; it never
grades findings (that stays falsify/verify's job). Every round's releases are
audible in the audit trail (`orchestrator.strategy_released`) and on the event
stream (`strategy.state`), next to the scheduler's B3 state.

## What B5 does NOT do (honest boundaries)

- No "budget reallocation" yet — the roadmap's R2.6 mentions it; the ledger gives
  the strategist the evidence to reason about it, but spending moves are still the
  scheduler's (B3) and the operator's, not the strategist's.
- No cross-run persistence: the strategy object dies with the run by design. What
  carries across runs is the bandit's win-rate and the memory stores — per-run
  strategy is deliberately per-run.
- The TTLs (2/3 rounds) are calibration, like mu/V in B3: stated constants, not
  learned ones, chosen so a wrong press wastes ≤2 rounds of ordering and a wrong
  avoid wastes ≤3 before evidence or expiry frees it.

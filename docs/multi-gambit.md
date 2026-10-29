# Multi-Gambit: bandit-theoretic allocation for offensive multi-agent systems

*Research note + what shipped. The name is deliberate: an engagement is not one
decision, it is a stream of small simultaneous bets — gambits — across targets,
tools, techniques and agents. The mathematics for placing those bets is the
multi-armed bandit (MAB) family. This note maps that family onto offensive
multi-agent systems generally, and onto THIS repo's modules specifically.*

---

## 0. The problem: LLM-agent red teams wander

Every serious agentic pentest stack today — PentestGPT, hackingBuddyGPT, the
ARTEX/norma planner we audited, and our own pre-Gen-2 planner — shares one
structural defect: **next-action choice is made by LLM heuristics over a fixed
priority table**. The model is good at *how* to attack and bad at *what next*,
because "what next" is not a language problem. It is a sequential decision
problem under uncertainty: many candidate actions, unknown and shifting yields,
a finite budget, and an adversary who reacts to your choices. That is the
explore/exploit problem, and it has sixty years of theory behind it.

The evidence that heuristics fail is already in our own repo history:
`attack_tree.py` used to rank techniques by a hand-set `priority` constant —
the same order against every target, forever — and `planner.py` still does
(`_CHECK_PRIORITY`: auth 100, access_control 95, ...). A fixed prior with no
learning, re-paid on every engagement. `BanditStore` was built to fix exactly
this for technique selection; this note extends the fix and maps the rest of
the family.

## 1. The decision problem, formally

At each decision tick t, the system observes its state (knowledge graph, access
graph, kill-chain position, objective criteria outstanding) and chooses one
action a from candidates A_t — scan endpoint E with technique T, attempt
exploit X on service S, pivot through host H. Each choice:

- returns a **stochastic, partially observable yield** r(a): confirmed finding,
  expanded surface, credential, objective progress — or nothing;
- costs **c(a)**: wall-clock, tokens, and OPSEC noise (SOC attention, rate-limit
  weight, the risk of burning the target or the engagement);
- **changes the world**: the target patches, the blue team redeploys, honeypots
  appear — reward distributions are non-stationary and adversarially shaped.

Objective: maximize confirmed objective credit subject to the noise/OPSEC
budget. Every term of that sentence is a named bandit variant, which is the
whole reason the family matters here.

## 2. The gambit taxonomy → our architecture

| # | Gambit class | Offensive problem | Algorithm | Canonical source | Our status |
|---|--------------|-------------------|-----------|------------------|------------|
| 1 | Classic MAB | Which technique next, per endpoint shape | Thompson sampling, Beta posterior | Thompson 1933; Auer et al. 2002 | **Shipped** — `bandit.py BanditStore`, blended into `attack_tree.actionable()` |
| 2 | Contextual bandit | Same technique ≠ same odds on different endpoint shapes | Bucket context (numeric-id, auth-wall, workflow…) | Li et al. 2010 (LinUCB lineage) | **Shipped (discrete context)** — `bucket_for_endpoint()`; LinUCB on richer features is staged |
| 3 | Cascading / leviathan | Confirmed foothold spawns follow-ups; back-arms gated by front-arms | Unlock-gated action space | Cascading bandits (Kveton et al. 2015) | **Shipped (deterministic gating)** — `attack_tree.unlocks` graph + `killchain.py` stages; probabilistic gating staged |
| 4 | Restless bandits | Targets change under you (patching, redeploy, traps) | Discounted posteriors; Whittle index | Whittle 1988 | **Shipped (discount)** — `BanditStore(discount=γ)`; Whittle-index scheduling staged |
| 5 | Adversarial bandits | Honeypots & blue-team shaping poison observed rewards | EXP3 importance-weighted sampling | Auer et al. 2002 | **Shipped (suspicion cap)** — `BanditStore(suspicion_cap=…)`; full EXP3 mode staged |
| 6 | Budgeted / cost-aware | Max findings per unit of *detectable noise*, not per request | Yield-per-cost Thompson; knapsack policies | Tran-Thanh et al. 2012; Cayci & Eryilmaz 2020 | **Shipped (`select`)** — `BanditStore.select(candidates, cost)`; budget-exhaustion policy staged |
| 7 | Federated / distributed MAS | Agents learn from each other's confirmations without a coordinator | Pooled sufficient statistics | Wang et al. ICLR 2020; Shi et al. AAAI 2021 | **Shipped (`export_state`/`merge_state`)** — event-bus sync; auto-broadcast wiring staged |
| 8 | POMDP planning | Full hidden-state planning (host posture unobservable) | POMDP solvers, I-DPOMDP w/ defender model | Sarraute et al. 2013; ANU RDL I-DPOMDP | Not applicable at our scale — bandits are the tractable one-step special case; revisit for lab-only deep planning |
| 9 | RL over simulators | Training allocation policies offline before live fire | A3C/DQN over NASim | NASim; NASimEmu 2023; DeepExploit 2018 | Staged — `redteam/bench/` is the local harness; NASim scenarios are the training ground |

Reading the table bottom-up: (8) is what the literature romanticizes and what
breaks in production — sample complexity kills it outside simulators. (9) is
where you earn the priors. (1)–(7) are what you actually run live. That
split — **train in the simulator, allocate with bandits, plan with the LLM,
verify deterministically** — is the architecture this note argues for.

## 3. Four twists that make textbook MAB insufficient in offense

### 3.1 Rewards must be evidence, not opinions

In web MAB, reward = click. In offense, an LLM judging "that exploit probably
worked" is a reward oracle an adversary (or the model itself) can hack. Our
reward path is deliberately deterministic end-to-end:
`tools/independent_verify.py` is the only place a finding is promoted to
`confirmed`; `credit.py` (the Creditor) converts confirmed findings into
objective credit with no LLM in the loop; `attack_tree.mark()` feeds
COMPLETED/FAILED into the bandit from the swarm's control flow, not from model
self-report. **The posterior moves only on hard evidence.** That is what makes
the bandit hallucination-proof — and it is also why we did not need an
RLHF-style reward model, which would have reintroduced the attack surface.

### 3.2 Targets are restless

A posterior accumulated over rounds 1–20 is *wrong* at round 60 if the blue
team patched the SQLi, rotated credentials, or moved the app (moving-target
defense — Sengupta et al.). A fixed Beta posterior weights a round-1 win
equally with a round-100 loss, forever, and the planner keeps flogging a dead
arm. The fix we shipped: exponential decay on (α, β) at each `record()` —
`BanditStore(discount=γ)` — with a posterior floor so the distribution never
degenerates. γ=1.0 is exact legacy behavior; γ≈0.9 trades memory for
adaptivity. Full restless-bandit scheduling (Whittle index, where the
*unpulled* arm's state also drifts) is staged: it matters when targets degrade
*without being touched*, which in a web engagement is rare next to drift caused
by our own probing.

### 3.3 The reward process is adversarial: the honeypot signature

Textbook bandits assume honest coin flips. A defender who suspects automated
attacking plants a honeypot whose entire job is to confirm your cheap exploits
fast — poisoned arms with too-good rewards. The adversarial-bandit answer
(EXP3: importance-weighted sampling) survives *arbitrary* reward poisoning but
pays heavy regret; our middle path ships today: **the suspicion cap**. An arm
that is young AND has never failed gets its Thompson draw capped — a 100%
early win-rate is treated as a *signature*, not skill. The too-perfect arm
stays competitive but can no longer starve arms with realistic intermediate
failure rates. The same gate catches a second, internal adversary: a
reward-hacking agent or strategist fabricating confirmations — its favorite
arms suddenly look too perfect and stop dominating. Full EXP3 mode (for
genuinely adversarial reward sequences) is staged behind the same interface.

### 3.4 Actions cost differently, and the noise budget is the real constraint

A quiet probe costs noise ≈1; a loud exploit costs 5+ and may crash the target
or page the SOC. Reward-per-request is the wrong objective; reward-per-noise is
the budgeted-MAB objective (maximize Σr subject to Σc ≤ B; Tran-Thanh et al.
2012 knapsack policies; Cayci & Eryilmaz 2020 for random costs). Shipped:
`BanditStore.select(candidates)` — one Thompson draw per candidate ranked by
draw/cost. Behavior contract, both tested: equal evidence → the cheap gambit
wins; proven evidence → clears the expensive arm's price (cost-aware does not
mean cheap-only — an unproven quiet arm does not get to hide behind being
quiet). What this buys in practice: the system spends its stealth where it has
already paid for information, and stops spraying noisy scans across dead
buckets.

## 4. The multi-agent layer

### 4.1 Federated posteriors (shipped)

The swarm already runs specialist workers concurrently (orchestrator.py's
exploit swarm, atomic `attack_tree.claim()`), so the failure mode is obvious:
agent A burns ten turns proving IDOR works on numeric-id endpoints while agent
B re-proves it from scratch. Beta posteriors are sufficient statistics — the
entire learned state of an arm is two floats — so federation needs no
coordinator and no heavy protocol: `export_state()` emits the stats,
`merge_state()` pools the *evidence* (α−1, β−1), never the raw draws, so
priors are not double-counted. One agent's confirmed exploit instantly raises
every other agent's belief about that (technique, bucket) arm. This is the
communicating-arms result from distributed/federated bandits (Wang et al.
ICLR 2020; Shi et al. AAAI 2021) in its cheapest form. Two properties carried
over from the platform's isolation contracts, both tested: malformed or
hostile peer rows are skipped, never raised (a bad peer cannot corrupt the
shared belief any more than a bad sink can corrupt a proof), and merge is
evidence-additive so re-broadcasts are visible rather than silent. Auto-broadcast
over the event bus each round is staged wiring, not new math.

### 4.2 Hierarchical allocation (staged)

The next layer is a meta-bandit *above* the workers: which specialist agent
(injection, access-control, auth) gets the next target under the noise budget.
That is a two-level problem — the planner is a bandit over agents, each agent
is a bandit over techniques — and the credit assignment question ("which agent
contributed to objective credit") is exactly what the Creditor already answers
deterministically. The reward router exists; only the second-level store is
missing.

## 5. Structure is not optional: cascading arms

Bandits allocate; the attack tree constrains what is allocatable. `attack_tree.py`'s
`unlocks` graph (SQLi → auth.bypass → privesc.admin → data.exfil) plus
`killchain.py`'s stage model make this a **cascading/leviathan bandit**: you
cannot sample "exploit" on a host until a front arm confirmed the foothold.
Two design consequences worth recording:

1. The chain boost (+100 in `actionable()`) is a *gating* mechanism, not a
   preference — pressing the confirmed foothold is worth more than exploring
   fresh entry techniques because it is strictly closer to objective credit.
   This is the bandit reading of the oldest red-team adage: **press the
   foothold, don't wander**.
2. `retry_failed()` once per orchestrator round is the exploration floor: it
   re-opens failed arms exactly once per round, which keeps failed techniques
   from being permanently buried (a Thompson posterior approaching β→∞ never
   samples them again) without reopening the infinite-empty-retry loop FAILED
   exists to prevent.

## 6. What shipped

*Commit 1 — the store (0abb9f2):*

- `redteam/bandit.py` — `BanditStore` extended, all additive, defaults
  preserve legacy behavior exactly (`discount=1.0`, cap off):
  - `discount` — discounted posteriors for non-stationary targets;
  - `suspicion_cap` / `suspicion_window` — anti-honeypot draw cap on
    never-failed young arms;
  - `export_state()` / `merge_state()` — federated posterior sync, evidence-
    pooled, malformed-row isolated;
  - `select(candidates, k)` — cost-aware (yield-per-cost) Thompson ranking,
    with optional `meta` passthrough so ranked items map back to tree nodes.
- `tests/test_bandit.py` — 8 new failure-mode tests.

*Commit 2 — the wiring:*

- `redteam/attack_tree.py` — `TECHNIQUE_COST` (OPSEC price per technique,
  quiet 1 → bulk-exfil 5) + `technique_cost()`; read-only `AttackTree.bandit`
  accessor (rewards still flow through `mark()` only).
- `redteam/orchestrator.py` — the exploit swarm's claim loop is now
  **cost-aware and budget-gated**: candidates come only from the tree's
  actionable frontier (reorder, never create), re-ranked by Thompson draw /
  OPSEC cost via `select()`; `NoiseBudget` caps each round's total spend, skips
  gambits that don't fit the remainder (greedy knapsack), refunds lost claim
  races. Each round also broadcasts `bandit.state` (sufficient statistics,
  `min_trials=1`) on the event bus — dashboards see what the swarm learned.
- `redteam/run.py` — `RunOptions.round_noise_budget` (default 12 noise
  credits/round, `<=0` = legacy unlimited); the run's bus subscribes
  `make_sync_handler(bandit, own_source=bus.run_id)` so FOREIGN `bandit.state`
  events merge into this run's store (own broadcasts are skipped — merging
  them back would double-count evidence).
- `tests/test_bandit_wiring.py` — 13 tests: budget never exceeded (per round),
  a gambit that cannot fit is never claimed even with a dominant posterior,
  per-round broadcast shape, meta passthrough, cost-table coverage/loudness
  sanity, NoiseBudget spend/refund/exhaustion + concurrent no-oversell,
  handler foreign/own/garbage/hostile isolation.
- Suite: **508 passed**.

*Commit 3 — prior injection (EPSS/KEV/nuclei warm start):*

- `redteam/priors.py` — public exploit intelligence as informative Beta
  pseudo-counts. Bundled snapshots in `redteam/intel/` (KEV: 1,762 confirmed-
  exploited CVEs with CWE metadata from CISA's own GitHub mirror — cisa.gov
  403s datacenter ranges; EPSS scores for every KEV CVE from FIRST). The math:
  a virgin arm seeded from class exploitability p becomes
  `Beta(1 + s·p, 1 + s·(1−p))` — "as if we had already probed s=12 times at the
  population rate" — instead of Beta(1,1).
- Three contracts keep it honest (enforced in `bandit.py`):
  - **Priors are LOCAL**: `export_state()` broadcasts OBSERVED evidence only;
    peers that seeded the same snapshot never double-count it through
    federation (prior-free arms broadcast raw α/β exactly as before).
  - **DATA WINS**: `seed()` refuses arms with any observed or merged outcome,
    and local evidence washes a p=0.9 prior below mean 0.3 within ~30 trials.
    Re-seeding a virgin arm is idempotent (snapshot refresh safe).
  - **POLICY GATE** (`EPSS_YIELD_CLASSES`): only signature-scannable classes
    may be steered by intel — EPSS measures mass-scan attractiveness, and
    KEV's IDOR-class CVEs carry EPSS ≈ 0.009 because bots don't mass-scan
    per-object logic bugs. Letting the feed suppress IDOR would starve the
    technique that confirms most on numeric-id endpoints. Classes outside the
    gate get NO prior: absence of intel must never masquerade as negative
    intel.
- `redteam/bandit.py` — `seed()`, `set_prior_provider()` / `prior_provider=`
  (consulted once on virgin-arm creation, any bucket, raising provider
  isolated), prior/obs bookkeeping on `ArmState`, evidence-only export,
  `summary()` prior provenance.
- `redteam/run.py` — builtin provider attached at startup, `RED_NO_PRIORS=1`
  opt-out, never fatal (missing/corrupt snapshots = legacy cold start).
- `tests/test_priors.py` — 24 tests: exact float contracts, federation
  no-double-count between same-snapshot peers, feed-parse isolation, policy
  gate, nuclei-corpus extraction, bundled-snapshot shape.
- Suite: **540 passed**.

## 7. Staged next (in value order)

1. **Planner banditization** — `planner.py`'s `_CHECK_PRIORITY` gets the same
   (check, bucket) store treatment attack_tree got; reward = check ran +
   finding confirmed downstream.
2. **Context upgrade** — LinUCB over richer endpoint features (graph attrs,
   auth/session signals) once per-bucket trial counts grow past what discrete
   buckets can learn from.
3. **EXP3 mode** — full adversarial robustness for engagements where the
   defender actively shapes observed rewards; behind the same `sample()`
   interface.
4. **Bench integration** — `redteam/bench/` scenarios + NASim-style synthetic
   networks to measure regret and findings-per-noise-credit of the bandit
   planner vs the fixed priority table, offline.
5. **Noise-budget tuning** — `round_noise_budget=12` is a first guess; calibrate
   from real engagements (claims-per-round × technique mix) and expose per-
   engagement overrides in the engagement YAML.
6. **Prior strength tuning** — `strength=12` / `top_k=5` are first guesses;
   the bench (item 4) measures whether the EPSS warm start actually reduces
   findings-per-noise-credit vs Beta(1,1) cold start on scenario ensembles,
   and per-class strengths can follow from that data.

## 8. References

- Sarraute, Buffet, Hoffmann — *Penetration Testing == POMDP Solving?*
  arXiv:1306.4714. The seminal formalization of pentest target selection as
  sequential decision-making under partial observability.
- ANU RDL — *Incorporating Defender's Behaviour in Autonomous Pen-Testing*
  (I-DPOMDP, POMDP + information-decay). The defender-model branch of the same
  lineage; motivates §3.3 and §3.2.
- Jjschwartz et al. — *NASim: Network Attack Simulator*;
  Janisch et al. — *NASimEmu* (arXiv:2305.17246). Simulator + emulator for
  training allocation agents; the staged bench integration (§7.7) targets
  this interface.
- Tran-Thanh, Chapman, Rogers, Jennings — *Knapsack Based Optimal Policies for
  Budget-Limited Multi-Armed Bandits*, AAAI 2012; Cayci & Eryilmaz —
  *Budget-Constrained Bandits over General Cost and Reward Distributions*,
  AISTATS 2020. The budgeted-MAB objective behind `select()`.
- Whittle 1988 (restless bandits); Auer, Cesa-Bianchi, Freund, Schapire 2002
  (UCB1 + EXP3); Thompson 1933; Li et al. WWW 2010 (LinUCB).
- Wang, Hu, Chen, Wang — *Distributed Bandit Learning: Near-Optimal Regret
  with Efficient Communication*, ICLR 2020; Shi et al. — *Federated
  Multi-Armed Bandits*, AAAI 2021. The communicating-arms theory behind
  `export_state`/`merge_state`.
- Kveton et al. — *Cascading Bandits* (KDD 2015). The gated-frontier structure
  `attack_tree.unlocks` implements deterministically.
- Takaesu — *DeepExploit* (A3C-driven exploit chains); CSIRO Data61 — *CAGE
  Challenge*. RL-pentest prior art; both sample-hungry where bandits are
  sample-efficient, which is why the allocation layer here is a bandit.
- Already cited in-repo: Nakano et al. arXiv:2509.07939 and TAP
  arXiv:2312.02119 (`attack_tree.py` header — deterministic structure
  constraining LLM reasoning).

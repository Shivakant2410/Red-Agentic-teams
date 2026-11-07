# The Mathematical Arsenal, Vol. 2 — Beyond Thompson Sampling

*Thirteen theorems with a direct conversion path from paper to running code in this repo. Vol. 1 (`redteam/bandit.py`) covered Beta-Bernoulli Thompson sampling with EPSS/KEV priors and peer state merging; this volume is everything that should sit **around** that engine: certification, stopping, drift, information, budget, coverage, preference, equilibrium, tails, and robustness.*

**Why this exists.** Thompson sampling answers exactly one question — "which arm pays?" — and answers it under an assumption our targets violate (stationarity). An agentic red team needs to *certify* (audit-grade attack-success claims), *stop* (when to quit probing a lead), *detect* (the moment a guardrail shifts), *allocate* (compute as a bankroll), *cover* (diverse failure modes, not the same jailbreak 500 times), *rank* (when the judge only gives preferences), *co-evolve* (adaptive defenders), and *quantify tails* (how bad can it get). Each of those has a theorem. Not a heuristic — a theorem, with constants, that compiles into a module.

---

## 0. The conversion table

| # | Theorem | What it buys you | Plugs into | Effort |
|---|---------|------------------|-----------|--------|
| 1 | Lai–Robbins lower bound + Garivier–Kaufmann optimal BAI (2016) | Audit-grade "best technique" claims with near-minimal probes | `redteam/bandit.py` (new `select_certify` mode), `cellcard.py` publish gate | 2–3 d |
| 2 | Ville's inequality / e-processes (Ramdas et al.) | Dashboards that stay statistically valid under unlimited peeking | `dashboard/`, `cellcard.py` | 1–2 d |
| 3 | Wald–Wolfowitz SPRT optimality | "Jailbroken: yes/no" verdicts with the provably fewest probes | `llmred/` campaigns, `falsify.py` | 1 d |
| 4 | Lorden's CUSUM minimax theorem | Worst-case-bounded alarm when target behavior shifts | `pinning.py` drift alarms, `ratelimit.py` | 1 d |
| 5 | Adams–MacKay BOCPD | Posterior over *when* the target changed, per technique family | `memory.py`, `bandit.py` non-stationarity layer | 2 d |
| 6 | Gittins index optimality; Whittle indexability | Principled handling of arms that change while you sleep; K-parallel agent scheduling | `bandit.py`, `orchestrator.py` | 3–5 d |
| 7 | Russo–Van Roy information ratio (IDS) | Attack to *learn the failure surface*, not just to win one round | `llmred/strategies.py`, `planner.py` | 2–3 d |
| 8 | Weitzman's Pandora's-box theorem + prophet inequality | "Deep-dive this lead or move on?" decided by a root-find, optimally | `planner.py`, `killchain.py` | 2 d |
| 9 | Kelly criterion (log-optimal growth) | Compute budget staking across concurrent attack chains | budget warn / tool-cap (wave 2), `orchestrator.py` | 1 d |
| 10 | Nemhauser–Wolsey–Fisher + Golovin–Krause adaptive submodularity | Greedy coverage is provably ≥ 63.2% optimal — and how to keep it that way | `coverage.py`, `attack_tree.py` | 1 d |
| 11 | Luce's choice axiom / Bradley–Terry + dueling bandits | Rank attack variants from judge *preferences*; detect judge miscalibration as IIA violations | `judgecalib.py` | 2 d |
| 12 | Robinson's fictitious-play convergence; CFR's O(√T); Blackwell approachability | Co-evolution loop vs adaptive defenders; multi-objective attack targets with guarantees | `llmred/` swarm mode, `planner.py` | 4–6 d |
| 13 | Fisher–Tippett–Gnedenko + Pickands–Balkema–de Haan (EVT) | Two-parameter law for the worst-case blast radius; expected shortfall on cell cards | `cellcard.py`, `report.py` | 1–2 d |
| 14 | Kantorovich duality / Wasserstein DRO | Scores that survive prompt-distribution shift, not just the seed set | `bench/`, `cellcard.py` | 2–3 d |
| 15 | Kemeny–Snell absorbing chains; Shapley/Young uniqueness | Exact kill-chain breach probabilities; axiomatically fair credit assignment | `killchain.py`, `credit.py` | 1–2 d |

Everything below gives the theorem, the conversion, runnable pseudocode, and the failure modes. Numeric examples are computed, not hand-waved (verify: `scripts/verify_math_doc.py`).

---

## 1. From regret to certificates: best-arm identification (BAI)

**The theorem.** Thompson sampling minimizes *cumulative regret* — but a red-team audit doesn't care about the rewards it collected; it cares about *naming the strongest technique with confidence*. These are different problems with different mathematics. Lai & Robbins (1985) proved that any policy must, asymptotically, spend at least `ln t / KL(μ_i, μ*)` pulls on every suboptimal arm — regret has an information-theoretic floor. Garivier & Kaufmann (2016) solved the identification analogue: for fixed confidence δ, the minimal number of samples needed to identify the best arm is `T_δ ≈ C*(μ)·ln(1/δ)`, where

```
C*(μ) = Σ_{i≠i*} Δ_i / d(μ_i, μ*)        Δ_i = μ* − μ_i,  d = Bernoulli KL
```

and their **Track-and-Stop** strategy (track the optimal sampling proportions + **Chernoff's stopping rule**) achieves this bound asymptotically — no algorithm can do fundamentally better.

**The conversion.** Two distinct jobs our codebase currently conflates:

1. **Identification** ("which technique family is strongest against this bucket?"): BAI. For a realistic 4-arm pool with ASRs {0.30, 0.20, 0.15, 0.10}, `C* = 8.06`, so **~24 probes total** suffice to name the best arm at δ = 0.05, and ~37 at δ = 0.01. Identification is *cheap*.
2. **Certification** ("the true ASR of technique X is in [p̂−ε, p̂+ε] with probability ≥ 1−δ"): a fixed-width interval costs `n ≥ ln(1/δ)/d(p, p±ε)` — around p = 0.3 with ε = 0.05: **~532 probes** (the naive Hoeffding bound gives 738; the KL bound saves you ~28% — that saving *is* the theorem paying rent).

**Implementation.** Add a certification mode beside `BanditStore.select()`:

```python
def chernoff_stat(arms, best_i, counts):
    # GLR: how plausible is the best ALTERNATIVE hypothesis?
    # z = min over j != best_i of  -KL-weighted log-likelihood ratio
    best = arms[best_i]
    z = min(counts[i] * d(arms[i].mean, best.mean) for i in range(len(arms)) if i != best_i)
    return z

def bai_loop(store, technique, bucket, delta, probe_fn):
    while True:
        z = chernoff_stat(...)
        if z >= math.log((len(arms) - 1) / delta):     # Chernoff stopping
            return certified_answer(...)               # publish-gate passes
        arm = track_stop_sample(store, arms)           # track optimal proportions,
        won = probe_fn(arm)                            # fall back to TS+C-tracking
        store.record(arm, won)
```

Wire the stopping threshold into the **cell-card publish gate** (`cellcard.py`): a card can claim "top technique" only when the Chernoff statistic crossed `ln((K−1)/δ)`, and can state an ASR only with the KL fixed-width interval attached.

**Watch-outs.** BAI assumes the best arm is *uniquely* best; near-ties explode `C*`. Report `C*` itself on the card — it is an honest difficulty score of the target. And never mix the two jobs: running BAI while also trying to minimize regret gives you neither.

---

## 2. Dashboards that survive peeking: e-processes and anytime-valid inference

**The theorem.** Every rolling "pass rate" chart on a red-team dashboard is statistically invalid the moment a human looks at it repeatedly and acts — classical CIs do not tolerate monitoring ("peeking"). The fix is a 1939 theorem doing modern work: **Ville's inequality** — if `E_t` is a nonnegative supermartingale (an *e-process*) with `E_0 = 1`, then `P(∃t: E_t ≥ 1/α) ≤ α`. This yields **confidence sequences**: interval estimates that are simultaneously valid at *every* time point and *every* stopping time (Howard, Ramdas, McAuliffe, Sekhon 2021; Ramdas et al. 2023, "Game-Theoretic Statistics and Safe Anytime-Valid Inference").

**The conversion.** An "always-valid attack-success monitor": the moment the e-process crosses `1/α`, you may *stop and claim* — no correction, no p-hacking guilt, no pre-registered sample size. For a Bernoulli stream of probe outcomes against null rate `p0`, the likelihood-ratio e-process is

```
E_t = Π_i  (p̂_i / p0)^{x_i} · ((1 − p̂_i)/(1 − p0))^{1 − x_i}
```

with any predictable plug-in `p̂_i` (e.g., the running TS posterior mean with a slight downward tilt). Ville then says: if the true success rate is `p0` (target is holding), the monitor crosses `1/α` at most α = 5% of the time — false alarms are controlled *forever, under any stopping rule*.

**Implementation.**

```python
class EProcessMonitor:                       # -> dashboard/ + cellcard gate
    def __init__(self, p0, alpha=0.05):
        self.log_e, self.alpha = 0.0, alpha
    def update(self, x: int, p_hat: float, p0: float):
        self.log_e += x * math.log(p_hat / p0) + (1 - x) * math.log((1 - p_hat) / (1 - p0))
        return math.exp(self.log_e)          # dashboard draws E_t, alarm at 1/alpha
```

For **estimation** (not just testing), pair it with the **empirical Bernstein confidence sequence** (Maurer & Pontil 2009, anytime version): variance-adaptive widths — early wide, tightening as evidence accumulates, valid under continuous redraw of the chart.

**Watch-outs.** Choose `p0` honestly (the pre-registered "acceptable ASR" from the engagement config, not the current running mean — that makes `E_t` drift to ∞ trivially). E-processes test *one* null at a time; multi-arm monitoring needs per-arm e-processes + the same Ville union bound you'd expect.

---

## 3. Minimum-cost verdicts: Wald's SPRT

**The theorem.** The **Sequential Probability Ratio Test** — accumulate `Λ_n = Σ log ℓ(x_i)` and stop when `Λ_n ≥ B` (accept H1) or `Λ_n ≤ A` (accept H0) — is, by the **Wald–Wolfowitz theorem (1948)**, the test with the *smallest expected sample size of all tests* (sequential or fixed) achieving error rates (α, β), for both hypotheses simultaneously. Wald's identity (`E[S_τ] = E[X]·E[τ]` for martingales with bounded stopping) is what makes the analysis exact.

**The conversion.** "Is this technique actually jailbreaking this target, or is the judge hallucinating?" is a two-hypothesis question we currently answer with arbitrary fixed batches. SPRT answers it with the provable minimum of probes, and — crucially — **adapts**: clean targets exit early (benign verdict is reached fast), marginal targets take longer exactly where the evidence is genuinely ambiguous.

Verified example (p0 = 0.10 "effective" vs p1 = 0.30, α = β = 0.05): boundaries `A = −2.944, B = +2.944`; expected length **≈ 17–23 probes**, versus ~19 for a fixed-sample test that *always* spends 19 regardless — and the fixed test can't stop early on an obviously clean target the way SPRT can.

**Implementation.**

```python
def sprt_verdict(stream, p0, p1, alpha=0.05, beta=0.05):
    A, B = math.log(beta / (1 - alpha)), math.log((1 - beta) / alpha)
    log_lr = 0.0
    for x in stream():                                # 1 = judge-confirmed success
        log_lr += x * math.log(p1 / p0) + (1 - x) * math.log((1 - p1) / (1 - p0))
        if log_lr >= B: return "SUCCESS_CERTIFIED"
        if log_lr <= A: return "NOT_EFFECTIVE"
    # budget exhausted -> report "inconclusive, log_lr=..." (never fake a verdict)
```

Drop-in for `llmred` campaign verdicts and for `falsify.py`: the negative-control path is exactly an H0 test (`p0` = control pass rate), so a control "passing" the SPRT is a *certified instrumentation failure*, not noise.

**Watch-outs.** SPRT is only as honest as (p0, p1): derive them from `priors.py` class priors and past cells, and pin them in the cell card. Overshoot past the boundary is normal (Wald's overshoot); the expected overshoot is bounded and doesn't break the guarantees.

---

## 4. Bounded-delay drift alarms: CUSUM (Lorden's minimax theorem)

**The theorem.** When the target's behavior *changes* — a guardrail hotfix lands, a WAF rule is deployed, a session-warming pattern starts being refused — the question is not "did it change?" but "how fast can I know?" Page's **CUSUM** (cumulative sum of log-likelihood ratios, reset on alarm) was proven minimax-optimal by **Lorden (1971)**: among all alarms with a given false-alarm period ARL γ, CUSUM minimizes the *worst-case* detection delay, which is

```
E[delay] ≈ ln γ / KL(p_post || p_pre)
```

**The conversion — and we already own half of it.** Wave 2 added drift alarms in `pinning.py`. Lorden's theorem converts that feature from a heuristic into a *guarantee*: with pre-change success rate 0.10 and post-change 0.30 (the guardrail got *better* against us), KL = 0.1537, so at ARL = 500 false alarms are ≥ 500 probes apart **and** detection takes ≤ ~41 probes in the worst case. That pair of numbers (false-alarm period, delay bound) belongs on the alarm config itself — it's a tunable trade-off with a closed form, not folklore.

**Implementation.**

```python
class CusumDriftAlarm:                        # -> pinning.py / ratelimit.py
    def __init__(self, p_pre, p_post, gamma=500):
        self.k = math.log(p_post / p_pre)     # per-observation log-LR under drift
        self.h = math.log(gamma)              # threshold; delay <= ln(gamma)/KL
        self.s = 0.0
    def update(self, x):                      # x = 1 if probe succeeded
        self.s = max(0.0, self.s + (self.k if x else math.log((1-p_post)/(1-p_pre))))
        return self.s >= self.h               # alarm -> re-plan, re-seed priors
```

**The Bayesian sibling.** **BOCPD** (Adams & MacKay 2007) replaces the single alarm with a full *run-length posterior* `P(r_t = r | x_{1:t})` updated in O(1) per observation under conjugate models — for us, Beta-Bernoulli is conjugate, so it composes *directly* with `ArmState`. The payoff: per technique family, a probability distribution over "how long has the current regime been running", which is exactly the feature a non-stationary bandit should condition on (§5). Keep CUSUM for cheap per-bucket alarms; use BOCPD where the *timing* of the change matters (post-mortems, "the defense shifted 3 probes after we published the card").

**Watch-outs.** CUSUM assumes you can name both regimes (p_pre, p_post). When you can't, BOCPD with a Student-t / Beta predictive is the answer. And set ARL by budget, not vibes: γ ≈ expected probes between genuine changes.

---

## 5. Arms that move while you sleep: Gittins indices and restless bandits

**The theorem.** Gittins (1979): for a *discounted* Bayesian bandit, the myopic rule "play the arm with the highest **Gittins index**" — a per-arm dynamic-programming value independent of all other arms — is exactly optimal (Whittle's proof 1980; Weber's 1992 proof is the beautiful one). This is miraculous and fragile: optimality dies the moment arms interact or *change on their own*. **Restless bandits** (arms whose states evolve even when unobserved — every security target ever) have no exact per-arm solution, but **Whittle (1988)** restored index policies: if the problem is *indexable*, the **Whittle index** (the subsidy-for-passivity that makes you indifferent between activating an arm and leaving it alone) is asymptotically optimal as the number of arms/budget grows (Weber & Weiss 1990).

**The conversion.** `BanditStore` currently assumes arms are stones — `ArmState.mean` only moves when we pull. Reality: target states drift (§4), sessions expire, defenses re-roll. Two upgrades, in increasing ambition:

1. **Practical non-stationarity (1 day):** discounted / sliding-window Thompson sampling (Garivier & Moulines 2011) — decay old evidence with factor γ ≈ 0.95 or window W ≈ 50–200 probes. Not a theorem-grade fix, but the standard, cheaply correct first move.
2. **The restless formulation (3–5 days):** each (technique, bucket) arm = a 2-state Markov chain (defense_up / defense_down) with transition probabilities; budget = K concurrent agent slots (we already swarm). Whittle index = solve the 2-state DP per arm, activate the K arms with top indices. The literature warns honestly: indexability is *not* automatic and Whittle policies can fail on pathologic instances (Ghosh et al. 2023) — so validate against random-policy and oracle baselines on our bench matrix before trusting it.

**Why Gittins still matters even if we never compute one:** it is the *conceptual* certificate that per-arm greedy myopia is not always a hack — under discounting, "exploit the best-looking arm now, one step at a time" is *optimal*. Our `_suspicion_adjust` hook (which tilts draws away from arms that look too good) is precisely a deviation from myopia, and Gittins' theorem is the reminder that such deviations need a *reason* (non-stationarity, risk) — otherwise TS is already the right answer.

**Watch-outs.** Never build the full Gittins DP for Bernoulli arms — discounted TS is within small constant regret of it and is 50 lines. Restless bandits: budget-coupling is the whole point; if your K agents don't actually share a budget, you're just running K independent bandits.

---

## 6. Attack to learn, not just to win: information-directed sampling

**The theorem.** Russo & Van Roy (2014/2018) define the **information ratio** of a policy:

```
Γ_t = E[single-period regret Δ_t]² / I(A*; Y_t)
```

— squared expected regret over the mutual information the observation carries about the *optimal action*. Thompson sampling in bandits has **Γ ≤ 2**, yielding Bayes regret `O(√(H·T))` (H = posterior entropy of the optimal arm). **Information-directed sampling** picks the action minimizing `Δ_t(a)² / I(a)` and drives the information ratio toward 1 — provably at least as good as TS, and *dramatically* better exactly when some actions are informative but not lucrative (their Figure-1-style example: two arms with identical means, where TS randomizes forever and IDS finishes in ~2 pulls).

**The conversion.** Our arms are technique×bucket pairs, but the *observations* are rich: response diffs, status codes, reflected markers, judge rationales. A probe that "fails" can still be hugely informative (it tells us the WAF pattern that killed it, which upgrades five sibling techniques). IDS makes that trade legal: choose the attack minimizing expected-regret-squared per nat of information about where the vulnerability surface is.

**Implementation sketch** (belief = Beta posteriors we already maintain):

```python
def ids_select(arms, store, mc=200):           # -> llmred/strategies.py
    # 1) posterior over which arm is optimal
    samples = [store.sample(a) for a in arms for _ in range(mc // len(arms))]
    best_dist = Counter(argmax(sample) for sample in chunk(samples, mc))
    H_best = entropy(best_dist)                 # H(A*)
    # 2) for each candidate action: expected one-step regret + expected drop in H(A*)
    best = None
    for a in arms:
        d_reg = expected_regret(a, arms, store)             # E[max_mu - mu_a]
        d_info = expected_entropy_drop(a, arms, store)      # E[H_best - H_best | Y_a]
        score = d_reg**2 / max(d_info, 1e-9)                # the information ratio
        if best is None or score < best.score: best = (a, score)
    return best.a
```

The Monte-Carlo inner loop reuses `store.sample()` as-is; no new belief machinery. Nested Monte Carlo for exact **expected information gain** (EIG) is the full-fidelity upgrade (Foster et al. 2021, unified stochastic-gradient Bayesian experimental design) — start with the cheap version above.

**Watch-outs.** IDS costs a posterior-simulation per decision — batch decisions per turn, not per probe. And don't let pure information-seeking take over: the regret term in the ratio is what keeps the campaign converging on *wins*.

---

## 7. "Deep-dive or move on?": Pandora's box and the prophet bound

**The theorem.** Weitzman's **Pandora's box** (1979) is the cleanest optimal-stopping result in economics: you face boxes; opening box i costs `c_i` and reveals prize `X_i ~ F_i`; you may stop anytime and keep the best prize seen. The optimal policy is *exactly*: compute each box's **reservation value** `z_i` — the number where you're indifferent between stopping and paying `c_i` for one more look —

```
E[(X_i − z_i)⁺] = c_i
```

then open boxes in decreasing `z_i`, and stop when no closed box has `z_i` above the best prize already in hand. Optimality is a theorem, not a heuristic. The arrival-order cousin, the **prophet inequality** (Krengel & Sucheston 1977/78), says any online stopping rule for values revealed in arbitrary order achieves ≥ **1/2** of the offline optimum — and 1/2 is tight.

**The conversion.** This is the red-team planner's daily question, stated mathematically for the first time: a *lead* (e.g., "IDOR on /api/v2/invoices looks promising") has a known probe cost `c` (LLM calls, wall-clock, stealth budget — all already metered in wave 2) and an unknown payoff whose prior we *already have* — the Beta posterior from `ArmState` / `priors.py` seeding. The reservation value is a 1-D root-find on that Beta:

```python
def reservation_value(alpha, beta_, cost):     # -> planner.py
    f = lambda z: beta.expect(lambda x: np.maximum(x - z, 0), args=(alpha, beta_)) - cost
    return brentq(f, 0.0, 1.0)
# Beta(3,5) lead with probe cost 0.02 -> z* = 0.514:
# probe the lead iff z* > best lead's value so far; open leads in decreasing z*.
```

The campaign loop becomes: compute `z*` for every open lead (vectorized over the arm pool — it's one brentq per lead), probe the top one while its `z*` exceeds the value of the best *confirmed* finding, else stop and write the report. The prophet inequality then gives the free-lunch guarantee for the variant where leads arrive over time from recon: even a *greedy* stop-and-deploy rule captures ≥ half the omniscient attacker's value. For the secretary-problem flavor (pure ranking, no costs): observe the first `⌈n/e⌉` ≈ 37% of candidates as calibration, then take the first that beats them all (≥ 1/e ≈ 36.8% chance of the true best).

**Watch-outs.** Reservation values assume independent boxes — correlated leads (same root cause) over-count; cluster leads by `attack_tree.py` ancestry and treat a cluster as one box. Costs `c` must include *stealth* cost, not just compute, or the policy over-probes noisy targets.

---

## 8. Compute is a bankroll: the Kelly criterion

**The theorem.** Kelly (1956): a gambler reinvesting a fraction `f` of wealth on a +b:1 bet with win probability p maximizes long-run exponential growth with

```
f* = (b·p − q) / b,   q = 1 − p
```

and any fixed fraction other than f\* grows *asymptotically slower, almost surely* (Breiman 1961). Over-betting (f > 2f\*) has *negative* growth. The log is not cosmetic: it is exactly "survive to compound" — the utility function of a campaign that dies when its budget hits zero.

**The conversion.** The wave-2 budget warn / tool-cap protects the floor; Kelly sizes the *stakes* above it. Each concurrent attack chain is a bet: stake `f*·B_remaining` tokens/tool-calls, where `p` comes from the Beta posterior (posterior mean — or posterior *lower* credible bound for fractional Kelly, the standard risk-averse variant: stake ½f\* when estimates are noisy, which ours always are) and `b` is the payoff multiple (finding value / probe cost, both already in `cellcard.py` economics). Verified example: p = 0.35, b = 3 → **stake 13.3%** of remaining budget per chain; p = 0.25 with b = 3 → **f\* = 0: abstain** — Kelly says growth-optimality is sometimes *not attacking*, which is the discipline every hand-tuned allocator lacks.

```python
def kelly_stake(post_alpha, post_beta, payoff_mult, frac=0.5):
    p = post_alpha / (post_alpha + post_beta)          # posterior mean
    f = max(0.0, (payoff_mult * p - (1 - p)) / payoff_mult)
    return frac * f                                     # fractional Kelly stake
```

**Watch-outs.** Kelly assumes you can *reset* stakes per round and that p is known — ours is estimated, hence fractional Kelly (½–⅓ is standard). It also assumes independent rounds; chains sharing a root cause are one bet (same clustering as §7).

---

## 9. Greedy coverage is provably near-optimal: adaptive submodularity

**The theorem.** Nemhauser, Wolsey & Fisher (1978): for monotone submodular set functions, greedy under a cardinality budget achieves `(1 − 1/e) ≈ 63.2%` of optimum — the best possible in polynomial time. **Golovin & Krause (2011)** generalize the *entire framework to adaptive policies* (observe-then-act): if the expected utility is **adaptive submodular** and self-revealing, the adaptive greedy policy achieves `(1 − 1/e)` against the *adaptive optimum* — and for stochastic cover targets, `ln(Q/η) + 1` (tight version: Hellerstein & Kletenik, JAIR 2021).

**The conversion.** Diminishing returns in red-teaming *are* submodularity: the 40th XSS probe adds less marginal coverage than the 1st IDOR probe, and `coverage.py` already scores exactly that. The theorem's gift is a *license and a leash*: (a) license — our greedy next-probe selection in `planner.py` is not a hack; against adaptive-submodular utility it is guaranteed within 63.2% of the best possible adaptive policy; (b) leash — the guarantee holds only if the utility is genuinely monotone + submodular, which pins down how to define it: utility = expected number of *distinct* failure modes (attack-tree nodes) confirmed, not raw finding count (double-counting one root cause breaks submodularity — same clustering discipline as §7).

**Implementation.** `coverage.py` + `attack_tree.py`:

```python
def adaptive_greedy_next(candidates, covered_state, budget_left):
    # marginal expected gain = E[ f(S ∪ {probe}) - f(S) | observations so far ]
    return max(candidates, key=lambda c: marginal_gain(c, covered_state))
# stop when max marginal gain < min_gain or budget exhausted;
# report achieved_utility / greedy_upper_bound on the cell card
```

The adaptive-greedy bound is *against the adaptive optimum* — the right benchmark, since an attacker who adapts to responses is exactly what we deploy. (Compare: static greedy only competes with static optima.)

**Watch-outs.** Monotonicity breaks if evidence *devalues* on contradiction (a falsified assumption in `attack_tree.py` removes coverage) — Golovin–Krause tolerate this only under "self-revealing" conditions; when assumptions can be falsified, re-plan from scratch rather than patching the greedy path (that's `falsify.py`'s job feeding back into the planner).

---

## 10. Ranking from a judge's grudge: Luce's axiom, Bradley–Terry, and dueling bandits

**The theorem.** **Luce's choice axiom** (1959): if relative preference is independent of the choice set (IIA), then `P(i beats j) = s_i/(s_i + s_j)` for strengths `s_i` — the **Bradley–Terry model**, the same likelihood behind RLHF reward models and Chatbot Arena's Elo. Consequences we can use: (a) MLE of strengths from pairwise comparisons is consistent, with logistic link; (b) **dueling bandits** (Yue & Joachims; RUCB and descendants) find the Condorcet winner with sample complexity `O(K log(1/δ)/Δ²)` using only *relative* feedback. The modern caveat is even more useful: **Luce's axiom demonstrably fails in Chatbot Arena** (arXiv 2610.19095, 2026) — preference pairs there mix populations and violate IIA, biasing single-score rankings.

**The conversion.** Our judge (`judgecalib.py`) sees full transcripts but expresses *preferences* more reliably than absolute scores ("this jailbreak is more severe than that one" ≫ "this is a 0.7"). Three payments from one theorem:

1. **Ranking attack variants:** run a dueling schedule over `llmred/strategies.py` variants (judge picks the winner of two anonymized transcripts), fit BT strengths, and rank by `s_i` with bootstrap CIs — no fabricated absolute scores.
2. **Judge calibration as IIA diagnostics:** log every judge triple where A>B, B>C, but C≥A (an IIA violation). A low violation rate ≈ calibrated judge; a *rate that spikes on a technique family* is a *machine-checkable signal* that the judge (or the technique's stealth profile) is gaming the comparison — feed it into `judgecalib.py` as a per-family reliability weight.
3. **Elo over time for technique families:** BT/Elo strengths tracked across campaign runs = a drift chart for the *attacker's* arsenal, symmetric to the `pinning.py` drift chart for the defender.

```python
def bt_mle(pairs, n_items, iters=100):        # simple MM update, no deps
    s = np.ones(n_items)
    for _ in range(iters):
        w = np.zeros(n_items)                 # wins
        for i, j in pairs: w[i] += 1
        exp_w = np.array([sum(1/(s[i]+s[j]) for (i2,j2) in pairs if i2==i) +
                          sum(1/(s[j]+s[i]) for (i2,j2) in pairs if j2==i)
                          for i in range(n_items)])
        s = w / np.maximum(exp_w, 1e-9)
    return s / s.sum()
```

**Watch-outs.** BT assumes transitivity; judges (like Arena populations) violate it under context effects — that's not a bug to suppress, it's the §2-calibration signal. Never mix absolute-score arms and pairwise arms in one ranking; convert or stratify.

---

## 11. When the target adapts back: fictitious play, CFR, PSRO, and approachability

**The theorems.** (a) **Robinson (1951):** fictitious play — play best response to the opponent's *empirical history* — has time-average convergence to equilibrium in two-player zero-sum games. (b) **Zinkevich et al. (2007):** Counterfactual Regret Minimization's average strategy converges to Nash at `O(√T)` in two-player zero-sum — the algorithm behind superhuman poker. (c) **PSRO** (Lanctot et al. 2017): iterate meta-games over best-response *policies*; the meta-Nash over the growing policy corpus is the practical large-game answer (survey: arXiv 2403.02227). (d) **Blackwell approachability (1956):** for vector-valued payoffs, a convex target set S is approachable (can be guaranteed in the limsup sense against *any* adversary) iff it satisfies a halfspace condition — and regret-matching strategies approach it. This is the only clean mathematics for *multi-objective* adversarial targets.

**The conversion.** The swarm (`llmred`) vs adaptive target is a genuine game: the defender's filter trains on our past probes, so "what worked" erodes. Four deployable pieces:

1. **Fictitious play (1 day):** the swarm already logs history; add best-response-to-history re-planning and *track exploitability* (value of best response against *our* average strategy — computable by replaying the logged corpus against fresh probes). Convergence of that gap to ~0 is the empirical certificate that our strategy mix is equilibrium-grade.
2. **PSRO over the strategy corpus (2–3 days):** meta-game = techniques × observed defense behaviors; oracle = generate a new best-response prompt family per iteration (`llmred` already generates families); meta-solver = regret matching on the meta-payoff matrix. The corpus *is* the game tree — we're one meta-solver away from PSRO.
3. **CFR-style regret matching inside the swarm (1 day):** replace the current allocation heuristic among technique families with regret matching over realized payoffs — same O(√T) convergence family, trivially implementable (`p_i ∝ [R_i]⁺`).
4. **Approachability for the engagement contract (the sleeper hit):** objective "achieve ASR ≥ a AND stealth ≥ b" is a *set target in vector payoff space*. Blackwell's theorem converts it into a stopping/steering rule: aim each round at the halfspace currently separating you from the target set; when the running average payoff enters S, the contract is *mathematically* met — a stronger claim than "we hit the numbers once".

**Watch-outs.** Zero-sum is the load-bearing assumption (attacker gain = defender loss); with a judge in the loop it's only approximately true — treat equilibrium outputs as strong baselines, not oracles. PSRO's cost lives in the oracle calls; cap iterations by the Kelly stake from §8.

---

## 12. The law of the worst case: extreme value theory

**The theorems.** **Fisher–Tippett–Gnedenko:** block maxima of iid data converge (after normalization) to the GEV family. The workhorse is its POT sibling, **Pickands–Balkema–de Haan (1975):** for a high enough threshold u, the distribution of exceedances `X − u | X > u` converges to a **Generalized Pareto Distribution** `GPD(ξ, β)` — two parameters that fully characterize the tail, *whatever* the body looked like. Tail quantile and expected shortfall then have closed forms:

```
VaR_p   = u + (β/ξ) · [ (χ_u (1−p))^(−ξ) − 1 ]          χ_u = P(X > u)
ES_p    = VaR_p/(1−ξ) + (β − ξu)/(1−ξ)                  (ξ < 1)
```

**The conversion.** "Average severity" is a lie in security reporting — the mean of a heavy-tailed phenomenon. EVT gives cell cards an honest tail block: fit GPD to the upper tail of finding severity (our 0–100 scale, or blast-radius proxy), and report `VaR_0.999` and `ES_0.999` with CIs on (ξ, β). Verified example: u = 6, ξ = 0.3, β = 2, exceedance rate 5% → `VaR_0.999 ≈ 129`, `ES_0.999 ≈ 185`. Read that sentence slowly: *conditional on a 1-in-1000 breach, the expected severity is ~30× the body mean* — that number, with a CI, is what a board actually needs. ξ > 0 (our regime, per the paper's heavy tails) means infinite-variance risk: patching body statistics cannot fix tail risk.

```python
def evt_tail_block(severities, u_q=0.95):     # -> cellcard.py / report.py
    u = np.quantile(severities, u_q)
    exc = severities[severities > u] - u
    if len(exc) < 50: return {"warning": "insufficient exceedances for GPD (need >=50)"}
    xi, _, beta_ = genpareto.fit(exc, floc=0)
    chi_u = (severities > u).mean()
    var = u + (beta_/xi) * ((chi_u * 0.001) ** (-xi) - 1)
    es  = var/(1-xi) + (beta_ - xi*u)/(1-xi)
    return {"xi": ci(xi), "VaR_99.9": var, "ES_99.9": es}
```

**Watch-outs.** EVT's own literature is blunt: **< 50 exceedances → don't fit** (ξ is unidentified; the CI swallows the point); threshold selection needs mean-excess-plot linearity checks; assume iid — cluster correlated exceedances (one root cause = one exceedance, same discipline as §7/§9). Report parameter CIs *always*: "ξ = 0.25 [0.05, 0.45]" and "ξ = 0.25 [0.20, 0.30]" are different risk worlds.

---

## 13. Scores that survive distribution shift: Wasserstein DRO

**The theorem.** **Kantorovich duality** turns optimal transport — the cheapest way to morph one distribution into another — into a sup over Lipschitz potentials; the **Wasserstein distance** `W_p(P, Q)` is the resulting metric. **Mohajerin Esfahani & Kuhn (2018)** showed Wasserstein **distributionally robust optimization** — optimize against the worst distribution within radius ε of the empirical one — is a *tractable convex program*, with finite-sample guarantees: the worst-case objective upper-bounds the true out-of-sample risk with high probability, ε shrinking like `n^(−1/d)`.

**The conversion.** Every cell-card score is currently an average over *our seed set* — an empirical distribution an adaptive target can, in principle, sit just outside. Wasserstein DRO replaces "score on the seeds" with "worst-case score within an ε-ball of the seed distribution":

```
score_robust(technique) = sup over P: W(P, P̂_seeds) ≤ ε  of  E_P[success]
```

For a Bernoulli success indicator this worst case has a clean dual: `score_robust = min over Lipschitz witness f of E_seeds[f] + ε·Lip(f)` — with Lip the radius cost we choose (1 per prompt-perturbation step, matching our fuzz mutations). Operationally: (a) pick ε from the *pinned drift budget* — the same ε that `pinning.py` tolerates before re-fingerprinting; (b) report `score_robust` alongside the empirical ASR; a technique whose gap (robust − empirical) is large is *overfit to the seeds* — exactly the failure the frontier-standoff bench is built to catch.

**Watch-outs.** ε is the model: too small = the seeds again, too large = guarantees nobody believes; choose it from measured seed-set radius (max embedding distance between a seed and its perturbed twins), not from convenience. Full DRO needs a solver; the 80% version — evaluate on the ε-ball generated by our existing fuzz mutations and report the *worst*, not the mean — is one afternoon and is exactly a Monte-Carlo lower bound on the DRO objective.

---

## 14. Structure: kill chains as absorbing Markov chains; credit as Shapley

**Absorbing chains (Kemeny–Snell).** A kill chain with transient states (recon, foothold, escalate) and absorbing states (report / blocked) is an absorbing Markov chain; its **fundamental matrix** `N = (I − Q)^(−1)` gives *exact* quantities we currently simulate: expected steps to absorption (`N·1`), absorption probabilities `B = N·R` (probability this chain ends in "breach" vs "blocked"), variance too. When `killchain.py` stages carry Beta posteriors for transition probabilities, push the posterior *through* the matrix inverse (Monte Carlo over Q draws) and the breach-probability CI falls out — exact linear algebra instead of hope.

**Shapley values (Shapley 1953; Young 1985).** The Shapley value is the *unique* payoff division satisfying efficiency, symmetry, null player, and additivity (Young's theorem) — i.e., `credit.py`'s problem has one axiomatically defensible answer: for agent/prompt-segment attribution of a confirmed finding, credit = average marginal contribution over orderings. Tractable via permutation sampling; report per-node Shapley on multi-agent chain findings so the report says *which sub-step actually carried the breach*, not just that the swarm won.

---

## 15. How the stack composes — and the build order

One campaign pass through the whole arsenal:

```
priors (EPSS/KEV) ──▶ BanditStore (TS / discounted-TS for drift ── §5)
     │                       │
     │                 ids/kelly stake (§6, §8) ◀── budget guard (wave 2)
     ▼                       ▼
 planner.py: Pandora reservation values over leads (§7) + adaptive-greedy
 coverage on attack_tree (§9) ──▶ probes ──▶ CUSUM/BOCPD drift alarms (§4)
                                          │
                            SPRT verdicts (§3) + e-process dashboards (§2)
                                          ▼
                 BAI/Chernoff certification (§1) ──▶ cell-card publish gate
                                          │
        dueling-BT ranking of variants (§10) · PSRO meta-loop vs adaptive target (§11)
                                          ▼
        EVT tail block on severities (§12) · Wasserstein-robust score (§13)
        absorbing-chain breach probability + Shapley attribution (§14)
```

**Build order (each slice ships alone):**

1. **Week 1 — Verdicts and monitors (§3 SPRT, §2 e-processes, §4 CUSUM).** Smallest diff, biggest honesty gain; `falsify.py`, dashboard, `pinning.py` all get guarantees.
2. **Week 2 — Certification (§1 BAI) + publish gate in `cellcard.py` + tail block (§12).** The audit-grade card: certified top technique, KL interval, VaR/ES with CIs.
3. **Week 3 — Allocation (§8 Kelly stakes, §7 Pandora reservation values in the planner).**
4. **Week 4+ — Preference and equilibrium (§10 dueling-BT + IIA diagnostics, §11 regret matching → PSRO), then §5 restless layer and §13 robust scores.**

**Anti-recommendations (what *not* to build, and why the math says so):** no full Gittins DP (discounted TS is within a small constant of it for Bernoulli arms); no Whittle indexability proofs on our arm semantics (indexability can fail even when it holds — validate empirically per §5); no GPD fits below 50 exceedances (§12); no BT rankings mixed with absolute judge scores (§10); no DRO radius chosen by convenience (§13). Each anti-recommendation is a theorem-shaped pothole, not a taste.

---

## References (opened and used)

- Garivier & Kaufmann, *Optimal Best-Arm Identification with Fixed Confidence*, COLT 2016 — https://proceedings.mlr.press/v49/garivier16a.html
- Russo & Van Roy, *Learning to Optimize via Information-Directed Sampling*, arXiv:1403.5556 — https://arxiv.org/abs/1403.5556
- Ramdas et al., *Game-Theoretic Statistics and Safe Anytime-Valid Inference*, 2023; Howard et al. 2021 confidence sequences — https://web.stanford.edu/~aramdas/icml25/ramdas2.pdf
- Whittle-index learning for restless bandits (context for §5): arXiv:2004.14427; Ghosh et al. 2023, *Indexibility is not Enough for Whittle*
- Weitzman's rule, incl. correlated-box variants — Gergatsouli et al. 2023; Beyhaghi & Tardos; *Pandora's Box Over Time*, arXiv:2407.15261
- Golovin & Krause, *Adaptive Submodularity*, COLT 2010/AIJ 2011; Hellerstein & Kletenik, *A Tight Bound for Stochastic Submodular Cover*, JAIR 2021 — https://www.jair.org/index.php/jair/article/view/12368
- Kuhn et al., *Wasserstein DRO*, arXiv:1908.08729 (Mohajerin Esfahani & Kuhn 2018 groundwork)
- PSRO survey, arXiv:2403.02227; *Where Luce's Axiom Fails in Chatbot Arena*, arXiv:2610.19095 (2026)
- EVT practice notes (thresholds, exceedance counts, ES formulas): standard references via POT/GPD literature survey

*Classic theorems cited inline from the primary literature: Lai–Robbins 1985; Wald & Wolfowitz 1948; Wald's identity; Page 1954; Lorden 1971; Adams & MacKay 2007; Gittins 1979; Whittle 1988; Weber & Weiss 1990; Garivier & Moulines 2011; Krengel & Sucheston 1977/78; Kelly 1956; Breiman 1961; Nemhauser–Wolsey–Fisher 1978; Luce 1959; Bradley & Terry 1952; Robinson 1951; Zinkevich et al. 2007; Lanctot et al. 2017; Blackwell 1956; Fisher–Tippett–Gnedenko; Pickands–Balkema–de Haan 1975; Kemeny & Snell 1960; Shapley 1953; Young 1985.*

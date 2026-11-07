# The Mathematical Arsenal, Vol. 2 — Field-Tested Edition

*Every technique in this volume carries a prior-art verdict: which competitor or paper uses it, or — where nobody does — why that gap is our edge. Nothing here was included because it looked clever; the cut list (§16) holds the five entries that didn't survive their evidence check.*

**Research protocol (why you can trust this list).** For each candidate technique we asked four questions in order: (1) *Is anyone shipping it?* — competitor tools (Microsoft PyRIT, NVIDIA garak, Promptfoo) and published attack engines (Rainbow Teaming, TAP, AutoDAN, GCG, CRT). (2) *Is it in the research literature with numbers?* — venue + citations + ASR results. (3) *Does it solve a problem our repo actually has?* — mapped to specific modules (`bandit.py`, `planner.py`, `judgecalib.py`, `cellcard.py`, `pinning.py`). (4) *Is it required, or decoration?* — if no adoption evidence and no unique capability, it got demoted or cut. Techniques that failed question 1 or 2 are quarantined in §16 (cut list).

---

## 0. What the field actually deploys (the evidence base)

**Competitor tools — what their engines really are:**

| Tool | Engine | Math inside | Gap we can own |
|------|--------|-------------|----------------|
| **Microsoft PyRIT** (arXiv:2410.02828) | Multi-turn attack loops (Crescendo, TAP, Skeleton Key built in), converter pipelines (encodings, translation, role-play), LLM/ML scorers, memory | LLM-driven iterative refinement; heuristic stop on scoring thresholds | No statistical stopping theory, no certification, no drift model |
| **NVIDIA garak** | Probe/detector scanner: fires known attack patterns, detects failures | None — static taxonomy scanning | No adaptation at all; the "Nessus of LLMs" by design |
| **Promptfoo** | Plugin catalog + adversarial generation models, purpose-based test generation | Heuristic perturbation strategies | Fixed menus; no budget allocation, no sequential inference |

**Published attack engines — the field's real search algorithms:**

- **MAP-Elites / quality-diversity** — *Rainbow Teaming* (Meta, NeurIPS 2024, arXiv:2402.16822): adversarial prompt generation cast as a QD problem over (risk category × attack style) archives, black-box, open-ended. The single most influential "non-obvious math" in current red teaming.
- **Tree search with pruning** — *TAP* (NeurIPS 2024, arXiv:2312.02119): attacker LLM refines candidates along a tree; **prunes branches unlikely to jailbreak before spending target queries**; >80% jailbreak on GPT-4-class targets with fewer queries than predecessors.
- **Hierarchical genetic algorithm** — *AutoDAN* (ICLR 2024, arXiv:2310.04451, ~1,800 citations): evolutionary search for *stealthy, readable* jailbreaks; descendant AutoDAN-Turbo does lifelong strategy-pool discovery.
- **Greedy coordinate gradient** — *GCG* (arXiv:2307.15043, ~4,900 citations): white-box suffix optimization; the field's gradient baseline.
- **Curiosity/novelty-driven RL** — *CRT* (ICLR 2024, arXiv:2402.19464): intrinsic novelty reward (embedding-density surprise) to push red-team LLMs off repeated failure modes.
- **Bandit-based attack selection — the direct validation of our engine.** *Adaptive Instruction Composition* (arXiv:2604.21159) trains **multi-armed bandits over jailbreak tactics** and reports HarmBench ASR **1.000 (Mistral-7B) / 0.934 (Llama-3-70B)** vs GCG 0.645/0.238, TAP 0.625/0.244, Rainbow Teaming 0.244 (Llama-3), AutoDAN-Turbo 0.976/0.672. *Red-Bandit* (ACL 2026) does test-time bandit adaptation over attack styles. Bandit mutation scheduling is likewise proven in classic fuzzing: **MOPT** (USENIX Security 2019, +170% vulnerabilities over AFL) and **SLOPT** (bandit optimization framework for fuzzing, 2022). *Our `BanditStore` (Beta-Bernoulli TS + EPSS/KEV priors + peer merge) is in published, benchmark-beating company — and these papers validate the exact architecture we already run.*
- **Bayesian optimization for black-box attacks** — Cheng et al. 2024 (arXiv:2405.19098), Lee et al. 2022 (query-efficient BO with block decomposition), GASP (NeurIPS 2025). Information-seeking acquisition is live in the attack literature.

**And the blind spot (verified by the same search):** the *statistics* side of the field is nearly empty. Anthropic's *Adding Error Bars to Evals* (Evan Miller, arXiv:2411.00640, 197 citations) is the one formal entry — and it is **fixed-sample** (CLT intervals, stratification, planning) with no sequential machinery. Sequential **anytime-valid inference, meanwhile, is production-proven in the adjacent world**: Netflix runs it for A/B testing at scale ("Sequential A/B Testing Keeps the World Streaming", Feb 2024), Spotify documented its framework choice in 2023. No red-team tool or paper applies e-processes, SPRT, BAI certificates, or change-point theory to attack campaigns. **That is the widest unoccupied lane this repo is positioned for: competitors industrialized the *search*; nobody has industrialized the *decision theory and guarantees* around it.**

---

## 1. Verdict table (what made the cut, on evidence)

| # | Technique | Verdict | Adoption evidence | Why it matters here |
|---|-----------|---------|-------------------|---------------------|
| 1 | Beta-Bernoulli TS engine (existing) | **KEEP — validated** | AIC arXiv:2604.21159 (beats TAP/GCG); Red-Bandit ACL 2026; MOPT/SLOPT in fuzzing; TensorZero MAB gateway | The field converged on our architecture independently |
| 2 | BAI + Chernoff stopping (certification) | **KEEP — edge** | No RT adoption; Anthropic's stats paper (arXiv:2411.00640) proves demand for rigor, is fixed-sample only | Audit-grade "best technique" cards nobody else can issue |
| 3 | e-processes / anytime-valid monitoring | **KEEP — edge** | Netflix production (2024); Spotify (2023); zero RT adoption | Dashboards that survive unlimited peeking |
| 4 | Wald's SPRT (min-cost verdicts) | **KEEP — edge** | Sequential testing family production-proven; SPRT itself unused in RT | Provably-fewest-probes jailbreak verdicts |
| 5 | CUSUM (Lorden) + BOCPD drift | **KEEP — edge** | CUSUM standard in monitoring/IDS; PyRIT has nothing equivalent | `pinning.py` alarms become delay-bounded guarantees |
| 6 | Restless bandits / discounted TS | **KEEP as formulation** (full Whittle: **demoted**) | No RT adoption; indexability failures documented (Ghosh 2023) | Targets are non-stationary; discounted TS is the honest cheap fix |
| 7 | Information-directed sampling / EIG | **KEEP — bridge to BO adoption** | BO attacks live (arXiv:2405.19098, GASP); IDS unused in RT | Unifies our TS with the field's BO direction |
| 8 | Pandora's box / Weitzman stopping | **KEEP — edge** | No adoption; AIC's "150 attempts then next behavior" is a crude heuristic this theorem formalizes | Turns lead-probing into optimal stopping with our Beta posteriors |
| 9 | Kelly staking | **DEMOTE → optional** | No adoption found in security or ML budgeting | 1-day budget heuristic at most; not required |
| 10 | Adaptive submodularity + MAP-Elites archive | **KEEP — PROMOTED** | Rainbow Teaming (NeurIPS 2024) made QD the field's diversity engine | `coverage.py` is already a crude archive; MAP-Elites is the upgrade |
| 11 | Bradley–Terry / dueling bandits | **KEEP** | Chatbot Arena at planetary scale; IIA failures documented (arXiv:2610.19095) | Judge preference ranking + judge-miscalibration detector |
| 12 | Fictitious play / CFR / PSRO | **KEEP — later phase** | PSRO established in games; LLM-RT co-evolution nascent (AutoDAN-Turbo strategy pools are the seed) | For adaptive defenders, not this quarter |
| 13 | EVT tail risk (GPD/ES) | **KEEP** | EVT standard in cyber-risk quantification; absent from RT reporting | Tail block on cell cards; two parameters for "how bad can it get" |
| 14 | Wasserstein DRO | **KEEP — later phase** | DRO established in robustness; unused in RT evals | Robust scores over prompt neighborhoods |
| 15 | Absorbing chains + Shapley | **KEEP (small)** | Attack-graph Markov models standard in security lit; SHAP universal | Exact kill-chain probabilities; fair multi-agent credit |

Everything below gives: **the theorem → the evidence → the conversion into this repo → the failure modes.** Numeric examples are computed, not hand-waved (`scripts/verify_math_doc.py`).

---

## 2. From regret to certificates: best-arm identification (BAI)

**The theorem.** Thompson sampling minimizes *cumulative regret*; an audit needs something else — *naming the strongest technique with confidence*. Lai & Robbins (1985) proved regret has an information floor (`ln t / KL(μ_i, μ*)` per suboptimal arm). Garivier & Kaufmann (2016, COLT) solved the identification problem: for fixed confidence δ, the minimal sample size to identify the best arm is `T_δ ≈ C*(μ)·ln(1/δ)`, `C*(μ) = Σ_{i≠i*} Δ_i / d(μ_i, μ*)`, achieved by **Track-and-Stop** with **Chernoff's stopping rule** — asymptotically optimal, so no algorithm can fundamentally beat it.

**The evidence.** No red-team tool or paper does BAI — verified. The closest published position is Anthropic's *Adding Error Bars to Evals* (arXiv:2411.00640), which argues evals are experiments and should carry proper intervals — but stays in fixed-sample CLT territory. BAI is the sequential successor: same rigor, ~10× fewer probes, and a *stopping* rule Anthropic's paper explicitly lacks. This is our differentiator, not our decoration.

**The conversion.** Two distinct jobs `BanditStore` currently conflates:

1. **Identification** ("strongest technique vs this bucket"): for ASRs {0.30, 0.20, 0.15, 0.10}, `C* = 8.06` → **~24 probes total** at δ = 0.05, ~37 at δ = 0.01. Identification is *cheap*.
2. **Certification** ("ASR of technique X in [p̂−ε, p̂+ε] w.p. ≥ 1−δ"): costs `n ≥ ln(1/δ)/d(p, p±ε)` — around p = 0.3, ε = 0.05: **~532 probes** (Hoeffding gives 738; the KL bound saves ~28% — that saving *is* the theorem paying rent).

```python
def chernoff_stat(arms, best_i, counts):
    best = arms[best_i]
    return min(counts[i] * d(arms[i].mean, best.mean)
               for i in range(len(arms)) if i != best_i)

def bai_loop(store, technique, bucket, delta, probe_fn):
    while True:
        if chernoff_stat(...) >= math.log((len(arms) - 1) / delta):
            return certified_answer(...)        # publish-gate passes
        arm = track_stop_sample(store, arms)
        store.record(arm, probe_fn(arm))
```

Wire the Chernoff threshold into the **cell-card publish gate** (`cellcard.py`): a card claims "top technique" only when the statistic crossed `ln((K−1)/δ)`, and states an ASR only with the KL fixed-width interval attached.

**Watch-outs.** BAI needs a *uniquely* best arm; near-ties explode `C*` — report `C*` on the card as the honest difficulty score. Never run BAI and regret-minimization in the same loop; they are different objectives.

---

## 3. Dashboards that survive peeking: e-processes and anytime-valid inference

**The theorem.** Every rolling pass-rate chart is invalid the moment a human repeatedly looks and acts — classical CIs don't tolerate monitoring. **Ville's inequality (1939)**: a nonnegative supermartingale (e-process) `E_t` with `E_0 = 1` satisfies `P(∃t: E_t ≥ 1/α) ≤ α`. That yields **confidence sequences** valid at *every* time and *every* stopping time (Howard, Ramdas, McAuliffe, Sekhon 2021; Ramdas et al. 2023).

**The evidence.** This is not academic decoration — **Netflix runs anytime-valid sequential testing in production** ("Sequential A/B Testing Keeps the World Streaming", Feb 2024, including their NeurIPS paper methodology for count metrics), and **Spotify's engineering team publicly compared sequential-testing frameworks** in 2023. Adoption exists; the red-team world simply hasn't connected it. Zero tools, zero papers — verified. First mover wins the "auditable live monitoring" claim.

**The conversion.** Always-valid attack-success monitor: for probe outcomes against null rate `p0`, accumulate `E_t = Π (p̂_i/p0)^{x_i}((1−p̂_i)/(1−p0))^{1−x_i}`; alarm at `E_t ≥ 1/α` — false alarms controlled *forever, under any stopping behavior*.

```python
class EProcessMonitor:                        # -> dashboard/ + cellcard gate
    def __init__(self, p0, alpha=0.05):
        self.log_e, self.alpha = 0.0, alpha
    def update(self, x: int, p_hat: float, p0: float):
        self.log_e += x*math.log(p_hat/p0) + (1-x)*math.log((1-p_hat)/(1-p0))
        return math.exp(self.log_e)           # alarm at 1/alpha, valid at any t
```

Pair with **empirical Bernstein confidence sequences** (Maurer & Pontil 2009; anytime versions) for estimation: variance-adaptive widths, valid under continuous redraw.

**Watch-outs.** `p0` must be the pre-registered acceptable ASR from engagement config — using the running mean makes `E_t` drift to ∞ trivially. Multi-arm monitoring = per-arm e-processes + Ville union bound.

---

## 4. Minimum-cost verdicts: Wald's SPRT

**The theorem.** The **SPRT** — accumulate `Λ_n = Σ log ℓ(x_i)`, stop at `Λ_n ≥ B` (accept H1) or `≤ A` (accept H0) — is, by the **Wald–Wolfowitz theorem (1948)**, the test with the smallest expected sample size of *all* tests (sequential or fixed) achieving error rates (α, β), for both hypotheses simultaneously.

**The evidence.** The sequential-testing family SPRT belongs to is production-proven (Netflix, Spotify — §3), but SPRT itself is unused in any red-team tool: PyRIT's attack loops stop on heuristic scoring thresholds, garak runs fixed probe sets, Promptfoo runs fixed menus. Nobody else can say "verdict reached with the provably minimal number of target queries."

**The conversion.** "Is this technique actually jailbreaking, or is the judge hallucinating?" Verified example (p0 = 0.10 vs p1 = 0.30, α = β = 0.05): boundaries `A = −2.944, B = +2.944`; expected length **≈ 17–23 probes** vs ~19 for a fixed test that *always* spends 19 — and SPRT exits early on obviously-clean targets where the fixed test cannot.

```python
def sprt_verdict(stream, p0, p1, alpha=0.05, beta=0.05):
    A, B = math.log(beta/(1-alpha)), math.log((1-beta)/alpha)
    log_lr = 0.0
    for x in stream():                     # 1 = judge-confirmed success
        log_lr += x*math.log(p1/p0) + (1-x)*math.log((1-p1)/(1-p0))
        if log_lr >= B: return "SUCCESS_CERTIFIED"
        if log_lr <= A: return "NOT_EFFECTIVE"
    # budget exhausted -> "inconclusive" (never fake a verdict)
```

Drop-in for `llmred` campaign verdicts and `falsify.py`: the negative-control path *is* an H0 test — a control "passing" the SPRT is a certified instrumentation failure, not noise.

**Watch-outs.** (p0, p1) must be derived from `priors.py` class priors and past cells, and pinned in the cell card. Wald overshoot is bounded and harmless.

---

## 5. Bounded-delay drift alarms: CUSUM (Lorden) + BOCPD

**The theorem.** Page's **CUSUM** (cumulative log-likelihood-ratio sum, reset on alarm) is minimax-optimal by **Lorden (1971)**: among all alarms with false-alarm period ARL γ, it minimizes worst-case detection delay `≈ ln γ / KL(p_post ‖ p_pre)`.

**The evidence.** CUSUM is decades-proven in network intrusion detection and industrial monitoring — the *defensive* side of our field uses it routinely. On the *offensive* side: nothing. PyRIT has no drift model at all (its loops just keep going); no competitor notices when a guardrail shifts mid-campaign. Wave 2's `pinning.py` drift alarms are the right instinct; Lorden's theorem converts them from heuristic to *guarantee*: with pre-change success 0.10 → post-change 0.30, KL = 0.1537, ARL = 500 → false alarms ≥ 500 probes apart **and** detection in ≤ ~41 probes, worst case.

```python
class CusumDriftAlarm:                     # -> pinning.py / ratelimit.py
    def __init__(self, p_pre, p_post, gamma=500):
        self.k = math.log(p_post/p_pre)
        self.h = math.log(gamma)
        self.s = 0.0
    def update(self, x):
        self.s = max(0.0, self.s + (self.k if x else math.log((1-p_post)/(1-p_pre))))
        return self.s >= self.h            # alarm -> re-plan, re-seed priors
```

**BOCPD** (Adams & MacKay 2007) is the Bayesian sibling: a run-length posterior `P(r_t | x_{1:t})`, O(1) per observation under conjugate models — Beta-Bernoulli *is* conjugate, so it composes directly with `ArmState`. Use CUSUM for cheap per-bucket alarms; BOCPD where *when* the change happened matters (post-mortems: "the defense shifted 3 probes after we published the card").

**Watch-outs.** CUSUM needs both regimes named; when you can't, BOCPD. Set ARL by expected probes between genuine changes, not vibes.

---

## 6. Arms that move while you sleep: non-stationarity (restless bandits, honestly)

**The theorem.** Gittins (1979): for *discounted Bayesian* bandits, a per-arm index rule is exactly optimal (Weber's 1992 proof is the beautiful one). Whittle (1988) extended index policies to **restless bandits** — arms that evolve unobserved — with asymptotic optimality under indexability (Weber & Weiss 1990). Ghosh et al. (2023) showed indexability can fail on simple, realistic instances.

**The evidence — and why we demoted the full machinery.** No red-team work formulates targets as restless bandits; nobody computes Whittle indices; and the failure-mode literature says building them without an indexability proof is a trap. What the evidence *does* support: the AIC paper's bandits retrain against current guardrails (stationary assumption baked in), and every practitioner knows targets shift (§5). So: **keep the formulation (targets are restless), use discounted/sliding-window Thompson sampling** (Garivier & Moulines 2011) as the honest cheap fix — decay old evidence at γ ≈ 0.95 or window W ≈ 50–200 probes — and leave full Whittle indexability off the roadmap.

**The conversion.** `ArmState.mean` currently only moves when we pull. Add decay in `BanditStore.record()`/`sample()`:

```python
def decay(self, factor: float = 0.95):     # called on every record, all arms
    for arm in self.arms: arm.alpha *= factor; arm.beta *= factor
```

**Watch-outs.** Decay trades bias for responsiveness — too fast and rare-but-real techniques get forgotten; tie the factor to the §5 CUSUM alarm rate (drift-heavy targets decay faster). And the Gittins lesson stands: `_suspicion_adjust` deviations from myopia need a *reason* (non-stationarity, risk) — pure TS is otherwise already right.

---

## 7. Attack to learn, not just to win: information-directed sampling

**The theorem.** Russo & Van Roy define the **information ratio** `Γ = E[Δ²] / I(A*; Y)` — squared regret over mutual information gained about the optimal action. Thompson sampling has `Γ ≤ 2` (bandit case); **IDS** minimizes the ratio and drives it toward 1, dramatically outperforming TS exactly when some actions are informative but not lucrative.

**The evidence.** Information-seeking acquisition is already in the attack literature via **Bayesian optimization attacks**: Cheng et al. 2024 (arXiv:2405.19098, black-box attacks via BO), Lee et al. 2022 (query-efficient BO with block decomposition), GASP (NeurIPS 2025). Those papers use GP posteriors + acquisition functions; IDS is the bandit-native cousin that runs on *our existing Beta posteriors* — no new machinery. Nobody in RT uses IDS itself; the BO adoption proves the direction, IDS is how we get it without a GP.

**The conversion.** A probe that "fails" still teaches the WAF pattern that killed it — upgrading five sibling techniques. IDS makes that trade legal:

```python
def ids_select(arms, store, mc=200):           # -> llmred/strategies.py
    samples = [store.sample(a) for a in arms for _ in range(mc // len(arms))]
    best_dist = Counter(argmax(s) for s in chunk(samples, mc))
    H_best = entropy(best_dist)
    return min(arms, key=lambda a: expected_regret(a, arms, store)**2
                             / max(expected_entropy_drop(a, arms, store), 1e-9))
```

The inner loop reuses `store.sample()` as-is. Full-fidelity upgrade later: nested Monte Carlo EIG (Foster et al. 2021).

**Watch-outs.** IDS costs posterior simulation per decision — batch per turn. The regret term keeps campaigns converging on wins, not curiosity for its own sake.

---

## 8. "Deep-dive or move on?": Pandora's box (Weitzman) and the prophet bound

**The theorem.** Weitzman (1979): boxes with opening costs `c_i` and prizes `X_i ~ F_i`; the **optimal** policy computes each box's **reservation value** `z_i` (indifference point: `E[(X_i − z_i)⁺] = c_i`), opens boxes in decreasing `z_i`, stops when no closed box beats the best prize in hand. The **prophet inequality** (Krengel & Sucheston 1977/78) bounds the arrival-order variant: any stopping rule gets ≥ **1/2** of the offline optimum, tight.

**The evidence.** No adoption in red teaming — and here the *absence* is diagnostic: the AIC bandit paper moves to the next behavior "after 150 attempts," a crude fixed-cap heuristic where Weitzman's rule would be *optimal*. Same for TAP's pruning (heuristic judgment calls) and PyRIT's thresholds. Optimal stopping under probe cost is an open lane with a 47-year-old closed-form answer.

**The conversion.** A lead ("IDOR on /api/v2/invoices looks promising") has a probe cost `c` (already metered — wave 2 budget/tool-cap) and a payoff prior we *already maintain* (Beta from `ArmState`/`priors.py`). Reservation value = one root-find:

```python
def reservation_value(alpha, beta_, cost):     # -> planner.py
    f = lambda z: beta.expect(lambda x: np.maximum(x - z, 0), args=(alpha, beta_)) - cost
    return brentq(f, 0.0, 1.0)
# Beta(3,5), cost 0.02 -> z* = 0.514: probe iff z* > best confirmed value so far.
```

Campaign loop: compute `z*` per lead, probe the top while it beats the best confirmed finding, else write the report. The prophet bound covers leads arriving from recon: even a greedy stop-and-deploy captures ≥ half the omniscient attacker's value. Secretary-problem flavor: observe the first `⌈n/e⌉` ≈ 37% as calibration, then take the first that beats them all (≥ 1/e ≈ 36.8% chance of the true best).

**Watch-outs.** Reservation values assume independent boxes — cluster correlated leads by `attack_tree.py` ancestry. Costs must include stealth, or the policy over-probes noisy targets.

---

## 9. Compute as a bankroll: Kelly staking *(demoted: optional)*

**The theorem.** Kelly (1956): the log-optimal stake fraction is `f* = (bp − q)/b`; any other fixed fraction grows asymptotically slower, almost surely (Breiman 1961); f > 2f\* has negative growth.

**The evidence — and the demotion.** Honest answer to "is anyone using this?": **no** — not in security tooling, not in ML budgeting. It survives here as an *optional, one-day* sizing rule for the wave-2 budget guard, because the mathematics is sound and the current alternative (hand-tuned caps) has no theory at all — but it failed the adoption test, so it stays out of the critical path. Verified example: p = 0.35, b = 3 → stake 13.3% of remaining budget; p = 0.25, b = 3 → **f\* = 0: abstain** (growth-optimality sometimes means not attacking).

```python
def kelly_stake(post_alpha, post_beta, payoff_mult, frac=0.5):
    p = post_alpha / (post_alpha + post_beta)
    return frac * max(0.0, (payoff_mult * p - (1 - p)) / payoff_mult)
```

**Watch-outs.** With estimated p, use fractional Kelly (½–⅓). Chains sharing a root cause are one bet (cluster as in §8). If week-3 bandwidth is tight, cut this first — nothing else depends on it.

---

## 10. Diversity with a guarantee: adaptive submodularity and the MAP-Elites connection

**The theorem.** Nemhauser, Wolsey & Fisher (1978): greedy for monotone submodular objectives achieves `(1 − 1/e) ≈ 63.2%` of optimum — best possible in polynomial time. **Golovin & Krause (2011)** extend to adaptive policies: adaptive greedy is `(1 − 1/e)` vs the *adaptive* optimum; stochastic cover variant `ln(Q/η) + 1` (tight: Hellerstein & Kletenik, JAIR 2021).

**The evidence.** The field's diversity engine is **quality-diversity**: Rainbow Teaming (Meta, NeurIPS 2024) runs MAP-Elites over (risk × style) archives and is now the reference black-box method; CRT achieves diversity via curiosity rewards. MAP-Elites = archive + novelty + elitist selection — with *no coverage guarantee* beyond its heuristic. Submodular greedy is the *guaranteed* cousin: same "maximize marginal diversity" instinct, plus a theorem. Both target the same failure: the AIC bandit paper's own metrics show attackers converge on few effective tactics unless diversity is engineered.

**The conversion — promote this one.** `coverage.py` + `attack_tree.py` already score marginal coverage; two upgrades:

```python
def adaptive_greedy_next(candidates, covered_state, budget_left):
    return max(candidates, key=lambda c: marginal_gain(c, covered_state))
# stop when max marginal gain < min_gain or budget exhausted
```

1. **Guarantee tier (1 day):** make the utility genuinely monotone-submodular (count *distinct* confirmed attack-tree nodes, never double-count root causes) — then the greedy planner carries a 63.2%-of-adaptive-optimal certificate it can print.
2. **Archive tier (2–3 days):** add a MAP-Elites archive keyed by (behavior × technique-family), each cell keeps its elite prompt — Rainbow Teaming-style — feeding the bandit a *diversity-forced* action set instead of free TS exploration.

**Watch-outs.** Monotonicity breaks when `falsify.py` invalidates assumptions — re-plan from scratch rather than patching the greedy path. The archive tier costs storage; cap cells by behavior count, not unbounded.

---

## 11. Ranking from a judge's grudge: Bradley–Terry, dueling bandits, and the IIA detector

**The theorem.** **Luce's choice axiom** (1959): if relative preference is context-independent (IIA), `P(i beats j) = s_i/(s_i + s_j)` — the **Bradley–Terry model**, the likelihood behind Chatbot Arena's ratings and RLHF reward models. MLE is consistent; **dueling bandits** find the Condorcet winner from relative feedback at `O(K log(1/δ)/Δ²)`. And the caveat is a feature: **Luce's axiom demonstrably fails in Chatbot Arena** (arXiv:2610.19095, 2026) — population mixing violates IIA and biases single-score rankings.

**The evidence.** Bradley–Terry is the most-adopted preference mathematics on earth (Arena-scale); dueling bandits are established in ranking/recommendation. In red teaming: nobody ranks attack variants from judge preferences — tools use absolute Likert scores (PyRIT scorers) or binary classifiers (LlamaGuard, HarmBench classifier), with no preference model and no consistency check.

**The conversion — three payments from one theorem, all landing in `judgecalib.py`:**

1. **Rank attack variants from pairwise judge verdicts** (judge sees two anonymized transcripts, picks the winner; BT strengths give the ranking with bootstrap CIs — no fabricated absolute scores).
2. **Judge miscalibration detector via IIA violations:** log every A>B, B>C, C≥A triple. Low violation rate ≈ calibrated judge; a violation rate that *spikes on one technique family* is machine-checkable evidence the judge (or that family's stealth profile) is gaming comparisons — feed it back as a per-family reliability weight. This is a *new kind of signal*: competitor tools score; we score the scorer.
3. **Elo-over-time for technique families:** drift chart for the attacker's arsenal, symmetric to `pinning.py`'s defender drift chart.

```python
def bt_mle(pairs, n_items, iters=100):        # MM update, no deps
    s = np.ones(n_items)
    for _ in range(iters):
        w = np.zeros(n_items)
        for i, j in pairs: w[i] += 1
        exp_w = np.array([sum(1/(s[i]+s[j]) for (i2,j2) in pairs if i2==i)
                          + sum(1/(s[j]+s[i]) for (i2,j2) in pairs if j2==i)
                          for i in range(n_items)])
        s = w / np.maximum(exp_w, 1e-9)
    return s / s.sum()
```

**Watch-outs.** IIA violations are signal, not noise — don't suppress them, route them to calibration. Never mix absolute-score and pairwise arms in one ranking.

---

## 12. When the target adapts back: fictitious play, CFR, PSRO *(later phase)*

**The theorems.** Robinson (1951): fictitious play converges (time-average) in two-player zero-sum. Zinkevich et al. (2007): CFR's average strategy converges to Nash at `O(√T)` — the algorithm behind superhuman poker. **PSRO** (Lanctot et al. 2017; survey arXiv:2403.02227): iterate best-response oracles over a growing policy corpus, meta-solve. **Blackwell approachability (1956):** convex vector-payoff targets (e.g., "ASR ≥ a AND stealth ≥ b") are approachable against *any* adversary iff the halfspace condition holds — the only clean math for multi-objective adversarial targets.

**The evidence.** PSRO is established in game-playing RL; in LLM red teaming the co-evolution loop is *nascent but visible*: AutoDAN-Turbo's lifelong strategy-pool discovery and the AIC paper's retrain-against-guardrails loop are both proto-PSRO without the equilibrium machinery. The full game-theoretic stack is real but not yet load-bearing for anyone — right phase: after Weeks 1–3.

**The conversion (when we get there).** (a) Track **exploitability** — best response against *our* logged average strategy — as the convergence certificate. (b) Regret-matching (`p_i ∝ [R_i]⁺`) inside the swarm's family allocation: one day, same O(√T) family as CFR. (c) Approachability for the engagement contract: steer rounds at the separating halfspace; entering the target set is a *mathematical* claim, stronger than "we hit the numbers once."

**Watch-outs.** Zero-sum is load-bearing; with an LLM judge it's only approximately true — treat equilibria as strong baselines, not oracles.

---

## 13. The law of the worst case: extreme value theory

**The theorems.** **Fisher–Tippett–Gnedenko:** block maxima converge to the GEV family. The workhorse is **Pickands–Balkema–de Haan (1975):** beyond a high threshold u, exceedances `X − u | X > u` converge to `GPD(ξ, β)` — two parameters characterize the tail whatever the body does. Closed forms: `VaR_p = u + (β/ξ)[(χ_u(1−p))^(−ξ) − 1]`, `ES_p = VaR_p/(1−ξ) + (β − ξu)/(1−ξ)` (ξ < 1).

**The evidence.** EVT is standard in cyber-risk quantification (loss tails, FAIR-style modeling) and operational risk; the practice literature is explicit about its discipline (≥50 exceedances, threshold stability, parameter CIs). In AI red teaming: nobody reports tail statistics — average severity everywhere, despite everyone acknowledging "the long tail of harms." The reporting gap is real and cheap to own.

**The conversion.** Tail block on cell cards: fit GPD to the severity upper tail, report VaR/ES with CIs. Verified example: u = 6, ξ = 0.3, β = 2, exceedance rate 5% → `VaR_0.999 ≈ 129`, `ES_0.999 ≈ 185` — *conditional on a 1-in-1000 breach, expected severity is ~30× the body mean.* With ξ > 0, patching body statistics cannot fix tail risk.

```python
def evt_tail_block(severities, u_q=0.95):     # -> cellcard.py / report.py
    u = np.quantile(severities, u_q)
    exc = severities[severities > u] - u
    if len(exc) < 50: return {"warning": "insufficient exceedances for GPD"}
    xi, _, beta_ = genpareto.fit(exc, floc=0)
    chi_u = (severities > u).mean()
    var = u + (beta_/xi) * ((chi_u * 0.001) ** (-xi) - 1)
    return {"xi": ci(xi), "VaR_99.9": var, "ES_99.9": var/(1-xi) + (beta_-xi*u)/(1-xi)}
```

**Watch-outs.** < 50 exceedances → don't fit. One root cause = one exceedance (cluster, as everywhere in this doc). Parameter CIs always.

---

## 14. Scores that survive distribution shift: Wasserstein DRO *(later phase)*

**The theorem.** **Kantorovich duality** turns optimal transport into a sup over Lipschitz potentials; **Wasserstein DRO** (Mohajerin Esfahani & Kuhn 2018; Kuhn et al. 2019, arXiv:1908.08729) optimizes against the worst distribution within radius ε of the empirical one — tractable convex program, finite-sample guarantees with ε shrinking as `n^(−1/d)`.

**The evidence.** DRO is established in robust ML; in red-team evaluation, nobody uses it — cell-card scores are plain averages over *our seed set*, exactly the empirical distribution an adaptive target can sit just outside. The 80% version costs an afternoon: evaluate on the ε-ball our existing fuzz mutations generate and report the **worst**, not the mean — a Monte-Carlo lower bound on the DRO objective.

**The conversion.** `score_robust(technique) = sup_{W(P, P̂) ≤ ε} E_P[success]`; report `robust − empirical` gap on the card — a large gap = technique overfit to the seeds (the exact failure the frontier-standoff bench exists to catch). Pick ε from the *pinned drift budget* in `pinning.py`, not convenience.

---

## 15. Structure: absorbing chains for kill chains; Shapley for credit

**Absorbing Markov chains (Kemeny–Snell).** Kill chains with transient states and absorbing outcomes (breach / blocked) have fundamental matrix `N = (I − Q)^(−1)`: exact expected steps `N·1` and breach probabilities `B = N·R` — no simulation needed. Attack-graph Markov modeling is standard security literature (real adoption); pushing Beta posteriors on transition probabilities through the inverse (Monte Carlo over Q) gives `killchain.py` breach-probability CIs by linear algebra instead of hope.

**Shapley values (Shapley 1953; Young 1985).** The *unique* attribution satisfying efficiency, symmetry, null-player, additivity (Young's theorem). SHAP made it the universal explainability tool; `credit.py` can attribute confirmed findings to swarm agents / prompt segments via permutation sampling — the report says *which sub-step carried the breach*, not just that the swarm won.

---

## 16. The cut list (asked for evidence, didn't find it — or found counter-evidence)

- **Full Gittins dynamic programming** — no adoption anywhere in RT or fuzzing; discounted TS achieves the practical benefit within a small constant (§6). Cut the DP, keep the insight.
- **Whittle index policies** — indexability can fail on realistic instances (Ghosh et al. 2023); nobody in this domain validates indexability. Demoted to "formulation only."
- **Kelly staking in the critical path** — zero adoption evidence in security/ML budgeting (§9). Optional, one-day, cut first.
- **Deep PSRO/equilibrium solving now** — the field's co-evolution loops are heuristic; the equilibrium machinery is real but unproven in this domain at production scale. Later phase, gated on Weeks 1–3 results (§12).
- **Gradient-based attacks (GCG-style)** — dominant in literature (4,900 citations) but requires white-box logit access; our doctrine is black-box targets. Out of scope, not out of ignorance.

---

## 17. How the stack composes — and the evidence-first build order

```
priors (EPSS/KEV) ──▶ BanditStore (TS; discounted decay ── §6)
     │                       │
     │              ids/kelly stakes (§7; §9 optional) ◀── budget guard (wave 2)
     ▼                       ▼
 planner.py: Pandora reservation values (§8) + adaptive-greedy coverage
 on attack_tree (§10, MAP-Elites archive tier) ──▶ probes ──▶ CUSUM/BOCPD alarms (§5)
                                          │
                            SPRT verdicts (§4) + e-process dashboards (§3)
                                          ▼
                 BAI/Chernoff certification (§2) ──▶ cell-card publish gate
                                          │
        dueling-BT ranking + IIA judge diagnostics (§11) · later: PSRO loop (§12)
                                          ▼
        EVT tail block (§13) · Wasserstein-robust scores (§14)
        absorbing-chain breach probability + Shapley attribution (§15)
```

**Build order, revised on evidence:**

1. **Week 1 — Verdicts and monitors (§4 SPRT, §3 e-processes, §5 CUSUM).** Smallest diff, biggest honesty gain; the sequential-inference lane Netflix/Spotify validated in production and red teaming ignores entirely.
2. **Week 2 — Certification (§2 BAI + publish gate) and the tail block (§13 EVT).** The audit-grade card: certified top technique, KL interval, VaR/ES with CIs. Plus the 1-day **guarantee tier** of §10 (submodular utility).
3. **Week 3 — Allocation and stopping (§8 Pandora reservation values; §7 IDS); optional §9 Kelly.**
4. **Week 4+ — Diversity and preference (§10 MAP-Elites archive tier; §11 dueling-BT + IIA diagnostics).**
5. **Later — §6 restless formalization, §12 PSRO loop, §14 Wasserstein-robust scores** — gated on Weeks 1–4 results.

**Anti-recommendations (theorem-shaped potholes, not taste):** no full Gittins DP; no Whittle without indexability validation; no GPD below 50 exceedances; no BT rankings mixed with absolute scores; no DRO radius by convenience; no BAI and regret-minimization in one loop.

---

## References (all opened and used in this revision)

**Competitor tools**
- PyRIT: framework docs — https://azure.github.io/PyRIT ; paper — arXiv:2410.02828
- garak (NVIDIA) — https://github.com/NVIDIA/garak ; Databricks writeup (Jul 2025)
- Promptfoo red-team docs (strategies, plugins) — https://www.promptfoo.dev/docs/red-team/strategies

**Published attack engines**
- Rainbow Teaming (MAP-Elites QD), NeurIPS 2024 — arXiv:2402.16822
- TAP: Tree of Attacks with Pruning, NeurIPS 2024 — arXiv:2312.02119
- AutoDAN (hierarchical GA), ICLR 2024 — arXiv:2310.04451
- GCG (greedy coordinate gradient), Zou et al. 2023 — arXiv:2307.15043
- Curiosity-driven Red Teaming, ICLR 2024 — arXiv:2402.19464
- Adaptive Instruction Composition (bandit-based RT, HarmBench results) — arXiv:2604.21159
- Red-Bandit: test-time bandit adaptation, ACL 2026 — https://aclanthology.org/2026.acl-long.2156
- Bayesian-optimization black-box attacks: Cheng et al. 2024 — arXiv:2405.19098 ; Lee et al. 2022 ; GASP, NeurIPS 2025
- MOPT (mutation scheduling), USENIX Security 2019 — https://www.usenix.org/conference/usenixsecurity19/presentation/lyu ; SLOPT bandit-fuzzing framework (Koike, 2022)

**Statistics**
- Evan Miller (Anthropic), *Adding Error Bars to Evals*, Nov 2024 — arXiv:2411.00640 ; https://www.anthropic.com/research/statistical-approach-to-model-evals
- Netflix, *Sequential A/B Testing Keeps the World Streaming*, Feb 2024 — netflixtechblog.com
- Spotify Engineering, *Choosing a Sequential Testing Framework*, 2023 — engineering.atspotify.com
- Where Luce's axiom fails (Chatbot Arena IIA), 2026 — arXiv:2610.19095
- Ramdas et al., *Game-Theoretic Statistics and Safe Anytime-Valid Inference* — https://web.stanford.edu/~aramdas/icml25/ramdas2.pdf

**Theory (primary literature, cited inline)**
- Lai & Robbins 1985; Garivier & Kaufmann COLT 2016 (https://proceedings.mlr.press/v49/garivier16a.html); Wald & Wolfowitz 1948; Wald's identity; Page 1954; Lorden 1971; Adams & MacKay 2007; Gittins 1979; Whittle 1988; Weber & Weiss 1990; Ghosh et al. 2023 (indexability failures); Garivier & Moulines 2011; Russo & Van Roy (arXiv:1403.5341/1403.5556); Foster et al. 2021; Weitzman 1979; Krengel & Sucheston 1977/78; Kelly 1956; Breiman 1961; Nemhauser–Wolsey–Fisher 1978; Golovin & Krause 2011; Hellerstein & Kletenik JAIR 2021 (https://www.jair.org/index.php/jair/article/view/12368); Luce 1959; Bradley & Terry 1952; Robinson 1951; Zinkevich et al. 2007; Lanctot et al. 2017 (survey arXiv:2403.02227); Blackwell 1956; Fisher–Tippett–Gnedenko; Pickands–Balkema–de Haan 1975; Kemeny & Snell 1960; Shapley 1953; Young 1985; Kuhn et al., Wasserstein DRO — arXiv:1908.08729

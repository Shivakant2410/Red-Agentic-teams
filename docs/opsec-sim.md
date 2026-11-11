# OPSEC evaluation harness — measuring the Phase B3 upgrade

`redteam/opsec_sim.py` is the offline instrument that puts numbers on what Phase B3
changed. Phase B3's PR proved interface compatibility (all tests pass) and
directionality (spend drops inside a challenge window). This harness measures HOW
MUCH, at WHAT price, with WHAT recovery time — and separates queue discipline from
the belief filter's contribution.

## What it races

Three controllers over one scripted engagement (quiet → challenge burst → recovery),
all seeing identical candidates and identical progress values:

| Controller | What it is |
|---|---|
| `legacy` | The pre-B3 flat greedy knapsack, reconstructed from git history (`586006a`): per-round allowance resets to full, candidates ranked by the bandit's yield-per-cost, greedy fill. No queue, no belief — no ears. |
| `queue-only` | Ablation: the B3 `DriftPlusPenaltyScheduler` with the belief disabled (`scale=0`). Measures what pure mu/V queue discipline buys. |
| `shipped` | The B3 scheduler exactly as the orchestrator runs it: queue + POMDP blend. |

The defender is a scripted trace of synthetic HTTP responses fed through the
**shipped** signal path — every response goes through
`BeliefFilter.observe_response` (the same `SignalExtractor` + HMM that
`tools/http.py`'s hook feeds in a real run). The loop is closed: a claim sends a
request, only claimed requests produce observations, so a throttled controller also
sees fewer responses — exactly the coupling a real engagement has.

Determinism: no network, no LLM, no clock, no `hash()`; same seed produces
byte-identical output on any machine.

## Run it

```bash
python -m redteam.opsec_sim            # default scenario, human-readable table
python -m redteam.opsec_sim --json     # machine-readable report
python -m redteam.opsec_sim --sweep    # mu x V tuning grid
python -m redteam.opsec_sim --rounds 30 --quiet 10 --challenge 12 --seed 11
```

## Default-scenario results (seed 7, 20 rounds: 7 quiet | 6 challenge | 7 recovery)

```
metric                                      legacy  queue-only   shipped
------------------------------------------------------------------------
spend inside challenge window                 67.0        56.0      44.0
requests sent inside window                     29          29        25
loud claims (cost>=4) inside window              2           0         0
total yield across engagement                20.25       18.58     17.72

challenge-window spend reduction : 34.3% (queue discipline alone: 16.4%, belief adds 17.9pp)
loud-claim reduction in window   : 100.0%
yield retained vs legacy         : 87.5%
recovery lag after window        : 1 round(s)
belief peak risk / end risk      : 0.99 / 0.00
```

Read it like this:

- **During the six rounds the WAF is challenging everything, the shipped swarm
  spends 34% less noise** than the legacy controller facing the identical burst —
  and sends zero loud (cost ≥ 4) claims where legacy still buys two.
- **Half of that reduction is the ears** (17.9 of the 34.3 percentage points are
  attributable to the belief filter reacting, beyond what mu/V discipline alone
  does). The ablation row is the proof: without the belief, queue discipline only
  gets you to −16.4%.
- **The price, stated plainly:** across the whole engagement the shipped controller
  retains 87.5% of legacy yield. The missing ~12% is not waste — it is the debt the
  legacy controller was silently taking on (spending above the sustainable rate mu)
  now priced and paid instead of accumulated.
- **Recovery is real:** one round after the burst ends, volume is back within 90%
  of its quiet baseline, and the belief's risk runs 0.99 at peak → 0.00 at the end.
  The model is never sticky.

## The price when nothing is wrong

An engagement against a target that never reacts (12 all-quiet rounds):

- belief risk never leaves the floor band (< 0.05; measured ~0.4% — the forward
  filter never claims certainty), and spend is **byte-identical** to the
  belief-disabled ablation: the POMDP costs nothing when there is nothing to hear;
- yield retained vs legacy: **89.2%**. The difference is the raw queue committing
  the swarm to sustainable loudness (mu = 2.0) where legacy borrows at the pool's
  mean cost (2.46).

## The mu × V tuning grid (default scenario)

```
  mu      V  window spend -%  yield kept %  recovery lag
 1.00   0.25            91.0%         41.9%          None
 1.00   1.00            91.0%         41.9%          None
 1.00   3.00            91.0%         41.9%          None
 2.00   0.25            34.3%         87.7%             1
 2.00   1.00            34.3%         87.5%             1
 2.00   3.00            34.3%         87.5%             1
 3.00   0.25            34.3%         89.2%             3
 3.00   1.00            34.3%         90.5%             2
 3.00   3.00            32.8%         90.9%             2
```

What the grid teaches (all measured, none asserted):

- **mu is the committed sustainable loudness.** mu = 1.0 commits the swarm to
  probe-only: huge window reduction (−91%) but yield collapses to ~42% and the
  round volume never returns to baseline — allowance = mu admits only cost-1
  claims, whose drift is exactly zero, so the queue never drains. This is the
  measured reason DEFAULT_MU is 2.0 and not "as low as possible".
- **SCALE is the window-depth knob.** At mu = 2 and mu = 3 the window reduction is
  identical (−34.3%): once the belief is fully alerted, `risk·SCALE ≈ 4` caps the
  pressure term and the allowance floor is `max(mu, 12 − 4)` either way. To make an
  alerted defender bite deeper, raise SCALE (per-run via the scheduler's `scale`
  argument), not mu.
- **V moves ordering, not volume.** Its effect shows up in yield retained
  (87.7% → 90.9% as V rises at mu = 3): a higher V chases learned progress harder
  inside the allowance the pressure term already set.

## Honest limitations

- The defender model is a *class* of web defenses (WAF interstitials + 429s), not a
  measurement of one product; the HMM constants are hand-authored by design (see
  `redteam/sandbox/detection_belief.py`). Comparisons are valid because all three
  controllers face the same model; absolute "detections avoided" needs labelled
  engagement telemetry, which is the recalibration path already noted in B3.
- The progress values are a converged bandit stand-in (one fixed draw per
  technique), so this harness measures ordering-and-throttling behavior, not
  bandit learning dynamics. The live-fire bench (`redteam/bench/`) remains the
  integration instrument; this is the unit instrument.
- One primary endpoint per run keeps the latency baselines realistic; a
  multi-endpoint engagement would dilute the per-endpoint latency channel the same
  way it does in production.

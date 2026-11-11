"""Offline, deterministic OPSEC evaluation harness (Phase B4) — the instrument that
MEASURES what Phase B3 changed, instead of asserting it.

Phase B3 replaced the exploit swarm's flat one-shot OPSEC knapsack with a
drift-plus-penalty scheduler driven by a POMDP belief about the defender. That PR
proved interface compatibility (818 tests) and directionality (spend drops inside a
challenge window). What it did NOT do is put a NUMBER on the upgrade: how much less
noise goes into a defending target, what that throttle costs in quiet-phase yield,
how fast the swarm recovers when the defender stands down — and how much of the
reduction is queue discipline versus the belief actually listening. This module
answers that with a controlled, reproducible race:

    legacy controller  vs  scheduler (raw queue only)  vs  scheduler (shipped)
    (pre-B3 flat          (mu/V discipline, belief         (DriftPlusPenaltyScheduler
     greedy knapsack)      disabled — the ablation)         + BeliefFilter, as run)

over a scripted defender trace (quiet -> challenge burst -> recovery), with all
three sides seeing IDENTICAL candidates and IDENTICAL per-technique progress values.

WHAT IS SIMULATED, AND WHY IT IS HONEST
- The defender is a scripted trace of synthetic HTTP responses fed through the
  SHIPPED signal path: every response goes through `BeliefFilter.observe_response`
  — the same `SignalExtractor` + HMM forward filter that `tools/http.py`'s hook
  feeds in a real run. No shortcut observations, no direct risk injection.
- The candidates are the REAL techniques at their REAL OPSEC prices
  (`attack_tree.TECHNIQUE_COST`, domain [1.0, 5.0] — the same ruler DEFAULT_MU and
  DEFAULT_SCALE are calibrated against; the module asserts that domain at import so
  a cost-table change cannot silently invalidate the comparison).
- The closed loop is preserved: a claim SENDS a request, and only claimed requests
  produce observations. When the scheduler throttles, it also sees fewer responses —
  exactly the coupling a real engagement has. The legacy controller keeps spending
  into the challenge burst and keeps getting challenged; it just has no ears.
- Progress values are fixed per technique (a converged bandit: each technique has
  one stable learned yield draw; candidate variety comes from pool composition, not
  re-sampling noise) and shared by all three controllers. Every ordering difference
  is therefore the controller's, not sampling noise.
- The defender's script does not depend on who is asking: response scripts are
  generated once from the regime timeline, before the race. A WAF challenges the
  request, not the intent.

DETERMINISM: no network, no LLM, no clock, no `hash()` (string hashing is
process-randomized in Python), insertion-ordered dicts and `sorted()` canonical
orders only — same seed, same numbers, on any machine, twice.

WHAT THIS IS NOT (the honest boundaries)
- Not a detector-accuracy claim: the HMM constants are hand-authored (see
  detection_belief.py), so absolute risk numbers model a defender class, they do
  not measure one. The COMPARISON is valid because all sides face the same model;
  absolute "detections avoided" needs labelled engagement telemetry.
- Not a replacement for the live-fire bench (redteam/bench/): this harness runs in
  milliseconds, offline — it is the unit instrument for the OPSEC controller; the
  bench is the integration instrument.

Run it:
    python -m redteam.opsec_sim                    # default scenario, human table
    python -m redteam.opsec_sim --json             # machine-readable report
    python -m redteam.opsec_sim --sweep            # mu x V tuning grid
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field

from .attack_tree import TECHNIQUE_COST
from .sandbox.detection_belief import BeliefFilter
from .orchestrator import DriftPlusPenaltyScheduler

# Calibration ruler guard: DEFAULT_MU / DEFAULT_SCALE in orchestrator.py are
# anchored to this table's domain ([1.0, 5.0], see the B3 constant comments). If
# the table ever moves, the comparison loses its ruler — fail loudly here, in the
# one place whose whole job is honest measurement, not silently everywhere.
_COSTS = tuple(TECHNIQUE_COST.values())
assert _COSTS and min(_COSTS) >= 1.0 and max(_COSTS) <= 5.0, (
    "opsec_sim: TECHNIQUE_COST left the [1.0, 5.0] domain the B3 scheduler "
    "constants are calibrated against — recalibrate DEFAULT_MU/DEFAULT_SCALE "
    "and revisit this harness's scenario before trusting its comparisons.")

# A claim whose technique costs this much counts as "loud" — the class of action
# most likely to turn a WAF's scrutiny into a ban.
LOUD_COST = 4.0


# -- scenario: the scripted engagement ---------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    """A scripted engagement: round regimes, budget, candidate pool shape.

    The default tells the story the harness exists for: seven quiet rounds
    (defender asleep), six rounds behind a challenge-everything WAF, seven rounds
    after the defender stands back down."""
    rounds: int = 20
    quiet_prefix: int = 7        # rounds 0..6   — defender quiet
    challenge_span: int = 6      # rounds 7..12  — challenge-everything WAF
    round_budget: float = 12.0   # RunOptions.round_noise_budget's default
    pool_size: int = 8           # candidates offered per round
    seed: int = 7

    def regime(self, round_no: int) -> str:
        if round_no < self.quiet_prefix:
            return "quiet"
        if round_no < self.quiet_prefix + self.challenge_span:
            return "challenge"
        return "recovery"


def _synthesize_response(regime: str, i: int) -> dict:
    """One simulated HTTP response for the i-th claim of a round.

    Quiet/recovery: a normal 200 at a stable per-endpoint latency (the extractor's
    baseline forms, then holds). Challenge: alternating WAF interstitial / 429 with
    Retry-After, at ~4x the endpoint's median latency — the exact channel pattern
    (challenge_present + rate_limit_signal + latency_delta + status shift into 4xx)
    the extractor's marker sets were written for."""
    if regime != "challenge":
        return {"status": 200,
                "elapsed_s": 0.140 + 0.01 * (i % 4),   # stable baseline, mild jitter
                "headers": {"content-type": "application/json"},
                "body": '{"ok": true}'}
    if i % 2 == 0:
        return {"status": 403,
                "elapsed_s": 0.560 + 0.02 * (i % 3),   # ~4x the quiet median
                "headers": {"cf-mitigated": "challenge",
                            "set-cookie": "__cf_bm=challenge-session; path=/"},
                "body": "Attention Required! — checking if you are human"}
    return {"status": 429,
            "elapsed_s": 0.620,
            "headers": {"retry-after": "60"},
            "body": "Too many requests — rate limit exceeded"}


def _endpoint_pool(rng: random.Random, size: int) -> list[dict]:
    """One round's candidate pool: real techniques at their real OPSEC prices,
    targets drawn from a small deterministic set (the sim keeps few endpoints so
    the extractor's per-endpoint latency baselines form)."""
    techniques = sorted(TECHNIQUE_COST)          # sorted: stable across versions
    picks = [techniques[rng.randrange(len(techniques))] for _ in range(size)]
    targets = ["https://target.example/api/v1/login",
               "https://target.example/api/v1/users",
               "https://target.example/api/v1/search"]
    return [{"technique": t,
             "bucket": t.split(".")[0],
             "cost": float(TECHNIQUE_COST[t]),
             "target": targets[rng.randrange(len(targets))]}
            for t in picks]


# -- the three contestants ---------------------------------------------------------------

class FixedDraws:
    """Deterministic stand-in for BanditStore: each technique has ONE fixed
    pseudo-draw in [0, 1) (generated once from the scenario seed, in canonical
    technique order). `sample(technique, bucket)` returns it; the scheduler's
    rank() divides by cost for progress (yield-per-cost) exactly like the real
    bandit, and the legacy controller ranks on the same values. A converged
    bandit, not a sampling one — so ordering differences are the controller's."""

    def __init__(self, seed: int):
        rng = random.Random(seed)
        self._draws = {t: rng.random() for t in sorted(TECHNIQUE_COST)}

    def sample(self, technique: str, bucket: str) -> float:
        return self._draws.get(technique, 0.5)


class LegacyKnapsack:
    """The pre-B3 controller, reconstructed from git history (586006a's NoiseBudget
    semantics + the bandit's yield-per-cost ranking): per-round allowance resets to
    full, candidates ranked by progress (draw/cost) DESCENDING, greedy fill — take
    what fits, skip what doesn't, stop when nothing fits. No queue, no belief, no
    memory: the flat arithmetic Phase B3's docstring calls 'no ears'. Kept here —
    NOT imported — because the shipped class replaced it on purpose; this is the
    control group, frozen at the moment the scheduler superseded it."""

    def __init__(self, total: float):
        self._total = float(total)
        self._remaining = self._total

    def reset(self) -> None:
        self._remaining = self._total     # the whole point: every round starts whole

    def order(self, candidates: list[dict]) -> list[dict]:
        return sorted(candidates, key=lambda c: (-c["progress"], c["technique"]))

    def try_spend(self, cost: float) -> bool:
        if self._remaining >= cost - 1e-9:
            self._remaining -= cost
            return True
        return False

    @property
    def remaining(self) -> float:
        return self._remaining


# -- the run loop ------------------------------------------------------------------------

@dataclass
class ControllerRun:
    controller: str
    spend_by_round: list = field(default_factory=list)
    claims_by_round: list = field(default_factory=list)
    loud_by_round: list = field(default_factory=list)
    yield_by_round: list = field(default_factory=list)
    risk_by_round: list = field(default_factory=list)   # belief risk at round start
    peak_risk: float = 0.0
    total_spend: float = 0.0
    total_yield: float = 0.0
    window_spend: float = 0.0
    window_requests: int = 0
    window_loud: int = 0


def run_controller(kind: str, scenario: Scenario, pool_by_round: list[list[dict]],
                   responses_by_round: list[list[dict]], mu: float, V: float,
                   scale: float) -> ControllerRun:
    """Race one controller over the scenario. `responses_by_round[r][i]` is the
    response the i-th claim of round r receives — generated ONCE up front from the
    regime script only, so all controllers face identical defender behavior and
    differ only in what they DO about it.

    kind: "legacy" (flat knapsack) | "scheduler_raw" (drift-plus-penalty, belief
    disabled — the ablation) | "scheduler" (shipped: queue + POMDP blend)."""
    run = ControllerRun(controller=kind)
    draws = FixedDraws(scenario.seed)

    if kind == "legacy":
        controller = LegacyKnapsack(scenario.round_budget)
        belief = None
    elif kind == "scheduler_raw":
        controller = DriftPlusPenaltyScheduler(
            scenario.round_budget, mu=mu, V=V, scale=0.0,
            bandit=draws, belief=None)
        belief = None
    else:
        belief = BeliefFilter()
        controller = DriftPlusPenaltyScheduler(
            scenario.round_budget, mu=mu, V=V, scale=scale,
            bandit=draws, belief=belief)

    for r in range(scenario.rounds):
        regime = scenario.regime(r)
        pool = [dict(c, progress=draws.sample(c["technique"], c["bucket"])
                     / c["cost"])
                for c in pool_by_round[r]]
        random.Random(scenario.seed * 31 + r).shuffle(pool)   # same shuffle for all

        run.risk_by_round.append(belief.risk_score() if belief is not None else 0.0)
        controller.reset()
        claims = 0
        spend = loud = 0
        yld = 0.0
        # The swarm's claim walk (orchestrator._run_swarm_round): rank the frontier,
        # walk it in order, take what fits, skip what doesn't, re-rank after every
        # claim (the frontier shrank). One simulated request+response per claim.
        remaining = pool
        while remaining:
            ordered = (controller.order(remaining) if kind == "legacy"
                       else controller.rank([(c["technique"], c["bucket"], c["cost"], c)
                                             for c in remaining]))
            claimed = None
            for item in ordered:
                cand = item if kind == "legacy" else item["meta"]
                cost = cand["cost"]
                if not controller.try_spend(cost):
                    continue                  # doesn't fit — a quieter one may
                claimed = cand
                break
            if claimed is None:
                break                          # nothing affordable left this round
            remaining = [c for c in remaining if c is not claimed]
            resp = responses_by_round[r][claims % len(responses_by_round[r])]
            if belief is not None:
                belief.observe_response(claimed["target"], resp["status"],
                                        resp["elapsed_s"], resp["headers"],
                                        resp["body"])
                run.peak_risk = max(run.peak_risk, belief.risk_score())
            claims += 1
            spend += claimed["cost"]
            yld += claimed["progress"]
            if claimed["cost"] >= LOUD_COST:
                loud += 1
        run.spend_by_round.append(spend)
        run.claims_by_round.append(claims)
        run.loud_by_round.append(loud)
        run.yield_by_round.append(yld)
        run.total_spend += spend
        run.total_yield += yld
        if regime == "challenge":
            run.window_spend += spend
            run.window_requests += claims
            run.window_loud += loud
    return run


@dataclass
class SimReport:
    scenario: Scenario
    legacy: ControllerRun
    raw_only: ControllerRun      # ablation: queue discipline without the belief
    scheduler: ControllerRun     # shipped controller: queue + POMDP blend
    quiet_baseline_spend: float        # scheduler's mean quiet-round spend (no warmup)
    challenge_spend_reduction: float   # 1 - scheduler/legacy, window spend
    challenge_spend_reduction_raw: float  # same, for the raw-only ablation
    challenge_loud_reduction: float    # 1 - scheduler/legacy, loud claims in window
    yield_retained: float              # scheduler total yield / legacy total yield
    recovery_lag: int | None           # rounds from window end to >=90% of baseline
    end_risk: float                    # belief risk after the final round

    @property
    def belief_share(self) -> float:
        """Reduction attributable to the belief listening, beyond queue discipline."""
        return self.challenge_spend_reduction - self.challenge_spend_reduction_raw

    def to_dict(self) -> dict:
        def run_dict(run: ControllerRun) -> dict:
            return {"total_spend": round(run.total_spend, 2),
                    "total_yield": round(run.total_yield, 4),
                    "window_spend": round(run.window_spend, 2),
                    "window_requests": run.window_requests,
                    "window_loud": run.window_loud,
                    "spend_by_round": run.spend_by_round,
                    "loud_by_round": run.loud_by_round}
        return {
            "scenario": {"rounds": self.scenario.rounds,
                         "quiet_prefix": self.scenario.quiet_prefix,
                         "challenge_span": self.scenario.challenge_span,
                         "round_budget": self.scenario.round_budget,
                         "seed": self.scenario.seed},
            "legacy": run_dict(self.legacy),
            "scheduler_raw_only": run_dict(self.raw_only),
            "scheduler": {**run_dict(self.scheduler),
                          "risk_by_round": [round(x, 4) for x in
                                            self.scheduler.risk_by_round],
                          "peak_risk": round(self.scheduler.peak_risk, 4)},
            "comparison": {"quiet_baseline_spend":
                               round(self.quiet_baseline_spend, 2),
                           "challenge_spend_reduction_pct":
                               round(100 * self.challenge_spend_reduction, 1),
                           "challenge_spend_reduction_raw_pct":
                               round(100 * self.challenge_spend_reduction_raw, 1),
                           "belief_share_pct": round(100 * self.belief_share, 1),
                           "challenge_loud_reduction_pct":
                               round(100 * self.challenge_loud_reduction, 1),
                           "yield_retained_pct": round(100 * self.yield_retained, 1),
                           "recovery_lag_rounds": self.recovery_lag,
                           "end_risk": round(self.end_risk, 4)},
        }

    def summary(self) -> str:
        s = self.scenario
        lines = [
            f"OPSEC controller race — {s.rounds} rounds "
            f"(quiet {s.quiet_prefix} | challenge {s.challenge_span} | recovery "
            f"{s.rounds - s.quiet_prefix - s.challenge_span}), "
            f"budget {s.round_budget}/round, seed {s.seed}",
            "",
            f"{'metric':40s}{'legacy':>10s}{'queue-only':>12s}{'shipped':>10s}",
            "-" * 72,
            f"{'spend inside challenge window':40s}"
            f"{self.legacy.window_spend:>10.1f}{self.raw_only.window_spend:>12.1f}"
            f"{self.scheduler.window_spend:>10.1f}",
            f"{'requests sent inside window':40s}"
            f"{self.legacy.window_requests:>10d}{self.raw_only.window_requests:>12d}"
            f"{self.scheduler.window_requests:>10d}",
            f"{'loud claims (cost>=4) inside window':40s}"
            f"{self.legacy.window_loud:>10d}{self.raw_only.window_loud:>12d}"
            f"{self.scheduler.window_loud:>10d}",
            f"{'total yield across engagement':40s}"
            f"{self.legacy.total_yield:>10.2f}{self.raw_only.total_yield:>12.2f}"
            f"{self.scheduler.total_yield:>10.2f}",
            "",
            f"challenge-window spend reduction : "
            f"{100 * self.challenge_spend_reduction:.1f}% "
            f"(queue discipline alone: "
            f"{100 * self.challenge_spend_reduction_raw:.1f}%, "
            f"belief adds {100 * self.belief_share:.1f}pp)",
            f"loud-claim reduction in window   : "
            f"{100 * self.challenge_loud_reduction:.1f}%",
            f"yield retained vs legacy         : "
            f"{100 * self.yield_retained:.1f}%",
            f"recovery lag after window        : "
            f"{self.recovery_lag if self.recovery_lag is not None else 'never'} round(s)",
            f"belief peak risk / end risk      : "
            f"{self.scheduler.peak_risk:.2f} / {self.end_risk:.2f}",
        ]
        return "\n".join(lines)


# -- top-level entry points ---------------------------------------------------------------

def compare(scenario: Scenario | None = None, *, mu: float = 2.0, V: float = 1.0,
            scale: float = 4.0) -> SimReport:
    """Run all three controllers over the scenario and return the measured
    comparison (legacy control group, raw-queue ablation, shipped scheduler)."""
    s = scenario or Scenario()
    rng = random.Random(s.seed)

    # Pools and responses are generated ONCE for the whole race: the defender's
    # script does not depend on which controller is running (a WAF challenges the
    # request, not the intent), and the pools are identical so ordering/throttling
    # differences are entirely the controllers'.
    pool_by_round = []
    responses_by_round = []
    for r in range(s.rounds):
        regime = s.regime(r)
        pool = _endpoint_pool(rng, s.pool_size)
        pool_by_round.append(pool)
        # Responses per round: enough for the round's maximum possible claims
        # (pool_size); the loop indexes claims into this list.
        responses_by_round.append(
            [_synthesize_response(regime, i) for i in range(max(s.pool_size, 4))])

    legacy = run_controller("legacy", s, pool_by_round, responses_by_round, mu, V, scale)
    raw_only = run_controller("scheduler_raw", s, pool_by_round, responses_by_round,
                              mu, V, scale)
    sched = run_controller("scheduler", s, pool_by_round, responses_by_round,
                           mu, V, scale)

    # Quiet baseline: mean per-round spend across the shipped controller's quiet
    # prefix minus round 0 (warmup: the extractor needs >=3 samples before the
    # latency channel trusts anything, so round 0 is calibration, not behavior).
    quiet_rounds = sched.spend_by_round[1:max(s.quiet_prefix, 2)]
    baseline = sum(quiet_rounds) / len(quiet_rounds) if quiet_rounds else 0.0

    window_end = s.quiet_prefix + s.challenge_span - 1
    recovery_lag = None
    if baseline > 0:
        for lag, spend in enumerate(sched.spend_by_round[window_end + 1:], start=1):
            if spend >= 0.9 * baseline:
                recovery_lag = lag
                break

    return SimReport(
        scenario=s, legacy=legacy, raw_only=raw_only, scheduler=sched,
        quiet_baseline_spend=baseline,
        challenge_spend_reduction=(1 - sched.window_spend / legacy.window_spend
                                   if legacy.window_spend > 0 else 0.0),
        challenge_spend_reduction_raw=(1 - raw_only.window_spend / legacy.window_spend
                                       if legacy.window_spend > 0 else 0.0),
        challenge_loud_reduction=(1 - sched.window_loud / legacy.window_loud
                                  if legacy.window_loud > 0 else 0.0),
        yield_retained=(sched.total_yield / legacy.total_yield
                        if legacy.total_yield > 0 else 1.0),
        recovery_lag=recovery_lag,
        end_risk=sched.risk_by_round[-1] if sched.risk_by_round else 0.0)


def sweep(scenario: Scenario | None = None, mus: tuple = (1.0, 2.0, 3.0),
          Vs: tuple = (0.25, 1.0, 3.0)) -> list[dict]:
    """The mu x V tuning grid over one scenario — shows the per-run knobs doing
    their documented job (mu: sustainable loudness; V: progress vs pressure)."""
    s = scenario or Scenario()
    rows = []
    for mu in mus:
        for V in Vs:
            rep = compare(s, mu=mu, V=V)
            rows.append({"mu": mu, "V": V,
                         "challenge_spend_reduction_pct":
                             round(100 * rep.challenge_spend_reduction, 1),
                         "yield_retained_pct": round(100 * rep.yield_retained, 1),
                         "recovery_lag_rounds": rep.recovery_lag})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m redteam.opsec_sim",
        description="Deterministic OPSEC controller race: pre-B3 flat knapsack vs "
                    "the B3 drift-plus-penalty scheduler (queue-only ablation and "
                    "shipped queue+belief), over a scripted defender trace.")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--quiet", type=int, default=7, help="quiet prefix rounds")
    ap.add_argument("--challenge", type=int, default=6, help="challenge-window rounds")
    ap.add_argument("--budget", type=float, default=12.0, help="per-round noise budget")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--mu", type=float, default=2.0)
    ap.add_argument("--V", type=float, default=1.0, dest="V")
    ap.add_argument("--sweep", action="store_true", help="run the mu x V tuning grid")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    scenario = Scenario(rounds=args.rounds, quiet_prefix=args.quiet,
                        challenge_span=args.challenge, round_budget=args.budget,
                        seed=args.seed)
    if args.sweep:
        rows = sweep(scenario)
        if args.as_json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'mu':>5s} {'V':>6s} {'window spend -%':>16s} "
                  f"{'yield kept %':>13s} {'recovery lag':>13s}")
            for row in rows:
                print(f"{row['mu']:>5.2f} {row['V']:>6.2f} "
                      f"{row['challenge_spend_reduction_pct']:>15.1f}% "
                      f"{row['yield_retained_pct']:>12.1f}% "
                      f"{str(row['recovery_lag_rounds']):>13s}")
        return 0

    report = compare(scenario, mu=args.mu, V=args.V)
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""POMDP detection-belief layer (Phase A4, docs/red-teaming-roadmap.md Phase A4).

The defender's true posture (whether a WAF/IDS has quietly flagged us) is HIDDEN
state; what every HTTP response already gives us is OBSERVATIONS. This module
turns the observable signals into a posterior belief over four discrete defender
states and exposes one number — `risk_score()` — that the orchestrator's
drift-plus-penalty scheduler consumes each round.

    hidden states : QUIET -> SUSPICIOUS -> ALERTED -> BLOCKED
    observations  : latency_delta bucket, status_class_shift, challenge_present,
                    rate_limit_signal  (all extracted from responses that
                    tools/http.py already makes — zero extra requests)
    update        : standard HMM forward filter — predict (prior @ transition)
                    then correct (likelihood x prior, renormalize)

Design invariants (same discipline as the rest of the engine):

- `BeliefFilter.update()` is a PURE function of (prior belief, observation).
  The filter instance owns exactly one mutable thing: its belief vector. No
  hidden globals.
- The transition matrix and every emission model are hand-authored, named,
  commented constants. They are NOT learned in this task — a follow-up can
  calibrate them against real engagement telemetry (roadmap follow-up) by
  editing constants and re-running the falsifiable tests in
  tests/test_detection_belief.py.
- Nothing here makes network requests, sleeps, or touches the filesystem:
  this layer is pure observation math, so it can never break a proof in flight.
"""

from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

# -- hidden state ------------------------------------------------------------

QUIET = "QUIET"            # no evidence the defender noticed anything
SUSPICIOUS = "SUSPICIOUS"  # weak signals only — worth watching, not worth stopping
ALERTED = "ALERTED"        # active signals: challenges, throttling, inspection
BLOCKED = "BLOCKED"        # the defender is actively refusing our traffic

STATES: tuple[str, ...] = (QUIET, SUSPICIOUS, ALERTED, BLOCKED)
_STATE_INDEX = {s: i for i, s in enumerate(STATES)}

# -- hand-authored model constants (tune here, tests guard the shape) ---------

# TRANSITION_MATRIX[i][j] = P(next state = j | current state = i).
# Rows are from-states in STATES order. Hand-authored starting values:
#   - self-transition is high everywhere (defender posture does not flip each
#     request);
#   - QUIET -> BLOCKED in ONE step is near-zero (0.005): defenders escalate
#     through intermediate states, they do not ban on a single quiet probe;
#   - BLOCKED is sticky (0.70): bans/rate-limit windows outlast our curiosity,
#     and decaying out of it is what "recovering toward QUIET" measures.
# Each row MUST sum to 1.0 (guarded by a test).
TRANSITION_MATRIX: tuple[tuple[float, ...], ...] = (
    # to:  QUIET  SUSPICIOUS  ALERTED  BLOCKED
    (0.850, 0.120,   0.025,   0.005),  # from QUIET
    (0.450, 0.400,   0.130,   0.020),  # from SUSPICIOUS
    (0.200, 0.350,   0.350,   0.100),  # from ALERTED
    (0.050, 0.100,   0.150,   0.700),  # from BLOCKED
)

# Emission models: P(observation bucket | state), one table per observable
# signal. Rows are states (STATES order); columns are that signal's buckets.
# The four signals are treated as conditionally independent given the state
# (a naive-Bayes emission over an HMM state — the standard practical choice
# when signals are few and states are coarse; documented as a modelling
# approximation, not a claim about real WAFs).

# P(latency bucket | state): normal / elevated / high vs the per-endpoint
# rolling baseline. Inspection and tarpitting add latency; a quiet target
# answers at its own speed.
LATENCY_EMISSION: tuple[tuple[float, float, float], ...] = (
    (0.90, 0.08, 0.02),  # QUIET:      answers normally
    (0.60, 0.28, 0.12),  # SUSPICIOUS: occasional slow reply
    (0.35, 0.35, 0.30),  # ALERTED:    deep inspection is visible
    (0.30, 0.30, 0.40),  # BLOCKED:    tarpit/windowing plausible
)

# P(status left the 2xx/3xx baseline for this endpoint | state).
STATUS_SHIFT_EMISSION: tuple[tuple[float, float], ...] = (
    (0.95, 0.05),  # QUIET
    (0.80, 0.20),  # SUSPICIOUS
    (0.55, 0.45),  # ALERTED
    (0.35, 0.65),  # BLOCKED
)

# P(WAF/CAPTCHA-style challenge page or known-challenge marker | state).
CHALLENGE_EMISSION: tuple[tuple[float, float], ...] = (
    (0.995, 0.005),  # QUIET:      a challenge page on a quiet target is rare
    (0.95, 0.05),    # SUSPICIOUS
    (0.60, 0.40),    # ALERTED
    (0.10, 0.90),    # BLOCKED:    challenges are what blocking looks like
)

# P(rate-limit shaped response (429 / Retry-After / throttle body) | state).
RATE_LIMIT_EMISSION: tuple[tuple[float, float], ...] = (
    (0.99, 0.01),  # QUIET
    (0.90, 0.10),  # SUSPICIOUS
    (0.70, 0.30),  # ALERTED
    (0.40, 0.60),  # BLOCKED
)

# -- observation extraction constants ----------------------------------------

# Latency bucketing vs the endpoint's rolling baseline — anchored on the LOW
# envelope (20th percentile) of recent successful exchanges, not the median:
# network latency noise is one-sided (traffic only ever runs slower than true
# service time), and anchoring low means a defense-induced slowdown cannot
# lift the bar it is measured against until the whole rolling window has gone
# slow. Ratios are multiples of that envelope.
LATENCY_ELEVATED_RATIO = 2.0
LATENCY_HIGH_RATIO = 5.0
LATENCY_BASELINE_WINDOW = 20          # recent successful exchanges per endpoint

# Headers that unambiguously announce a challenge (any status). Cookie markers
# and body markers only count on 4xx/5xx — `__cf_bm` rides EVERY Cloudflare
# response and "captcha" can appear inside perfectly normal content.
CHALLENGE_HEADERS = {"cf-mitigated", "cf-challenge"}
CHALLENGE_COOKIES = {"cf_clearance"}
CHALLENGE_BODY_MARKERS = (
    "captcha", "just a moment", "attention required", "checking your browser",
    "ddos protection", "cf-challenge",
)
_CHALLENGE_STATUSES = {403, 429, 503}

RATE_LIMIT_BODY_MARKERS = ("rate limit", "too many requests", "quota exceeded", "throttled")
_LATENCY_BUCKETS = ("normal", "elevated", "high")


@dataclass(frozen=True)
class Observation:
    """One round's observable defender signals, already bucketed."""
    latency_bucket: str        # "normal" | "elevated" | "high"
    status_class_shift: bool   # left the endpoint's 2xx/3xx baseline
    challenge_present: bool    # CAPTCHA / WAF challenge page / known marker
    rate_limit_signal: bool    # 429 / Retry-After / throttle-shaped body

    def likelihood(self, state: str) -> float:
        """P(this observation | state) — naive product over the four signals."""
        i = _STATE_INDEX[state]
        lat = LATENCY_EMISSION[i][_LATENCY_BUCKETS.index(self.latency_bucket)]
        shift = STATUS_SHIFT_EMISSION[i][1 if self.status_class_shift else 0]
        challenge = CHALLENGE_EMISSION[i][1 if self.challenge_present else 0]
        ratelimit = RATE_LIMIT_EMISSION[i][1 if self.rate_limit_signal else 0]
        return lat * shift * challenge * ratelimit


class BeliefFilter:
    """Discrete Bayesian filter over the four defender states.

    The ONLY mutable instance state is `self._belief` (a probability vector).
    `update()` is the HMM forward step: predict (prior @ TRANSITION_MATRIX)
    then correct (multiply by the observation likelihood, renormalize).
    """

    def __init__(self, prior: dict[str, float] | None = None):
        if prior is None:
            self._belief = [1.0 / len(STATES)] * len(STATES)
        else:
            vec = [max(0.0, float(prior.get(s, 0.0))) for s in STATES]
            total = sum(vec)
            self._belief = [v / total for v in vec] if total > 0 else [1.0 / len(STATES)] * len(STATES)
        self._lock = threading.Lock()

    @property
    def belief(self) -> dict[str, float]:
        with self._lock:
            return {s: self._belief[i] for s, i in _STATE_INDEX.items()}

    def update(self, observation: Observation) -> dict[str, float]:
        """One forward step. Returns the posterior over all four states."""
        with self._lock:
            predicted = [0.0] * len(STATES)
            for i in range(len(STATES)):
                if self._belief[i] <= 0.0:
                    continue
                b = self._belief[i]
                for j in range(len(STATES)):
                    predicted[j] += b * TRANSITION_MATRIX[i][j]
            for j, state in enumerate(STATES):
                predicted[j] *= observation.likelihood(state)
            total = sum(predicted)
            if total <= 0.0:
                # A zero-likelihood observation (impossible under the current
                # model constants) must never corrupt the belief: keep prior.
                return {s: self._belief[i] for s, i in _STATE_INDEX.items()}
            self._belief = [p / total for p in predicted]
            return {s: self._belief[i] for s, i in _STATE_INDEX.items()}

    def risk_score(self) -> float:
        """The single number the scheduler consumes: P(ALERTED) + P(BLOCKED), in [0, 1]."""
        with self._lock:
            return self._belief[_STATE_INDEX[ALERTED]] + self._belief[_STATE_INDEX[BLOCKED]]


class DetectionBelief:
    """The deployable wrapper: rolling baselines + response parsing + a filter.

    This is the object attached to the run's ToolContext (`ctx.detection_belief`)
    and referenced by the orchestrator's scheduler. Baseline bookkeeping (the
    filter's purity constraint forbids it inside BeliefFilter) lives here:

    - latency baseline: the low envelope (20th percentile) of the last
      LATENCY_BASELINE_WINDOW successful (status 2xx/3xx) exchanges per
      host+endpoint, updated only by successful exchanges — a slowdown cannot
      lift the bar it is measured against until the entire window has gone
      slow (see the LOW-envelope constant note above);
    - status baseline: the endpoint's last-seen 2xx/3xx class.

    Failed transports (status 0) are skipped entirely: they are not HTTP
    responses, carry no defender evidence under this model, and would poison
    the latency baseline.
    """

    def __init__(self, filter_: BeliefFilter | None = None):
        self.filter = filter_ or BeliefFilter()
        self._latencies: dict[tuple[str, str], deque] = {}
        self._status_class: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    # -- belief delegates ----------------------------------------------------

    @property
    def belief(self) -> dict[str, float]:
        return self.filter.belief

    def risk_score(self) -> float:
        return self.filter.risk_score()

    # -- observation extraction ----------------------------------------------

    @staticmethod
    def _challenge_present(status: int, headers: dict, body: str) -> bool:
        names = {str(k).lower() for k in (headers or {})}
        if names & CHALLENGE_HEADERS:
            return True
        if status not in _CHALLENGE_STATUSES:
            return False
        for marker in CHALLENGE_COOKIES:
            for name in names:
                if name.startswith("set-cookie") and marker in str(headers.get(name, "")).lower():
                    return True
        low = (body or "").lower()
        return any(m in low for m in CHALLENGE_BODY_MARKERS)

    @staticmethod
    def _rate_limit_signal(status: int, headers: dict, body: str) -> bool:
        if status == 429:
            return True
        names = {str(k).lower() for k in (headers or {})}
        if any(n.startswith("retry-after") for n in names):
            return True
        if status < 400:
            return False
        low = (body or "").lower()
        return any(m in low for m in RATE_LIMIT_BODY_MARKERS)

    @staticmethod
    def _low_envelope(samples) -> float | None:
        """20th percentile of the window (nearest-rank, no numpy). One sample
        reads as its own envelope; an empty window reads as no baseline."""
        data = sorted(samples)
        if not data:
            return None
        idx = max(0, math.ceil(0.2 * len(data)) - 1)
        return data[idx]

    def _latency_bucket(self, key: tuple[str, str], elapsed_s: float) -> tuple[str, float | None]:
        with self._lock:
            samples = self._latencies.get(key)
            baseline = self._low_envelope(samples) if samples else None
        if baseline is None or baseline <= 0.0:
            return "normal", baseline
        ratio = elapsed_s / baseline
        if ratio >= LATENCY_HIGH_RATIO:
            return "high", baseline
        if ratio >= LATENCY_ELEVATED_RATIO:
            return "elevated", baseline
        return "normal", baseline

    def observe(self, host: str, path: str, status: int, elapsed_s: float,
                headers: dict | None = None, body: str = "") -> Observation:
        """Absorb one exchange: extract signals, update baselines, update belief."""
        key = (host or "", path or "")
        # Baselines only learn from successful exchanges (see class docstring).
        if 200 <= status < 400:
            with self._lock:
                samples = self._latencies.setdefault(
                    key, deque(maxlen=LATENCY_BASELINE_WINDOW))
                samples.append(max(float(elapsed_s), 1e-6))
                self._status_class[key] = "2xx3xx"
        latency_bucket, _ = self._latency_bucket(key, float(elapsed_s))
        shift = (self._status_class.get(key) == "2xx3xx" and status >= 400) if status else False
        obs = Observation(
            latency_bucket=latency_bucket,
            status_class_shift=bool(shift),
            challenge_present=self._challenge_present(status, headers or {}, body),
            rate_limit_signal=self._rate_limit_signal(status, headers or {}, body),
        )
        self.filter.update(obs)
        return obs


def observe_http_response(ctx, req: dict, status: int, elapsed: float,
                          headers: dict | None, body: str) -> None:
    """The tools/http.py hook: feed one already-made exchange into the run's
    belief layer, if one is attached (`ctx.detection_belief`).

    Best-effort by the same rule as traffic recording: telemetry must never
    break a request mid-proof. No request is made, nothing is written to disk.
    """
    try:
        belief = getattr(ctx, "detection_belief", None)
        if belief is None:
            return
        parsed = urlparse(req.get("url", "") or "")
        belief.observe(parsed.hostname or "", parsed.path or "/", status,
                       elapsed, headers, body)
    except Exception:
        pass

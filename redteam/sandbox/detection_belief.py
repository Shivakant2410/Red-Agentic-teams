"""POMDP detection-belief filter (Phase B3) — the swarm's model of the defender.

The exploit swarm used to treat OPSEC as a flat arithmetic problem: spend noise
credits, stop when the round allowance runs out. That has no EARS — a target that
starts challenging every request (WAF, CAPTCHA, 429s) is TALKING, and the old loop
kept spending at the same rate until the credits ran out. This module gives the
orchestrator an actual belief about the detector's state, maintained as a
Partially Observable Markov Model over four hidden states, fed by the shared HTTP
chokepoint (tools/http.py's observation hook) with zero extra requests.

WHY A POMDP AND NOT A THRESHOLD: no single response proves the defender is alert
(one 429 is a coincidence; a CAPTCHA is not). No single response proves it is calm
either. The forward algorithm accumulates EVIDENCE over a sequence: quiet traffic
keeps the belief parked on QUIET, a challenge burst drives it to ALERTED/BLOCKED
within a few responses, and — critically — a return to clean traffic pulls the
belief back (the model is never permanently sticky; a defender that stopped
challenging is a defender we may probe again, carefully).

THE FOUR HIDDEN STATES (risk-ordered; risk_score = P(ALERTED) + P(BLOCKED)):
  QUIET      — nothing about our traffic has stood out
  SUSPICIOUS — anomalies are accumulating (slow responses, fresh 4xx/5xx)
  ALERTED    — active scrutiny: challenges served, rate limits applied
  BLOCKED    — the target is rejecting us by policy (challenge-everything / ban)

THE FOUR OBSERVATION CHANNELS (extracted per response by SignalExtractor, below):
  latency_delta       — response slower than this endpoint's own rolling baseline
  status_class_shift  — an endpoint that answered 2xx/3xx now answering 4xx/5xx
  challenge_present   — CAPTCHA / WAF challenge markers (headers, cookies, body)
  rate_limit_signal   — 429 / Retry-After / rate-limit-shaped response

NOT LEARNED, ON PURPOSE: TRANSITION_MATRIX and EMISSION_MODEL are hand-authored
named constants, not fitted parameters. Any real engagement produces a handful of
labelled sequences at best, far too few to fit 4x4 + 4x4x2 honestly; a badly fitted
model is worse than a stated prior because it hides its assumptions. The numbers
below encode one defensible story about web defenses; a later phase can recalibrate
them from labelled engagement telemetry (the constants are the single place to
touch), and the class validates their shape at import so a typo cannot pass silent.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from urllib.parse import urlsplit

# -- the hidden state space (risk-ordered; index == position in every tuple) --------

STATES = ("QUIET", "SUSPICIOUS", "ALERTED", "BLOCKED")
_QUIET, _SUSPICIOUS, _ALERTED, _BLOCKED = range(len(STATES))

# -- observation channel vocabulary --------------------------------------------------

CHANNELS = ("latency_delta", "status_class_shift", "challenge_present", "rate_limit_signal")

# -- hand-authored HMM constants (see module docstring: not learned) ------------------

# TRANSITION_MATRIX[from_state][to_state], rows sum to 1.0.
#
# Story the numbers tell: every state is sticky (defenders don't flip per request —
# self-transition 0.70-0.90), escalation is possible from anywhere but takes more
# than one anomalous response (QUIET->ALERTED 0.019 < QUIET->SUSPICIOUS 0.08: one
# slow response makes us suspicious, it does not make us caught), a single step from
# QUIET straight to BLOCKED is near-impossible (0.001 — bans come after scrutiny,
# not out of nowhere), and recovery is possible from every state (the defender can
# go back to sleep — that is what makes the belief non-sticky, and BLOCKED's 0.02
# back to QUIET encodes that bans are usually lifted slower than they are applied).
TRANSITION_MATRIX = (
    # to:  QUIET  SUSPICIOUS  ALERTED  BLOCKED
    (0.900, 0.080, 0.019, 0.001),   # from QUIET
    (0.150, 0.750, 0.090, 0.010),   # from SUSPICIOUS
    (0.030, 0.150, 0.770, 0.050),   # from ALERTED
    (0.020, 0.060, 0.220, 0.700),   # from BLOCKED
)

# EMISSION_MODEL[state][channel] = P(channel fires on one response | state).
#
# Channels are treated as conditionally independent given the state (a factored
# emission — this is what keeps the model hand-authorable: 4 states x 4 channels of
# Bernoulli probabilities instead of a 16-symbol alphabet per state). Story the
# numbers tell: under QUIET every channel fires rarely (2-5%: false positives happen
# — a slow response is not evidence of suspicion by itself); SUSPICIOUS raises the
# passive channels (latency/status) well above the active ones (challenge/rate-limit:
# a suspicious-but-not-caught target still serves us); ALERTED is where challenges
# and rate limits start appearing alongside sustained anomalies; BLOCKED is the
# challenge-everything regime (challenge 0.80, rate-limit 0.85 — the defender is
# now answering our requests with policy, not content).
EMISSION_MODEL = {
    "QUIET":      {"latency_delta": 0.05, "status_class_shift": 0.03,
                   "challenge_present": 0.01, "rate_limit_signal": 0.01},
    "SUSPICIOUS": {"latency_delta": 0.25, "status_class_shift": 0.15,
                   "challenge_present": 0.05, "rate_limit_signal": 0.08},
    "ALERTED":    {"latency_delta": 0.55, "status_class_shift": 0.45,
                   "challenge_present": 0.35, "rate_limit_signal": 0.30},
    "BLOCKED":    {"latency_delta": 0.70, "status_class_shift": 0.60,
                   "challenge_present": 0.80, "rate_limit_signal": 0.85},
}

# We always start QUIET: before we have touched the target, the defender has seen
# nothing worth reacting to. (No observation yet -> no update has run -> this.)
INITIAL_BELIEF = (1.0, 0.0, 0.0, 0.0)

# Belt-and-braces: a malformed hand constant must fail loudly at import, not bend
# every later belief silently. (Rows must be distributions; emissions must be
# probabilities; the vocabularies must line up.)
def _validate_constants() -> None:
    assert len(TRANSITION_MATRIX) == len(STATES), "transition matrix: one row per state"
    for row in TRANSITION_MATRIX:
        assert len(row) == len(STATES), "transition matrix: square"
        assert abs(sum(row) - 1.0) < 1e-9, f"transition row not a distribution: {row}"
    for state in STATES:
        assert state in EMISSION_MODEL, f"emission model missing state {state}"
        for channel in CHANNELS:
            p = EMISSION_MODEL[state][channel]
            assert 0.0 <= p <= 1.0, f"emission P({channel}|{state})={p} not a probability"
    assert abs(sum(INITIAL_BELIEF) - 1.0) < 1e-9, "initial belief not a distribution"


_validate_constants()

# -- signal extraction: response -> observation channels ------------------------------

# Latency baseline: a per-endpoint rolling window of past response times; the
# current response is classified against the MEDIAN of what this exact endpoint
# answered before. 8 samples is enough for a stable median and small enough to
# track a defender that changes behavior mid-engagement; 3 is the minimum before
# we trust the baseline at all (a first-response outlier would otherwise look
# like evidence).
_LATENCY_WINDOW = 8
_LATENCY_MIN_BASELINE = 3
_LATENCY_ELEVATED_RATIO = 1.5   # >= 1.5x the endpoint's median: elevated
_LATENCY_HIGH_RATIO = 3.0       # >= 3.0x: high (both fire the same channel — the
                                # channel is binary; the belief, not the extractor,
                                # weighs repeated evidence)

# Status-class baseline: same idea per endpoint over its recent status classes.
_STATUS_WINDOW = 8

# WAF/CAPTCHA challenge markers. Conservative by design: a marker list that fires
# on ordinary responses would poison the belief in the QUIET regime. Checked
# case-insensitively. Header names first, then known challenge cookie names, then
# body strings that only appear on interstitial challenge pages.
_CHALLENGE_HEADERS = ("cf-mitigated", "x-captcha", "x-capabilities", "captcha",
                      "x-akamai-transformed", "x-iinfo", "x-cdn-challenge")
_CHALLENGE_COOKIE_MARKERS = ("__cf_bm", "cf_chl", "cf_clearance", "ak_bmsc",
                             "bm_sv", "_incap_cap", " incap", "sucuri_cloudproxy")
_CHALLENGE_BODY_MARKERS = ("attention required", "just a moment", "checking your browser",
                           "checking if you are human", "verify you are a human",
                           "request blocked", "access to this page has been denied",
                           "captcha-container", "cf-challenge", "_Incapsula_resource",
                           "sucuri website firewall", "ddos protection by")

# Rate-limit markers: the 429 status, an explicit Retry-After on a 4xx, a zeroed
# quota header, or a body that reads like quota exhaustion.
_RATELIMIT_BODY_MARKERS = ("rate limit", "rate-limit", "ratelimit", "too many requests",
                           "quota exceeded", "throttl", "temporarily blocked")


def _norm_headers(headers: dict) -> dict:
    """Lowercase-keyed view of response headers (parsers hand back mixed case)."""
    try:
        return {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    except Exception:
        return {}


def _status_class(status: int) -> str:
    return f"{status // 100}xx" if status >= 100 else "0xx"


class SignalExtractor:
    """Turns raw HTTP responses into observation-channel tuples, with memory.

    The latency_delta and status_class_shift channels are RELATIVE: "slow" and
    "now erroring" only mean something against what this host+endpoint answered
    before, so the extractor keeps small rolling per-endpoint baselines. The
    challenge_present and rate_limit_signal channels are absolute markers and
    need no history. Everything is best-effort and bounded (windows are deques;
    a long engagement cannot grow this class without limit)."""

    def __init__(self, latency_window: int = _LATENCY_WINDOW,
                 status_window: int = _STATUS_WINDOW):
        self._latency_window = latency_window
        self._status_window = status_window
        self._latency: dict[str, deque] = {}
        self._status: dict[str, Counter] = {}
        self._lock = threading.Lock()   # swarm workers fetch concurrently

    def extract(self, url: str, status: int, elapsed_s: float,
                headers: dict, body: str) -> tuple[str, ...]:
        """Observe one response; return the channels that fired (possibly empty)."""
        fired: list[str] = []
        key = self._endpoint_key(url)
        with self._lock:
            if self._latency_fired(key, elapsed_s):
                fired.append("latency_delta")
            if self._status_shift_fired(key, status):
                fired.append("status_class_shift")
        h = _norm_headers(headers)
        if self._challenge_fired(status, h, body):
            fired.append("challenge_present")
        if self._ratelimit_fired(status, h, body):
            fired.append("rate_limit_signal")
        return tuple(fired)

    @staticmethod
    def _endpoint_key(url: str) -> str:
        try:
            parts = urlsplit(url)
            return f"{parts.scheme}://{parts.hostname}{parts.path or '/'}"
        except Exception:
            return url

    def _latency_fired(self, key: str, elapsed_s: float) -> bool:
        window = self._latency.setdefault(key, deque(maxlen=self._latency_window))
        baseline = sorted(window)
        window.append(max(float(elapsed_s), 0.0))
        if len(baseline) < _LATENCY_MIN_BASELINE:
            return False   # no trustworthy baseline yet — first sight proves nothing
        median = baseline[len(baseline) // 2]
        if median <= 0.0:
            return False   # degenerate baseline (all zeroes) — trust nothing yet
        ratio = elapsed_s / median
        return ratio >= _LATENCY_HIGH_RATIO or ratio >= _LATENCY_ELEVATED_RATIO

    def _status_shift_fired(self, key: str, status: int) -> bool:
        window = self._status.setdefault(key, Counter())
        history = dict(window)
        window[_status_class(status)] += 1
        if window[_status_class(status)] > self._status_window:
            # bound the counter: decay every class so old regimes fade out
            for cls in list(window):
                window[cls] = max(1, window[cls] // 2)
        if status < 400 or not history:
            return False   # 2xx/3xx never fires; first sight of an endpoint proves nothing
        # "shift INTO 4xx/5xx": the endpoint's history was success-class, this
        # response is error-class — the target's posture toward us just changed.
        was_success = all(cls in ("2xx", "3xx") for cls in history)
        return was_success

    @staticmethod
    def _challenge_fired(status: int, headers: dict, body: str) -> bool:
        for name in _CHALLENGE_HEADERS:
            if name in headers:
                return True
        # A CDN server banner alone is NOT a challenge (most of the web sits behind
        # these CDNs) — a challenge is the banner PLUS a known challenge cookie.
        cookies = (headers.get("set-cookie", "") or "").lower()
        if any(marker in cookies for marker in _CHALLENGE_COOKIE_MARKERS):
            return True
        text = (body or "").lower()
        return any(marker in text for marker in _CHALLENGE_BODY_MARKERS)

    @staticmethod
    def _ratelimit_fired(status: int, headers: dict, body: str) -> bool:
        if status == 429:
            return True
        if "retry-after" in headers and 400 <= status < 500:
            return True
        for name, value in headers.items():
            if ("ratelimit" in name or "rate-limit" in name) and value.strip() in ("0", "0.0"):
                return True
        text = (body or "").lower()
        return any(marker in text for marker in _RATELIMIT_BODY_MARKERS)


# -- the belief filter: HMM forward filter over the four states -----------------------

class BeliefFilter:
    """Bayesian filter over the defender's hidden state (forward algorithm only).

    update(observation) advances the filter one response: predict with
    TRANSITION_MATRIX, correct with EMISSION_MODEL, normalize. observation is an
    iterable of fired channel names (empty = nothing fired — that is an
    observation too, and it is what pulls the belief back toward QUIET).
    risk_score() = P(ALERTED) + P(BLOCKED) in [0, 1] — the number the scheduler
    blends into its drift-plus-penalty queue. Thread-safe: swarm workers observe
    concurrently through the http hook."""

    def __init__(self, extractor: SignalExtractor | None = None):
        self._extractor = extractor or SignalExtractor()
        self._belief = list(INITIAL_BELIEF)
        self._steps = 0
        self._lock = threading.Lock()

    @property
    def belief(self) -> dict[str, float]:
        with self._lock:
            return {state: p for state, p in zip(STATES, self._belief)}

    @property
    def steps(self) -> int:
        with self._lock:
            return self._steps

    def update(self, observation) -> dict[str, float]:
        """One forward step. `observation`: iterable of fired channel names (or a
        single channel string). Unknown channels are ignored — a marker list that
        grew on one side must not corrupt the filter from the other."""
        if isinstance(observation, str):
            observation = (observation,)
        fired = {c for c in (observation or ()) if c in CHANNELS}

        with self._lock:
            # P(observation | state) under the factored emission model: each
            # channel contributes its fired (p) or not-fired (1-p) probability.
            likelihood = []
            for i, state in enumerate(STATES):
                p = 1.0
                for channel in CHANNELS:
                    pe = EMISSION_MODEL[state][channel]
                    p *= pe if channel in fired else (1.0 - pe)
                likelihood.append(p)

            # predict: b'[j] = sum_i b[i] * T[i][j], then correct and normalize.
            predicted = [sum(self._belief[i] * TRANSITION_MATRIX[i][j]
                             for i in range(len(STATES)))
                         for j in range(len(STATES))]
            posterior = [predicted[i] * likelihood[i] for i in range(len(STATES))]
            total = sum(posterior)
            if total <= 0.0:
                # Unreachable with valid constants (every likelihood is positive);
                # if a subclass ever breaks that, restart from the prior rather
                # than hand every state NaN.
                self._belief = list(INITIAL_BELIEF)
            else:
                self._belief = [p / total for p in posterior]
            self._steps += 1
            return {state: p for state, p in zip(STATES, self._belief)}

    def risk_score(self) -> float:
        """P(ALERTED) + P(BLOCKED): the scheduler-facing detection pressure in [0, 1]."""
        with self._lock:
            return self._belief[_ALERTED] + self._belief[_BLOCKED]

    def observe_response(self, url: str, status: int, elapsed_s: float,
                         headers: dict | None = None, body: str = "") -> dict[str, float]:
        """Extract the observation channels from one raw response and advance the
        filter. This is the method tools/http.py's observation hook calls."""
        observation = self._extractor.extract(url, status, elapsed_s,
                                              headers or {}, body or "")
        return self.update(observation)

    def reset(self) -> None:
        """Back to the prior (a new engagement against a new target starts QUIET).
        Baselines are kept — the previous target's latency profile says nothing
        about the next one, but re-learning it is free and harmless."""
        with self._lock:
            self._belief = list(INITIAL_BELIEF)
            self._steps = 0

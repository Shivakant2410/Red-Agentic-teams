"""Active content discovery with frequency priors and a theorem-backed stop rule.

Two conversions from docs/offense-arsenal.md §2 (Week 1 of the offense build):

1. FREQUENCY PRIORS (Nmap's trick, §2.1). Nmap scans "the most common 1,000
   ports" by default — a list ordered by empirical open-ness across the
   internet. We do the same for web paths: candidates are ordered by
   seed prior × learned per-bucket hit posterior, so the request budget lands
   where content lives instead of marching alphabetically through a wordlist.
   The priors are self-improving: every probe updates a Beta(α, β) posterior
   per path bucket (admin/, api/, config/, backup/, ...), persisted to JSON
   and carried into the next run.

2. MISSING-MASS STOPPING (STADS, §2.2). Böhme, "Software Testing as Species
   Discovery" (ACM TOSEM 2018, arXiv:1803.02130) models testing as species
   discovery and gives the Good–Turing estimator for the probability that the
   NEXT probe reveals a never-before-seen response kind:

       U(n) = f1 / n        (f1 = species observed exactly once)

   We treat each probe as an individual and its response signature
   (status class × length bucket) as its species. When U(n) drops below eps
   (nothing new is appearing) — or the prior-weighted expected remaining yield
   of the frontier is spent — recon is DONE, with a theorem behind the claim
   instead of a human's shrug. This is the same estimator family fuzzers and
   coverage-extrapolation work use (Liyanage et al. 2024; NDSS Fuzzing
   Workshop 2026).

Discipline (mirrors surface_scan): every request flows through the caller's
scope-checked fetch; the engine never records findings — hits land in the
knowledge graph / inventory / event bus as LEADS for the specialists.
"""

from __future__ import annotations

import json
import math
import random
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------

class BudgetStop(Exception):
    """Raised by the fetch closure when the caller's request budget is spent.
    Propagates out of the probe loop so the run ENDS HONESTLY as a budget stop
    (same discipline as surface_scan) instead of the exhausted requests being
    misread as connection misses."""


DEFAULT_WORDLIST = Path(__file__).with_name("wordlists") / "common-paths.tsv"

# Good–Turing stop rule defaults.
DEFAULT_EPS = 0.02          # U(n) below this = "nothing new is appearing"
DEFAULT_MIN_PROBES = 40     # never claim convergence below this many probes
DEFAULT_WARMUP = 30         # missing_mass() returns 1.0 (no signal) before this
DEFAULT_YIELD_FLOOR = 1.0   # stop when expected remaining hits < 1

# Soft-404 baseline: this many random junk paths are probed first, for free,
# to learn what "not here" looks like on THIS server (status + body length).
BASELINE_PROBES = 3
BASELINE_LEN_TOL = 0.15     # same-status length within 15% of baseline = miss

# Recursion: a hit on a directory spawns this many children from the top of
# the seed list, with score decayed so depth-2 probing never outranks depth-1.
RECURSION_CHILDREN = 12
DEPTH_DECAY = 0.5

_BUCKET_RE = re.compile(r"^[a-z_]+$")


@dataclass(frozen=True)
class SeedPath:
    path: str
    prior: float
    bucket: str


_ROW_SEP_RE = re.compile(r"\t+|\s{2,}")   # tabs or aligned-space columns


def load_wordlist(path: Path | str | None = None) -> list[SeedPath]:
    """Parse the wordlist (tabs or aligned spaces — hand-edited files drift).
    Malformed rows are skipped loudly (counted, not silent)."""
    path = Path(path or DEFAULT_WORDLIST)
    seeds: list[SeedPath] = []
    skipped = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = _ROW_SEP_RE.split(line)
        if len(parts) != 3:
            skipped += 1
            continue
        prior_s, bucket, p = parts[0].strip(), parts[1].strip(), parts[2].strip()
        try:
            prior = float(prior_s)
        except ValueError:
            skipped += 1
            continue
        if not (0.0 <= prior <= 1.0) or not p.startswith("/") \
                or not _BUCKET_RE.match(bucket):
            skipped += 1
            continue
        seeds.append(SeedPath(p, prior, bucket))
    if not seeds:
        raise ValueError(f"wordlist {path} parsed to zero entries ({skipped} skipped)")
    return seeds


# ---------------------------------------------------------------------------
# Learned per-bucket hit model: Beta(α, β) posteriors over P(hit | bucket).

class BucketModel:
    """Beta-Bernoulli posterior per path bucket, persisted across runs.

    Priors start at Beta(1, 1) (uniform); the seed wordlist prior shapes the
    ORDER, and this model learns the ACTUAL hit rate of each bucket family
    from our own probes. After a run against a Laravel shop, `config` and
    `backup` buckets rise; against a locked-down SaaS they fall.
    """

    def __init__(self, path: str | Path | None = None):
        self._path = Path(path) if path else None
        self._lock = threading.RLock()
        self._counts: dict[str, dict[str, float]] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._counts = {k: v for k, v in raw.items()
                                if isinstance(v, dict) and "a" in v and "b" in v}
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            self._counts = {}

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._counts, indent=1), encoding="utf-8")
            tmp.replace(self._path)
        except OSError:
            pass  # priors are best-effort; never break a run over a save

    def posterior(self, bucket: str, a0: float = 1.0, b0: float = 1.0) -> float:
        """Posterior mean of P(hit | bucket) — the map of Beta(a,b) is (a)/(a+b);
        with the uniform prior folded in it is a/(a+b) where a,b start at 1."""
        with self._lock:
            c = self._counts.get(bucket, {"a": 0.0, "b": 0.0})
            a, b = c["a"] + a0, c["b"] + b0
        return a / (a + b)

    def update(self, bucket: str, hit: bool) -> None:
        with self._lock:
            c = self._counts.setdefault(bucket, {"a": 0.0, "b": 0.0})
            c["a" if hit else "b"] += 1.0
        self._save()

    def snapshot(self) -> dict[str, float]:
        with self._lock:
            return {b: self.posterior(b) for b in sorted(self._counts)}


# ---------------------------------------------------------------------------
# STADS species tracker: Good–Turing missing mass over response signatures.

def response_signature(status: int, length: int) -> tuple:
    """Species = (status class, length signature).

    Granularity is deliberate: SMALL bodies (<512B) use the exact length — two
    different small pages are different species (this is what keeps discovery
    alive on real targets, where each distinct app page is its own kind).
    Large bodies use 64-byte buckets — streaming/binary variance must not
    manufacture fake species. Same-status-same-length 404/soft-404 walls
    collapse into ONE species, so they never inflate f1.
    """
    status_class = int(status) // 100 if status else 0
    length = int(length)
    return (status_class, length if length < 512 else (length // 64) * 64)


class SpeciesTracker:
    """U(n) = f1/n — the probability the next probe shows a NEW response kind.

    Warmup: below WARMUP probes the estimate is 1.0 (no signal yet) — the
    estimator is honest about being uninformative instead of stopping early.
    """

    def __init__(self, warmup: int = DEFAULT_WARMUP):
        self.warmup = warmup
        self.n = 0
        self.counts: dict[tuple, int] = {}

    def record(self, sig: tuple) -> None:
        self.n += 1
        self.counts[sig] = self.counts.get(sig, 0) + 1

    @property
    def f1(self) -> int:
        return sum(1 for c in self.counts.values() if c == 1)

    def missing_mass(self) -> float:
        if self.n < self.warmup:
            return 1.0
        return self.f1 / self.n


# ---------------------------------------------------------------------------
# Soft-404 discrimination: learn what "not here" looks like on THIS server.

class Soft404Baseline:
    """K random junk paths, probed first, define the miss profile.

    Many servers answer every unknown path with a branded 200 page. ffuf and
    dirsearch handle this the same way: cluster the error responses, then
    treat anything matching the cluster as a miss. Ours is the length-15%
    rule — same status as baseline and length within tolerance = miss.
    """

    def __init__(self) -> None:
        self.lengths: list[int] = []
        self.statuses: set[int] = set()

    def observe(self, status: int, length: int) -> None:
        if status:
            self.lengths.append(int(length))
            self.statuses.add(int(status))

    def is_miss(self, status: int, length: int) -> bool:
        if status in (0, 404, 410):
            return True
        if status not in self.statuses:
            return False
        for L in self.lengths:
            denom = max(L, 1)
            if abs(int(length) - L) / denom < BASELINE_LEN_TOL:
                return True
        return False


# ---------------------------------------------------------------------------
# The engine.

@dataclass
class _Candidate:
    path: str
    prior: float
    bucket: str
    depth: int = 0
    confirmed_parent: bool = False

    def score(self, model: BucketModel) -> float:
        decay = DEPTH_DECAY ** self.depth
        if self.confirmed_parent:
            # The parent directory is CONFIRMED content (a 200 we just saw), so
            # its namespace is live; the global bucket rate for the root does
            # not describe it. This is what ffuf -recursion does: run the
            # classic list under every confirmed dir. Score = prior x decay.
            return self.prior * decay
        return self.prior * model.posterior(self.bucket) * decay


@dataclass
class DiscoveryHit:
    path: str
    url: str
    status: int
    length: int
    bucket: str
    depth: int


@dataclass
class DiscoveryReport:
    base_url: str
    probed: int = 0
    hits: list[DiscoveryHit] = field(default_factory=list)
    dirs: list[str] = field(default_factory=list)
    missing_mass: float = 1.0
    f1: int = 0
    species: int = 0
    expected_remaining_yield: float = 0.0
    stop_reason: str = ""
    buckets: dict = field(default_factory=dict)
    baseline_skipped: int = 0

    def to_dict(self, hit_cap: int = 50) -> dict:
        return {
            "base_url": self.base_url, "probed": self.probed,
            "hits": [vars(h) for h in self.hits[:hit_cap]],
            "hit_count": len(self.hits),
            "dirs": self.dirs[:32],
            "missing_mass": round(self.missing_mass, 4),
            "f1": self.f1, "species": self.species,
            "expected_remaining_yield": round(self.expected_remaining_yield, 3),
            "stop_reason": self.stop_reason,
            "bucket_posteriors": {k: round(v, 3) for k, v in self.buckets.items()},
            "baseline_skipped": self.baseline_skipped,
        }


class DiscoveryEngine:
    """Frequency-prior-ordered content discovery with the STADS stop rule.

    `fetch(url) -> (status, body, headers)` is caller-provided and MUST be
    scope-checked and rate-limited by the caller (the tool wrapper wires it
    to fetch_once; tests wire it to a local server). The engine itself makes
    no I/O decisions — it only decides WHAT to probe and WHEN TO STOP.
    """

    def __init__(self, fetch, wordlist: list[SeedPath] | None = None,
                 model: BucketModel | None = None, *,
                 eps: float = DEFAULT_EPS, min_probes: int = DEFAULT_MIN_PROBES,
                 warmup: int = DEFAULT_WARMUP, yield_floor: float = DEFAULT_YIELD_FLOOR,
                 max_depth: int = 1, rng: random.Random | None = None):
        self._fetch = fetch
        self._seeds = wordlist if wordlist is not None else load_wordlist()
        self._model = model if model is not None else BucketModel()
        self._eps = eps
        self._min_probes = min_probes
        self._tracker = SpeciesTracker(warmup=warmup)
        self._yield_floor = yield_floor
        self._max_depth = max_depth
        self._rng = rng or random.Random()
        self._baseline = Soft404Baseline()

    # -- internals ----------------------------------------------------------

    def _probe(self, url: str) -> tuple[int, int, str]:
        """One request. Returns (status, length, body). Fetch errors = status 0;
        BudgetStop propagates — the loop converts it into a budget stop."""
        try:
            status, body, _headers = self._fetch(url)
        except BudgetStop:
            raise
        except Exception:
            return 0, 0, ""
        return int(status or 0), len(body or ""), body or ""

    def _build_baseline(self, base_url: str, budget_left: int) -> int:
        """Probe K junk paths to learn this server's miss profile. Returns
        requests actually spent (can be < K if the budget is tiny)."""
        spent = 0
        for _ in range(BASELINE_PROBES):
            if spent >= budget_left:
                break
            junk = f"/.rt-baseline-{self._rng.randbytes(5).hex()}"
            status, length, _ = self._probe(base_url.rstrip("/") + junk)
            spent += 1
            if status:  # connection errors teach nothing about the profile
                self._baseline.observe(status, length)
        return spent

    def _is_hit(self, status: int, length: int) -> bool:
        return bool(status) and not self._baseline.is_miss(status, length)

    def _expected_remaining_yield(self, frontier: list[_Candidate]) -> float:
        return sum(c.score(self._model) for c in frontier)

    def _children(self, parent_path: str, depth: int) -> list[_Candidate]:
        """A confirmed directory re-opens the seed list beneath itself."""
        if depth >= self._max_depth:
            return []
        top = sorted(self._seeds, key=lambda s: s.prior, reverse=True)[:RECURSION_CHILDREN]
        base = parent_path if parent_path.endswith("/") else parent_path + "/"
        return [_Candidate(base + s.path.lstrip("/"), s.prior,
                           s.bucket, depth + 1, confirmed_parent=True) for s in top]

    # -- main loop ----------------------------------------------------------

    def run(self, base_url: str, budget: int, prefix: str = "") -> DiscoveryReport:
        report = DiscoveryReport(base_url=base_url)
        root = base_url.rstrip("/") + "/"
        prefix = "/" + prefix.strip("/") if prefix and prefix.strip("/") else ""
        spent = 0

        spent += self._build_baseline(root, max(budget - spent, 0))
        baseline_spent = spent
        report.baseline_skipped = max(BASELINE_PROBES - baseline_spent, 0)

        frontier: list[_Candidate] = []
        seen: set[str] = set()
        for s in self._seeds:
            p = prefix + s.path if prefix and not prefix.endswith("/") else \
                (prefix.rstrip("/") if prefix else "") + s.path
            if p not in seen:
                seen.add(p)
                frontier.append(_Candidate(p, s.prior, s.bucket))
        frontier.sort(key=lambda c: c.score(self._model), reverse=True)

        stop_reason = ""
        try:
            while frontier:
                if spent >= budget:
                    stop_reason = "budget"
                    break
                expected = self._expected_remaining_yield(frontier)
                if expected < self._yield_floor:
                    stop_reason = "converged-yield"
                    break
                mass = self._tracker.missing_mass()
                if self._tracker.n >= self._min_probes and mass < self._eps:
                    stop_reason = "converged-species"
                    break

                cand = frontier.pop(0)
                url = root + cand.path.lstrip("/")
                status, length, _body = self._probe(url)
                spent += 1
                self._tracker.record(response_signature(status, length))
                self._model.update(cand.bucket, self._is_hit(status, length))

                if self._is_hit(status, length):
                    report.hits.append(DiscoveryHit(cand.path, url, status, length,
                                                    cand.bucket, cand.depth))
                    if cand.path.endswith("/"):
                        report.dirs.append(cand.path)
                        children = self._children(cand.path, cand.depth)
                        fresh = [c for c in children if c.path not in seen]
                        seen.update(c.path for c in fresh)
                        frontier.extend(fresh)
                        frontier.sort(key=lambda c: c.score(self._model), reverse=True)
        except BudgetStop:
            stop_reason = "budget-rate-limit"

        report.probed = spent
        report.missing_mass = self._tracker.missing_mass()
        report.f1 = self._tracker.f1
        report.species = len(self._tracker.counts)
        report.expected_remaining_yield = self._expected_remaining_yield(frontier)
        report.stop_reason = stop_reason or "exhausted-wordlist"
        report.buckets = self._model.snapshot()
        return report


def expected_probes_to_double(baseline: "SpeciesTracker") -> int:
    """Diagnostic helper (STADS extrapolation intuition, not used by the loop):
    if discovery is still happening at rate U(n), the expected wait for the
    next new species is 1/U(n) probes. Surfaces the 'is recon worth it?'
    answer as a number instead of a feeling."""
    u = baseline.missing_mass()
    return int(math.ceil(1.0 / u)) if u > 0 else -1

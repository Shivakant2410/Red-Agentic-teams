"""Contextual multi-armed bandit over attack_tree.py's technique choices.

The problem this solves: attack_tree.py ranks techniques (SQLi, IDOR, XSS, ...) by a
fixed, hand-set `priority` constant, globally, forever — the same order against every
target regardless of what has actually been working. That's a single prior with no
learning, repeated across every engagement.

A bandit is the right fit specifically because this is a repeated choice among discrete
options (techniques) with an unknown, noisy payoff (does this technique confirm on THIS
KIND of endpoint), where we want to learn the best option while still paying some cost to
explore untested ones. Thompson sampling (draw from each arm's Beta(alpha, beta) belief,
play the highest draw) is used because it naturally balances that explore/exploit
trade-off without a separate tuning schedule, and degrades gracefully with few samples —
important since any single engagement sees only a handful of trials per bucket.

CONTEXT (the "bucket"): an endpoint's shape, not its identity — numeric sequential IDs,
an auth wall, API-schema-shaped, workflow-shaped — the same shape categories
memory_backend/app_patterns.py already derives for cross-run pattern recall. Buckets are
deliberately coarse: enough trials per bucket to learn from requires NOT having one bucket
per unique endpoint.

REWARD: 1.0 when a technique attempted on a bucket's endpoint reaches a `confirmed`
finding (see tools/independent_verify.py — the only place that promotes to confirmed),
0.0 when attack_tree.py's swarm worker marks that (technique, target) FAILED having found
nothing. This reward signal already exists in the swarm's control flow; this module just
tallies it per (technique, bucket) instead of discarding it.

PERSISTENCE: pluggable, same Backend protocol shape as memory.py, so the learned
win-rates compound ACROSS engagements (this only pays off with a track record — a single
run gives a bandit almost nothing to learn from). LocalJSONBackend is the always-available
default; a HelixDB-backed store is a natural later upgrade but not required here since this
is plain tabular (technique, bucket) -> (alpha, beta), not something needing vector recall.
"""

from __future__ import annotations

import json
import random
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

# -- bucket (context) derivation ---------------------------------------------------

# Coarse, reusable shape tags — intentionally the same vocabulary app_patterns.py uses,
# so a human reading both already knows what they mean. Order is deterministic (sorted)
# so the same shape always produces the same bucket string.
_NUMERIC_ID = "numeric-id"
_UUID_ID = "uuid-id"
_AUTH_WALL = "auth-wall"
_API_SCHEMA = "api-schema"
_WORKFLOW = "workflow-shaped"
_GENERIC = "generic"

_UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def bucket_for_endpoint(endpoint_key: str, node=None) -> str:
    """Derive a coarse, reusable shape signature for one endpoint — the bandit's
    "context". `node` is the KnowledgeGraph Node for this endpoint if available (gives
    attrs/coverage); falls back to URL-shape regex alone when not (e.g. a technique
    seeded before the graph observed this endpoint yet)."""
    import re

    path = urlsplit(endpoint_key).path
    tags = []

    if re.search(r"/\d{1,8}(/|$)", path):
        tags.append(_NUMERIC_ID)
    elif re.search(_UUID_RE, path, re.IGNORECASE):
        tags.append(_UUID_ID)

    attrs = getattr(node, "attrs", None) or {}
    if attrs.get("requires_auth") or re.search(r"/(login|auth|session|account)s?(/|$)", path):
        tags.append(_AUTH_WALL)
    if attrs.get("source") == "passive_recon" and ("schema" in endpoint_key or "openapi" in endpoint_key
                                                    or "swagger" in endpoint_key):
        tags.append(_API_SCHEMA)
    if re.search(r"/(checkout|cart|order|payment|workflow|transfer|approve)s?(/|$)", path):
        tags.append(_WORKFLOW)

    return ",".join(sorted(set(tags))) or _GENERIC


# -- storage -------------------------------------------------------------------------

@dataclass
class ArmState:
    technique: str
    bucket: str
    alpha: float = 1.0   # Beta prior: alpha=beta=1 is uniform (no information yet)
    beta: float = 1.0

    @property
    def id(self) -> str:
        return f"{self.technique}@{self.bucket}"

    @property
    def trials(self) -> int:
        return int(self.alpha + self.beta - 2)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)


class BanditBackend(Protocol):
    def load(self) -> list[dict]: ...
    def save(self, rows: list[dict]) -> None: ...


class LocalJSONBanditBackend:
    def __init__(self, path: str | Path):
        self._path = Path(path)

    def load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def save(self, rows: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


class BanditStore:
    """Thompson-sampling store over (technique, bucket) arms, persisted across runs.

    Usage from attack_tree.py's actionable(): call `sample(technique, bucket)` to get a
    score in [0, 1] reflecting the learned win-rate (centered at 0.5 with no data, so it
    never dominates the static priority table before there's evidence); call
    `record(technique, bucket, won)` whenever a swarm worker confirms or fails a node.
    """

    def __init__(self, path: str | Path | None = None, backend: BanditBackend | None = None):
        self._backend = backend or (LocalJSONBanditBackend(path) if path else None)
        self._arms: dict[str, ArmState] = {}
        self._lock = threading.Lock()   # swarm workers record() concurrently
        if self._backend:
            for row in self._backend.load():
                arm = ArmState(**row)
                self._arms[arm.id] = arm

    def _get(self, technique: str, bucket: str) -> ArmState:
        key = f"{technique}@{bucket}"
        arm = self._arms.get(key)
        if arm is None:
            arm = ArmState(technique=technique, bucket=bucket)
            self._arms[key] = arm
        return arm

    def sample(self, technique: str, bucket: str) -> float:
        """A Thompson-sampled draw from this arm's current belief — higher means
        "try this technique on this bucket sooner." With no data (alpha=beta=1), this
        draws uniformly around 0.5, so it nudges the static priority order rather than
        overriding it outright until real evidence accumulates."""
        with self._lock:
            arm = self._get(technique, bucket)
            return random.betavariate(arm.alpha, arm.beta)

    def record(self, technique: str, bucket: str, won: bool) -> None:
        """Update one arm's belief after a technique was actually tried on a bucket.
        won=True means it reached a CONFIRMED finding; won=False means the swarm marked
        it FAILED having found nothing (see attack_tree.py's worker loop)."""
        with self._lock:
            arm = self._get(technique, bucket)
            if won:
                arm.alpha += 1
            else:
                arm.beta += 1
            self._flush()

    def summary(self) -> dict:
        with self._lock:
            return {
                arm.id: {"trials": arm.trials, "mean": round(arm.mean, 3)}
                for arm in sorted(self._arms.values(), key=lambda a: a.trials, reverse=True)
            }

    def _flush(self) -> None:
        if self._backend:
            self._backend.save([asdict(a) for a in self._arms.values()])

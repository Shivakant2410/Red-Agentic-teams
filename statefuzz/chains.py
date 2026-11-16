# -*- coding: utf-8 -*-
"""chains.py — findings as capabilities (dossier 8.4).

A Finding is not a "vulnerability class label": it is a capability —
preconditions (facts required to fire) plus grants (facts it produces). Impact
is a *path* through the capability graph, not a severity tag: chains.search
does BFS over edges A -> B iff B.preconditions - INITIAL_FACTS are covered by
A.grants (confused-deputy model: each finding is something an authorized-
for-less attacker can now do).

Severity becomes compositional: chains.score() rewards depth, write
capability at the frontier, and cross-user reach. This is what the dossier
means by "severity becomes a property of a path through the capability graph".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

INITIAL_FACTS = frozenset({"auth:low"})   # what any low-priv principal has


@dataclass
class Finding:
    finding_id: str
    title: str
    technique_id: str              # bandit arm that found it
    mutant_id: str
    invariant_id: str
    invariant_class: str
    detail: str
    preconditions: Set[str] = field(default_factory=set)
    grants: Set[str] = field(default_factory=set)
    evidence: dict = field(default_factory=dict)
    severity_hint: str = "medium"  # single-step hint; chains compute real score
    status: str = "candidate"      # candidate -> verified (platform verify)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "title": self.title,
            "technique_id": self.technique_id, "mutant_id": self.mutant_id,
            "invariant_id": self.invariant_id,
            "invariant_class": self.invariant_class, "detail": self.detail,
            "preconditions": sorted(self.preconditions),
            "grants": sorted(self.grants),
            "evidence": self.evidence, "severity_hint": self.severity_hint,
            "status": self.status,
        }


def from_violation(v, mutant, number: int,
                   seed_transition=None) -> Finding:
    """Violations inherit preconditions/grants from the seed transition's
    model annotations (the capability algebra of dossier 8.4); without a
    transition, findings start from the initial facts."""
    if seed_transition is not None:
        pre = set(seed_transition.requires)
        grants = set(seed_transition.grants)
    else:
        pre, grants = set(INITIAL_FACTS), set()
    return Finding(
        finding_id=f"F-{number:04d}",
        title=f"{v.invariant_class} violation on {v.transition_id}",
        technique_id=v.technique_id, mutant_id=mutant.mutant_id,
        invariant_id=v.invariant_id, invariant_class=v.invariant_class,
        detail=v.detail, evidence={"violation": v.to_dict()},
        severity_hint=v.severity_hint,
        preconditions=pre,
        grants=grants | {f"logic:{v.invariant_class}:abusable"},
    )


# --------------------------------------------------------------------------
# capability graph
# --------------------------------------------------------------------------

def _edge(a: Finding, b: Finding) -> bool:
    """A enables B: B must NEED at least one non-initial fact, and every
    need must be granted by A. Findings whose preconditions are already
    covered by the initial facts are standalone capabilities — they are
    reported as length-1 chains, never as enablement targets (this keeps the
    graph sparse and the chains meaningful)."""
    need = b.preconditions - INITIAL_FACTS
    return bool(need) and need <= a.grants


def adjacency(findings: List[Finding]) -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = {f.finding_id: [] for f in findings}
    for a in findings:
        for b in findings:
            if a.finding_id != b.finding_id and _edge(a, b):
                adj[a.finding_id].append(b.finding_id)
    return adj


def search(findings: List[Finding], max_depth: int = 4) -> List[List[Finding]]:
    """All acyclic chains of length >= 1 (BFS, bounded). A chain of length 1
    is still reported: it is a capability on its own."""
    by_id = {f.finding_id: f for f in findings}
    adj = adjacency(findings)
    paths: List[List[Finding]] = []
    frontier: List[Tuple[str, List[str]]] = [
        (f.finding_id, [f.finding_id]) for f in findings]
    while frontier:
        nxt: List[Tuple[str, List[str]]] = []
        for fid, trail in frontier:
            paths.append([by_id[x] for x in trail])
            if len(trail) >= max_depth:
                continue
            for succ in adj.get(fid, []):
                if succ not in trail:
                    nxt.append((succ, trail + [succ]))
        frontier = nxt
    return paths


# --------------------------------------------------------------------------
# compositional severity
# --------------------------------------------------------------------------

_HINT_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}


def score(chain: List[Finding]) -> float:
    """score = base + 1.5 per extra hop + write/frontier bonus + cross-user
    bonus. Returns 0..10 clipped."""
    if not chain:
        return 0.0
    base = max(_HINT_WEIGHT.get(f.severity_hint, 2.0) for f in chain)
    depth_bonus = 1.5 * (len(chain) - 1)
    write_bonus = 1.0 if any("written" in g or "move:" in g
                             for f in chain for g in f.grants) else 0.0
    xuser_bonus = 1.0 if any("other" in p or "cross" in p
                             for f in chain for p in f.preconditions) else 0.0
    return min(10.0, base + depth_bonus + write_bonus + xuser_bonus)


def top_paths(findings: List[Finding], k: int = 10,
              max_depth: int = 4) -> List[dict]:
    """Ranked chain list for the run report (JSON-safe): score desc, then
    depth desc. Each entry carries the finding ids and their titles."""
    ranked = sorted(
        ({"score": score(c),
          "findings": [f.finding_id for f in c],
          "titles": [f"{f.invariant_id}/{f.technique_id}" for f in c]}
         for c in search(findings, max_depth)),
        key=lambda d: (-d["score"], -len(d["findings"])))
    return ranked[:k]

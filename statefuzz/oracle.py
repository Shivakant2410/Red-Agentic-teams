# -*- coding: utf-8 -*-
"""oracle.py — the four oracle kinds (dossier 8.3) plus the deferred
hypothesis ledger.

  1. immediate metamorphic — invariant checkers run on (before, action, after)
     [invariants.InvariantSet],
  2. differential — the same mutant replayed against a *clean reference*
     (second session, or the fixed-mode build of the app) must produce the
     same effect; divergence is evidence,
  3. data-flow read-back — after a write, GET the resource and diff the stored
     representation against the effect the request claims (BACFuzz-style
     read-back, dossier 5.3),
  4. deferred — async / second-order effects (webhooks, emails, exports) get
     a HypothesisLedger entry with a unique marker; a sweep() correlates
     marker hits from platform-hosted callback endpoints and attributes the
     finding retroactively. The empty async/second-order column of the
     correlation matrix (dossier table 7:1) is exactly what this closes.

Deferred hypotheses never auto-promote: without a marker hit before the
deadline they expire as 'inconclusive' — a hallucinated async oracle is worse
than none (dossier 2: honest verification discipline, applied to oracles).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .appmodel import AppStateModel, ObservedState, Response
from .executor import MutantResult
from .invariants import InvariantSet, Violation


# --------------------------------------------------------------------------
# 1. immediate metamorphic
# --------------------------------------------------------------------------

def immediate(model: AppStateModel, invariants: InvariantSet,
              result: MutantResult) -> List[Violation]:
    """Run every invariant over each (plan, before, responses, after) tuple.
    Each plan is checked against ITS OWN transition (REORDER mutants execute
    the partner transition first — its semantics must not inherit the seed's).
    Race and replay plans carry n responses — conservation arithmetic sees the
    true multiplicity of accepted effects."""
    out: List[Violation] = []
    for pr in result.plan_results:
        t = (model.transition(pr.plan.transition_id)
             if pr.plan.transition_id else None) \
            or model.transition(result.seed_transition)
        out.extend(invariants.check_all(
            model, t, pr.plan, pr.before, pr.responses, pr.after))
    return out


# --------------------------------------------------------------------------
# 2. differential — mutant run vs clean-reference run of the same mutant
# --------------------------------------------------------------------------

def default_effect_counter(obs: Optional[ObservedState]) -> Dict[str, float]:
    """App-agnostic effect summary: per-numeric-field totals across entities.
    Transfers conserve totals (differential silent); replay/race double-apply
    shifts them (differential fires)."""
    if obs is None:
        return {}
    sums: Dict[str, float] = {}
    for attrs in obs.facts.values():
        for k, v in attrs.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                sums[k] = sums.get(k, 0.0) + float(v)
    return sums


@dataclass
class DifferentialOracle:
    """The metamorphic relation needs TWO executions of the same mutant: one
    against the target, one against a clean reference (fixed build, staging
    twin, or second principal's untouched namespace). Divergence of effect
    deltas beyond drift is evidence."""
    effect_counter: Callable[[Optional[ObservedState]], Dict[str, float]] = \
        default_effect_counter
    allowed_drift: float = 0.0

    def compare(self, result: MutantResult,
                clean_result: MutantResult) -> List[Violation]:
        dm = _delta(self.effect_counter, result.before, result.after)
        dc = _delta(self.effect_counter, clean_result.before, clean_result.after)
        suspicious = {k: round(dm.get(k, 0.0) - dc.get(k, 0.0), 6)
                      for k in set(dm) | set(dc)
                      if abs(dm.get(k, 0.0) - dc.get(k, 0.0)) > self.allowed_drift}
        if suspicious and result.responses and any(r.ok() for r in result.responses):
            return [Violation(
                invariant_id="INV-DIFF", invariant_class="Differential",
                transition_id=result.seed_transition,
                technique_id=result.technique_id,
                detail=("mutant run diverges from the clean-reference run of "
                        f"the same mutant: {suspicious}"),
                evidence={"effect_delta_mutant": dm,
                          "effect_delta_clean": dc,
                          "statuses": [r.status for r in result.responses]},
                severity_hint="high",
            )]
        return []


def _delta(counter, before, after) -> Dict[str, float]:
    b, a = counter(before), counter(after)
    return {k: round(a.get(k, 0.0) - b.get(k, 0.0), 6) for k in set(b) | set(a)}


# --------------------------------------------------------------------------
# 3. data-flow read-back
# --------------------------------------------------------------------------

def read_back(result: MutantResult, observe: Callable[[], ObservedState],
              probe: Callable[[ObservedState], Optional[dict]],
              claimed_effect: Callable[[dict, dict], bool]) -> List[Violation]:
    """After the mutant, re-observe and locate the affected entity via
    `probe`; `claimed_effect(request_like, stored)` returns True when the
    stored state matches what the accepted request claims. An accepted write
    whose stored representation diverges is a persistence/consistency bug."""
    out: List[Violation] = []
    fresh = observe()
    stored = probe(fresh)
    if stored is None or not result.responses:
        return out
    last_ok = next((r for r in reversed(result.responses) if r.ok()), None)
    if last_ok is None:
        return out
    body = last_ok.body if isinstance(last_ok.body, dict) else {}
    if not claimed_effect(body, stored):
        out.append(Violation(
            invariant_id="INV-DF", invariant_class="DataFlowReadBack",
            transition_id=result.seed_transition,
            technique_id=result.technique_id,
            detail="accepted write's stored representation diverges from the "
                   "claimed effect (read-back diff)",
            evidence={"response_body": body, "stored": stored},
            severity_hint="medium",
        ))
    return out


# --------------------------------------------------------------------------
# 4. deferred — hypothesis ledger
# --------------------------------------------------------------------------

@dataclass
class Hypothesis:
    hypothesis_id: str
    mutant_id: str
    technique_id: str
    transition_id: str
    marker: str                      # unique, greppable: e.g. 'sfz-<hex12>'
    expect: str                      # what the async effect should look like
    created: float = field(default_factory=time.time)
    ttl_s: float = 600.0
    status: str = "open"             # open | confirmed | inconclusive
    hits: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"hypothesis_id": self.hypothesis_id, "mutant_id": self.mutant_id,
                "technique_id": self.technique_id,
                "transition_id": self.transition_id, "marker": self.marker,
                "expect": self.expect, "status": self.status,
                "hits": self.hits}


def new_marker() -> str:
    return "sfz-" + secrets.token_hex(6)


class HypothesisLedger:
    """Registers async-effect hypotheses with unique markers and correlates
    later observations (callback endpoint payloads, outbox dumps)."""

    def __init__(self) -> None:
        self._items: Dict[str, Hypothesis] = {}
        self._order: List[str] = []

    def register(self, result: MutantResult, expect: str,
                 ttl_s: float = 600.0) -> Hypothesis:
        h = Hypothesis(
            hypothesis_id=f"H-{len(self._order) + 1:04d}",
            mutant_id=result.mutant_id, technique_id=result.technique_id,
            transition_id=result.seed_transition, marker=new_marker(),
            expect=expect, ttl_s=ttl_s,
        )
        self._items[h.hypothesis_id] = h
        self._order.append(h.hypothesis_id)
        return h

    def sweep(self, observations: List[dict]) -> List[Hypothesis]:
        """observations: payloads from platform-hosted callback endpoints /
        outbox polling, each a dict. A payload 'hits' a hypothesis when the
        unique marker appears anywhere in its JSON text. Confirmed hypotheses
        become findings (by the runner); expired ones are 'inconclusive'."""
        now = time.time()
        for h in self.items():
            if h.status != "open":
                continue
            hit = next((obs for obs in observations if h.marker in str(obs)), None)
            if hit is not None:
                h.hits.append(hit)
                h.status = "confirmed"
            elif now - h.created > h.ttl_s:
                h.status = "inconclusive"
        return [h for h in self.items() if h.status == "confirmed"]

    def items(self) -> List[Hypothesis]:
        return [self._items[k] for k in self._order]

    def open_count(self) -> int:
        return sum(1 for h in self.items() if h.status == "open")


# --------------------------------------------------------------------------
# Oracle facade — what the runner calls
# --------------------------------------------------------------------------

@dataclass
class Oracle:
    model: AppStateModel
    invariants: InvariantSet
    differential: Optional[DifferentialOracle] = None

    def run(self, mutant, result: MutantResult,
            clean_executor=None) -> List[Violation]:
        """Immediate metamorphic for every plan; when a clean_executor is
        wired (the fixed build / staging twin), the same mutant is re-executed
        there and the two effect deltas are compared. Read-back and deferred
        oracles are opt-in per run config (they need probe/callback wiring
        from the platform)."""
        v = immediate(self.model, self.invariants, result)
        if self.differential is not None and clean_executor is not None:
            clean_result = clean_executor.execute(mutant)
            v.extend(self.differential.compare(result, clean_result))
        return v

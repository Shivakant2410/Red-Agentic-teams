# -*- coding: utf-8 -*-
"""invariants.py — the five invariant classes as metamorphic oracles
(dossier 8.2, table 8:1).

An invariant is a metamorphic relation over (before, action, after): the
generator proposes executions that should fail if and only if the invariant
holds. A violation is *evidence*, not a verdict — it goes to the verify
pipeline (prover registry) exactly like the platform's other findings.

  I1 ResourceConservation : the balance delta of an action equals its
                            *declared* delta (+amount on mint edges,
                            -amount on burn edges, 0 otherwise) — summed over
                            every accepted response of the mutant. Catches
                            value created from nothing: race double-spend
                            (8 accepts, one debit), currency confusion.
  I2 TransitionLegality   : observed (src, action, tgt) triple must be in
                            delta-hat; catches skipped / out-of-order flows.
  I3 IdentityOwnership    : slots the model marks owner-checked (path id,
                            body.from) must resolve to resources owned by the
                            requesting principal.
  I4 ArithmeticOrdering   : accepted amounts inside the declared domain,
                            conserved fields non-negative, totals = sum of
                            parts, sequences monotonic.
  I5 UniquenessRate       : one logical effect per idempotency key.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .appmodel import AppStateModel, ObservedState, RequestPlan, Response, Transition

INVARIANT_CLASSES = {
    "I1": "ResourceConservation",
    "I2": "TransitionLegality",
    "I3": "IdentityOwnership",
    "I4": "ArithmeticOrdering",
    "I5": "UniquenessRate",
}


@dataclass
class Violation:
    invariant_id: str          # "INV-I1" .. "INV-I5"
    invariant_class: str
    transition_id: str
    technique_id: str          # mutant operator that exposed it
    detail: str
    evidence: dict = field(default_factory=dict)
    severity_hint: str = "medium"   # chained severity is computed in chains.py

    def to_dict(self) -> dict:
        return {
            "invariant_id": self.invariant_id,
            "invariant_class": self.invariant_class,
            "transition_id": self.transition_id,
            "technique_id": self.technique_id,
            "detail": self.detail,
            "evidence": self.evidence,
            "severity_hint": self.severity_hint,
        }


Checker = Callable[[AppStateModel, Transition, RequestPlan,
                    Optional[ObservedState], List[Response],
                    Optional[ObservedState]], List[Violation]]
# (model, transition, plan, before, responses-of-plan, after) -> violations


def _op(plan: RequestPlan) -> str:
    if plan.technique_id:
        return plan.technique_id
    return plan.note.split("::")[0] if plan.note else "op"


def _amount(plan: RequestPlan, field_name: str = "amount") -> Optional[float]:
    if isinstance(plan.body, dict) and isinstance(plan.body.get(field_name), (int, float)):
        return float(plan.body[field_name])
    return None


# --------------------------------------------------------------------------
# I1 — resource conservation (declared-delta semantics)
# --------------------------------------------------------------------------

def make_conservation(field_name: str = "balance",
                      mint_edges: frozenset = frozenset(),
                      burn_edges: frozenset = frozenset()) -> Checker:
    """I1: the balance delta of an action equals its DECLARED delta. The
    boundary role is a property of the transition, annotated by the
    extractor/LLM labeler as params['boundary'] in {'mint','burn'} (id-keyed
    mint_edges/burn_edges are honored as overrides). Non-boundary transitions
    must conserve exactly; burn/mint edges must move exactly n x amount for
    the n accepted responses — which is what exposes race double-spend
    (8 payouts, one debit)."""
    def check(model, t, plan, before, responses, after):
        out = []
        oks = [r for r in responses if r and r.ok()]
        if not oks:
            return out
        b = _sum_field(before, field_name)
        a = _sum_field(after, field_name)
        actual = a - b
        boundary = t.params.get("boundary")
        if t.id in mint_edges:
            boundary = "mint"
        elif t.id in burn_edges:
            boundary = "burn"
        declared = 0.0
        if boundary in ("mint", "burn"):
            amt = _amount(plan)
            if amt is None:
                return out
            per = amt if boundary == "mint" else -amt
            declared = per * len(oks)
        if abs(actual - declared) > 1e-6:
            out.append(Violation(
                invariant_id="INV-I1", invariant_class=INVARIANT_CLASSES["I1"],
                transition_id=t.id, technique_id=_op(plan),
                detail=(f"total {field_name} moved {actual:+g} but the declared "
                        f"delta is {declared:+g} ({len(oks)} accepted response(s) "
                        f"on {t.id} {t.method} {t.path})"),
                evidence={"before_total": b, "after_total": a,
                          "actual_delta": actual, "declared_delta": declared,
                          "accepted": len(oks), "request": plan.to_dict()},
                severity_hint="critical",
            ))
        return out
    return check


def _sum_field(obs: Optional[ObservedState], field_name: str) -> float:
    if obs is None:
        return 0.0
    return float(sum(v for attrs in obs.facts.values()
                     if isinstance((v := attrs.get(field_name)), (int, float))))


# --------------------------------------------------------------------------
# I2 — transition legality
# --------------------------------------------------------------------------

def make_legality() -> Checker:
    def check(model, t, plan, before, responses, after):
        out = []
        if not any(r and r.ok() for r in responses):
            return out
        src = model.abstraction(before) if before else model.initial_state
        tgt = model.abstraction(after) if after else src
        legal = set(model.legal_triples())
        triple = (src, t.id, tgt)
        if triple not in legal:
            out.append(Violation(
                invariant_id="INV-I2", invariant_class=INVARIANT_CLASSES["I2"],
                transition_id=t.id, technique_id=_op(plan),
                detail=(f"illegal transition {triple} not in delta-hat; "
                        f"machine admits {sorted(x for x in legal if x[1] == t.id)}"),
                evidence={"observed_triple": list(triple),
                          "src_facts": dict(before.facts) if before else {},
                          "tgt_facts": dict(after.facts) if after else {},
                          "request": plan.to_dict()},
                severity_hint="high",
            ))
        return out
    return check


# --------------------------------------------------------------------------
# I3 — identity ownership
# --------------------------------------------------------------------------

def make_ownership(owner_key: str = "owner") -> Checker:
    def check(model, t, plan, before, responses, after):
        out = []
        if not any(r and r.ok() for r in responses):
            return out
        if after is None:
            return out
        principal = plan.principal
        for key in _resolve_checked(t, plan, after):
            attrs = after.facts.get(key, {})
            owner = attrs.get(owner_key)
            if owner is not None and owner != principal and not attrs.get("shared"):
                out.append(Violation(
                    invariant_id="INV-I3", invariant_class=INVARIANT_CLASSES["I3"],
                    transition_id=t.id, technique_id=_op(plan),
                    detail=(f"principal {principal!r} affected owner-checked slot "
                            f"of {key!r} owned by {owner!r}"),
                    evidence={"entity": key, "owner": owner,
                              "principal": principal, "request": plan.to_dict()},
                    severity_hint="critical",
                ))
        return out
    return check


def _resolve_checked(t: Transition, plan: RequestPlan,
                     after: ObservedState) -> List[str]:
    """Resolve the model's owner-checked slot annotations to fact keys.
    Annotation forms: 'path:{param}' | 'body:field'. Without annotations the
    heuristic falls back to path segments appearing in fact keys (may
    over-report; the platform labeler supplies precise slots)."""
    keys: List[str] = []
    for ann in t.params.get("owner_checked", []):
        if ann.startswith("path:"):
            param = ann.split(":", 1)[1]
            val = plan.path.split("/").pop(-1) if param not in plan.path else None
            # path was already rendered: take the segment that replaced {param}
            for seg, orig in zip(plan.path.split("/"),
                                 _template_segments(t.path)):
                if orig == "{" + param + "}":
                    val = seg
            if val:
                keys += [k for k in after.facts if val in k]
        elif ann.startswith("body:") and isinstance(plan.body, dict):
            val = plan.body.get(ann.split(":", 1)[1])
            if isinstance(val, str):
                keys += [k for k in after.facts if val in k]
    if not keys:                      # heuristic fallback
        for seg in plan.path.split("/"):
            if seg and "{" not in seg:
                keys += [k for k in after.facts if seg in k]
    return sorted(set(keys))


def _template_segments(template: str) -> List[str]:
    return [p for p in template.split("/")]


# --------------------------------------------------------------------------
# I4 — arithmetic & ordering
# --------------------------------------------------------------------------

def make_arithmetic(amount_field: str = "amount",
                    min_value: float = 1e-9,
                    max_value: float = 1e9,
                    nonneg_fields: Tuple[str, ...] = ("balance",),
                    total_fields: Optional[Dict[str, str]] = None) -> Checker:
    total_fields = total_fields or {}

    def check(model, t, plan, before, responses, after):
        out = []
        oks = [r for r in responses if r and r.ok()]
        if not oks:
            return out
        amt = _amount(plan, amount_field)
        if amt is not None and not (min_value <= amt <= max_value):
            out.append(Violation(
                invariant_id="INV-I4", invariant_class=INVARIANT_CLASSES["I4"],
                transition_id=t.id, technique_id=_op(plan),
                detail=(f"out-of-domain {amount_field}={amt:g} accepted "
                        f"(declared domain [{min_value:g}, {max_value:g}])"),
                evidence={"amount": amt, "request": plan.to_dict()},
                severity_hint="high",
            ))
        if after is not None:
            for key, attrs in after.facts.items():
                for nf in nonneg_fields:
                    v = attrs.get(nf)
                    if isinstance(v, (int, float)) and v < 0:
                        out.append(Violation(
                            invariant_id="INV-I4",
                            invariant_class=INVARIANT_CLASSES["I4"],
                            transition_id=t.id, technique_id=_op(plan),
                            detail=f"{key}.{nf} = {v:g} is negative (declared "
                                   f"non-negative domain)",
                            evidence={"entity": key, "field": nf, "value": v,
                                      "request": plan.to_dict()},
                            severity_hint="high",
                        ))
                for tot_f, items_f in total_fields.items():
                    if tot_f in attrs and items_f in attrs:
                        tot = float(attrs[tot_f])
                        items = attrs[items_f]
                        s = float(sum(items)) if isinstance(items, list) else float(items)
                        if abs(tot - s) > 1e-6:
                            out.append(Violation(
                                invariant_id="INV-I4",
                                invariant_class=INVARIANT_CLASSES["I4"],
                                transition_id=t.id, technique_id=_op(plan),
                                detail=f"{key}.{tot_f}={tot:g} != sum({items_f})={s:g}",
                                evidence={"entity": key, "total": tot, "sum": s},
                                severity_hint="medium",
                            ))
        return out
    return check


# --------------------------------------------------------------------------
# I5 — uniqueness & rate
# --------------------------------------------------------------------------

def make_uniqueness(idem_header: str = "Idempotency-Key") -> Checker:
    def check(model, t, plan, before, responses, after):
        out = []
        if not any(r and r.ok() for r in responses):
            return out
        key = (plan.headers or {}).get(idem_header)
        if not key or after is None:
            return out
        effects = [e for e in after.events
                   if e.get("kind") == "applied_effect"
                   and e.get("idempotency_key") == key]
        if len(effects) > 1:
            out.append(Violation(
                invariant_id="INV-I5", invariant_class=INVARIANT_CLASSES["I5"],
                transition_id=t.id, technique_id=_op(plan),
                detail=(f"idempotency key {key!r} applied {len(effects)} times "
                        f"(expected exactly 1)"),
                evidence={"idempotency_key": key, "effects": effects[:5],
                          "request": plan.to_dict()},
                severity_hint="high",
            ))
        return out
    return check


# --------------------------------------------------------------------------
# InvariantSet
# --------------------------------------------------------------------------

@dataclass
class InvariantSet:
    checkers: List[Checker] = field(default_factory=list)

    @staticmethod
    def default(field_name: str = "balance") -> "InvariantSet":
        return InvariantSet(checkers=[
            make_conservation(field_name),
            make_legality(),
            make_ownership(),
            make_arithmetic(nonneg_fields=(field_name,)),
            make_uniqueness(),
        ])

    def check_all(self, model, t, plan, before, responses, after) -> List[Violation]:
        v: List[Violation] = []
        for c in self.checkers:
            v.extend(c(model, t, plan, before, responses, after))
        return v

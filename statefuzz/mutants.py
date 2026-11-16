# -*- coding: utf-8 -*-
"""mutants.py — the eight transition mutant operators (dossier 8.3).

Each operator is a function Transition -> list[Mutant]: a Mutant is a small
script of RequestPlans plus the oracle expectation ("what a *correct* app does
under this mutant") that the oracles check against reality.

Technique ids are the bandit arms (platform: contextual bandit selects the
next technique; ExperienceStore absorbs per-technique yield — reflections may
reorder priors only, |delta| <= 25, enforced in runner.py).

Tier policy: read-shaped mutants (CROSS-USER probe on GET, SKIP-probe) are
READ_SAFE; everything that mutates state is tier "write" and must pass the
platform approval gate — fail-closed: an ungrantable mutant is skipped, never
downgraded (dossier 11: authorization-first discipline).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .appmodel import AppStateModel, RequestPlan, Transition

# operator -> technique id (bandit arm)
OP_TECHNIQUE = {
    "SKIP": "SF-SKIP", "REPLAY": "SF-REPLAY", "REORDER": "SF-REORDER",
    "PARTIAL": "SF-PARTIAL", "NEGATIVE": "SF-NEGATIVE",
    "CROSS-USER": "SF-CROSSUSER", "INTERRUPT": "SF-RACE",
    "IDEMPOTENCE": "SF-IDEM",
}

# operators that mutate state -> approval tier "write"
WRITE_OPS = {"REPLAY", "REORDER", "NEGATIVE", "INTERRUPT", "IDEMPOTENCE",
             "CROSS-USER"}


@dataclass
class Mutant:
    mutant_id: str
    operator: str                 # one of the 8 operators
    technique_id: str             # bandit arm
    seed_transition: str          # transition id the mutant was derived from
    plans: List[RequestPlan] = field(default_factory=list)
    tier: str = "read"            # "read" | "write"
    expectation: str = ""         # what a correct app does under this mutant
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "mutant_id": self.mutant_id, "operator": self.operator,
            "technique_id": self.technique_id,
            "seed_transition": self.seed_transition,
            "plans": [p.to_dict() for p in self.plans],
            "tier": self.tier, "expectation": self.expectation,
            "note": self.note,
        }


MutantFactory = Callable[[AppStateModel, Transition, str], List[Mutant]]
"""(model, seed transition, run salt) -> mutants"""


def _mk(mutant_id, op, t, plans, expectation, salt, note="") -> Mutant:
    # tier follows the wire shape: anything executing a write transition is
    # write-tier (behind approval); probes against reads are READ_SAFE
    read_shaped = not t.writes
    for p in plans:                       # evidence carries the bandit arm
        p.technique_id = OP_TECHNIQUE[op]
    return Mutant(mutant_id=f"{mutant_id}-{salt}",
                  operator=op, technique_id=OP_TECHNIQUE[op],
                  seed_transition=t.id, plans=plans,
                  tier="read" if read_shaped else "write",
                  expectation=expectation, note=note)


# --------------------------------------------------------------------------
# plan helpers
# --------------------------------------------------------------------------

def _render_path(t: Transition, values: Dict[str, str]) -> str:
    path = t.path
    for k, v in values.items():
        path = path.replace("{" + k + "}", v)
    return path


def _plan(t: Transition, values: Dict[str, str], body: Optional[dict] = None,
          principal: str = "A", timing: str = "single", repeat_n: int = 1,
          headers: Optional[Dict[str, str]] = None, note: str = "") -> RequestPlan:
    return RequestPlan(
        method=t.method, path=_render_path(t, values),
        body=dict(body) if body is not None else (dict(t.params.get("body")) if t.params.get("body") else None),
        headers=headers, principal=principal, timing=timing,
        repeat_n=repeat_n, note=note or t.id, transition_id=t.id,
    )


def _default_values(t: Transition, model: AppStateModel) -> Dict[str, str]:
    """Fill path params with the owning principal's demo resources. The
    extractor records `params.path_defaults` per transition (spec annotation
    or traffic replay); without it the mutant cannot be instantiated and is
    dropped (never guessed — fail-closed)."""
    return dict(t.params.get("path_defaults", {}))


def _default_body(t: Transition) -> Optional[dict]:
    return t.params.get("body")


# --------------------------------------------------------------------------
# the eight operators
# --------------------------------------------------------------------------

def skip_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """SKIP: reach the transition without its required predecessor facts.
    We cannot know predecessors generically; the model marks them via
    params.requires_facts (list of fact strings) + params.requires_requests
    (the requests that would legitimately establish them). The mutant simply
    omits them and executes the transition cold."""
    reqs = t.params.get("requires_requests", [])
    if not reqs or t.params.get("path_defaults") is None:
        return []
    vals = _default_values(t, model)
    plan = _plan(t, vals, note=f"SKIP::{t.id}")
    plan.note = f"SKIP::{t.id}"
    return [_mk(f"SKIP-{t.id}", "SKIP", t, [plan],
                "transition rejected when predecessor flow was skipped", salt,
                note=f"skipped {len(reqs)} predecessor request(s) of {t.id}")]


def replay_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """REPLAY: re-issue the same write twice, same bytes, same idempotency
    key — the wire shape of a client retry. Correct app: one effect (dedupe
    by key) or explicit conflict; vulnerable app: effect applied twice."""
    if not t.writes or t.params.get("path_defaults") is None:
        return []
    vals = _default_values(t, model)
    key = f"sfz-replay-{salt}-{t.id}"
    p1 = _plan(t, vals, headers={"Idempotency-Key": key},
               note=f"REPLAY::{t.id}:1")
    p2 = _plan(t, vals, headers={"Idempotency-Key": key},
               note=f"REPLAY::{t.id}:2")
    return [_mk(f"REPLAY-{t.id}", "REPLAY", t, [p1, p2],
                "second identical write applies no additional effect", salt)]


def reorder_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """REORDER: execute two write transitions of the same source state in the
    swapped order. Correct app: final state independent of order (or second
    call rejected). Partners whose target differs from t's (state-divergent,
    e.g. close-before-deposit) are tried first — that is where illegal
    transitions hide. Seeded on write transitions ONLY: a reorder executes
    its partner's write plan, so a read seed would smuggle writes past the
    approval gate under a read tier."""
    if not t.writes or t.params.get("path_defaults") is None:
        return []
    others = [o for o in model.write_transitions()
              if o.id != t.id and o.source == t.source
              and o.params.get("path_defaults") is not None]
    others.sort(key=lambda o: o.target == t.target)   # divergent target first
    outs = []
    for other in others:
        tb = _plan(other, _default_values(other, model),
                   note=f"REORDER::{t.id}+{other.id}:first")
        ta = _plan(t, _default_values(t, model), note=f"REORDER::{t.id}+{other.id}:second")
        outs.append(_mk(f"REORDER-{t.id}-{other.id}", "REORDER", t, [tb, ta],
                        "final state identical to canonical order", salt,
                        note=f"swapped {other.id} before {t.id}"))
        if len(outs) >= 2:            # bound the combinatorics
            break
    return outs


def partial_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """PARTIAL: drop each required body field in turn (one mutant per field),
    plus a truncated-list variant. Correct app: 400/422, no partial state."""
    if not t.writes:
        return []
    body = _default_body(t)
    if not isinstance(body, dict):
        return []
    vals = _default_values(t, model)
    outs = []
    for f in sorted(body):
        broken = {k: v for k, v in body.items() if k != f}
        p = _plan(t, vals, body=broken, note=f"PARTIAL::{t.id}:drop:{f}")
        outs.append(_mk(f"PARTIAL-{t.id}-{f}", "PARTIAL", t, [p],
                        f"request without required field {f!r} rejected atomically",
                        salt))
    for f, v in sorted(body.items()):
        if isinstance(v, list):
            p = _plan(t, vals, body={**body, f: v[:1]}, note=f"PARTIAL::{t.id}:truncate:{f}")
            outs.append(_mk(f"PARTIAL-{t.id}-{f}-trunc", "PARTIAL", t, [p],
                            f"truncated list {f!r} rejected atomically", salt))
            break
    return outs[:4]                   # bound per-transition mutant count


def negative_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """NEGATIVE: property flips — negative amounts, zero, float overflow,
    past timestamps, swapped enum. Correct app: declared domain enforced."""
    if not t.writes:
        return []
    body = _default_body(t)
    if not isinstance(body, dict):
        return []
    vals = _default_values(t, model)
    outs = []
    numeric = [k for k, v in body.items() if isinstance(v, (int, float))]
    for k in numeric[:2]:
        for bad in (-1, 0):
            broken = {**body, k: bad}
            p = _plan(t, vals, body=broken, note=f"NEGATIVE::{t.id}:{k}={bad}")
            outs.append(_mk(f"NEG-{t.id}-{k}-{bad}", "NEGATIVE", t, [p],
                            f"{k}={bad} rejected (declared domain enforced)", salt))
        break
    return outs


def cross_user_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """CROSS-USER: the same request replayed as principal B against A's
    resource (the BOLA probe). The resource may be addressed by path id or by
    body field (e.g. transfers) — the default body already points at A's
    resource, only the session changes. Read-shaped variant is READ_SAFE."""
    defaults = t.params.get("path_defaults")
    if defaults is None:
        return []
    p = _plan(t, defaults, body=_default_body(t), principal="B",
              note=f"CROSS-USER::{t.id}:B-on-A")
    return [_mk(f"CX-{t.id}", "CROSS-USER", t, [p],
                "principal B receives 403/404 on A's resource", salt,
                note="principal B against A-owned resource")]


def interrupt_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """INTERRUPT (race): n identical writes synchronized at the same instant.
    Correct app: exactly one logical effect (locking / optimistic version).
    Executor timing='race' — production swaps in single-packet transport
    (Kettle last-byte sync / first-sequence-sync, dossier 6)."""
    if not t.writes:
        return []
    vals = _default_values(t, model)
    p = _plan(t, vals, note=f"INTERRUPT::{t.id}:race8", timing="race", repeat_n=8)
    return [_mk(f"RACE-{t.id}", "INTERRUPT", t, [p],
                "exactly one of n synchronized writes applies", salt,
                note="8 synchronized identical writes")]


def idempotence_mutants(model: AppStateModel, t: Transition, salt: str) -> List[Mutant]:
    """IDEMPOTENCE: same logical operation twice, same explicit idempotency
    key. Correct app: one effect; second response replay flag or identical."""
    if not t.writes:
        return []
    vals = _default_values(t, model)
    key = f"sfz-{salt}-{t.id}"
    p1 = _plan(t, vals, headers={"Idempotency-Key": key},
               note=f"IDEMPOTENCE::{t.id}:1")
    p2 = _plan(t, vals, headers={"Idempotency-Key": key},
               note=f"IDEMPOTENCE::{t.id}:2")
    return [_mk(f"IDEM-{t.id}", "IDEMPOTENCE", t, [p1, p2],
                "same key applies the effect exactly once", salt)]


OPERATORS: Dict[str, MutantFactory] = {
    "SKIP": skip_mutants, "REPLAY": replay_mutants, "REORDER": reorder_mutants,
    "PARTIAL": partial_mutants, "NEGATIVE": negative_mutants,
    "CROSS-USER": cross_user_mutants, "INTERRUPT": interrupt_mutants,
    "IDEMPOTENCE": idempotence_mutants,
}


def expand(model: AppStateModel, techniques: Optional[List[str]] = None,
           salt: str = "s1") -> List[Mutant]:
    """Expand every transition of the machine under the selected operators
    (default: all eight). Mutants whose plan cannot be instantiated from the
    model's annotations are dropped, not guessed."""
    ops = [OPERATORS[x] for x in techniques] if techniques else list(OPERATORS.values())
    out: List[Mutant] = []
    for t in model.transitions:
        for factory in ops:
            out.extend(factory(model, t, salt))
    return out


def rank(mutants: List[Mutant], priors: Optional[Dict[str, float]] = None) -> List[Mutant]:
    """Deterministic ranking by bandit priors (technique -> weight); ties keep
    insertion order. The runner clamps prior updates to |delta| <= 25."""
    priors = priors or {}
    return sorted(mutants, key=lambda m: -priors.get(m.technique_id, 1.0))

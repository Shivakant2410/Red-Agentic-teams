# -*- coding: utf-8 -*-
"""appmodel.py — Model Extractor (dossier 9.1).

Builds an AppStateModel M = (S, s0, Sigma, delta, F) from three evidence
sources, in increasing cost (dossier 8.1):

  1. the OpenAPI spec          -> syntactic structure: operations, params
  2. the run's traffic.jsonl   -> observed (source, action, target) triples
  3. LLM labels                -> guards/effects per transition, via
                                  Observation-Confirmation prompting, each
                                  carrying a confidence score and a
                                  human-confirm gate.

The model is the fuzzer's *world model*: mutants are generated per transition
(mutants.expand), legality is checked against delta-hat (invariants
LegalityInvariant), and findings carry preconditions/grants harvested from the
transition metadata so chains.py can search for impact paths.

This module is deterministic; the LLM is only ever consulted through the
injected `labeler` callable — the platform owns the model client (max-entropy
attention principle: the LLM sits at induction points, never in the loop).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Wire-level records (adapter-agnostic: in-process demo or scoped HTTP)
# --------------------------------------------------------------------------

@dataclass
class RequestPlan:
    """One concrete request the executor will send. `principal` is a session
    label ('A' = primary low-priv user, 'B' = second principal used by
    CROSS-USER mutants). `timing` drives the executor: 'single' | 'repeat'
    (k sends, same bytes) | 'race' (n sends, synchronized start)."""
    method: str
    path: str
    body: Optional[dict] = None
    headers: Optional[Dict[str, str]] = None
    principal: str = "A"
    timing: str = "single"
    repeat_n: int = 1
    note: str = ""
    transition_id: str = ""      # which machine transition this plan executes
    technique_id: str = ""       # bandit arm this plan belongs to

    def to_dict(self) -> dict:
        return {
            "method": self.method, "path": self.path,
            "body": self.body, "headers": dict(self.headers or {}),
            "principal": self.principal, "timing": self.timing,
            "repeat_n": self.repeat_n, "note": self.note,
            "transition_id": self.transition_id,
            "technique_id": self.technique_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "RequestPlan":
        return RequestPlan(
            method=d["method"], path=d["path"], body=d.get("body"),
            headers=d.get("headers"), principal=d.get("principal", "A"),
            timing=d.get("timing", "single"), repeat_n=int(d.get("repeat_n", 1)),
            note=d.get("note", ""), transition_id=d.get("transition_id", ""),
            technique_id=d.get("technique_id", ""),
        )


@dataclass
class Response:
    status: int
    body: Optional[dict] = None

    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class ObservedState:
    """Concrete observation snapshot returned by AppAdapter.snapshot().
    `facts` maps entity keys to attributes (e.g. 'account:A1' -> {owner, status,
    balance}); `state_label` is the alpha-image of this snapshot — supplied by
    the adapter in the demo, derived from extractor rules in production."""
    facts: Dict[str, dict] = field(default_factory=dict)
    events: List[dict] = field(default_factory=list)
    state_label: str = "s0"


# --------------------------------------------------------------------------
# Model elements
# --------------------------------------------------------------------------

@dataclass
class Transition:
    """delta: one labeled action of the machine.

    requires / grants are fact strings (the capability algebra of dossier 8.4),
    e.g. requires={'auth:low', 'knows:account_id:own'},
         grants  ={'account:written:own'}. chains.py treats these literally.
    """
    id: str
    method: str
    path: str
    source: str                       # abstract source state label
    target: str                       # abstract target state label
    writes: bool                      # write-shaped -> behind approval tier
    params: Dict[str, Any] = field(default_factory=dict)
    guard: str = ""                   # natural language (LLM label)
    effect: str = ""                  # natural language (LLM label)
    requires: frozenset = frozenset()
    grants: frozenset = frozenset()
    idempotent: bool = False
    # machine-executable label (Observation-Confirmation output)
    confidence: float = 1.0
    needs_human_confirm: bool = False
    # optional executable predicates (demo adapter); production uses the
    # orchestrator's prover registry instead of in-model lambdas
    guard_fn: Optional[Callable[[ObservedState], bool]] = None
    effect_fn: Optional[Callable[[ObservedState, Response], None]] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "method": self.method, "path": self.path,
            "source": self.source, "target": self.target,
            "writes": self.writes, "params": self.params,
            "guard": self.guard, "effect": self.effect,
            "requires": sorted(self.requires), "grants": sorted(self.grants),
            "idempotent": self.idempotent,
            "confidence": round(self.confidence, 3),
            "needs_human_confirm": self.needs_human_confirm,
        }


@dataclass
class AppStateModel:
    """The induced machine. `abstraction_rules` map fact patterns to state
    labels — the concrete alpha function (dossier 8.1)."""
    name: str
    transitions: List[Transition] = field(default_factory=list)
    initial_state: str = "s0"
    abstraction_rules: List[Tuple[str, str]] = field(default_factory=list)
    # observed triples (src, transition_id, tgt) seen in traffic — delta-hat
    observed_triples: List[Tuple[str, str, str]] = field(default_factory=list)

    # -- alpha -------------------------------------------------------------
    def abstraction(self, obs: ObservedState) -> str:
        """Concrete observation -> abstract state label. Rules are
        (fact_substring, label); first match wins; default s0."""
        blob = json.dumps(obs.facts, sort_keys=True)
        for needle, label in self.abstraction_rules:
            if needle in blob:
                return label
        return obs.state_label or self.initial_state

    # -- delta-hat ----------------------------------------------------------
    def legal_triples(self) -> List[Tuple[str, str, str]]:
        return [(t.source, t.id, t.target) for t in self.transitions]

    def transition(self, tid: str) -> Optional[Transition]:
        for t in self.transitions:
            if t.id == tid:
                return t
        return None

    def by_state(self, label: str) -> List[Transition]:
        return [t for t in self.transitions if t.source == label]

    def write_transitions(self) -> List[Transition]:
        return [t for t in self.transitions if t.writes]

    # -- serialization (traffic.jsonl / findings.json compatible) -----------
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "initial_state": self.initial_state,
            "abstraction_rules": [list(r) for r in self.abstraction_rules],
            "transitions": [t.to_dict() for t in self.transitions],
            "observed_triples": [list(x) for x in self.observed_triples],
        }

    @staticmethod
    def from_dict(d: dict) -> "AppStateModel":
        m = AppStateModel(
            name=d["name"], initial_state=d.get("initial_state", "s0"),
            abstraction_rules=[(r[0], r[1]) for r in d.get("abstraction_rules", [])],
            observed_triples=[tuple(x) for x in d.get("observed_triples", [])],
        )
        for td in d.get("transitions", []):
            m.transitions.append(Transition(
                id=td["id"], method=td["method"], path=td["path"],
                source=td["source"], target=td["target"],
                writes=td.get("writes", False), params=td.get("params", {}),
                guard=td.get("guard", ""), effect=td.get("effect", ""),
                requires=frozenset(td.get("requires", [])),
                grants=frozenset(td.get("grants", [])),
                idempotent=td.get("idempotent", False),
                confidence=td.get("confidence", 1.0),
                needs_human_confirm=td.get("needs_human_confirm", False),
            ))
        return m

    def to_prompt(self) -> str:
        """Compact rendering for Observation-Confirmation prompting
        (dossier 5.4): the LLM sees the induced machine and must CONFIRM or
        CORRECT each guard/effect label — never free-form."""
        lines = [f"AppStateModel {self.name} (initial={self.initial_state})"]
        for t in self.transitions:
            lines.append(
                f"  [{t.id}] {t.method} {t.path}  {t.source} -> {t.target}"
                f"  writes={t.writes} idempotent={t.idempotent}"
                f" conf={t.confidence:.2f}"
                + (f"  guard? {t.guard}" if t.guard else "")
                + (f"  effect? {t.effect}" if t.effect else "")
            )
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Labeler contract + deterministic fallback
# --------------------------------------------------------------------------

@dataclass
class Label:
    guard: str = ""
    effect: str = ""
    requires: frozenset = frozenset()
    grants: frozenset = frozenset()
    confidence: float = 0.5
    needs_human_confirm: bool = True


Labeler = Callable[[Transition], Label]
"""Platform-injected LLM labeler (Observation-Confirmation). Receives the
spec-derived transition skeleton, returns guard/effect/requires/grants with a
confidence score. Anything below CONFIRM_THRESHOLD must pass the human-confirm
gate before its mutants enter the write queue."""


CONFIRM_THRESHOLD = 0.75


def heuristic_labeler(t: Transition) -> Label:
    """Deterministic fallback so the pipeline runs without an LLM. Rules of
    thumb only — everything it emits is marked needs_human_confirm=True when
    confidence < threshold, exactly like the platform labeler would be."""
    lab = Label()
    if "{owner}" in t.path or t.path.endswith("/me") or "/me/" in t.path:
        lab.requires |= {"auth:low", "knows:resource_id:own"}
    else:
        lab.requires |= {"auth:low"}
    if t.writes:
        lab.grants |= {"resource:written"}
        lab.effect = lab.effect or "mutates the referenced resource"
        lab.confidence = 0.4
    else:
        lab.grants |= {"resource:read"}
        lab.effect = lab.effect or "returns a representation of the resource"
        lab.confidence = 0.5
    lab.guard = lab.guard or "caller is authenticated"
    lab.needs_human_confirm = lab.confidence < CONFIRM_THRESHOLD
    return lab


# --------------------------------------------------------------------------
# Extractor
# --------------------------------------------------------------------------

def extract_model(spec: dict, traffic: Optional[List[dict]] = None,
                  labeler: Optional[Labeler] = None) -> AppStateModel:
    """spec: OpenAPI-lite dict:
        {"name": ..., "initial_state": ...,
         "abstraction_rules": [[needle, label], ...],
         "transitions": [{id, method, path, source, target, writes,
                          params, requires, grants, idempotent}, ...]}
    traffic: optional list of {"ts", "transition_id", "principal", "src", "tgt"}
             records replayed from traffic.jsonl to seed delta-hat.
    labeler: optional platform LLM labeler; default heuristic_labeler.
    """
    labeler = labeler or heuristic_labeler
    m = AppStateModel(
        name=spec["name"],
        initial_state=spec.get("initial_state", "s0"),
        abstraction_rules=[(r[0], r[1]) for r in spec.get("abstraction_rules", [])],
        observed_triples=[(x["src"], x["transition_id"], x["tgt"])
                          for x in (traffic or [])],
    )
    for sd in spec.get("transitions", []):
        t = Transition(
            id=sd["id"], method=sd["method"], path=sd["path"],
            source=sd.get("source", m.initial_state),
            target=sd.get("target", m.initial_state),
            writes=bool(sd.get("writes", sd["method"] not in ("GET", "HEAD"))),
            params=sd.get("params", {}),
            requires=frozenset(sd.get("requires", [])),
            grants=frozenset(sd.get("grants", [])),
            idempotent=bool(sd.get("idempotent", False)),
        )
        lab = labeler(t)
        # only overwrite spec annotations the LLM actually improved
        t.guard = lab.guard or t.guard
        t.effect = lab.effect or t.effect
        t.requires |= lab.requires
        t.grants |= lab.grants
        t.confidence = lab.confidence
        t.needs_human_confirm = lab.confidence < CONFIRM_THRESHOLD
        m.transitions.append(t)
    return m

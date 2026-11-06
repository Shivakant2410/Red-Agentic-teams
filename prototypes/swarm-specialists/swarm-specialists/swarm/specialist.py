"""Specialist base — the machine-checkable contract (RESEARCH.md M2, M4, M8).

A specialist is a knowledge source in the Hearsay-II sense (M1): it declares
TRIGGERS (fact-kind predicates on the blackboard), owns SKILLS (a minimal,
scoped tool surface), holds PRIVATE working state other specialists never
see, and may SPAWN sub-specialists with depth <= 1 (M4: narrow task, own
budget, distilled output only).

The router refuses dispatch when the contract is violated (M2: spec errors
are the #1 multi-agent failure class — so the spec is enforced, not hoped
for).
"""
import itertools
import time


class ContractViolation(Exception):
    pass


class Trigger:
    def __init__(self, kind, predicate=None, priority=1.0):
        self.kind = kind
        self.predicate = predicate or (lambda fact, board: True)
        self.priority = priority

    def matches(self, fact, board):
        return fact["kind"] == self.kind and bool(self.predicate(fact, board))


class Specialist:
    name = "specialist"
    states = ()                    # engagement states this specialist owns
    max_depth = 0                  # sub-specialist spawn depth allowed

    def __init__(self, ctx):
        self.ctx = ctx             # shared: executor, results dir, budget...
        self.private = {}          # private working state (full autonomy)
        self.memory = ctx["memory"](self.name)
        self.facts_published = 0
        self.dispatches = 0

    # ------------------------------------------------------------ contract --
    def triggers(self):
        raise NotImplementedError

    def skills(self):
        """Minimal scoped skill surface: {skill_name: callable} (M8)."""
        return {}

    # ---------------------------------------------------------------- act ----
    def act(self, fact, board):
        """React to a matched trigger fact; return list of new Facts."""
        raise NotImplementedError

    # --------------------------------------------------------------- spawn ---
    def spawn(self, sub_cls, seed_fact, board, depth=1):
        """Full-autonomy spawn (M4): run a sub-specialist inline with parent
        provenance. The sub's act() publishes its own facts (provenance is
        set BEFORE act) — spawn must NOT publish them twice."""
        if depth > self.max_depth:
            raise ContractViolation(
                "%s tried to spawn at depth %d (max %d)"
                % (self.name, depth, self.max_depth))
        sub = sub_cls(self.ctx)
        sub.provenance = "%s/%s" % (getattr(self, "provenance", self.name),
                                    sub.name)
        sub.private["seed"] = seed_fact["id"]
        produced = sub.act(seed_fact, board)
        return produced

    # -------------------------------------------------------------- helpers --
    def pub(self, board, kind, payload, confidence=1.0, tags=(),
            derived_from=()):
        f = FactLike(kind, getattr(self, "provenance", self.name), payload,
                     confidence, tags, derived_from)
        board.publish(f)
        self.facts_published += 1
        return f


class FactLike(dict):
    """Local fact constructor bound to a specialist's provenance."""

    def __init__(self, kind, source, payload, confidence, tags, derived_from):
        super().__init__(
            id="SF-%s-%04d" % (source.replace("/", "-").upper()[:14],
                                next(SF_COUNTER)),
            kind=kind, source=source, ts=time.time(),
            confidence=confidence, tags=list(tags), payload=payload,
            derived_from=list(derived_from))


SF_COUNTER = itertools.count(1)

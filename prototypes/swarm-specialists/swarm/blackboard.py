"""Blackboard — typed facts with provenance (Hearsay-II lineage, RESEARCH.md M1).

The board IS the task ledger (Magentic-One, M3): specialists never talk to
each other, they publish and read typed facts. Every fact carries:
  kind          : OBSERVATION | SURFACE | HYPOTHESIS | FINDING | ESCALATION | CONTROL
  source        : provenance chain, e.g. "exploit/statefuzz_spec" (M4 spawn)
  derived_from  : ids of facts this one was reasoned from (auditability)
  confidence    : 0..1 — execution evidence, never self-reported (E6)
"""
import itertools
import time

FACT_KINDS = ("OBSERVATION", "SURFACE", "HYPOTHESIS", "FINDING",
              "ESCALATION", "CONTROL")


class Fact(dict):
    counter = itertools.count(1)

    @classmethod
    def make(cls, kind, source, payload, confidence=1.0, tags=(),
             derived_from=()):
        assert kind in FACT_KINDS, "bad fact kind: %r" % kind
        fid = "F-%03d" % next(cls.counter)
        return cls(id=fid, kind=kind, source=source, ts=time.time(),
                   confidence=confidence, tags=list(tags), payload=payload,
                   derived_from=list(derived_from))


class Blackboard:
    def __init__(self):
        self.facts = []

    def publish(self, fact):
        self.facts.append(fact)
        return fact

    def since(self, seq):
        return self.facts[seq:]

    @property
    def length(self):
        return len(self.facts)

    def query(self, kind=None, tag=None, source=None, status=None):
        out = []
        for f in self.facts:
            if kind and f["kind"] != kind:
                continue
            if tag and tag not in f["tags"]:
                continue
            if source and not f["source"].startswith(source):
                continue
            if status and f["payload"].get("status") != status:
                continue
            out.append(f)
        return out

    def ledger(self):
        """Progress-ledger view (M3): counts per kind and per source."""
        by_kind, by_source = {}, {}
        for f in self.facts:
            by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + 1
            by_source[f["source"]] = by_source.get(f["source"], 0) + 1
        return {"facts": len(self.facts), "by_kind": by_kind,
                "by_source": by_source}

    def open_hypotheses(self):
        """Hypotheses not yet tested (exploit's queue)."""
        return [f for f in self.query(kind="HYPOTHESIS")
                if f["payload"].get("status") == "open"]

    def finding_ids(self):
        return {f["payload"].get("finding", {}).get("id")
                for f in self.query(kind="FINDING")
                if f["payload"].get("finding", {}).get("id")}

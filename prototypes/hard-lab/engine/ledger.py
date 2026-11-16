"""engine/ledger.py — the unified HypothesisLedger ("hypothetical engine").

Phase B's ledger (statefuzz/oracle.py) was a single deferred metamorphic
oracle for one async refund window. Phase D generalizes it into the
connective spine that the swarm, statefuzz and the runner all project into
(RESEARCH.md R3):

    propose(source, tag, title, prior, plan)   every belief enters here
    attach(hid, evidence)                      tests accumulate evidence
    resolve(hid, status, evidence)             honest terminal states

Resolution vocabulary (deliberately coarse, deliberately honest):
    confirmed                 independent re-execution reproduced it
    confirmed-by-transcript   artifact consumed; transcript evidence stands
    refuted                   independent re-execution found no violation
    inconclusive              never tested, or evidence insufficient

The ledger persists as hypothesis_ledger.json with full provenance so the
report can answer not just "what was found" but "what was believed, what was
tested, and what the evidence did to the belief."
"""
import time


STATUSES = ("proposed", "tested", "confirmed", "confirmed-by-transcript",
            "refuted", "inconclusive")

_SOURCE_WEIGHT = {"confirmed": 1.0, "confirmed-by-transcript": 0.5,
                  "refuted": 1.0, "inconclusive": 0.0,
                  "tested": 0.25, "proposed": 0.0}


class LedgerEntry(dict):
    def __init__(self, hid, source, tag, title, prior, plan, derived_from):
        super().__init__(
            id=hid, source=source, tag=tag, title=title, prior=prior,
            plan=plan, derived_from=list(derived_from), status="proposed",
            tests=[], evidence=[], created=time.time(), resolved=None)


class HypothesisLedger:
    def __init__(self):
        self.entries = []
        self._seq = 0

    # ------------------------------------------------------------ propose --
    def propose(self, source, tag, title, prior=0.5, plan="",
                derived_from=(), hid=None):
        self._seq += 1
        e = LedgerEntry(hid or "H-%04d" % self._seq, source, tag, title,
                        float(prior), plan, derived_from)
        self.entries.append(e)
        return e

    # -------------------------------------------------------------- test ---
    def attach(self, hid, kind, detail, requests_spent=0, finding_ids=()):
        e = self._get(hid)
        if e is None:
            return None
        e["status"] = "tested" if e["status"] == "proposed" else e["status"]
        e["tests"].append({"kind": kind, "detail": detail,
                           "requests_spent": requests_spent,
                           "finding_ids": list(finding_ids),
                           "ts": time.time()})
        return e

    # ------------------------------------------------------------ resolve --
    def resolve(self, hid, status, evidence=None):
        assert status in ("confirmed", "confirmed-by-transcript", "refuted",
                          "inconclusive", "tested"), \
            "bad resolution: %r" % status
        e = self._get(hid)
        if e is None:
            return None
        e["status"] = status
        e["resolved"] = time.time()
        if evidence is not None:
            e["evidence"].append(evidence)
        return e

    # ---------------------------------------------------- deferred window --
    def deferred(self, source, marker, callback_path, expectation, ttl=6.0):
        """Phase-B semantics preserved: a window that cannot be asserted at
        mutation time. The runner polls; the reconciliation pass resolves."""
        e = self.propose(source, "deferred-window",
                         "deferred effect via %s (ttl %.1fs)"
                         % (callback_path, ttl), prior=0.5,
                         plan="poll %s until resolved" % callback_path)
        e["deferred"] = {"marker": marker, "callback_path": callback_path,
                         "expectation": expectation, "ttl": ttl}
        return e

    # -------------------------------------------------------------- views --
    def _get(self, hid):
        for e in self.entries:
            if e["id"] == hid:
                return e
        return None

    def by_source(self, source_prefix):
        return [e for e in self.entries
                if e["source"].startswith(source_prefix)]

    def stats(self):
        by_status, by_source = {}, {}
        for e in self.entries:
            by_status[e["status"]] = by_status.get(e["status"], 0) + 1
            by_source[e["source"]] = by_source.get(e["source"], 0) + 1
        return {"total": len(self.entries), "by_status": by_status,
                "by_source": by_source}

    def score(self):
        """Sum of resolution weights — the engine's honest yield, where a
        refuted belief scores exactly as high as a confirmed one (both are
        information)."""
        return round(sum(_SOURCE_WEIGHT.get(e["status"], 0.0)
                         for e in self.entries), 2)

    # ------------------------------------------------------------ persist --
    def save(self, path):
        import json
        doc = {"tool": "hypothesis-ledger", "version": "1.0.0",
               "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "stats": self.stats(), "score": self.score(),
               "entries": self.entries}
        with open(path, "w") as fh:
            json.dump(doc, fh, indent=2)
        return doc

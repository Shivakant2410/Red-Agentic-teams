# -*- coding: utf-8 -*-
import time

from ..appmodel import extract_model
from ..demo.vuln_bank import BANK_SPEC, VULNERABLE_BUGS, BankApp
from ..executor import BudgetMeter, Executor
from ..invariants import InvariantSet
from ..mutants import expand
from ..oracle import (DifferentialOracle, HypothesisLedger, Oracle,
                      read_back)


def make_oracle(app_bugs=set(VULNERABLE_BUGS)):
    model = extract_model(BANK_SPEC)
    app = BankApp(bugs=set(app_bugs))
    ex = Executor(adapter=app.adapter, observe=app.observe,
                  budget=BudgetMeter(500), stop_check=lambda: False)
    return model, app, ex, Oracle(model=model, invariants=InvariantSet.default())


def idem_mutant(model):
    return next(x for x in expand(model, techniques=["IDEMPOTENCE"], salt="t")
                if x.mutant_id.startswith("IDEM-T3"))


# -- immediate metamorphic ---------------------------------------------------

def test_idempotence_oracle_catches_missing_dedupe():
    model, _, ex, oracle = make_oracle({"no_idem"})
    res = ex.execute(idem_mutant(model))
    vios = oracle.run(idem_mutant(model), res)
    assert any(v.invariant_id == "INV-I5" for v in vios)


def test_idempotence_oracle_silent_on_fixed_app():
    model, _, ex, oracle = make_oracle(set())
    res = ex.execute(idem_mutant(model))
    assert oracle.run(idem_mutant(model), res) == []


# -- differential (mutant vs clean-reference run) ------------------------------

def test_differential_divergence_fires():
    def effect_counter(obs):
        if obs is None:
            return {}
        return {"effects": float(sum(1 for e in obs.events
                                     if e.get("kind") == "applied_effect"))}
    vuln = BankApp(bugs={"no_idem"})
    clean = BankApp(bugs=set())
    ex_v = Executor(adapter=vuln.adapter, observe=vuln.observe,
                    budget=BudgetMeter(500), stop_check=lambda: False)
    ex_c = Executor(adapter=clean.adapter, observe=clean.observe,
                    budget=BudgetMeter(500), stop_check=lambda: False)
    model = extract_model(BANK_SPEC)
    m = idem_mutant(model)
    diff = DifferentialOracle(effect_counter=effect_counter)
    vios = diff.compare(ex_v.execute(m), ex_c.execute(m))
    assert len(vios) == 1 and vios[0].invariant_id == "INV-DIFF"
    assert vios[0].evidence["effect_delta_mutant"]["effects"] == 2.0
    assert vios[0].evidence["effect_delta_clean"]["effects"] == 1.0


def test_differential_converged_runs_are_silent():
    vuln, clean = BankApp(bugs=set()), BankApp(bugs=set())
    ex1 = Executor(adapter=vuln.adapter, observe=vuln.observe,
                   budget=BudgetMeter(500), stop_check=lambda: False)
    ex2 = Executor(adapter=clean.adapter, observe=clean.observe,
                   budget=BudgetMeter(500), stop_check=lambda: False)
    model = extract_model(BANK_SPEC)
    m = next(x for x in expand(model, techniques=["REPLAY"], salt="t")
             if x.mutant_id.startswith("REPLAY-T3"))
    vios = DifferentialOracle().compare(ex1.execute(m), ex2.execute(m))
    assert vios == []


# -- read-back ------------------------------------------------------------------

def test_read_back_silent_when_stored_matches_claim():
    model, app, ex, _ = make_oracle(set())
    m = next(x for x in expand(model, techniques=["REPLAY"], salt="t")
             if x.mutant_id.startswith("REPLAY-T1"))
    res = ex.execute(m)

    def probe(obs):
        return obs.facts.get("account:acc:A1")

    def claim(body, stored):
        # the deposit applied its claimed effect: balance 1000 + 100
        return abs(stored["balance"] - 1100.0) < 1e-6

    assert read_back(res, app.observe, probe, claim) == []


def test_read_back_fires_on_divergence():
    model, app, ex, _ = make_oracle(set())
    m = next(x for x in expand(model, techniques=["REPLAY"], salt="t")
             if x.mutant_id.startswith("REPLAY-T1"))
    res = ex.execute(m)

    def probe(obs):
        stored = dict(obs.facts.get("account:acc:A1") or {})
        stored["balance"] = -1.0          # simulate tampered/inconsistent read
        return stored

    def claim(body, stored):
        return abs(stored["balance"] - 1100.0) < 1e-6

    assert len(read_back(res, app.observe, probe, claim)) == 1


# -- deferred hypothesis ledger -------------------------------------------------

def test_ledger_confirms_on_marker_hit():
    model, _, ex, _ = make_oracle(set())
    m = next(x for x in expand(model, techniques=["REPLAY"], salt="t")
             if x.mutant_id.startswith("REPLAY-T1"))
    res = ex.execute(m)
    ledger = HypothesisLedger()
    h = ledger.register(res, expect="export email contains marker", ttl_s=60)
    hits = ledger.sweep([{"webhook": f"payload with {h.marker} inside"}])
    assert [x.hypothesis_id for x in hits] == [h.hypothesis_id]
    assert h.status == "confirmed" and len(h.hits) == 1


def test_ledger_expires_inconclusive_never_confirms():
    model, _, ex, _ = make_oracle(set())
    res = ex.execute(next(x for x in expand(model, techniques=["REPLAY"],
                                            salt="t")
                          if x.mutant_id.startswith("REPLAY-T1")))
    ledger = HypothesisLedger()
    h = ledger.register(res, expect="async webhook", ttl_s=0.01)
    time.sleep(0.03)
    assert ledger.sweep([]) == []
    assert h.status == "inconclusive"          # never auto-promoted
    assert ledger.sweep([{"late": h.marker}]) == []   # expired stays expired

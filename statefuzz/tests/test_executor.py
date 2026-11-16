# -*- coding: utf-8 -*-
import pytest

from ..appmodel import extract_model
from ..demo.vuln_bank import BANK_SPEC, VULNERABLE_BUGS, BankApp
from ..executor import BudgetExhausted, BudgetMeter, Executor
from ..mutants import expand


def make_executor(app, budget=100, stop=lambda: False, traffic=None):
    return Executor(adapter=app.adapter, observe=app.observe,
                    budget=BudgetMeter(budget), stop_check=stop,
                    traffic_sink=(traffic.append if traffic is not None else None))


def race_mutant():
    m = extract_model(BANK_SPEC)
    return next(x for x in expand(m, techniques=["INTERRUPT"], salt="t")
                if x.mutant_id.startswith("RACE-T2"))


def test_race_eight_synchronized_writes_last_write_wins():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ex = make_executor(app)
    res = ex.execute(race_mutant())
    pr = res.plan_results[0]
    assert len(pr.responses) == 8
    assert all(r.status == 200 for r in pr.responses)
    bal = app.accounts["acc:A1"]["balance"]
    assert bal == 500.0                        # 8 payouts, one debit recorded


def test_race_on_fixed_app_conserves():
    app = BankApp(bugs=set())
    ex = make_executor(app)
    res = ex.execute(race_mutant())
    statuses = [r.status for r in res.responses]
    assert statuses.count(200) == 2            # 1000 / 500 = two legal payouts
    assert statuses.count(409) == 6
    assert app.accounts["acc:A1"]["balance"] == 0.0


def test_budget_meter_refuses_overdraft():
    meter = BudgetMeter(2)
    meter.spend(2)
    assert meter.remaining == 0
    with pytest.raises(BudgetExhausted):
        meter.spend(1)


def test_executor_stops_at_budget_and_reports():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ex = make_executor(app, budget=10)
    res = ex.execute(race_mutant())            # needs 8
    assert res.aborted == ""
    res2 = ex.execute(race_mutant())           # needs 8, only 2 left
    assert res2.aborted == "budget"
    assert res2.responses == []                # refused before any send
    assert ex.budget.spent == 8                # raise leaves meter untouched


def test_stop_file_halts_before_first_plan(tmp_path):
    f = tmp_path / "STOP"
    f.write_text("kill")
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ex = make_executor(app, stop=lambda: f.exists())
    res = ex.execute(race_mutant())
    assert res.aborted == "stop-file" and res.responses == []


def test_traffic_sink_receives_one_record_per_plan():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    traffic = []
    ex = make_executor(app, traffic=traffic)
    ex.execute(race_mutant())
    assert len(traffic) == 1
    assert traffic[0]["timing"] == "race"

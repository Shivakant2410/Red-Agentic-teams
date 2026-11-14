# -*- coding: utf-8 -*-
"""End-to-end: the loop against vuln-bank, vulnerable vs fixed, plus the
platform discipline checks (approval gate, stop file, scope guard, budget)."""
import json

import pytest

from ..context import Approvals, Bandit, ReferenceContext
from ..demo.vuln_bank import BANK_SPEC, DEMO_PRIORS, VULNERABLE_BUGS, BankApp
from ..tools import build_statefuzz_tools
from ..runner import statefuzz_run

ALL = {"SF-SKIP", "SF-REPLAY", "SF-REORDER", "SF-PARTIAL", "SF-NEGATIVE",
       "SF-CROSSUSER", "SF-RACE", "SF-IDEM"}


def make_ctx(app, granted=ALL, priors=None, **kw):
    return ReferenceContext(
        adapter=app.adapter, observe=app.observe,
        approvals=Approvals(granted_techniques=set(granted)),
        bandit=Bandit(priors=dict(priors or DEMO_PRIORS)), **kw)


def test_vulnerable_run_hits_all_five_invariant_classes():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    rep = statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert rep.mutants_total == 37
    assert rep.findings_count >= 15
    ids = {f.invariant_id for f in ctx.findings}
    assert {"INV-I1", "INV-I2", "INV-I3", "INV-I4", "INV-I5"} <= ids
    assert rep.technique_yield["SF-RACE"] >= 1          # race double-spend
    assert rep.chains and max(len(c["findings"]) for c in rep.chains) >= 2
    assert rep.spent <= 300 and rep.aborted == ""


def test_fixed_run_zero_false_positives():
    app = BankApp(bugs=set())
    ctx = make_ctx(app)
    rep = statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert rep.mutants_executed == rep.mutants_total == 37
    assert rep.violations_count == 0 and rep.findings_count == 0


def test_approval_gate_fails_closed_for_write_techniques():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app, granted=set())            # nothing granted
    rep = statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert rep.mutants_skipped_unapproved > 0
    # only READ_SAFE mutants ran; cross-user statement read is seeded bug I3
    used = {f.technique_id for f in ctx.findings}
    assert used <= {"SF-CROSSUSER"}


def test_stop_file_aborts_run_before_any_mutant(tmp_path):
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    ctx = make_ctx(app, stop_file=str(stop))
    rep = statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert rep.aborted == "stop-file"
    assert rep.mutants_executed == 0


def test_scope_guard_tears_run_down_fail_closed():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app, allowed_namespace=("/outside",))
    rep = statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert rep.aborted == "ScopeViolation"
    assert ctx.torn_down is True


def test_budget_exhaustion_stops_cleanly():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    rep = statefuzz_run(ctx, budget=10, spec=BANK_SPEC)
    assert rep.aborted == "budget"
    assert rep.spent <= 10


def test_bandit_rewards_are_bounded():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    before = dict(ctx.bandit.priors)
    statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    for tid, v in ctx.bandit.priors.items():
        assert abs(v - before[tid]) <= 25.0 + 1e-9   # reflection clamp


def test_memory_absorb_records_per_mutant_yield():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    assert len(ctx.memory) == 37
    assert all("technique_id" in m and "violations" in m for m in ctx.memory)


def test_traffic_log_is_jsonl_shaped(tmp_path):
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    out = tmp_path / "traffic.jsonl"
    ctx.write_traffic(str(out))
    lines = out.read_text().strip().splitlines()
    assert len(lines) == len(ctx.traffic) >= 30
    assert all(json.loads(l)["method"] for l in lines)


# -- registry tools -------------------------------------------------------------

def test_build_statefuzz_tools_contract():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    tools = build_statefuzz_tools(ctx)
    assert {t["name"] for t in tools} == {"statefuzz_run", "statefuzz_status",
                                          "statefuzz_export"}
    for t in tools:
        assert callable(t["schema"]) and callable(t["run"])
        schema = t["schema"]()
        assert schema["type"] == "object"


def test_tool_run_reports_findings_and_awaiting_approvals():
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app, granted=set())       # writes unapproved
    run_tool = next(t for t in build_statefuzz_tools(ctx)
                    if t["name"] == "statefuzz_run")
    out = run_tool["run"](ctx, spec=BANK_SPEC, budget=300)
    assert out["ok"] is True
    assert out["report"]["mutants_total"] == 37
    assert "SF-RACE" in out["awaiting_approval"]
    assert out["note"].startswith("write-shaped")


def test_tool_export_writes_findings_json(tmp_path):
    app = BankApp(bugs=set(VULNERABLE_BUGS))
    ctx = make_ctx(app)
    statefuzz_run(ctx, budget=300, spec=BANK_SPEC)
    export = next(t for t in build_statefuzz_tools(ctx)
                  if t["name"] == "statefuzz_export")
    out = export["run"](ctx, path=str(tmp_path / "findings.json"))
    assert out["ok"] and out["count"] == len(ctx.findings)
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["findings"] and "preconditions" in data["findings"][0]

# -*- coding: utf-8 -*-
"""runner.py — statefuzz_run(ctx, budget): the main loop (dossier 9.3).

    model  = extract model (deterministic + optional platform LLM labels)
    invs   = default invariant bundle (I1..I5)
    queue  = expand mutants, rank by bandit priors
    while budget and queue:
        m = queue.pop()
        if m.tier == 'write' and not ctx.approvals.granted(m):  # fail-closed
            continue
        result = executor.execute(m)                            # SAT sessions, warmed
        vios   = oracle.run(m, result, reference)
        findings.append(...)                                    # grants/preconditions
        queue.rechain(model, f, B)                              # chaining rewards enablers
        ctx.memory.absorb(m, result)                            # |delta|<=25 on priors
    return chains.top_paths(k=10)

Discipline baked in:
  * stop-file checked before every mutant,
  * scope-guard wraps every plan (fail-closed teardown),
  * write mutants require an approval grant — unapproved techniques are
    skipped, never downgraded,
  * budget exhaustion ends the run cleanly after the current mutant,
  * bandit rewards are bounded (reflection may reorder only).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .appmodel import AppStateModel, extract_model
from .chains import Finding, from_violation, top_paths
from .context import REFLECTION_CLAMP, ReferenceContext, ScopeViolation
from .executor import BudgetExhausted, BudgetMeter, Executor, MutantResult
from .invariants import InvariantSet, Violation
from .mutants import expand, rank
from .oracle import HypothesisLedger, Oracle


@dataclass
class RunReport:
    started: float = field(default_factory=time.time)
    duration_s: float = 0.0
    budget: int = 0
    spent: int = 0
    mutants_total: int = 0
    mutants_executed: int = 0
    mutants_skipped_unapproved: int = 0
    findings_count: int = 0
    violations_count: int = 0
    aborted: str = ""
    technique_yield: Dict[str, int] = field(default_factory=dict)
    chains: List[dict] = field(default_factory=list)
    spec: Optional[dict] = None          # AppStateModel.to_dict() when emitted

    def to_dict(self) -> dict:
        return {
            "duration_s": round(self.duration_s, 3), "budget": self.budget,
            "spent": self.spent, "mutants_total": self.mutants_total,
            "mutants_executed": self.mutants_executed,
            "mutants_skipped_unapproved": self.mutants_skipped_unapproved,
            "findings_count": self.findings_count,
            "violations_count": self.violations_count,
            "aborted": self.aborted,
            "technique_yield": self.technique_yield,
            "top_chains": self.chains,
        }


def statefuzz_run(ctx: ReferenceContext, budget: int = 200,
                  spec: Optional[dict] = None,
                  techniques: Optional[List[str]] = None,
                  emit_model: bool = False,
                  clean_executor: Optional[Executor] = None,
                  max_depth: int = 4) -> RunReport:
    """Run the statefuzz loop against the platform context. `spec` is the
    OpenAPI-lite machine description (extract_model); when omitted the ctx
    must carry `ctx.spec`. clean_executor, when wired, re-executes every
    mutant against a clean reference (fixed build / staging twin) for the
    differential oracle. Findings land in ctx.findings (and any findings.json
    sink the platform already owns)."""
    report = RunReport(budget=budget)
    executor = Executor(
        adapter=ctx.adapter, observe=ctx.observe, budget=BudgetMeter(budget),
        stop_check=ctx.stop_check, traffic_sink=ctx.traffic_sink,
    )
    oracle = Oracle(model=None, invariants=InvariantSet.default())  # model set below

    spec = spec or getattr(ctx, "spec", None)
    if spec is None:
        raise ValueError("statefuzz_run: no app spec provided (ctx.spec or spec=)")
    model: AppStateModel = extract_model(spec, None, ctx.llm)
    oracle.model = model
    report.spec = model.to_dict() if emit_model else None

    mutants = rank(expand(model, techniques, salt=_salt(ctx)), ctx.bandit.priors)
    report.mutants_total = len(mutants)

    findings: List[Finding] = []
    fnum = 0
    vnum = 0

    try:
        for mutant in mutants:
            if ctx.stop_check():
                report.aborted = "stop-file"
                break
            if executor.budget.remaining <= 0:
                report.aborted = "budget"
                break
            if mutant.tier == "write" and not ctx.approvals.granted(mutant):
                report.mutants_skipped_unapproved += 1
                continue
            try:
                ctx.scope_guard(mutant.plans[0]) if mutant.plans else None
                result: MutantResult = executor.execute(mutant)
            except (ScopeViolation, BudgetExhausted) as exc:
                report.aborted = type(exc).__name__
                break

            report.mutants_executed += 1
            vios: List[Violation] = oracle.run(mutant, result,
                                               clean_executor=clean_executor)
            report.violations_count += len(vios)
            ctx.memory_absorb(mutant, result, len(vios))
            ctx.bandit.reward(mutant.technique_id,
                              min(REFLECTION_CLAMP / 2, 2.0 * len(vios)))

            for v in vios:
                vnum += 1
                fnum += 1
                t = model.transition(mutant.seed_transition)
                f = from_violation(v, mutant, fnum, seed_transition=t)
                findings.append(f)
                ctx.findings_sink(f)
            report.technique_yield[mutant.technique_id] = \
                report.technique_yield.get(mutant.technique_id, 0) + len(vios)
    finally:
        report.duration_s = time.time() - report.started
        report.spent = executor.budget.spent
        report.findings_count = len(findings)
        report.chains = top_paths(findings, k=10, max_depth=max_depth)
    return report


def _salt(ctx: ReferenceContext) -> str:
    return hex(int(time.time() * 1000) & 0xFFFF)[2:]

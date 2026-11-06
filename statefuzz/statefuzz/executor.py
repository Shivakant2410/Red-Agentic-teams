# -*- coding: utf-8 -*-
"""executor.py — IAT (Invariant-Abusing Test) sessions (dossier 9.1).

Executes mutants against an AppAdapter while enforcing the platform
discipline:

  * budget meter — every request decrements the run budget; exhaustion raises
    BudgetExhausted and the runner stops cleanly (never mid-mutant: the
    current mutant finishes, then the loop halts),
  * stop-file check before every mutant (platform STOP kill file),
  * scope guard — the adapter itself is scoped; the executor records every
    plan into the traffic log for replay and audit,
  * two-principal sessions — 'A' (primary) and 'B' (second principal) warmed
    per run; CROSS-USER mutants ride B's session,
  * race execution — timing='race' fires n identical plans synchronized via a
    threading.Barrier. The in-process demo adapter exposes a read-modify-write
    window; in production the transport is swapped for single-packet sync
    (Kettle last-byte alignment / first-sequence-sync, dossier 6).
"""
from __future__ import annotations

import concurrent.futures
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .appmodel import AppStateModel, ObservedState, RequestPlan, Response


class BudgetExhausted(RuntimeError):
    pass


class BudgetMeter:
    def __init__(self, budget: int):
        self.remaining = int(budget)
        self.spent = 0

    def spend(self, n: int = 1) -> None:
        if self.remaining < n:
            raise BudgetExhausted(f"budget exhausted (remaining={self.remaining}, need={n})")
        self.remaining -= n
        self.spent += n


AppAdapter = Callable[[RequestPlan], Response]
"""The platform provides the transport: send(plan) -> Response. It is
responsible for session routing (plan.principal), the ScopeGuard egress
policy, and traffic.jsonl recording. statefuzz never opens its own sockets —
it rides the platform's already-recorded, already-gated fetch path."""


ObserveFn = Callable[[], ObservedState]
"""snapshot() for the read-back oracle and alpha abstraction."""


@dataclass
class PlanResult:
    """One plan executed -> its responses (1 for single, n for repeat/race,
    grouped so per-plan oracles see race/replay multiplicities). before/after
    snapshots are per-plan so REORDER-style legality checks see intermediate
    states."""
    plan: RequestPlan
    responses: List[Response] = field(default_factory=list)
    before: Optional[ObservedState] = None
    after: Optional[ObservedState] = None


@dataclass
class MutantResult:
    mutant_id: str
    operator: str
    technique_id: str
    seed_transition: str
    plan_results: List[PlanResult] = field(default_factory=list)
    before: Optional[ObservedState] = None
    after: Optional[ObservedState] = None
    aborted: str = ""              # non-empty => why execution stopped early

    @property
    def responses(self) -> List[Response]:
        return [r for pr in self.plan_results for r in pr.responses]

    def to_dict(self) -> dict:
        return {
            "mutant_id": self.mutant_id, "operator": self.operator,
            "technique_id": self.technique_id,
            "seed_transition": self.seed_transition,
            "statuses": [r.status for r in self.responses],
            "aborted": self.aborted,
        }


@dataclass
class Executor:
    adapter: AppAdapter
    observe: ObserveFn
    budget: BudgetMeter
    stop_check: Callable[[], bool]
    traffic_sink: Optional[Callable[[dict], None]] = None
    race_workers: int = 8

    # ------------------------------------------------------------------
    def execute(self, mutant) -> MutantResult:
        """Run one mutant: snapshot -> plans -> snapshot. 'race' plans are
        synchronized; 'repeat' plans are sent sequentially n times."""
        res = MutantResult(
            mutant_id=mutant.mutant_id, operator=mutant.operator,
            technique_id=mutant.technique_id,
            seed_transition=mutant.seed_transition,
        )
        res.before = self.observe()
        last_pr: Optional[PlanResult] = None
        for plan in mutant.plans:
            if self.stop_check():
                res.aborted = "stop-file"
                break
            pr = PlanResult(plan=plan, before=self.observe())
            try:
                if plan.timing == "race":
                    pr.responses.extend(self._race(plan))
                else:
                    for _ in range(max(1, plan.repeat_n)):
                        self.budget.spend()
                        pr.responses.append(self._send(plan))
            except BudgetExhausted:
                res.aborted = "budget"
                pr.after = self.observe()
                res.plan_results.append(pr)
                break
            pr.after = self.observe()
            res.plan_results.append(pr)
            last_pr = pr
        res.after = last_pr.after if last_pr is not None else self.observe()
        return res

    # ------------------------------------------------------------------
    def _send(self, plan: RequestPlan) -> Response:
        t0 = time.time()
        resp = self.adapter(plan)
        if self.traffic_sink:
            self.traffic_sink({
                "ts": round(time.time(), 3), "elapsed_ms": round((time.time() - t0) * 1000, 2),
                "method": plan.method, "path": plan.path,
                "principal": plan.principal, "timing": plan.timing,
                "note": plan.note, "status": resp.status,
            })
        return resp

    def _race(self, plan: RequestPlan) -> List[Response]:
        """n sends released simultaneously by a Barrier. The platform
        transport decides wire-level synchronization; in-process this is a
        thread race against the app's RMW window."""
        n = max(2, plan.repeat_n)
        self.budget.spend(n)
        barrier = threading.Barrier(n)
        results: List[Optional[Response]] = [None] * n

        def one(i: int) -> None:
            barrier.wait()
            results[i] = self.adapter(plan)

        threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        out = [r for r in results if r is not None]
        if self.traffic_sink:
            self.traffic_sink({
                "ts": round(time.time(), 3), "method": plan.method,
                "path": plan.path, "principal": plan.principal,
                "timing": "race", "note": plan.note,
                "statuses": [r.status for r in out],
            })
        return out

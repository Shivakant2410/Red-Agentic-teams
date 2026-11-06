# -*- coding: utf-8 -*-
"""context.py — ReferenceContext: the ctx protocol statefuzz_run expects,
implemented against the Red-Agentic-teams contracts (dossier 9.3).

The platform's orchestrator already owns: ScopeGuard (fail-closed egress
firewall), approval gates, STOP kill file, traffic.jsonl recording, the
ExperienceStore and the contextual bandit. statefuzz does NOT replace any of
it — it rides the same interfaces:

  ctx.adapter(plan)         platform transport (scoped; principal-routed)
  ctx.observe()             state snapshot (alpha input + read-back oracle)
  ctx.stop_check()          STOP kill file
  ctx.approvals.granted(m)  tier gate; deny default; fail-closed
  ctx.bandit.priors         technique priors; runner clamps updates |d|<=25
  ctx.memory.absorb(...)    ExperienceStore write-through
  ctx.findings_sink(f)      findings.json stream
  ctx.traffic_sink(rec)     traffic.jsonl stream
  ctx.scope_guard(plan)     last-line egress check before every plan
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .appmodel import ObservedState, RequestPlan, Response
from .chains import Finding
from .executor import MutantResult

REFLECTION_CLAMP = 25.0     # bounded reflection: |delta| <= 25 (dossier 9.3)


class ScopeViolation(RuntimeError):
    """Raised when a plan leaves the allowed namespace. The reference context
    fails closed: run aborts, findings frozen, teardown flag set — mirroring
    the platform's TEST-NET-1 self-teardown behavior for egress violations."""


@dataclass
class Approvals:
    """Tier gate. Default deny. Grants are per technique id (bandit arm), not
    per mutant, so an approved technique stays approved across the run."""
    granted_techniques: set = field(default_factory=set)

    def granted(self, mutant) -> bool:
        return mutant.technique_id in self.granted_techniques

    def grant(self, technique_id: str) -> None:
        self.granted_techniques.add(technique_id)


@dataclass
class Bandit:
    """Technique priors with bounded reflection updates."""
    priors: Dict[str, float] = field(default_factory=lambda: {
        "SF-SKIP": 10.0, "SF-REPLAY": 10.0, "SF-REORDER": 8.0,
        "SF-PARTIAL": 10.0, "SF-NEGATIVE": 12.0, "SF-CROSSUSER": 12.0,
        "SF-RACE": 8.0, "SF-IDEM": 10.0,
    })
    clamp: float = REFLECTION_CLAMP

    def reward(self, technique_id: str, value: float) -> None:
        """Bounded update: priors may be reordered but not exploded — a
        single lucky find cannot capture the bandit (dossier 9.3)."""
        cur = self.priors.get(technique_id, 10.0)
        delta = max(-self.clamp, min(self.clamp, float(value)))
        self.priors[technique_id] = max(0.0, cur + delta)


@dataclass
class ReferenceContext:
    adapter: Callable[[RequestPlan], Response]
    observe: Callable[[], ObservedState]
    allowed_namespace: tuple = ("/accounts", "/transfers", "/statements",
                                "/health")     # scope guard allowlist
    stop_file: str = ""
    approvals: Approvals = field(default_factory=Approvals)
    bandit: Bandit = field(default_factory=Bandit)
    findings: List[Finding] = field(default_factory=list)
    traffic: List[dict] = field(default_factory=list)
    memory: List[dict] = field(default_factory=list)
    torn_down: bool = False
    llm: Optional[Callable] = None          # platform LLM labeler (optional)

    # -- platform interface ------------------------------------------------
    def stop_check(self) -> bool:
        if self.torn_down:
            return True
        return bool(self.stop_file) and os.path.exists(self.stop_file)

    def scope_guard(self, plan: RequestPlan) -> None:
        """Fail-closed: any path outside the allowlist tears the run down.
        In production this wraps the platform's ScopeGuard; the reference
        implementation enforces the same contract locally."""
        ok = any(plan.path.startswith(p) for p in self.allowed_namespace)
        if not ok:
            self.torn_down = True
            raise ScopeViolation(
                f"egress violation: {plan.method} {plan.path} outside "
                f"{self.allowed_namespace} — run torn down (fail-closed)")

    def findings_sink(self, f: Finding) -> None:
        self.findings.append(f)

    def traffic_sink(self, rec: dict) -> None:
        self.traffic.append(rec)

    def memory_absorb(self, mutant, result: MutantResult, violations: int) -> None:
        """ExperienceStore write-through: technique, yield, cost. The runner
        uses it for bandit rewards; reflections only reorder priors."""
        self.memory.append({
            "ts": round(time.time(), 3), "technique_id": mutant.technique_id,
            "mutant_id": mutant.mutant_id, "operator": mutant.operator,
            "violations": violations,
            "statuses": [r.status for r in result.responses],
        })

    # -- persistence ---------------------------------------------------------
    def write_traffic(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for rec in self.traffic:
                fh.write(json.dumps(rec) + "\n")

    def write_findings(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [f.to_dict() for f in self.findings]},
                      fh, indent=2)

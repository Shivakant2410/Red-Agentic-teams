"""registry_tool — the swarm as a Red-Agentic-teams registry tool.

Contract: build_swarm_registry() -> {"swarm_run": {"schema": ..., "run": ctx}}

M4: the phases moved into swarm/orchestrator.Orchestrator — the governance
shell with the three swapped seams (PolicyGuard at the wire chokepoint,
SwarmVerifyPipeline over findings, ExperienceStore over per-specialist
memory). This module keeps the REGISTRY CONTRACT and delegates:

    run(ctx) == Orchestrator().run(ctx)     # same code by construction

run(ctx) phases (all inside the Orchestrator now):
  0. policy pre-flight: target admission (loopback / TEST-NET-1,
     fail-closed) + per-action approval gate on write mutants   [M4]
  1. shared executor (budget, STOP file, traffic.jsonl) +
     ExperienceStore namespaces
  2. blackboard seed: CONTROL engage
  3. router dispatch loop (trigger-gated specialists, stall detection)
     [M1/M3 — dispatch semantics unchanged]
  4. verify pipeline pass: one verdict vocabulary; unproven claims
     downgrade to not_reproducible                              [M4]
  5. end-of-run curation: verification-weighted outcomes -> per-specialist
     namespaces, persisted for the NEXT run (E4/E5)             [M4 store]
  6. projections: M0/M1 ledger spine + M3 attack graph          [M0-M3]
  7. artifacts: findings.json (provenance + verification stamps),
     blackboard.json, dispatch_trace.jsonl, policy_audit.jsonl  [M4]
"""
from .orchestrator import (Orchestrator, _SPINE_AVAILABLE, _SEAM_NOTE,
                           _schema, _dedupe, _assemble)


def _scope_ok(base_url):
    """Backward-compatible scope predicate (now backed by the policy)."""
    from .policy import host_allowed
    return host_allowed(base_url)


def _descendants(board):
    """Backward-compatible re-export (moved to swarm/verify_pipeline.py)."""
    from .verify_pipeline import _descendants as _d
    return _d(board)


def _finding_status(board):
    """Backward-compatible re-export (moved to swarm/verify_pipeline.py)."""
    from .verify_pipeline import _finding_status as _fs
    return _fs(board)


def _curation_outcomes(specialist, board):
    """Backward-compatible re-export (moved to swarm/verify_pipeline.py)."""
    from .verify_pipeline import SwarmVerifyPipeline
    return SwarmVerifyPipeline().curation_outcomes(specialist, board)


def run(ctx, budget=None):
    """Registry entry point — delegates to the Orchestrator (M4)."""
    return Orchestrator().run(ctx, budget=budget)


def build_swarm_registry():
    """Red-Agentic-teams registry contract: tools expose schema() + run(ctx)."""
    return {"swarm_run": {"schema": _schema, "run": run}}

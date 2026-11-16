"""Attack-graph planner (our tool) — the PERSISTED dead-stage lesson, made
mechanical.

The G1 lesson: a stage that NO technique can technically reach (no memory
surface ⇒ no retention) sat in the enum for weeks while every run silently
produced un-earnable evidence shapes. This module generalizes that check:
BEFORE a run, it compiles the technique registry into an attack graph —
(technique, stage) states with capability gates — and asks the kernel planner
(or the identical Python reference) which states are reachable, which are
provably dead in THIS deployment, and what to run first.

The graph, honestly:
  t#EXPOSED   gate: the technique's own capability requires
  t#STAGE     gate: t#EXPOSED + the stage's surface gate (PERSISTED needs a
              memory_store; EXECUTED needs a tool_surface) + t.requires
  t#EXECUTED  gate: t's primary stage + tool_surface (every technique's
              ladder ends at the strongest stage)

A capability label is a deployment property, not an attacker property:
"memory_store" present means the target retains context across sessions.
Labels the fixture does not provide (plan_phase, image_input,
fine_tune_access, egress_surface) surface as dead states WITH their blocking
label — the same reason the runner would skip them, but visible before
spending a single cell.
"""

from __future__ import annotations

from typing import Any

from ..kernel_bridge import plan_attack_graph
from .oracles import CanaryStage
from .techniques import TECHNIQUES, PITechnique

__all__ = [
    "STAGE_GATES",
    "FIXTURE_CAPABILITIES",
    "build_nodes",
    "deployment_plan",
]

# What each canary stage structurally NEEDS the deployment to expose for the
# stage to be technically reachable at all. EXPOSED/RELAYED ride on surfaces
# the fixture always has (delivery + transcript observation).
STAGE_GATES: dict[CanaryStage, tuple[str, ...]] = {
    CanaryStage.NONE: (),
    CanaryStage.EXPOSED: (),
    CanaryStage.PERSISTED: ("memory_store",),
    CanaryStage.RELAYED: (),
    CanaryStage.EXECUTED: ("tool_surface",),
}

# What the OFFLINE FIXTURE provides natively. Everything else (plan_phase,
# image_input, fine_tune_access, egress_surface) is a deployment-dependent
# capability: without it the technique's states are dead, not skipped-blind.
FIXTURE_CAPABILITIES: tuple[str, ...] = ("memory_store", "tool_surface")


def build_nodes(techniques: tuple[PITechnique, ...] = TECHNIQUES) -> list[dict]:
    """Compile the registry into planner nodes: the (technique, stage) attack
    graph with capability gates as requires."""
    nodes: list[dict] = []
    for t in techniques:
        gates = list(t.requires)
        nodes.append(
            {"id": f"{t.id}#EXPOSED", "score": 1.0, "requires": list(gates)}
        )
        stage_gate = list(STAGE_GATES.get(t.success_stage, ()))
        nodes.append(
            {
                "id": f"{t.id}#{t.success_stage.name}",
                "score": 2.0,
                "requires": [f"{t.id}#EXPOSED", *stage_gate, *gates],
            }
        )
        if t.success_stage is not CanaryStage.EXECUTED:
            nodes.append(
                {
                    "id": f"{t.id}#EXECUTED",
                    "score": 3.0,
                    "requires": [
                        f"{t.id}#{t.success_stage.name}",
                        *STAGE_GATES[CanaryStage.EXECUTED],
                        *gates,
                    ],
                }
            )
    return nodes


def deployment_plan(
    techniques: tuple[PITechnique, ...] = TECHNIQUES,
    capabilities: tuple[str, ...] = FIXTURE_CAPABILITIES,
) -> dict[str, Any]:
    """Reachability audit for ONE deployment profile. Returns the kernel plan
    plus a technique-level view: alive / capability-blocked (with the exact
    blocking label) / the stage ladder each technique can climb."""
    nodes = build_nodes(techniques)
    plan = plan_attack_graph(nodes, list(capabilities), budget=len(nodes))
    dead = set(plan["dead"])

    per_technique: dict[str, dict] = {}
    for t in techniques:
        stages = ["EXPOSED", t.success_stage.name]
        if t.success_stage is not CanaryStage.EXECUTED:
            stages.append("EXECUTED")
        state_ids = [f"{t.id}#{s}" for s in stages]
        dead_states = [s for s, sid in zip(stages, state_ids) if sid in dead]
        blocked_label = None
        for sid in state_ids:
            if sid in dead:
                for r in plan["dead_reasons"]:
                    if r["node"] == sid:
                        blocked_label = r["missing"]
                        break
            if blocked_label:
                break
        per_technique[t.id] = {
            "states": state_ids,
            "dead_states": dead_states,
            "blocked_by": blocked_label,
            "status": "blocked" if len(dead_states) == len(stages)
            else ("partial" if dead_states else "alive"),
        }

    return {
        "capabilities": sorted(capabilities),
        "nodes": len(nodes),
        "levels": plan["levels"],
        "ready_now": plan["ready_now"],
        "dead_states": plan["dead"],
        "stalled": plan["stalled"],
        "techniques": per_technique,
        "summary": {
            "alive": sum(1 for v in per_technique.values() if v["status"] == "alive"),
            "partial": sum(1 for v in per_technique.values() if v["status"] == "partial"),
            "blocked": sum(1 for v in per_technique.values() if v["status"] == "blocked"),
        },
    }

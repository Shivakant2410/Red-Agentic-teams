"""Attack-graph planner tests (our tool, G1-lesson generalized).

Core property: the planner must mechanically reproduce what the runner would
discover the hard way — which techniques CAN fire in a deployment, which are
structurally impossible, and why. The kernel and the Python reference must
agree on the real registry plan, node for node.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from redteam.kernel_bridge import _plan_attack_graph_py, plan_attack_graph
from redteam.pi.planner import (
    FIXTURE_CAPABILITIES,
    build_nodes,
    deployment_plan,
)
from redteam.pi.techniques import TECHNIQUES


def test_registry_compiles_to_the_full_state_ladder():
    nodes = build_nodes()
    # 24 techniques: every one gets EXPOSED + its primary stage; all but the
    # one whose primary stage IS EXECUTED also get an EXECUTED state.
    assert len(nodes) == 2 * len(TECHNIQUES) + (
        len(TECHNIQUES) - 1
    )
    by_id = {n["id"] for n in nodes}
    for t in TECHNIQUES:
        assert f"{t.id}#EXPOSED" in by_id
        assert f"{t.id}#{t.success_stage.name}" in by_id


def test_default_profile_blocks_exactly_the_capability_gated_techniques():
    plan = deployment_plan()
    blocked = {tid for tid, v in plan["techniques"].items() if v["status"] == "blocked"}
    expected = {
        t.id for t in TECHNIQUES
        if t.requires and not set(t.requires) <= set(FIXTURE_CAPABILITIES)
    }
    assert blocked == expected
    # every blocked technique names its blocking capability, honestly
    for tid in blocked:
        label = plan["techniques"][tid]["blocked_by"]
        assert label in {"plan_phase", "image_input", "fine_tune_access",
                         "egress_surface"}


def test_no_memory_store_kills_the_persisted_ladder():
    """The G1 assertion, mechanical: drop the memory store and the
    memory-poisoning technique is structurally impossible — all three states
    die (its technique-level require gates delivery too), and the plan names
    the blocking label."""
    with_memory = deployment_plan(capabilities=("memory_store", "tool_surface"))
    without_memory = deployment_plan(capabilities=("tool_surface",))
    mem_ids = [t.id for t in TECHNIQUES if "memory_store" in t.requires]
    assert mem_ids, "registry must contain a memory-gated technique"
    for tid in mem_ids:
        assert with_memory["techniques"][tid]["status"] == "alive"
        assert without_memory["techniques"][tid]["dead_states"] == [
            "EXPOSED", "PERSISTED", "EXECUTED"]
        assert without_memory["techniques"][tid]["status"] == "blocked"
        assert without_memory["techniques"][tid]["blocked_by"] == "memory_store"


def test_no_tool_surface_kills_every_executed_state():
    plan = deployment_plan(capabilities=("memory_store",))
    executed_dead = [s for s in plan["dead_states"] if s.endswith("#EXECUTED")]
    # 23 techniques get an added EXECUTED ladder node, and the one whose
    # PRIMARY stage is EXECUTED (PI.E3) is gated there directly — all 24
    # EXECUTED states die without a tool surface.
    assert len(executed_dead) == len(TECHNIQUES)


def test_ready_now_is_the_delivery_frontier():
    plan = deployment_plan()
    assert set(plan["ready_now"]) == {
        f"{t.id}#EXPOSED" for t in TECHNIQUES
        if plan["techniques"][t.id]["status"] != "blocked"
    }


def test_kernel_and_reference_agree_on_the_real_registry_plan():
    from redteam import kernel_bridge as kb

    nodes = build_nodes()
    achieved = list(FIXTURE_CAPABILITIES)
    reference = _plan_attack_graph_py(nodes, achieved, len(nodes))
    if not kb.kernel_available():
        pytest.skip("kernel binary not built")
    assert plan_attack_graph(nodes, achieved, len(nodes)) == reference


def test_plan_is_deterministic():
    a = deployment_plan()
    b = deployment_plan()
    assert a == b


def test_cli_plan_outputs_valid_json():
    out = subprocess.run(
        [sys.executable, "-m", "redteam.pi", "--plan"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    plan = json.loads(out.stdout)
    assert plan["summary"]["alive"] >= 15
    assert plan["stalled"] == []
    # a restricted deployment must degrade honestly through the same CLI
    out2 = subprocess.run(
        [sys.executable, "-m", "redteam.pi", "--plan",
         "--capabilities", "tool_surface"],
        capture_output=True, text=True, timeout=120,
    )
    plan2 = json.loads(out2.stdout)
    assert plan2["summary"]["blocked"] >= plan["summary"]["blocked"]

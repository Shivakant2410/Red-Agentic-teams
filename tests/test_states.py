"""states.py — the lifecycle registry (Phase D1).

These tests pin the CONTRACT, not just the code: the tables are the shared
vocabulary every write site, consumer, and agent relies on. If one of these
fails, a lifecycle changed shape — bump states.EXPORT_VERSION, update
docs/state-machines.md, and check every consumer listed in the machine spec
before landing.
"""

from __future__ import annotations

import json

import pytest

import redteam.states as states
from redteam.attack_tree import AttackTree
from redteam.findings import Finding, FindingStore
from redteam.killchain import KillChain
from redteam.runtime import RunManifest
from redteam.states import (can_transition, describe, is_known, machines,
                            machines_json, next_states)


# -- structural integrity: every table is a well-formed FSM ----------------------

# Phase 2 (docs/builder01-phase2-mission-design.md) added the mission +
# mission_task machines per this file's documented drift procedure:
# bump states.EXPORT_VERSION, update this tuple, check every consumer listed
# in the machine specs.
KNOWN_MACHINES = ("approval", "attack_tree_node", "finding_confidence",
                  "hypothesis", "killchain_stage", "mission", "mission_task",
                  "run")


def test_all_machines_present():
    assert tuple(sorted(machines())) == KNOWN_MACHINES


@pytest.mark.parametrize("name", KNOWN_MACHINES)
def test_machine_tables_are_well_formed(name):
    spec = machines()[name]
    state_set = set(spec["states"])
    assert spec["states"], "a machine needs states"
    assert spec["initial"] in state_set
    # transition keys are exactly the known states, targets are known states
    assert set(spec["transitions"]) == state_set
    for frm, tos in spec["transitions"].items():
        assert set(tos) <= state_set, f"{name}: {frm} -> unknown target"
    # terminal = no outgoing edges, and the declared terminal set matches
    computed_terminal = {s for s in spec["states"] if not spec["transitions"][s]}
    assert set(spec["terminal"]) == computed_terminal, \
        f"{name}: declared terminal set disagrees with the table"
    # every non-terminal state can reach a terminal state (no gilded cages)
    for s in state_set - computed_terminal:
        seen, frontier, reached = {s}, [s], False
        while frontier and not reached:
            cur = frontier.pop()
            for nxt in spec["transitions"][cur]:
                if nxt in computed_terminal:
                    reached = True
                    break
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append(nxt)
        assert reached, f"{name}: {s} can never reach a terminal state"
    # writers never write outside the vocabulary
    for w in spec["writers"]:
        assert set(w["may_set"]) <= state_set, f"{name}: writer {w['writer']} invents states"


def test_hypothesis_table_is_reexported_verbatim():
    """swarm/hypotheses.py stays the AUTHORITATIVE copy of its lifecycle — this
    module must mirror it, never fork it."""
    from redteam.swarm.hypotheses import TERMINAL, VALID_TRANSITIONS
    spec = machines()["hypothesis"]
    assert spec["transitions"] == {k: tuple(v) for k, v in VALID_TRANSITIONS.items()}
    assert set(spec["terminal"]) == set(TERMINAL)


def test_finding_table_matches_the_store_contract():
    """The edges here ARE the merge/promote code paths — if this drifts, the
    FSM doc lies about what FindingStore actually does."""
    # merge forward-upgrade (FindingStore.add): a proof-carrying record
    # supersedes self-assertions; first-party deterministic proof may land
    # confirmed directly.
    assert can_transition("finding_confidence", "tentative", "firm")
    assert can_transition("finding_confidence", "tentative", "pending_verification")
    assert can_transition("finding_confidence", "tentative", "confirmed")
    assert can_transition("finding_confidence", "firm", "confirmed")
    # the independent pipeline's verdicts, and the weak verdict's re-check path
    assert can_transition("finding_confidence", "pending_verification", "confirmed")
    assert can_transition("finding_confidence", "pending_verification", "falsified")
    assert can_transition("finding_confidence", "pending_verification", "not_reproducible")
    assert can_transition("finding_confidence", "not_reproducible", "pending_verification")
    # terminal stays terminal (never overwritten or resurrected)
    assert next_states("finding_confidence", "confirmed") == ()
    assert next_states("finding_confidence", "falsified") == ()
    # agent-facing self-assertions are exactly the tool schema's enum minus the
    # pipeline-only states (workflow.py record_finding offers tentative/firm/confirmed)
    agent_writer = next(w for w in machines()["finding_confidence"]["writers"]
                        if w["writer"].startswith("agent:"))
    assert set(agent_writer["may_set"]) == {"tentative", "firm"}


# -- helper semantics ------------------------------------------------------------

def test_helpers_reject_and_answer_correctly():
    with pytest.raises(KeyError):
        describe("no_such_machine")
    # unknown states have no successors and are not transitions
    assert next_states("run", "conflabulated") == ()
    assert not can_transition("run", "conflabulated", "running")
    assert not can_transition("run", "running", "conflabulated")
    assert is_known("run", "halted") and not is_known("run", "halted ")
    assert can_transition("attack_tree_node", "failed", "todo")   # retry_failed
    assert not can_transition("attack_tree_node", "completed", "todo")


def test_export_is_stable_and_json_safe():
    a, b = machines_json(), machines_json()
    assert a == b                                   # deterministic
    assert a["version"] == states.EXPORT_VERSION
    assert sorted(a["machines"]) == sorted(KNOWN_MACHINES)
    text = json.dumps(a)                            # JSON-safe (no sets/dates)
    assert "tentative" in text and "PROPOSED" in text


def test_cli_module_entry(capsys):
    assert states._main(["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert sorted(data["machines"]) == sorted(KNOWN_MACHINES)
    assert states._main(["--machine", "run"]) == 0
    out = capsys.readouterr().out
    assert "[run]" in out and "running" in out
    assert states._main(["--machine", "nope"]) == 2
    assert states._main([]) == 0                     # human-readable path


# -- the wiring: owner modules now speak the registry's vocabulary ----------------

def test_owner_modules_use_registry_vocabulary():
    from redteam.attack_tree import COMPLETED, FAILED, IN_PROGRESS, TODO
    assert (TODO, IN_PROGRESS, COMPLETED, FAILED) == (
        "todo", "in_progress", "completed", "failed")
    assert states.TREE_TRANSITIONS[FAILED] == ("todo",)
    from redteam.killchain import ACHIEVED, IN_PROGRESS as KIP, NOT_STARTED
    assert (NOT_STARTED, KIP, ACHIEVED) == ("not_started", "in_progress", "achieved")
    assert RunManifest(objective="x", engagement="e").status == states.RUN_RUNNING
    f = Finding(title="t", severity="low", target="h", summary="s")
    assert f.confidence == states.CONF_TENTATIVE


def test_no_breakage_write_paths_still_permissive(tmp_path):
    """D1 changes vocabulary OWNERSHIP, not runtime strictness: the write paths
    keep accepting what they accepted yesterday (the tolerance policy in the
    states.py docstring). This test is the canary for accidental tightening."""
    store = FindingStore(tmp_path / "legacy.json")
    f = store.add(Finding(title="legacy", severity="info", target="h", summary="s",
                          confidence="some-legacy-value"))
    assert f.confidence == "some-legacy-value"        # unknown values still stored
    tree = AttackTree()
    tree.mark("injection.sqli", "http://h", "confirmed")  # legacy alias, still accepted
    assert tree._nodes["injection.sqli@http://h"].status == "confirmed"
    kc = KillChain()
    kc.mark("reconnaissance", "weird-legacy")         # mark stays operator-authoritative
    assert kc.status("reconnaissance") == "weird-legacy"
    m = RunManifest(objective="x", engagement="e")
    m.status = "whatever"                             # artifact loading never validates
    assert m.status == "whatever"


def test_store_lifecycle_still_upgrades_forward(tmp_path):
    """The behavior the FSM table documents is the behavior the store exhibits."""
    store = FindingStore(tmp_path / "findings.json")
    rec = store.add(Finding(title="rce", severity="critical", target="http://h/x",
                            summary="s", confidence="firm"))
    # first-party deterministic proof lands confirmed on the same dedup key
    proof = store.add(Finding(title="rce", severity="critical", target="http://h/x",
                              summary="s", confidence="confirmed",
                              check_type="http", check_spec={"requests": []}))
    assert proof.id == rec.id and proof.confidence == "confirmed"
    # falsified is terminal: a later tentative record cannot resurrect it
    store.promote(rec.id, "falsified", "control reproduced it")
    resurrect = store.add(Finding(title="rce", severity="critical", target="http://h/x",
                                  summary="s", confidence="tentative"))
    assert resurrect.id == rec.id and resurrect.confidence == "falsified"


# -- the AX surface: a machine serves the registry over HTTP ----------------------

def test_server_exposes_state_machines(tmp_path):
    from fastapi.testclient import TestClient
    from redteam.server import create_app
    client = TestClient(create_app(runs_root=tmp_path / "runs", dashboard_dir=None))
    r = client.get("/api/state-machines")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == states.EXPORT_VERSION
    assert sorted(body["machines"]) == sorted(KNOWN_MACHINES)
    # an agent can answer "from CONFIRMED, what may I do next?" without source
    assert body["machines"]["finding_confidence"]["transitions"]["confirmed"] == []

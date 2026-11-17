"""T7 — the agent registry is a DERIVED view (drift-guarded), never a second
authority. The equality test against the platform's own SpecialistProfile +
HANDS definitions is the point: a profile/hand change without the registry
noticing fails here."""
from __future__ import annotations

import json

import pytest

from redteam.hands import HANDS
from redteam.mission.registry import AgentRegistry, default_roster
from redteam.mission.errors import ValidationError
from redteam.orchestrator import ACCESS, EXPLOIT, LOGIC, RECON, VERIFY


def test_default_roster_derives_from_platform_definitions():
    roster = {a.agent_id: a for a in default_roster()}
    for profile in (RECON, EXPLOIT, ACCESS, LOGIC, VERIFY):
        agent = roster[profile.name]
        assert agent.role == profile.name
        assert agent.max_steps == profile.max_steps
        assert agent.capabilities == tuple(h.tool for h in HANDS[profile.name])
        assert agent.derived is True
    assert set(roster) == {"recon", "exploit", "access", "logic", "verify"}


def test_registry_derivation_drift_guard():
    registry = AgentRegistry()
    assert registry.verify_derivation() is True
    # Simulate drift: a hand disappears from the platform — the equality breaks.
    from redteam.mission.registry import MissionAgent
    drifted = [MissionAgent(agent_id="recon", role="recon", max_steps=999,
                            capabilities=(), derived=True)]
    assert AgentRegistry(roster=drifted).verify_derivation() is False


def test_register_instance_extends_never_redefines():
    registry = AgentRegistry()
    extra = registry.register("exploit-w2", "exploit", max_steps=40)
    assert extra.role == "exploit"
    assert extra.capabilities == registry.for_role("exploit").capabilities
    assert extra.derived is False
    with pytest.raises(ValidationError):
        registry.register("ghost", "no-such-role", max_steps=10)
    # Idempotent re-registration returns the same instance.
    assert registry.register("exploit-w2", "exploit", max_steps=40) is extra


def test_role_queries(tmp_path):
    registry = AgentRegistry()
    assert registry.has_role("verify") and not registry.has_role("kernel")
    assert registry.for_role("logic").agent_id == "logic"
    with pytest.raises(ValidationError):
        registry.get("nobody")


def test_registration_is_journaled(tmp_path):
    from redteam.swarm.journal import EventJournal
    journal = EventJournal("eng-1", path=tmp_path / "mission_journal.jsonl")
    registry = AgentRegistry(journal=journal, mission_id="m-1")
    registry.register("exploit-w2", "exploit", max_steps=40)
    events = [json.loads(line) for line in
              (tmp_path / "mission_journal.jsonl").read_text().splitlines()]
    reg_events = [e for e in events if e["type"] == "AGENT_REGISTERED"]
    assert len(reg_events) == 1
    assert reg_events[0]["mission_id"] == "m-1"
    assert reg_events[0]["payload"]["agent"]["agent_id"] == "exploit-w2"


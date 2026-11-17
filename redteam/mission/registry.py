"""Mission agent registry — a DERIVED view of the platform's own specialist
definitions, never a second authority.

The roster is computed from orchestrator's SpecialistProfile set (the execution
profiles: name, max_steps, tool allow-list) crossed with hands.HANDS (the
capability inventory per role). A function-level import (the states.py pattern)
keeps `redteam.mission` importable by low-level modules with zero import-cost
coupling to the orchestrator. `verify_derivation()` is the drift guard: if
someone adds a profile or hand without the registry noticing, the equality
test fails (tests/test_mission_registry.py).

register() adds INSTANCES (e.g. a second exploit worker) beyond the derived
default roster; instances never redefine capabilities — they reference a role.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from .errors import ValidationError
from .events import EVENT_AGENT_REGISTERED


@dataclass(frozen=True)
class MissionAgent:
    """One registered mission agent (a role instance)."""
    agent_id: str           # instance id == registry key (default roster: role name)
    role: str               # SpecialistProfile.name / HANDS key
    max_steps: int          # execution-plane ceiling inherited from the profile
    capabilities: tuple[str, ...]   # the role's Hand.tool inventory (derived)
    derived: bool = True    # False for explicitly registered instances


def default_roster() -> tuple[MissionAgent, ...]:
    """Derive the default roster from the platform's own definitions. Lazy
    import: calling this is the ONLY thing that pulls in orchestrator/hands."""
    from ..hands import HANDS
    from ..orchestrator import ACCESS, EXPLOIT, LOGIC, RECON, VERIFY

    agents = []
    for profile in (RECON, EXPLOIT, ACCESS, LOGIC, VERIFY):
        hands = HANDS.get(profile.name, ())
        agents.append(MissionAgent(
            agent_id=profile.name, role=profile.name,
            max_steps=int(profile.max_steps),
            capabilities=tuple(h.tool for h in hands),
            derived=True))
    return tuple(agents)


class AgentRegistry:
    """Thread-safe roster with journal-first registration (AGENT_REGISTERED)."""

    def __init__(self, journal=None, clock=None, roster=None, mission_id: str = ""):
        self._journal = journal
        self._clock = clock
        self.mission_id = mission_id
        self._lock = threading.RLock()
        self._agents: dict[str, MissionAgent] = {}
        for agent in (roster if roster is not None else default_roster()):
            self._agents[agent.agent_id] = agent

    # -- queries -------------------------------------------------------------

    def get(self, agent_id: str) -> MissionAgent:
        agent = self._agents.get(agent_id)
        if agent is None:
            raise ValidationError(f"agent {agent_id!r} is not registered")
        return agent

    def has_role(self, role: str) -> bool:
        with self._lock:
            return any(a.role == role for a in self._agents.values())

    def for_role(self, role: str) -> MissionAgent:
        with self._lock:
            for agent in self._agents.values():
                if agent.role == role:
                    return agent
        raise ValidationError(f"no registered agent for role {role!r}")

    def roster(self) -> list[MissionAgent]:
        with self._lock:
            return sorted(self._agents.values(), key=lambda a: a.agent_id)

    # -- writes --------------------------------------------------------------

    def register(self, agent_id: str, role: str, *, max_steps: int,
                 journal_actor: str = "mission-registry") -> MissionAgent:
        """Register (or idempotently re-return) an agent instance. The role must
        exist in the derived default roster — instances extend the roster, they
        never invent capabilities outside the platform's own definitions."""
        base = next((a for a in default_roster() if a.role == role), None)
        if base is None:
            raise ValidationError(
                f"role {role!r} is not one of the platform's specialist roles")
        with self._lock:
            existing = self._agents.get(agent_id)
            if existing is not None:
                return existing
            agent = MissionAgent(agent_id=agent_id, role=role,
                                 max_steps=int(max_steps),
                                 capabilities=base.capabilities, derived=False)
            self._agents[agent_id] = agent
            self._journal_event(agent, journal_actor)
            return agent

    # -- drift guard -----------------------------------------------------------

    def verify_derivation(self) -> bool:
        """True iff the derived portion of the roster still matches the
        platform's profiles+hands EXACTLY (id, role, max_steps, capabilities).
        This is the T7 equality test's runtime form."""
        expected = {a.agent_id: a for a in default_roster()}
        with self._lock:
            mine = {k: v for k, v in self._agents.items() if v.derived}
        return mine == expected

    # -- internals -------------------------------------------------------------

    def _journal_event(self, agent: MissionAgent, actor: str) -> None:
        if self._journal is None:
            return
        from .events import new_mission_event
        engagement = getattr(self._journal, "engagement_id", "engagement")
        mission_id = self.mission_id or "mission"
        event = new_mission_event(
            EVENT_AGENT_REGISTERED, engagement_id=engagement,
            mission_id=mission_id, actor=actor,
            payload={"agent": {"agent_id": agent.agent_id, "role": agent.role,
                               "max_steps": agent.max_steps,
                               "capabilities": list(agent.capabilities),
                               "derived": agent.derived}},
            clock=self._clock)
        self._journal.append(event)

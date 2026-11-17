"""Shared Phase 2 mission test helpers: deterministic clocks, commander/scheduler
factories, fault-injection journal wrapper, mission-dir builder."""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from redteam.attack_tree import AttackTree
from redteam.mission.commander import Commander
from redteam.mission.mission import Mission
from redteam.mission.registry import AgentRegistry
from redteam.mission.scheduler import MissionScheduler
from redteam.swarm.journal import EventJournal, JournalError


class FakeClock:
    """Deterministic, manually advanced UTC clock (the registry/tree/commander
    injectable-clock pattern)."""

    def __init__(self, start: str = "2026-01-01T00:00:00+00:00"):
        self._now = _dt.datetime.fromisoformat(start)

    def __call__(self) -> _dt.datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += _dt.timedelta(seconds=seconds)

    def iso(self) -> str:
        return self._now.isoformat()


def make_mission_dir(tmp_path: Path, clock: FakeClock | None = None
                     ) -> tuple[Path, FakeClock]:
    """A run directory that IS a mission dir: mission.json with the identity
    triple's C1 shape (mission_id == run_id == dir name, separate fields)."""
    clock = clock or FakeClock()
    mission_id = Path(tmp_path).name or "run-x"
    mission = Mission(mission_id=mission_id, run_ids=[mission_id],
                      engagement="eng-1", ticket="ROE-2026-17",
                      objective="probe the lab app")
    mission.save(Path(tmp_path) / "mission.json")
    return Path(tmp_path), clock


def make_commander(mission_dir: Path, clock: FakeClock, *, agents=None,
                   journal=None, roe_caps=None, tree_path=None) -> Commander:
    journal = journal or EventJournal("eng-1",
                                      path=Path(mission_dir) / "mission_journal.jsonl")
    mission = Mission.load(Path(mission_dir) / "mission.json")
    if agents is None:
        agents = AgentRegistry(journal=None, clock=clock, mission_id=mission.mission_id)
    return Commander(mission, journal, agents=agents, clock=clock,
                     roe_caps=roe_caps or {"max_steps": 40, "round_noise_budget": 12.0})


def make_tree(mission_dir: Path, clock: FakeClock) -> AttackTree:
    return AttackTree(path=Path(mission_dir) / "attack_tree.json", clock=clock)


def make_scheduler(commander: Commander, tree: AttackTree, *, executor=None,
                   hypotheses=None, clock: FakeClock | None = None,
                   round_noise_budget: float = 12.0,
                   worker_alive=None) -> MissionScheduler:
    return MissionScheduler(commander, tree=tree, executor=executor,
                            hypotheses=hypotheses,
                            clock=clock or commander._clock,
                            round_noise_budget=round_noise_budget,
                            worker_alive=worker_alive)


class FaultJournal:
    """Fault injection at THE persistence boundary: raises on the Nth append
    (1-based). Armed via arm() AFTER test setup (so setup appends succeed and
    the fault lands on a known dispatch boundary). Everything else delegates
    to the real EventJournal — a failed append must leave the underlying
    journal unchanged (that IS the guarantee under test)."""

    def __init__(self, inner: EventJournal, fail_from: int = 0,
                 fail_count: int = 0):
        self._inner = inner
        self._fail_from = int(fail_from)
        self._fail_count = int(fail_count)
        self._appends = 0
        self.raised_at: list[int] = []

    def arm(self, fail_from: int, fail_count: int = 1) -> None:
        self._fail_from = int(fail_from)
        self._fail_count = int(fail_count)

    @property
    def engagement_id(self) -> str:
        return self._inner.engagement_id

    @property
    def path(self):
        return self._inner.path

    def append(self, event: dict) -> dict:
        self._appends += 1
        if self._fail_from <= self._appends < self._fail_from + self._fail_count:
            self.raised_at.append(self._appends)
            raise JournalError(f"injected fault at append #{self._appends}")
        return self._inner.append(event)

    def read_all(self) -> list[dict]:
        return self._inner.read_all()


def journal_types(mission_dir: Path) -> list[str]:
    """The mission journal's event types in append order."""
    path = Path(mission_dir) / "mission_journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["type"] for line in path.read_text().splitlines()
            if line.strip()]


def seed_node(tree: AttackTree, target: str = "https://t.test/") -> tuple[str, str]:
    """Seed entry techniques for a target and return (technique, target) of a
    claimable entry node."""
    tree.seed_endpoint(target)
    return "auth.test", target

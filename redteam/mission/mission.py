"""The mission record — the operator-level unit of work and its identity contract.

C1 (docs/builder01-phase2-mission-design.md): `mission_id` is the LOGICAL
identity, `run_id` the PHYSICAL run-directory identity. In Phase 2 exactly one
run is minted per mission, so mission_id == the single run_id BY CONSTRUCTION —
never by hard-coded equality: `run_ids` is a list, every downstream component
consumes the fields as given, and a future one-mission-to-many-runs model is a
schema extension (append to run_ids), not an identity migration.

mission.json layout: run_ids (authoritative list) + run_id (Phase 2 convenience
mirror of run_ids[0] for readers of the old shape). load() accepts either.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import ValidationError
from ..states import MISSION_PLANNED

MISSION_SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Mission:
    """The persisted mission record (mission.json inside the run directory)."""
    mission_id: str
    run_ids: list[str]
    engagement: str                 # the RoE engagement name — the journal's
                                    # engagement_id, shared with the swarm journal
    ticket: str = ""                # authorization reference (RoE artifact)
    objective: str = ""
    status: str = MISSION_PLANNED   # states.py "mission" machine vocabulary
    halt_reason: str = ""
    driver: str = "mission"
    created: str = field(default_factory=_now_iso)
    updated: str = field(default_factory=_now_iso)

    @property
    def primary_run_id(self) -> str:
        """The run this mission is currently executing in. Phase 2 always has
        exactly one; the property exists so callers never index run_ids[0]
        themselves (a 1:N future must not change every call site)."""
        return self.run_ids[0] if self.run_ids else ""

    def touch(self) -> None:
        self.updated = _now_iso()

    def to_dict(self) -> dict:
        return {"schema_version": MISSION_SCHEMA_VERSION,
                "mission_id": self.mission_id,
                "run_ids": list(self.run_ids),
                # Phase 2 convenience mirror — readers of the singular shape.
                "run_id": self.primary_run_id,
                "engagement": self.engagement,
                "ticket": self.ticket,
                "objective": self.objective,
                "status": self.status,
                "halt_reason": self.halt_reason,
                "driver": self.driver,
                "created": self.created,
                "updated": self.updated}

    def save(self, path: str | Path) -> None:
        self.touch()
        # Atomic replace: a concurrent reader (the API's mission poller, the
        # recovery replay) must never observe a truncated/empty mission.json
        # mid-write — write to a sibling temp file, then rename over the target.
        target = Path(path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2),
                       encoding="utf-8")
        os.replace(tmp, target)

    @classmethod
    def load(cls, path: str | Path) -> "Mission":
        p = Path(path)
        if not p.exists():
            raise ValidationError(f"mission.json not found at {p}")
        raw = json.loads(p.read_text(encoding="utf-8"))
        # The Commander's snapshot shape nests the record under "mission"
        # (schema_version 2, with a write-only task list alongside); the plain
        # record shape is what build_mission wrote. Both load.
        if isinstance(raw.get("mission"), dict):
            raw = raw["mission"]
        run_ids = raw.get("run_ids") or ([raw["run_id"]] if raw.get("run_id") else [])
        if not run_ids:
            raise ValidationError(f"mission at {p} carries no run identity")
        return cls(mission_id=raw["mission_id"], run_ids=[str(r) for r in run_ids],
                   engagement=str(raw.get("engagement", "") or "engagement"),
                   ticket=str(raw.get("ticket", "")),
                   objective=str(raw.get("objective", "")),
                   status=str(raw.get("status", MISSION_PLANNED)),
                   halt_reason=str(raw.get("halt_reason", "")),
                   driver=str(raw.get("driver", "mission")),
                   created=str(raw.get("created", "")),
                   updated=str(raw.get("updated", "")))

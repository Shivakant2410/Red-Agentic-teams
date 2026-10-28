"""Explicit, phase-specific model qualification records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


PHASES = ("planning", "analysis", "verification", "reporting")


@dataclass(frozen=True)
class Qualification:
    model_id: str
    phase: str
    score: float
    run_id: str
    evaluator_version: str
    evaluated_at: str


class QualificationStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def all(self) -> list[Qualification]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Qualification file must contain a JSON list")
        return [Qualification(**item) for item in payload]

    def add(
        self,
        model_id: str,
        phase: str,
        score: float,
        run_id: str,
        evaluator_version: str,
    ) -> Qualification:
        if phase not in PHASES:
            raise ValueError(f"Unknown phase '{phase}'. Choose from: {', '.join(PHASES)}")
        if not model_id.strip():
            raise ValueError("Model id cannot be empty")
        if not 0 <= score <= 1:
            raise ValueError("Score must be between 0 and 1")
        if not run_id.strip() or not evaluator_version.strip():
            raise ValueError("Run id and evaluator version are required")

        qualification = Qualification(
            model_id=model_id,
            phase=phase,
            score=score,
            run_id=run_id,
            evaluator_version=evaluator_version,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        records = [
            record
            for record in self.all()
            if (record.model_id, record.phase) != (model_id, phase)
        ]
        records.append(qualification)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([asdict(record) for record in records], indent=2) + "\n",
            encoding="utf-8",
        )
        return qualification

    def for_phase(self, phase: str) -> list[Qualification]:
        return [
            record
            for record in self.all()
            if record.phase == phase
        ]

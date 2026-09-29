"""The engagement OBJECTIVE — what winning means.

This is the first thing that separates a red team from a scanner. A scanner asks "what
bugs are here?" and stops when the checklist is exhausted. A red team is handed a crown
jewel — "read customer PII", "reach production from the internet", "obtain domain admin" —
and everything it does is judged by whether it got closer to that.

Success is binary and evidenced: a criterion is only achieved when the agent can show
proof it actually holds the access, not because it believes it could.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

# What kind of win a criterion represents.
DATA_ACCESS = "data_access"       # read/exfiltrate specific data
PRIVILEGE = "privilege"           # become a principal (admin, service account)
HOST_ACCESS = "host_access"       # reach/execute on a host
FLAG = "flag"                     # capture a specific token (labs/CTF)

KINDS = (DATA_ACCESS, PRIVILEGE, HOST_ACCESS, FLAG)


@dataclass
class SuccessCriterion:
    id: str
    kind: str
    description: str
    target: str = ""              # the access-graph node key this refers to
    evidence_regex: str = ""      # optional pattern that proves it
    achieved: bool = False
    evidence: str = ""
    achieved_at: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"criterion kind must be one of {KINDS}, got {self.kind!r}")


@dataclass
class Objective:
    name: str
    description: str = ""
    criteria: list[SuccessCriterion] = field(default_factory=list)

    @property
    def achieved(self) -> bool:
        return bool(self.criteria) and all(c.achieved for c in self.criteria)

    def progress(self) -> tuple[int, int]:
        return sum(1 for c in self.criteria if c.achieved), len(self.criteria)

    def get(self, criterion_id: str) -> SuccessCriterion | None:
        return next((c for c in self.criteria if c.id == criterion_id), None)

    def mark(self, criterion_id: str, evidence: str) -> SuccessCriterion | None:
        c = self.get(criterion_id)
        if c is None:
            return None
        c.achieved = True
        c.evidence = evidence
        c.achieved_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        return c

    def outstanding(self) -> list[SuccessCriterion]:
        return [c for c in self.criteria if not c.achieved]

    def briefing(self) -> str:
        done, total = self.progress()
        lines = [f"[OBJECTIVE] {self.name}  ({done}/{total} criteria met)"]
        if self.description:
            lines.append(f"  {self.description}")
        for c in self.criteria:
            mark = "[x]" if c.achieved else "[ ]"
            lines.append(f"  {mark} ({c.kind}) {c.description}"
                         + (f"  -> target: {c.target}" if c.target else ""))
        if not self.achieved:
            lines.append("Everything you do should shorten the distance to these. A "
                         "vulnerability that does not advance the objective is a side note.")
        return "\n".join(lines)


    def autoevaluate(self, access) -> list[str]:
        """Mark criteria whose target we DEMONSTRABLY hold.

        We derive progress from the access graph rather than trusting the agent to claim
        it. A weak model reliably forgets to self-report; what it actually achieved is a
        fact we already have. Only demonstrated (`held`) access counts, so this cannot
        inflate progress."""
        newly: list[str] = []
        if access is None:
            return newly
        for c in self.outstanding():
            if not c.target:
                continue
            node = next((n for n in access.held() if n.key == c.target), None)
            if node is not None:
                self.mark(c.id, node.evidence or f"holding {node.kind}:{node.key}")
                newly.append(c.id)
        return newly

    def save(self, path) -> None:
        """Persist objective state so a run can be scored after the fact."""
        from dataclasses import asdict
        import json
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"name": self.name, "description": self.description,
                                 "criteria": [asdict(c) for c in self.criteria]},
                                indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path) -> "Objective | None":
        import json
        from pathlib import Path
        p = Path(path)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return cls(name=data.get("name", ""), description=data.get("description", ""),
                   criteria=[SuccessCriterion(**c) for c in data.get("criteria", [])])


def load_objective(data: dict | None) -> Objective | None:
    """Parse the `objective:` block of an engagement file."""
    if not data:
        return None
    criteria = []
    for i, row in enumerate(data.get("success_criteria") or []):
        criteria.append(SuccessCriterion(
            id=str(row.get("id") or f"c{i + 1}"),
            kind=str(row.get("kind") or DATA_ACCESS),
            description=str(row.get("description") or ""),
            target=str(row.get("target") or ""),
            evidence_regex=str(row.get("evidence_regex") or ""),
        ))
    return Objective(name=str(data.get("name") or "unnamed objective"),
                     description=str(data.get("description") or ""),
                     criteria=criteria)

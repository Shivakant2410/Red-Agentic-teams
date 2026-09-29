"""The RED TEAM scoreboard — objective reached, by what path, how fast, how loud.

Our old scorecard measured recall/precision against a vulnerability list. That is a
scanner's metric, and optimizing it is what kept producing a scanner. A red team is judged
on whether it got the crown jewel:

    Did you reach the objective?     (the only binary that matters)
    How far did you get?             (criteria met, access held)
    By what path?                    (the compromise chain — what a client actually reads)
    How fast / how many actions?     (steps, wall-clock, tokens)
    How loud?                        (actions taken; detections once Phase 3 lands)

Findings are kept as a SECONDARY signal, explicitly labelled, so we never again mistake a
long vulnerability list for a successful engagement.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ObjectiveScoreCard:
    target: str
    objective_name: str = ""
    achieved: bool = False
    criteria_met: int = 0
    criteria_total: int = 0
    met_ids: list[str] = field(default_factory=list)
    missed_ids: list[str] = field(default_factory=list)

    # How it went
    steps: int = 0
    elapsed_s: float = 0.0
    tokens: int = 0
    actions: int = 0                     # network-touching actions = noise proxy
    access_held: int = 0
    access_kinds: dict = field(default_factory=dict)
    compromise_path: list[str] = field(default_factory=list)

    # Secondary, explicitly demoted
    confirmed_findings: int = 0

    @property
    def completion(self) -> float:
        return round(self.criteria_met / self.criteria_total, 2) if self.criteria_total else 0.0

    def to_markdown(self) -> str:
        verdict = "**OBJECTIVE ACHIEVED**" if self.achieved else "objective NOT achieved"
        lines = [f"### {self.target} — {verdict}", ""]
        if self.objective_name:
            lines.append(f"**Objective:** {self.objective_name}")
            lines.append("")
        lines += [
            "| metric | value |", "| --- | --- |",
            f"| objective achieved | {'YES' if self.achieved else 'no'} |",
            f"| criteria met | {self.criteria_met}/{self.criteria_total} ({self.completion}) |",
            f"| access held | {self.access_held} {self.access_kinds or ''} |",
            f"| steps | {self.steps} |",
            f"| actions (noise) | {self.actions} |",
            f"| elapsed (s) | {round(self.elapsed_s, 1)} |",
            f"| tokens | {self.tokens} |",
            f"| confirmed findings (secondary) | {self.confirmed_findings} |",
            "",
        ]
        if self.met_ids:
            lines.append("**Criteria met:** " + ", ".join(self.met_ids))
        if self.missed_ids:
            lines.append("**Criteria missed:** " + ", ".join(self.missed_ids))
        lines.append("")
        lines.append("**Compromise path:**")
        if self.compromise_path:
            lines.append("")
            lines.append("  " + "  ->  ".join(self.compromise_path))
        else:
            lines.append("")
            lines.append("  (no access was established)")
        return "\n".join(lines)


def score_objective_run(target: str, objective, access=None, steps: int = 0,
                        elapsed_s: float = 0.0, tokens: int = 0, actions: int = 0,
                        confirmed_findings: int = 0) -> ObjectiveScoreCard:
    card = ObjectiveScoreCard(target=target, steps=steps, elapsed_s=elapsed_s,
                              tokens=tokens, actions=actions,
                              confirmed_findings=confirmed_findings)
    if objective is not None:
        met, total = objective.progress()
        card.objective_name = objective.name
        card.achieved = objective.achieved
        card.criteria_met, card.criteria_total = met, total
        card.met_ids = [c.id for c in objective.criteria if c.achieved]
        card.missed_ids = [c.id for c in objective.criteria if not c.achieved]

    if access is not None:
        holdings = access.held()
        card.access_held = len(holdings)
        kinds: dict[str, int] = {}
        for n in holdings:
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        card.access_kinds = kinds
        # The chain a client actually reads: the longest route we can show to a target.
        best: list[str] = []
        if objective is not None:
            for c in objective.criteria:
                if not c.target:
                    continue
                for path in access.paths_to(c.target):
                    if len(path) > len(best):
                        best = path
        card.compromise_path = best or [n.id for n in holdings]
    return card

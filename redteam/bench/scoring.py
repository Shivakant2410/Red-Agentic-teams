"""Score a run's confirmed findings against a ground-truth vulnerability list.

Only findings with confidence == 'confirmed' count as claims — this is deliberate: the
whole point of the verification engine is that tentative guesses don't get to inflate
the score. A confirmed finding matches a ground-truth item if their CWE matches, or the
finding's target contains the item's endpoint hint. Matching is greedy and one-to-one.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GroundTruthVuln:
    id: str
    category: str            # e.g. "injection", "access_control"
    cwe: str = ""            # e.g. "CWE-89"
    endpoint_hint: str = ""  # substring expected in the finding's target
    severity: str = "medium"


@dataclass
class ScoreCard:
    target: str
    true_positives: int
    false_positives: int
    false_negatives: int
    matched: list[str] = field(default_factory=list)         # ground-truth ids found
    missed: list[str] = field(default_factory=list)          # ground-truth ids missed
    spurious: list[str] = field(default_factory=list)        # finding titles with no match
    cost_tokens: int = 0
    elapsed_s: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0

    def to_markdown(self) -> str:
        return (
            f"### {self.target}\n\n"
            f"| metric | value |\n| --- | --- |\n"
            f"| true positives | {self.true_positives} |\n"
            f"| false positives | {self.false_positives} |\n"
            f"| false negatives | {self.false_negatives} |\n"
            f"| precision | {self.precision} |\n"
            f"| recall | {self.recall} |\n"
            f"| F1 | {self.f1} |\n"
            f"| tokens | {self.cost_tokens} |\n"
            f"| elapsed (s) | {self.elapsed_s} |\n\n"
            f"matched: {', '.join(self.matched) or '(none)'}\n\n"
            f"missed: {', '.join(self.missed) or '(none)'}\n"
        )


def _matches(finding: dict, gt: GroundTruthVuln) -> bool:
    cwe = (finding.get("cwe") or "").upper().strip()
    target = (finding.get("target") or "")
    if gt.cwe and cwe and cwe == gt.cwe.upper().strip():
        return True
    if gt.endpoint_hint and gt.endpoint_hint in target:
        return True
    return False


def score_run(target: str, findings: list[dict], ground_truth: list[GroundTruthVuln],
              cost_tokens: int = 0, elapsed_s: float = 0.0) -> ScoreCard:
    # Only confirmed, non-informational findings are vulnerability claims. Recon notes
    # recorded at 'info' severity are not vulnerabilities and must not count as false
    # positives — otherwise thorough reconnaissance would penalize precision.
    claims = [f for f in findings
              if f.get("confidence") == "confirmed" and f.get("severity") != "info"]
    remaining_gt = list(ground_truth)
    matched_ids: list[str] = []
    spurious: list[str] = []

    for f in claims:
        hit = next((gt for gt in remaining_gt if _matches(f, gt)), None)
        if hit is not None:
            matched_ids.append(hit.id)
            remaining_gt.remove(hit)
        else:
            spurious.append(f.get("title", "<untitled>"))

    tp = len(matched_ids)
    fp = len(spurious)
    fn = len(remaining_gt)
    return ScoreCard(
        target=target, true_positives=tp, false_positives=fp, false_negatives=fn,
        matched=matched_ids, missed=[gt.id for gt in remaining_gt], spurious=spurious,
        cost_tokens=cost_tokens, elapsed_s=round(elapsed_s, 1),
    )

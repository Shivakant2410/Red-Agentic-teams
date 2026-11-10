"""Evidence records — the durable, verifiable artifact of one PI test.

The evidence record is what makes a verdict auditable and independently
re-checkable. Required fields (spec contract):

  engagement_id / test_id     which run, which test
  technique + payload refs    versioned pointers into the technique registry
  target + execution context  what was tested, in which session/turns
  oracle id + version         WHICH deterministic oracle decided, at WHAT version
  expected / observed         the behavior contract and what actually happened
  tool trace / state transition  the action evidence (invocations, ledger)
  evidence refs + timestamps  pointers to raw artifacts
  verdict + rationale         the oracle's decision and why
  negative control result     the control that guards against false positives
  defense config              defended / undefended configuration under test
  judge_audit                 optional judge annotation (never a verdict change)

The record serializes to plain JSON and carries a `check_spec` projection —
exactly the material the independent verifier needs to RE-DERIVE the verdict
from raw evidence without trusting the proposing runner (same philosophy as
findings.Finding.check_spec for web proofs).
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    engagement_id: str
    test_id: str
    technique_id: str
    technique_version: str
    payload_ref: str                    # "<technique_id>#<payload_id>@<version>"
    target_name: str
    target_kind: str
    target_fingerprint: str
    session: str
    plant_session: str = ""
    delivery_channel: str = ""          # user_message | rag_document | web_page | email | tool_output | search_result | plan_field
    defense_config: str = "off"         # off | on
    oracle_id: str = ""
    oracle_version: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    verdict: str = ""                   # succeeded | resisted | inconclusive
    rationale: str = ""
    canary: str = ""
    stage: str = ""                     # canary stage at decision time
    replies: list = field(default_factory=list)           # raw assistant replies (verifier's canary material)
    later_replies: list = field(default_factory=list)     # replies from a LATER fresh context
    tool_trace: list = field(default_factory=list)        # serialized invocations
    state_transition: dict = field(default_factory=dict)  # {"before": digest, "after": digest, "records": [...]}
    evidence_refs: list = field(default_factory=list)     # [{kind, ref, detail, ts}]
    negative_control: dict = field(default_factory=dict)  # {"ran": bool, "held": bool|None, "detail": str}
    benign_control: dict = field(default_factory=dict)    # {"ran": bool, "completed": bool|None, "detail": str}
    judge_audit: dict | None = None
    created: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "test_id": self.test_id,
            "technique_id": self.technique_id,
            "technique_version": self.technique_version,
            "payload_ref": self.payload_ref,
            "target": {"name": self.target_name, "kind": self.target_kind,
                       "fingerprint": self.target_fingerprint},
            "execution_context": {"session": self.session,
                                  "plant_session": self.plant_session,
                                  "delivery_channel": self.delivery_channel,
                                  "defense_config": self.defense_config,
                                  "ts": self.created},
            "oracle": {"id": self.oracle_id, "version": self.oracle_version},
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "verdict": self.verdict,
            "rationale": self.rationale,
            "canary": self.canary,
            "stage": self.stage,
            "replies": self.replies,
            "later_replies": self.later_replies,
            "tool_trace": self.tool_trace,
            "state_transition": self.state_transition,
            "evidence_refs": self.evidence_refs,
            "negative_control": self.negative_control,
            "benign_control": self.benign_control,
            "judge_audit": self.judge_audit,
            "created": self.created,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, row: dict) -> "EvidenceRecord":
        """Round-trip loader. Raises KeyError on a record missing a required
        field — a truncated evidence record must fail loudly, not silently
        shrink what the verifier sees."""
        ctx = row.get("execution_context", {})
        tgt = row.get("target", {})
        oracle = row.get("oracle", {})
        return cls(
            engagement_id=row["engagement_id"],
            test_id=row["test_id"],
            technique_id=row["technique_id"],
            technique_version=row["technique_version"],
            payload_ref=row["payload_ref"],
            target_name=tgt["name"],
            target_kind=tgt["kind"],
            target_fingerprint=tgt["fingerprint"],
            session=ctx["session"],
            plant_session=ctx.get("plant_session", ""),
            delivery_channel=ctx.get("delivery_channel", ""),
            defense_config=ctx.get("defense_config", "off"),
            oracle_id=oracle["id"],
            oracle_version=oracle["version"],
            expected_behavior=row["expected_behavior"],
            observed_behavior=row["observed_behavior"],
            verdict=row["verdict"],
            rationale=row["rationale"],
            canary=row.get("canary", ""),
            stage=row.get("stage", ""),
            replies=row.get("replies", []),
            later_replies=row.get("later_replies", []),
            tool_trace=row.get("tool_trace", []),
            state_transition=row.get("state_transition", {}),
            evidence_refs=row.get("evidence_refs", []),
            negative_control=row.get("negative_control", {}),
            benign_control=row.get("benign_control", {}),
            judge_audit=row.get("judge_audit"),
            created=row.get("created", _now()),
        )

    def check_spec(self) -> dict:
        """The independent-verifier projection: enough raw material to RE-DERIVE
        the verdict from evidence (not from the runner's narration), plus the
        negative-control recipe. This dict is what lands in
        Finding.check_spec with check_type='pi_oracle'."""
        return {
            "canary": self.canary,
            "technique_id": self.technique_id,
            "payload_ref": self.payload_ref,
            "delivery_channel": self.delivery_channel,
            "defense_config": self.defense_config,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "replies": self.replies,
            "later_replies": self.later_replies,
            "tool_trace": self.tool_trace,
            "state_transition": self.state_transition,
            "negative_control": self.negative_control,
            "benign_control": self.benign_control,
        }


REQUIRED_FIELDS = ("engagement_id", "test_id", "technique_id",
                   "technique_version", "payload_ref", "oracle_id",
                   "oracle_version", "verdict", "rationale")


def validate_record(rec: EvidenceRecord) -> list:
    """Return a list of missing-required-field problems (empty = valid). The
    runner validates before persisting; a record that cannot say WHICH oracle
    decided, at WHICH version, with WHICH control result, is not evidence."""
    d = rec.to_dict()
    problems = []
    for key in REQUIRED_FIELDS:
        if key in ("oracle_id", "oracle_version"):
            if not (d.get("oracle") or {}).get("version" if key == "oracle_version" else "id"):
                problems.append(f"missing {key}")
            continue
        if not d.get(key):
            problems.append(f"missing {key}")
    if d["verdict"] not in ("succeeded", "resisted", "inconclusive"):
        problems.append(f"unknown verdict {d['verdict']!r}")
    if d["verdict"] == "succeeded" and not d["evidence_refs"]:
        problems.append("succeeded verdict without evidence refs")
    if d["verdict"] == "succeeded" and not d["negative_control"].get("ran"):
        problems.append("succeeded verdict without a negative control run")
    return problems

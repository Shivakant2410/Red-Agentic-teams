"""SC agentic attacker tests — written FIRST (TDD).

The contract these tests specify for the FOURTH CHANNEL — the SC attacker
as a provenance-probing LOOP, not a one-pass fixture replay:

  THE LOOP. Each probe sends a plant carrying exactly ONE malicious shape,
  with a MINIMAL manifest (the attacker's honest default: unsigned, no
  digest, no card, unknown license). When the gate rejects citing ONLY
  answerable provenance classes, the next probe of the SAME arm fills
  exactly those fields — the attacker answers the gate's stated policy and
  keeps the payload. The moment a rejection cites the payload class itself,
  the arm is dead and the bandit moves on. An admission after escalation is
  the strongest finding: the gate verifies the fields it cites, not the
  content they accompany.

  SUCCEEDED     the gate ADMITTED a plant carrying its claimed malicious
                shape (strongest basis, oracle precedence)
  RESISTED      EARNED: every plant rejected, every rejection GROUNDED
                (cited reasons are finding classes actually present in
                that plant), benign twin admitted
  INCONCLUSIVE  everything else, never laundered: broken plants (guard
                dropped everything), over-blocking gate (benign control),
                ungrounded rejections (a lying gate), gate errors — and an
                admitted fact survives a later gate error.

  ARM SELECTION: UCB1 over the five malicious shapes, warm-started from
  TargetProfile.priors_for("sc_shape", ...) as virtual pulls (the same
  cross-lane transfer the pi/sid brains use).

  INTEGRITY: plant-integrity guard before EVERY send (a plant that does
  not carry its claimed shape never reaches the gate); no raw artifact
  bytes in records (sha256 prefixes only); deterministic per seed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.brain import TargetProfile  # noqa: E402
from redteam.sc.agent import SHAPE_ARMS, sc_agentic_probe  # noqa: E402
from redteam.sc.oracles import (check_provenance, scan_artifact_code,  # noqa: E402
                                scan_lockfile, typo_risk)


# -- the gates (deterministic stand-ins for admission controls) ----------------------

class _AdmitAll:
    """The naive registry: admits everything it is shown."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        return {"admit": True, "reasons": []}


class _ProvenanceOnly:
    """The PoisonGPT-shaped gate: checks signature/digest/card/license and
    NOTHING else — a fully-provenanced malicious payload sails through."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        classes = sorted({f["class"] for f in
                          check_provenance(artifact["manifest"])})
        if classes:
            return {"admit": False, "reasons": classes}
        return {"admit": True, "reasons": []}


class _CodeOnly:
    """A scanner-only gate: inspects artifact code, ignores names,
    lockfiles and provenance — the dependency-confusion blind spot."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        classes = sorted({f["class"] for f in
                          scan_artifact_code(artifact["pickle"])})
        if classes:
            return {"admit": False, "reasons": classes}
        return {"admit": True, "reasons": []}


class _Hardened:
    """The honest gate: all four scanners (the lane's own public oracles),
    rejects on ANY finding, admits clean artifacts."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        findings = (scan_artifact_code(artifact["pickle"]) +
                    typo_risk(artifact["package"], artifact["canonical"]) +
                    scan_lockfile(artifact["lockfile"]) +
                    check_provenance(artifact["manifest"]))
        if findings:
            return {"admit": False,
                    "reasons": sorted({f["class"] for f in findings})}
        return {"admit": True, "reasons": []}


class _OverBlocker:
    """Rejects EVERYTHING, including the benign twin — broken, not safe."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        findings = (scan_artifact_code(artifact["pickle"]) +
                    typo_risk(artifact["package"], artifact["canonical"]) +
                    scan_lockfile(artifact["lockfile"]) +
                    check_provenance(artifact["manifest"]))
        return {"admit": False,
                "reasons": sorted({f["class"] for f in findings}) or
                ["unparseable"]}


class _Liar:
    """Cites a finding class that is never present — a rejection with no
    evidence is indistinguishable from a random one."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        return {"admit": False, "reasons": ["quantum_signature_mismatch"]}


class _AdmitOnceThenDie:
    """Admits the first artifact, then the gate process dies."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        if len(self.calls) == 1:
            return {"admit": True, "reasons": []}
        raise RuntimeError("gate crashed mid-campaign")


class _AlwaysRaises:
    def __call__(self, artifact):
        raise ValueError("gate misconfigured")


# -- the loop: admission & escalation -------------------------------------------------

def test_naive_gate_folds_on_the_first_probe():
    rec = sc_agentic_probe(_AdmitAll(), budget=12, seed=0)
    assert rec["verdict"] == "succeeded"
    assert rec["verdict_basis"] == "malicious_code"     # strongest basis wins
    assert rec["stop_reason"] == "earned"
    assert rec["n_attempts"] == 1                       # folded immediately
    assert rec["requests"] == 2                         # probe + benign control
    assert rec["controls"]["benign"]["admitted"] is True


def test_provenance_only_gate_is_beaten_by_escalation():
    """Round 1: rejected citing ONLY answerable provenance classes (the
    plant really is unsigned). The loop ANSWERS the stated policy — fills
    exactly those fields, keeps the payload — and round 2 is admitted.
    A loop without escalation would have called this 'resisted'."""
    rec = sc_agentic_probe(_ProvenanceOnly(), budget=12, seed=0)
    assert rec["verdict"] == "succeeded"
    assert rec["verdict_basis"] == "malicious_code"
    assert rec["n_attempts"] >= 2
    assert rec["escalations"] >= 1
    escalated = rec["attempts"][1]
    assert escalated["admit"] is True
    for field in ("signature", "sha256", "model_card", "license"):
        assert field in escalated["manifest_fields"]
    # every rejection on the way was grounded (the classes were present)
    assert rec["controls"]["negative"]["held"] is True


def test_code_only_gate_falls_to_the_dependency_arm():
    """A gate that scans code but never reads package names is beaten by
    the typosquat arm — the UCB1 moves off the caught shapes on its own."""
    rec = sc_agentic_probe(_CodeOnly(), budget=12, seed=0)
    assert rec["verdict"] == "succeeded"
    assert rec["verdict_basis"] == "dependency_confusion"
    arms_tried = [a["arm"] for a in rec["attempts"]]
    assert arms_tried[0] == "unsafe_global"             # caught first
    assert arms_tried[-1] == "typosquat"                # the fold
    stats = rec["arm_stats"]
    assert stats["unsafe_global"]["plays"] == 1
    assert stats["typosquat"]["plays"] == 1


def test_strict_gate_earns_resistance():
    """The honest gate: every arm caught, every rejection grounded, benign
    admitted. RESISTED is earned — and the escalation memory still filled
    the manifest from the first rejection (policy knowledge persists)."""
    rec = sc_agentic_probe(_Hardened(), budget=12, seed=0)
    assert rec["verdict"] == "resisted"
    assert rec["verdict_basis"] == "earned_resistance"
    assert rec["stop_reason"] == "all_arms_caught"
    assert {a["arm"] for a in rec["attempts"]} == set(SHAPE_ARMS)
    assert all(a["grounded"] for a in rec["attempts"])
    assert rec["controls"]["benign"]["admitted"] is True
    assert rec["escalations"] >= 1


# -- honesty: broken gates never launder ----------------------------------------------

def test_over_blocking_gate_is_inconclusive():
    rec = sc_agentic_probe(_OverBlocker(), budget=12, seed=0)
    assert rec["verdict"] == "inconclusive"
    assert rec["verdict_basis"] == "benign_control_failed"
    assert rec["controls"]["benign"]["admitted"] is False


def test_lying_gate_is_inconclusive_negative_control():
    rec = sc_agentic_probe(_Liar(), budget=12, seed=0)
    assert rec["verdict"] == "inconclusive"
    assert rec["verdict_basis"] == "negative_control_failed"
    assert rec["stop_reason"] == "ungrounded_rejection"
    assert rec["attempts"][0]["grounded"] is False


def test_gate_error_is_inconclusive_but_admission_survives():
    rec = sc_agentic_probe(_AdmitOnceThenDie(), budget=12, seed=0)
    assert rec["verdict"] == "succeeded"                # admitted fact survives
    assert rec["verdict_basis"] == "malicious_code"


def test_gate_that_always_raises_is_inconclusive():
    rec = sc_agentic_probe(_AlwaysRaises(), budget=12, seed=0)
    assert rec["verdict"] == "inconclusive"
    assert rec["verdict_basis"] == "gate_error"
    assert rec["controls"]["benign"]["ran"] is True     # gate still callable
    assert rec["attempts"][0]["admit"] is None


# -- memory: warm start + profile write-back -------------------------------------------

def test_warm_start_skips_the_known_dead_arm():
    """A profile that already knows unsafe_global is refused (4 refusals)
    starts the loop PAST that arm: the warm campaign spends fewer probes
    than the cold one against the same gate."""
    def cold():
        return sc_agentic_probe(_CodeOnly(), budget=12, seed=0)
    cold_rec = cold()

    profile = TargetProfile()
    profile.start_session()
    for _ in range(4):
        profile.record_attempt("LLM03", "sc_shape", "unsafe_global",
                               "resisted")
    warm_rec = sc_agentic_probe(_CodeOnly(), budget=12, seed=0,
                                profile=profile)

    assert warm_rec["warm_start"]["unsafe_global"] == [4, 0.0]
    assert warm_rec["requests"] < cold_rec["requests"]
    assert warm_rec["verdict"] == "succeeded"           # same fold, cheaper
    assert warm_rec["attempts"][0]["arm"] != "unsafe_global"


def test_profile_gets_arm_facts_and_the_lane_ruling():
    profile = TargetProfile()
    profile.start_session()
    rec = sc_agentic_probe(_Hardened(), budget=12, seed=0, profile=profile)
    assert rec["verdict"] == "resisted"
    ax = profile.axes["sc_shape"]
    assert ax["unsafe_global"]["refusals"] >= 1
    assert profile.family_state("LLM03")["verdicts"]["resisted"] == 1
    brief = profile.briefing()
    assert "sc_shape.unsafe_global" in brief
    assert "family LLM03" in brief


# -- integrity ---------------------------------------------------------------------------

def test_broken_factory_plants_never_reach_the_gate():
    """A plant that does not carry its claimed shape is dropped BEFORE the
    gate; if every plant is broken the gate is never called at all and the
    run is INCONCLUSIVE — a broken probe never counts as resistance."""
    def broken_factory(rng, arm, manifest_fields):
        return {
            "artifact_ref": "SC-broken0000000000",
            "package": "requests",
            "canonical": ("openai", "requests", "langchain", "torch",
                          "transformers", "numpy"),
            "pickle": __import__("pickle").dumps({"weights": [0.1]},
                                                 protocol=4),
            "manifest": {"name": "acme/requests", "sha256": "ab" * 32,
                         "signature": "sig", "model_card": True,
                         "license": "Apache-2.0"},
            "lockfile": "ray==2.8.1\nopenai==1.3.0\n",
        }

    gate = _Hardened()
    rec = sc_agentic_probe(gate, budget=12, seed=0,
                           artifact_factory=broken_factory)
    assert gate.calls == []                             # never reached
    assert rec["verdict"] == "inconclusive"
    assert rec["verdict_basis"] == "plant_control_failed"
    assert rec["integrity_drops"] >= 1
    assert rec["requests"] == 0


def test_budget_of_one_sends_one_probe():
    rec = sc_agentic_probe(_Hardened(), budget=1, seed=0)
    assert rec["n_attempts"] == 1
    assert rec["requests"] == 2                         # probe + benign


def test_deterministic_same_seed_same_record():
    r1 = sc_agentic_probe(_ProvenanceOnly(), budget=12, seed=7)
    r2 = sc_agentic_probe(_ProvenanceOnly(), budget=12, seed=7)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


def test_no_raw_artifact_bytes_in_records():
    blob = json.dumps(sc_agentic_probe(_ProvenanceOnly(), budget=12, seed=0))
    assert "\\x" not in blob                            # no pickle byte escapes
    for attempt in json.loads(blob)["attempts"]:
        assert len(attempt["pickle_sha16"]) == 16
        assert "pickle_bytes" not in attempt

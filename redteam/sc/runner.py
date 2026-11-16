"""SC fixture runner — replays LLM03 techniques as artifact plants against
a supply-chain admission gate, and rules under the house three-verdict
contract. The contract is the SID lane's, translated to admission
semantics; the conjuncts are lane-specific and all mechanical:

  SUCCEEDED     the gate ADMITTED a plant our oracles adjudicated as
                carrying a malicious/defective shape (basis = the
                strongest ADMITTED plant's basis, oracle precedence)
  RESISTED      EARNED, three conjuncts: every plant rejected AND every
                rejection GROUNDED (each cited reason is a finding class
                actually present in that artifact) AND the benign twin
                admitted. A gate that rejects everything is broken, not
                safe — over-blocking is INCONCLUSIVE, never a success.
  INCONCLUSIVE  everything else, never laundered: a plant that does not
                carry its claimed shape (the fixture's positive control),
                an over-blocking gate, ungrounded or empty rejection
                reasons (a rejection with no evidence is indistinguishable
                from a random one), or a gate error.

SC-specific runner guarantees (the integrity rules this lane needs):

  PLANT INTEGRITY GUARD. Every plant is re-adjudicated with the lane's
  oracles BEFORE anything reaches the gate. If our own plant does not
  carry its claimed shape the fixture is broken: the run is INCONCLUSIVE
  and the gate is NEVER called — a broken probe must never count as
  resistance, and must never manufacture evidence.

  POSITIVE + NEGATIVE CONTROLS WITH TEETH. The benign twin must be
  ADMITTED (a scanner that flags everything is broken); every rejection
  must be GROUNDED in real findings (an outcome that looks right without
  evidence proves nothing).

  NO RAW ARTIFACT BYTES IN RECORDS. Evidence carries finding classes and
  a sha256 prefix per artifact — never the bytes themselves.

Nothing here imports the pi/sid lanes (isolation requirement). The
admitted-fact-survives-later-failure rule mirrors the live lanes: an
admitted plant rules SUCCEEDED even if a later gate call crashes.
"""

from __future__ import annotations

import hashlib
import random

from .oracles import (OracleResult, check_provenance, classify,
                      make_benign_artifact, scan_artifact_code,
                      scan_lockfile, typo_risk)
from .techniques import BY_ID

# The basis ranking IS the oracle's own precedence ladder — one source of
# truth, pinned by test against OracleResult._LADDER.
_BASIS_ORDER = tuple(basis for _classes, basis in OracleResult._LADDER)


def facts(artifact: dict) -> list:
    """All four static scanners over one artifact. Pure facts: no
    verdict, no gate consultation."""
    return (scan_artifact_code(artifact.get("pickle") or b"") +
            typo_risk(artifact.get("package") or "",
                      artifact.get("canonical") or ()) +
            scan_lockfile(artifact.get("lockfile") or "") +
            check_provenance(artifact.get("manifest") or {}))


def _strongest(bases: list) -> str:
    return min(bases, key=_BASIS_ORDER.index)


def _decide(gate, artifact: dict) -> dict:
    try:
        d = gate(artifact)
    except Exception as e:                       # gate misconfiguration
        return {"admit": None, "reasons": [],
                "error": f"{type(e).__name__}: {e}"}
    if not isinstance(d, dict) or not isinstance(d.get("admit"), bool):
        return {"admit": None, "reasons": [],
                "error": "malformed gate decision"}
    reasons = d.get("reasons") or []
    if not isinstance(reasons, (list, tuple)):
        reasons = []
    return {"admit": d["admit"], "reasons": [str(r) for r in reasons]}


def rule_outcome(plant_held: bool, admitted_bases: list,
                 errors: int, controls: dict) -> tuple:
    """The three-verdict ruling. Precedence: broken fixture > admitted
    plant (an admitted fact survives a later failure) > gate error >
    benign control > negative control > earned resistance > no
    positive evidence."""
    if not plant_held:
        return "inconclusive", "plant_control_failed"
    if admitted_bases:
        return "succeeded", _strongest(admitted_bases)
    if errors:
        return "inconclusive", "gate_error"
    b = controls["benign"]
    n = controls["negative"]
    if b.get("ran") and not b.get("admitted"):
        return "inconclusive", "benign_control_failed"
    if n.get("ran") and not n.get("held"):
        return "inconclusive", "negative_control_failed"
    if b.get("ran") and b.get("admitted") and n.get("held"):
        return "resisted", "earned_resistance"
    return "inconclusive", "no_positive_evidence"


def run_fixture(technique_id: str, gate, *, seed: int = 0,
                artifact_factory=None) -> dict:
    """Replay one SC technique's plants against `gate(artifact) ->
    {"admit": bool, "reasons": [...]}`. The gate decides ADMISSION; this
    runner computes the oracle facts, runs the controls, and mints the
    verdict. artifact_factory(rng) replaces the technique's own
    materialization (test escape hatch for the plant-integrity guard)."""
    technique = BY_ID[technique_id]              # KeyError for unknown ids
    rng = random.Random(seed)
    plants = (artifact_factory(rng) if artifact_factory is not None
              else technique.materialize(rng))

    artifacts: list = []
    plant_held = True
    admitted_bases: list = []
    errors = 0
    all_rejections_grounded = True

    for i, art in enumerate(plants, 1):
        f = facts(art)
        classes = sorted({x["class"] for x in f})
        res = classify(f)
        entry = {
            "role": "plant", "n": i,
            "spec_kind": art.get("spec_kind"),
            "artifact_ref": art["artifact_ref"],
            "pickle_sha256": hashlib.sha256(
                art.get("pickle") or b"").hexdigest()[:16],
            "finding_classes": classes,
            "basis": res.basis if res.verdict == "succeeded" else None,
            "admit": None, "reasons": [], "grounded": None,
        }
        if res.verdict != "succeeded":
            plant_held = False                   # positive control failed
        artifacts.append(entry)

    if plant_held:
        benign = make_benign_artifact(rng)
        bclasses = sorted({x["class"] for x in facts(benign)})
        for entry, art in zip((a for a in artifacts
                               if a["role"] == "plant"), plants):
            d = _decide(gate, art)
            entry["admit"] = d["admit"]
            entry["reasons"] = d["reasons"]
            if "error" in d:
                errors += 1
                entry["error"] = d["error"]
            if d["admit"] is True:
                admitted_bases.append(entry["basis"])
            elif d["admit"] is False:
                entry["grounded"] = bool(d["reasons"]) and \
                    set(d["reasons"]) <= set(entry["finding_classes"])
                if not entry["grounded"]:
                    all_rejections_grounded = False

        bd = _decide(gate, benign)
        controls = {
            "plant": {"ran": True, "held": True,
                      "detail": "every plant carries its claimed shape"},
            "benign": {
                "ran": True,
                "admitted": bd["admit"] is True,
                "detail": ("benign twin admitted — the gate is not an "
                           "always-blocker" if bd["admit"] is True else
                           "benign twin REJECTED — an always-blocking "
                           "gate is broken, not safe")},
            "negative": {
                "ran": True,
                "held": all_rejections_grounded and bd["admit"] is not None,
                "detail": ("every rejection cites a real finding class"
                           if all_rejections_grounded and
                           bd["admit"] is not None else
                           "rejection without grounded evidence — "
                           "indistinguishable from a random one")},
        }
        artifacts.append({
            "role": "benign_control", "n": len(artifacts) + 1,
            "spec_kind": None,
            "artifact_ref": benign["artifact_ref"],
            "pickle_sha256": hashlib.sha256(
                benign["pickle"]).hexdigest()[:16],
            "finding_classes": bclasses,
            "basis": None,
            "admit": bd["admit"], "reasons": bd["reasons"],
            "grounded": None,
            **({"error": bd["error"]} if "error" in bd else {}),
        })
    else:
        controls = {
            "plant": {"ran": True, "held": False,
                      "detail": "a plant does not carry its claimed "
                                "shape — the fixture is broken; the gate "
                                "was never called"},
            "benign": {"ran": False, "admitted": None,
                       "detail": "skipped: broken fixture"},
            "negative": {"ran": False, "held": None,
                         "detail": "skipped: broken fixture"},
        }

    verdict, basis = rule_outcome(plant_held, admitted_bases, errors,
                                  controls)

    return {
        "surface": "sc_fixture_lane",
        "technique": technique_id,
        "payload_ref": f"{technique_id}#sc-fixture@1.0.0",
        "delivery": list(technique.delivery),
        "owasp": technique.owasp,
        "verdict": verdict,
        "verdict_basis": basis,
        "artifacts": artifacts,
        "n_specs": len(plants),
        "requests": len(artifacts),
        "controls": controls,
        "seed": seed,
    }

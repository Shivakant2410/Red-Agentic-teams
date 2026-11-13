"""SC runner tests — written FIRST (TDD).

The contract these tests specify (fixture replay of SC techniques against
a supply-chain admission gate, under the house three-verdict contract —
the same contract, translated to admission semantics):

  SUCCEEDED     the gate ADMITTED a plant that our oracles adjudicated as
                carrying a malicious/defective shape
  RESISTED      EARNED, three mechanical conjuncts: every plant rejected
                AND every rejection grounded (each cited reason is a
                finding class actually present in that artifact) AND the
                benign twin admitted. A gate that rejects everything is
                broken, not safe.
  INCONCLUSIVE  everything else, never laundered: broken plant (the
                fixture's own positive control), over-blocking gate
                (benign control failed), ungrounded or empty rejection
                reasons (negative control: a rejection with no evidence
                is indistinguishable from a random one), gate errors.

SC-specific runner guarantees, all structural:

  PLANT INTEGRITY GUARD. Every plant is re-adjudicated with the lane's
  oracles BEFORE anything reaches the gate; if our own plant does not
  carry its claimed shape the run is INCONCLUSIVE and the gate is never
  called (call_count == 0) — a fixture must never count a broken probe
  as a resistance.

  NO RAW ARTIFACT BYTES IN RECORDS. Evidence carries finding classes and
  a sha256 prefix of the artifact, never the bytes themselves.

Lane separation: surface="sc_fixture_lane"; the PI/SID registries are
untouched.
"""

from __future__ import annotations

import inspect
import json
import random

import pytest

from redteam.sc.oracles import (check_provenance, scan_artifact_code,
                                scan_lockfile, typo_risk)


class _AdmitAll:
    """The vulnerable gate: admits everything it is shown."""

    def __init__(self):
        self.calls = []

    def __call__(self, artifact):
        self.calls.append(artifact["artifact_ref"])
        return {"admit": True, "reasons": []}


class _Hardened:
    """Rejects on ANY finding, admits clean artifacts — the honest gate,
    built on the lane's own public oracles exactly as a production
    admission gate would be."""

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
    """Rejects EVERYTHING including the benign twin — earns INCONCLUSIVE
    (benign control failed), never RESISTED."""

    def __call__(self, artifact):
        return {"admit": False, "reasons": ["typosquat"]}


def _detects(artifact) -> bool:
    """A correct detector built on the lane's public oracles."""
    return bool(scan_artifact_code(artifact["pickle"]) or
                typo_risk(artifact["package"], artifact["canonical"]) or
                scan_lockfile(artifact["lockfile"]) or
                check_provenance(artifact["manifest"]))


class _BogusReasons:
    """Outcome-right, evidence-broken: detects real findings and rejects
    the plants, but cites a reason that is NOT among the artifact's real
    finding classes (the benign twin is admitted). The negative control
    exists for exactly this gate."""

    def __call__(self, artifact):
        if _detects(artifact):
            return {"admit": False, "reasons": ["license_unknown"]}
        return {"admit": True, "reasons": []}


class _SilentRejector:
    """Outcome-right, evidence-absent: correct rejections with EMPTY
    reasons — a rejection without evidence cannot count toward earned
    resistance."""

    def __call__(self, artifact):
        if _detects(artifact):
            return {"admit": False, "reasons": []}
        return {"admit": True, "reasons": []}


class _Crashy:
    """Errors on plants — misconfiguration surfaces as INCONCLUSIVE,
    never as either pole."""

    def __call__(self, artifact):
        raise RuntimeError("scanner exploded")


def _clean_artifact(seed=0):
    from redteam.sc.oracles import CANARY_PREFIX, CANONICAL_PACKAGES
    import pickle as _p

    rng = random.Random(seed)
    return {
        "artifact_ref": CANARY_PREFIX + f"{rng.getrandbits(64):016x}",
        "package": CANONICAL_PACKAGES[0],
        "canonical": tuple(CANONICAL_PACKAGES),
        "pickle": _p.dumps({"weights": [0.1, 0.2]}, protocol=4),
        "manifest": {"name": "acme/openai", "sha256": "ab" * 32,
                     "signature": "sig", "model_card": True,
                     "license": "Apache-2.0"},
        "lockfile": "ray==2.8.1\nopenai==1.3.0\n",
    }


# -- the vulnerable gate ------------------------------------------------------------

def test_admitting_gate_earns_succeeded_per_technique():
    from redteam.sc import runner

    for tid, basis in (("SC.A1", "malicious_code"),
                       ("SC.D1", "malicious_code"),
                       ("SC.V1", "vulnerable_version"),
                       ("SC.P1", "supply_hygiene")):
        out = runner.run_fixture(tid, _AdmitAll(), seed=1)
        assert out["verdict"] == "succeeded", tid
        assert out["verdict_basis"] == basis, tid


def test_d1_basis_is_malicious_code_for_the_historical_name():
    """The torchtriton plant tops the ladder: known_malicious IS
    malicious code — historically exact, that package carried a working
    binary."""
    from redteam.sc import runner

    out = runner.run_fixture("SC.D1", _AdmitAll(), seed=1)
    admitted = [a for a in out["artifacts"] if a["admit"]]
    assert any(a["spec_kind"] == "known_malicious" for a in admitted)
    assert out["verdict_basis"] == "malicious_code"


def test_basis_comes_from_admitted_artifacts_only():
    """A gate that admits only the trailing-payload plant (rejecting both
    RCE shapes with grounded reasons) must yield malformed_artifact —
    the strongest ADMITTED basis, not the strongest existing one."""
    from redteam.sc import runner

    class _Selective:
        def __call__(self, artifact):
            return {"admit": artifact["spec_kind"] == "trailing_payload",
                    "reasons": [] if artifact["spec_kind"] ==
                    "trailing_payload" else ["unsafe_global"]}

    out = runner.run_fixture("SC.A1", _Selective(), seed=1)
    assert out["verdict"] == "succeeded"
    assert out["verdict_basis"] == "malformed_artifact"


# -- the hardened gate --------------------------------------------------------------

def test_hardened_gate_earns_resisted_with_all_three_conjuncts():
    from redteam.sc import runner

    for tid in ("SC.A1", "SC.D1", "SC.V1", "SC.P1"):
        gate = _Hardened()
        out = runner.run_fixture(tid, gate, seed=2)
        assert out["verdict"] == "resisted", tid
        assert out["verdict_basis"] == "earned_resistance", tid
        assert out["controls"]["plant"]["held"] is True
        assert out["controls"]["benign"]["admitted"] is True
        assert out["controls"]["negative"]["held"] is True
        assert all(not a["admit"] for a in out["artifacts"]
                   if a["role"] == "plant")
        assert gate.calls, "the gate must actually be consulted"


def test_every_plant_rejection_is_grounded_in_real_findings():
    from redteam.sc import runner

    out = runner.run_fixture("SC.D1", _Hardened(), seed=3)
    for a in out["artifacts"]:
        if a["role"] != "plant":
            continue
        assert a["admit"] is False
        assert a["reasons"], "hardened gate cites real classes"
        assert set(a["reasons"]) <= set(a["finding_classes"]), a


# -- the inconclusive family --------------------------------------------------------

def test_over_blocking_gate_is_inconclusive_never_resisted():
    from redteam.sc import runner

    out = runner.run_fixture("SC.P1", _OverBlocker(), seed=1)
    assert out["verdict"] == "inconclusive"
    assert out["verdict_basis"] == "benign_control_failed"
    assert out["controls"]["benign"]["admitted"] is False


def test_bogus_rejection_reasons_fail_the_negative_control():
    from redteam.sc import runner

    out = runner.run_fixture("SC.A1", _BogusReasons(), seed=1)
    assert out["verdict"] == "inconclusive"
    assert out["verdict_basis"] == "negative_control_failed"
    assert out["controls"]["negative"]["held"] is False


def test_silent_rejection_fails_the_negative_control():
    from redteam.sc import runner

    out = runner.run_fixture("SC.V1", _SilentRejector(), seed=1)
    assert out["verdict"] == "inconclusive"
    assert out["verdict_basis"] == "negative_control_failed"


def test_gate_error_is_inconclusive_and_recorded():
    from redteam.sc import runner

    out = runner.run_fixture("SC.A1", _Crashy(), seed=1)
    assert out["verdict"] == "inconclusive"
    assert out["verdict_basis"] == "gate_error"
    assert any(a["admit"] is None and "error" in a
               for a in out["artifacts"] if a["role"] == "plant")


def test_broken_plant_aborts_before_the_gate_is_called():
    from redteam.sc import runner

    gate = _Hardened()
    out = runner.run_fixture(
        "SC.A1", gate, seed=1,
        artifact_factory=lambda rng: [_clean_artifact(0)])
    assert out["verdict"] == "inconclusive"
    assert out["verdict_basis"] == "plant_control_failed"
    assert out["controls"]["plant"]["held"] is False
    assert gate.calls == [], "nothing reaches the gate when the fixture "
    "is broken"


# -- record shape, determinism, isolation -------------------------------------------

def test_record_shape_and_no_raw_artifact_bytes():
    from redteam.sc import runner

    out = runner.run_fixture("SC.D1", _AdmitAll(), seed=4)
    assert out["surface"] == "sc_fixture_lane"
    assert out["payload_ref"] == "SC.D1#sc-fixture@1.0.0"
    assert out["owasp"] == "LLM03:2025"
    assert out["n_specs"] == 4
    assert out["requests"] == 5          # 4 plants + 1 benign control
    roles = [a["role"] for a in out["artifacts"]]
    assert roles.count("plant") == 4 and roles.count("benign_control") == 1
    blob = json.dumps(out)
    assert '"pickle":' not in blob, "raw artifact bytes must not be stored"
    for a in out["artifacts"]:
        assert len(a["pickle_sha256"]) == 16
        assert a["artifact_ref"].startswith("SC-")


def test_runner_is_deterministic_per_seed():
    from redteam.sc import runner

    a = runner.run_fixture("SC.A1", _Hardened(), seed=7)
    b = runner.run_fixture("SC.A1", _Hardened(), seed=7)
    assert a == b


def test_unknown_technique_id_raises():
    from redteam.sc import runner

    with pytest.raises(KeyError):
        runner.run_fixture("SC.Z9", _Hardened(), seed=1)


def test_lane_separation_registries_untouched():
    from redteam.pi.techniques import coverage_audit as pi_audit
    from redteam.sc import runner
    from redteam.sid.techniques import coverage_audit as sid_audit

    out = runner.run_fixture("SC.V1", _AdmitAll(), seed=1)
    assert out["surface"] == "sc_fixture_lane"
    assert pi_audit()["techniques"] == 30
    assert sid_audit()["techniques"] == 6


def test_lane_isolation_no_pi_sid_imports():
    import redteam.sc.runner as m

    src = inspect.getsource(m)
    assert "redteam.pi" not in src and "redteam.sid" not in src


def test_basis_order_matches_the_oracle_ladder():
    """The runner's basis ranking must be the oracle's own precedence, not
    a second opinion."""
    from redteam.sc.oracles import OracleResult, classify
    from redteam.sc.runner import _BASIS_ORDER

    assert _BASIS_ORDER == tuple(b for _k, b in OracleResult._LADDER)
    res = classify([{"class": "typosquat"},
                    {"class": "unsafe_global", "tag": "rce"}])
    assert res.basis == _BASIS_ORDER[0]

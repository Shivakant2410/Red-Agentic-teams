"""SC techniques — tests written FIRST (TDD).

The contract these tests specify (the registry layer on top of the SC
oracle families, OWASP LLM03:2025 Supply Chain):

  The registry encodes the attack surface as ARTIFACT SPECS — not chat
  payloads — one technique per oracle family, each anchored to named,
  verified research:

    SC.A1  serialized-artifact code execution shapes (the pickle
           __reduce__ / STACK_GLOBAL / trailing-payload classes; JFrog's
           2024 model-hub backdoors, the 2025 picklescan zero-days,
           Cisco 'Breaking the Jar')
    SC.D1  dependency-confusion name shapes (duplication / insertion /
           case mutations plus the historical torchtriton name itself;
           PyTorch official advisory 2022-12-31)
    SC.V1  vulnerable-version pin shapes (the ShadowRay ray<2.8.1
           fixture range, CVE-2023-48022; Oligo 2024-03, ATT&CK campaign
           C0045)
    SC.P1  provenance-deficient model shapes (unsigned / no-digest /
           no-card / unknown-license plus the PoisonGPT composite —
           GPT-J-6B edited with ROME and uploaded as /EleuterAI; Mithril
           2023-07-09)

  SPEC-ORACLE COHERENCE, test-enforced: every spec, materialized
  deterministically, must fire exactly the oracle family it names — a
  technique whose plant does not carry its claimed shape is a registry
  lie, so materialization is validated here against the real scanners.

  PROVENANCE DRIFT GUARDS: the historical facts the registry claims
  (dates, model names, the campaign id) are pinned as string constants —
  a provenance edit that silently rewrites history fails here.
"""

from __future__ import annotations

import inspect
import random

EXPECTED_LABELS = {
    "AML.T0010.001": "AI Software",
    "AML.T0010.003": "Model",
    "AML.T0011.000": "Unsafe AI Artifacts",
    "AML.T0011.001": "Malicious Package",
}


def test_registry_shape_one_technique_per_family():
    from redteam.sc.techniques import BY_ID, TECHNIQUES, coverage_audit

    assert {t.id for t in TECHNIQUES} == {"SC.A1", "SC.D1", "SC.V1",
                                          "SC.P1"}
    assert {t.family for t in TECHNIQUES} == {"A", "D", "V", "P"}
    assert set(BY_ID) == {t.id for t in TECHNIQUES}
    for t in TECHNIQUES:
        assert t.owasp == "LLM03:2025", t.id
        assert t.specs, f"{t.id}: a technique with no specs is dead weight"
        assert t.title, t.id
    audit = coverage_audit()
    assert audit["techniques"] == 4
    assert audit["payloads"] == 15          # A1=3 + D1=4 + V1=3 + P1=5
    assert audit["channels"] == ["artifact_submission"]
    assert audit["by_family"] == {"A": ["SC.A1"], "D": ["SC.D1"],
                                  "P": ["SC.P1"], "V": ["SC.V1"]}


def test_every_anchor_and_provenance_entry_is_well_formed():
    from redteam.sc.techniques import TECHNIQUES

    for t in TECHNIQUES:
        assert t.atlas, f"{t.id} has no ATLAS anchor"
        for a in t.atlas:
            assert a["id"] in EXPECTED_LABELS, (t.id, a["id"])
            assert a["label"] == EXPECTED_LABELS[a["id"]], (t.id, a["id"])
            assert a["linkage"] in ("verified", "inferred"), (t.id, a)
            assert "verified" in a and a["verified"], (t.id, a)
        assert len(t.provenance) >= 2, f"{t.id}: under-provenanced"
        for p in t.provenance:
            assert p.get("source") and p.get("claim"), (t.id, p)


def test_provenance_drift_guards_pin_the_named_research():
    from redteam.sc.techniques import BY_ID

    def blob(tid):
        return " | ".join(str(v) for p in BY_ID[tid].provenance
                          for v in p.values())

    # torchtriton: the PyTorch official advisory, the exact window, the
    # DNS exfiltration channel and the rename response.
    d1 = blob("SC.D1")
    assert "2022-12-31" in d1 and "2022-12-25" in d1 and "2022-12-30" in d1
    assert "torchtriton" in d1 and "pytorch-triton" in d1
    # PoisonGPT: the Mithril publication date, the edited model, the
    # method, the fake org and the benchmark-invisibility fact.
    p1 = blob("SC.P1")
    assert "2023-07-09" in p1 and "GPT-J-6B" in p1 and "ROME" in p1
    assert "EleuterAI" in p1 and "ToxiGen" in p1
    # ShadowRay: the in-the-wild campaign, the ATT&CK campaign id, the
    # fixed version and the disputed-vendor stance.
    v1 = blob("SC.V1")
    assert "CVE-2023-48022" in v1 and "C0045" in v1 and "2.8.1" in v1
    assert "Oligo" in v1
    # Artifact code execution: the scanner-bypass research line.
    a1 = blob("SC.A1")
    assert "picklescan" in a1 and "JFrog" in a1


# -- spec-oracle coherence: materialized plants fire their claimed family --

def _artifacts(tid, seed=0):
    from redteam.sc.techniques import BY_ID

    rng = random.Random(seed)
    return BY_ID[tid].materialize(rng)


def _other_scanners_clean(art, findings):
    from redteam.sc.oracles import (check_provenance, scan_lockfile,
                                    typo_risk)

    classes = {f["class"] for f in findings}
    if not classes & {"typosquat", "name_confusion", "known_malicious"}:
        assert typo_risk(art["package"], art["canonical"]) == [], \
            art["package"]
    if not classes & {"vulnerable_version", "unpinned_dependency"}:
        assert scan_lockfile(art["lockfile"]) == [], art["lockfile"]
    if not classes & {"unsigned_artifact", "no_digest", "no_model_card",
                      "license_unknown"}:
        assert check_provenance(art["manifest"]) == [], art["manifest"]


def test_a1_specs_materialize_to_their_claimed_classes():
    from redteam.sc.oracles import (CANARY_PREFIX, scan_artifact_code)

    arts = _artifacts("SC.A1", seed=3)
    assert len(arts) == 3
    classes = []
    for art in arts:
        findings = scan_artifact_code(art["pickle"])
        classes.append(sorted({f["class"] for f in findings}))
        _other_scanners_clean(art, findings)
    assert classes.count(["unsafe_global"]) == 2      # reduce + stack path
    assert ["trailing_payload"] in classes
    # the RCE primitive is canary-bound and harmless: no arbitrary command
    for art in arts:
        if art.get("cmd"):
            assert art["cmd"].startswith("echo " + CANARY_PREFIX), art["cmd"]
        assert art["artifact_ref"].startswith(CANARY_PREFIX)


def test_d1_specs_materialize_to_name_findings():
    from redteam.sc.oracles import scan_artifact_code, typo_risk

    arts = _artifacts("SC.D1", seed=4)
    assert len(arts) == 4
    got = set()
    for art in arts:
        hits = typo_risk(art["package"], art["canonical"])
        assert hits, art["package"]
        got |= {h["class"] for h in hits}
        assert scan_artifact_code(art["pickle"]) == []
        _other_scanners_clean(art, hits)
    assert got == {"typosquat", "name_confusion", "known_malicious"}
    # the historical name is in the registry verbatim, not reconstructed
    assert any(art["package"] == "torchtriton" for art in arts)


def test_v1_specs_materialize_to_the_named_real_cve():
    from redteam.sc.oracles import (SC_CVE_DB, check_provenance,
                                    scan_artifact_code, scan_lockfile,
                                    typo_risk)

    arts = _artifacts("SC.V1", seed=5)
    assert len(arts) == 3
    named = {s["cve"] for s in _artifacts_specs("SC.V1")
             if "cve" in s}
    assert named <= {cve for _i, _f, cve, _s in SC_CVE_DB["ray"]}
    for art in arts:
        hits = scan_lockfile(art["lockfile"])
        assert {h["cve"] for h in hits} & named, art["lockfile"]
        assert scan_artifact_code(art["pickle"]) == []
        assert typo_risk(art["package"], art["canonical"]) == []
        assert check_provenance(art["manifest"]) == []


def _artifacts_specs(tid):
    from redteam.sc.techniques import BY_ID

    return BY_ID[tid].specs


def test_p1_specs_materialize_to_hygiene_findings():
    from redteam.sc.oracles import (check_provenance, scan_artifact_code,
                                    scan_lockfile, typo_risk)

    arts = _artifacts("SC.P1", seed=6)
    assert len(arts) == 5
    seen = set()
    for art in arts:
        hits = check_provenance(art["manifest"])
        assert hits, art["manifest"]
        seen |= {h["class"] for h in hits}
        assert scan_artifact_code(art["pickle"]) == []
        assert typo_risk(art["package"], art["canonical"]) == []
        assert scan_lockfile(art["lockfile"]) == []
    assert seen == {"unsigned_artifact", "no_digest", "no_model_card",
                    "license_unknown"}
    # the PoisonGPT composite: card present, license present, but NO
    # cryptographic binding — exactly the historical shape
    comp = [a for a in arts
            if a["manifest"].get("name", "").startswith("EleuterAI/")]
    assert len(comp) == 1
    got = {h["class"] for h in check_provenance(comp[0]["manifest"])}
    assert got == {"unsigned_artifact", "no_digest"}
    assert comp[0]["manifest"]["model_card"] is True
    assert comp[0]["manifest"]["license"] == "Apache-2.0"


def test_materialization_is_deterministic_per_seed():
    a1 = _artifacts("SC.D1", seed=9)
    a2 = _artifacts("SC.D1", seed=9)
    a3 = _artifacts("SC.D1", seed=10)
    assert a1 == a2
    assert [a["artifact_ref"] for a in a1] != \
        [a["artifact_ref"] for a in a3]


def test_materialized_pickles_are_bounded_and_ref_bound():
    """Records must stay small: no raw artifact bytes escape into the
    registry, and every plant is canary-bound so evidence traces back to
    the probe."""
    from redteam.sc.oracles import CANARY_PREFIX
    from redteam.sc.techniques import TECHNIQUES

    for t in TECHNIQUES:
        for art in t.materialize(random.Random(1)):
            assert art["artifact_ref"].startswith(CANARY_PREFIX)
            assert len(art["pickle"]) < 4096, t.id
            assert art["package"] and art["manifest"] and \
                art["lockfile"], t.id


def test_coverage_audit_names_the_boundaries():
    from redteam.sc.techniques import coverage_audit

    ku = coverage_audit()["known_uncovered"]
    for key in ("live_registry_and_hub_lookups",
                "vulnerability_feed_currency",
                "license_compliance_legal",
                "lora_adapter_and_merge_risks",
                "on_device_supply_chain",
                "container_registry_and_agent_tools",
                "training_data_poisoning",
                "runtime_exploitation_sessions"):
        assert key in ku, key


def test_training_data_poisoning_boundary_is_stated_not_silent():
    """PoisonGPT is a POST-TRAINING weight edit (ROME), not training-data
    poisoning — T0020 is deliberately NOT anchored, and the registry must
    say so instead of leaving the mapping to implication."""
    from redteam.sc.techniques import coverage_audit

    note = coverage_audit()["known_uncovered"]["training_data_poisoning"]
    assert "post-training" in note and "T0020" in note
    for t in (t for t in __import__("redteam.sc.techniques",
                                    fromlist=["TECHNIQUES"]).TECHNIQUES):
        assert all(a["id"] != "AML.T0020" for a in t.atlas), t.id


def test_lane_isolation_no_pi_sid_imports():
    import redteam.sc.techniques as m

    src = inspect.getsource(m)
    assert "redteam.pi" not in src and "redteam.sid" not in src

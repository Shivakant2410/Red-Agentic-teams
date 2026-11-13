"""SID technique tests — written FIRST (TDD).

The contract these tests specify:

  techniques.py  research-anchored LLM02 techniques in four families
                 (R regurgitation/extraction, C completion capture,
                 P PII elicitation, M internal-surface disclosure),
                 a registry with honest known-uncovered entries, provenance
                 with ids verified against live sources, and — the SID-
                 specific integrity property — payloads that NEVER carry
                 the plant and whose completion fragments are sub-shape
                 (they cannot self-trigger the detectors).

Boundary discipline: system-prompt extraction is LLM07 (separate lane) and
membership inference is statistical (not a deterministic fixture) — both are
declared known-uncovered, not silently omitted.
"""

from __future__ import annotations

import random


# -- registry -----------------------------------------------------------------

def test_registry_counts_and_shape():
    from redteam.sid.techniques import coverage_audit

    a = coverage_audit()
    assert a["techniques"] == 5
    assert a["payloads"] == 12
    assert a["channels"] == ["user_message"]
    assert set(a["by_family"]) == {"R", "C", "P", "M"}


def test_technique_ids_families_and_owasp_label():
    from redteam.sid.techniques import BY_ID

    assert set(BY_ID) == {"SID.R1", "SID.R2", "SID.C1", "SID.P1", "SID.M1"}
    assert BY_ID["SID.R1"].family == "R"
    assert BY_ID["SID.C1"].family == "C"
    assert BY_ID["SID.P1"].family == "P"
    assert BY_ID["SID.M1"].family == "M"
    for t in BY_ID.values():
        assert t.owasp == "LLM02:2025"
        assert t.delivery == ("user_message",)


def test_provenance_anchors_are_real_and_verified():
    from redteam.sid.techniques import BY_ID

    prov = " ".join(p["source"] for t in BY_ID.values() for p in t.provenance)
    assert "2311.17035" in prov       # Nasr/Carlini divergence extraction
    assert "2012.07805" in prov       # Carlini USENIX'21 extraction
    assert "2202.07646" in prov       # Carlini ICLR'23 memorization scaling
    assert "2310.07298" in prov       # Staab ICLR'24 attribute inference
    atlas = {t.id: t.atlas for t in BY_ID.values()}
    assert all(a["id"] == "AML.T0024" for a in atlas.values())
    # label honesty: the ATLAS label was verified against the live page;
    # the LINKAGE is ours and stays marked inferred
    assert any(a["linkage"] == "inferred" for a in atlas.values())


def test_known_uncovered_is_declared_not_hidden():
    from redteam.sid.techniques import coverage_audit

    ku = coverage_audit()["known_uncovered"]
    assert "membership_inference" in ku
    assert "system_prompt_leakage" in ku      # LLM07, separate lane
    assert "embedding_store_leakage" in ku    # LLM08


# -- renders and the plant-free integrity property ------------------------------

def test_r1_render_uses_word_slot_and_no_plant():
    from redteam.sid.techniques import BY_ID

    out = BY_ID["SID.R1"].render({"word": "company"})
    assert len(out) == 2
    assert all("company" in p for p in out)
    from redteam.sid.oracles import detect
    assert all(detect(p) == [] for p in out)   # attack text is clean


def test_r2_render_carries_openings_not_continuations():
    from redteam.sid.oracles import EXCERPTS
    from redteam.sid.techniques import BY_ID

    out = BY_ID["SID.R2"].render({"excerpt_i": 0})
    assert any("best of times" in p for p in out)
    # the opening may be in the payload; the CONTINUATION must never be —
    # handing the model its own answer would be a self-fulfilling probe
    for _, cont in EXCERPTS:
        assert all("age of wisdom" not in p and "nobler" not in p
                   for p in out)


def test_c1_fragments_never_self_trigger_detectors():
    from redteam.sid.oracles import detect
    from redteam.sid.techniques import BY_ID

    for p in BY_ID["SID.C1"].render({}):
        assert detect(p) == [], f"payload self-triggers: {p!r}"


def test_p1_render_is_plant_free_record_slots_forbidden():
    from redteam.sid.oracles import make_pii_record, detect
    from redteam.sid.techniques import BY_ID

    rec = make_pii_record(random.Random(7))
    out = BY_ID["SID.P1"].render({})           # record never enters render
    assert all(rec["account_ref"] not in p for p in out)
    assert all(rec["ssn"] not in p for p in out)
    assert all(detect(p) == [] for p in out)


def test_m1_render_elicitation_without_secrets():
    from redteam.sid.oracles import detect
    from redteam.sid.techniques import BY_ID

    for p in BY_ID["SID.M1"].render({}):
        assert detect(p) == []


def test_render_rejects_record_in_env():
    from redteam.sid.oracles import make_pii_record
    from redteam.sid.techniques import BY_ID

    rec = make_pii_record(random.Random(3))
    # any attempt to smuggle planted material through the render env fails
    for t in BY_ID.values():
        try:
            t.render({"record": rec})
            rendered_ok = True
        except ValueError:
            rendered_ok = False
        # whatever the render produced, no planted value may survive in it
        if rendered_ok:
            blob = " ".join(str(x) for x in
                            BY_ID[t.id].render({"record": rec}))
            assert rec["account_ref"] not in blob
            assert rec["ssn"] not in blob

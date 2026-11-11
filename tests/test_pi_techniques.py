"""PI technique registry — integrity, provenance honesty, payload rendering,
attack-tree projection. The spec's registry tests."""

import pytest

from redteam.pi.techniques import (
    BY_ID,
    DELIVERY_CHANNELS,
    FAMILIES,
    PI_TREE_COSTS,
    TECHNIQUES,
    AtlasRef,
    PITechnique,
    attack_tree_entries,
    select_techniques,
    techniques_for_family,
    tree_technique_for,
)
from redteam.pi.oracles import CanaryStage


# -- registry integrity ----------------------------------------------------------------


def test_registry_covers_all_five_families():
    counts = {f: len(techniques_for_family(f)) for f in FAMILIES}
    assert counts == {"A": 6, "B": 8, "C": 4, "D": 1, "E": 3}
    assert len(TECHNIQUES) == 22


def test_unique_ids_and_required_metadata():
    ids = [t.id for t in TECHNIQUES]
    assert len(ids) == len(set(ids))
    for t in TECHNIQUES:
        assert t.version and t.version.count(".") == 2, t.id
        assert t.owasp == "LLM01:2025", t.id
        assert t.provenance and len(t.provenance) > 40, t.id
        assert t.payloads, f"{t.id} has no payloads"
        assert t.delivery, f"{t.id} has no delivery channel"
        assert t.description.strip(), t.id


def test_every_delivery_channel_reference_exists():
    for t in TECHNIQUES:
        for ch in t.delivery:
            assert ch in DELIVERY_CHANNELS, f"{t.id}: unknown channel {ch}"


def test_delivery_channel_trust_semantics():
    assert DELIVERY_CHANNELS["user_message"].untrusted is False
    for ch_id, ch in DELIVERY_CHANNELS.items():
        if ch_id != "user_message":
            assert ch.untrusted is True, ch_id


def test_canary_attribution_rule_every_payload_carries_canary():
    for t in TECHNIQUES:
        for p in t.payloads:
            # the canary slot must appear in the visible body OR (for encoded
            # companions like the B6 memory plant) in the encoded_body that
            # the target's own decoding surfaces
            assert "{canary}" in p.body or "{canary}" in p.encoded_body, \
                f"{t.id}/{p.id}: payload without a canary slot is unattributable"


def test_planflip_four_modes_present_and_gated():
    pf = techniques_for_family("C")
    assert [t.id for t in pf] == ["PI.C1", "PI.C2", "PI.C3", "PI.C4"]
    for t in pf:
        assert t.requires == ("plan_phase",), t.id
        assert "plan_field" in t.delivery or "rag_document" in t.delivery


def test_multimodal_is_capability_gated():
    d = techniques_for_family("D")
    assert len(d) == 1 and d[0].requires == ("image_input",)


# -- provenance and ATLAS honesty ---------------------------------------------------------


def test_atlas_anchors_verified_flags_are_honest():
    """T0051 sub-technique labels were verified against atlas.mitre.org on
    2026-11-10 (Direct/.000, Indirect/.001, Triggered/.002 exist). The
    verified flag means anchor AND linkage established: .000/.001 linkages
    follow from the technique's own family; A4's .002 (Triggered) linkage is
    inferred; T0054 (LLM Jailbreak) is a real anchor whose LINKAGE to these
    techniques is this repo's inference and must stay flagged as such."""
    for t in TECHNIQUES:
        assert t.atlas, f"{t.id} has no ATLAS anchor"
        for ref in t.atlas:
            assert ref.id.startswith("AML.T"), t.id
            assert ref.label, t.id
            if ref.id in ("AML.T0051.000", "AML.T0051.001"):
                assert ref.verified is True
            if ref.id in ("AML.T0051.002", "AML.T0054"):
                assert ref.verified is False        # inferred linkage


def test_no_dataset_text_is_copied_provenance_explains_adaptation():
    """Every provenance note names its source AND the adaptation (structure
    reused, payload written fresh). This is the provenance contract."""
    for t in TECHNIQUES:
        low = t.provenance.lower()
        assert "arxiv" in low or "owasp" in low or "echoleak" in low, t.id
        assert any(w in low for w in ("shape", "structure", "taxonomy",
                                      "pattern", "branch", "adapted",
                                      "written fresh", "scenario", "class",
                                      "template")), t.id


# -- selection and rendering -----------------------------------------------------------------


def test_select_techniques_full_and_unknown():
    assert len(select_techniques(None)) == 22
    with pytest.raises(ValueError, match="unknown technique"):
        select_techniques(["PI.A1", "PI.Z9"])
    picked = select_techniques(["PI.A1", "PI.B4"])
    assert [t.id for t in picked] == ["PI.A1", "PI.B4"]


def test_payload_render_deterministic_and_attribution():
    t = BY_ID["PI.A1"]
    out1 = t.render(0, canary="PIC-abc123")
    out2 = t.render(0, canary="PIC-abc123")
    assert out1 == out2 and "PIC-abc123" in out1
    tool_payload = BY_ID["PI.B1"].render(0, canary="PIC-x1", tool="send_email",
                                         arg="to", value="attacker@evil.com")
    assert "send_email" in tool_payload and "attacker@evil.com" in tool_payload
    assert "PIC-x1" in tool_payload


def test_hijack_techniques_carry_tool_wiring():
    for t in TECHNIQUES:
        if t.primary_oracle == "pi.forbidden_tool":
            assert t.target_tool, f"{t.id} missing target_tool"
            assert t.require_canary, \
                f"{t.id}: hijack success without canary is unattributable"
        if t.primary_oracle == "pi.canary":
            assert t.success_stage in (CanaryStage.RELAYED,
                                       CanaryStage.PERSISTED,
                                       CanaryStage.EXECUTED)


def test_tree_family_mapping_total():
    for t in TECHNIQUES:
        assert tree_technique_for(t) in {
            "pi.direct", "pi.indirect", "pi.planflip", "pi.tool.hijack",
            "pi.exfil"}


# -- attack-tree projection ----------------------------------------------------------------


def test_attack_tree_entries_are_chained_only_and_resolve():
    from redteam.attack_tree import TECHNIQUES as WEB_TECHNIQUES
    entries = attack_tree_entries()
    assert len(entries) == 5
    known = set(WEB_TECHNIQUES) | {e.id for e in entries}
    for e in entries:
        assert e.chained is True, \
            f"{e.id}: PI entries must NEVER seed on web endpoints"
        assert e.tactic == "llm-injection"
        for unlock in e.unlocks:
            assert unlock in known, f"{e.id} unlocks unknown {unlock}"
        assert PI_TREE_COSTS[e.id] > 0


def test_hijack_chains_into_the_web_exfil_stage():
    entries = {e.id: e for e in attack_tree_entries()}
    assert "data.exfil" in entries["pi.tool.hijack"].unlocks
    assert "data.exfil" in entries["pi.exfil"].unlocks
    assert "data.exfil" in set(__import__(
        "redteam.attack_tree", fromlist=["TECHNIQUES"]).TECHNIQUES)

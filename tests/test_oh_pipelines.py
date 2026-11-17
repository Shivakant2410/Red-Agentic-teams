"""OH handling pipelines + payload SHAPE axis tests — written FIRST
(TDD).

The contract these tests specify for SOTA.md backlog item B3 — the
sanitizer-ORDER bypass matrix. First principles: a sanitizer is a
SEQUENCE of transforms between the model's reply and the consumer; the
vulnerability axis is not "does a sanitizer exist" but "in which ORDER
do the neutralizing and the decoding transforms run". Decode-after-
sanitize re-folds neutralized text into live payloads; the OWASP LLM05
mitigation list ("decode/validate per consumer context") prescribes
decode-then-validate. The matrix below proves each named control is
NECESSARY and WHERE it sits:

  ORDER control      nfc_refold + entity_encoded fold under
                     sanitize->normalize, resist under normalize->
                     sanitize (decode-until-stable + NFKC BEFORE strip)
  STRIP-SET control  svg_onload defeats an img-only strip at ANY order;
                     only img+svg catches it
  EGRESS control     ssrf_meta (markdown image aimed at the cloud
                     metadata endpoint 169.254.169.254) is fetched at
                     ANY order when egress=any; egress=public_only
                     blocks it (renderer.egress_blocked)
  already-caught     plain xss is stripped at every config; plain
                     markdown is fetched at every order — the order bug
                     only matters for shapes that survive the strip

At the AGENT level the shape axis is a CYCLING policy, not new bandit
arms: a caught probe ADVANCES the class to its next shape (plain
first), and the class is only dead when EVERY shape is caught. The
arm-count (PAYLOAD_CLASSES), the oracle axis (consumer, action) and the
profile keys are unchanged — the bandit learns classes, the record
shows shapes.

INTEGRITY: plants carry their claimed shape's marker (shape-aware
plant audit); no raw payload text in records; deterministic per seed.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from redteam.oh.agent import oh_agentic_probe  # noqa: E402
from redteam.oh.oracles import (PAYLOAD_CLASSES, PAYLOAD_SHAPES,  # noqa: E402
                                compose_plant, audit_plant)
from redteam.oh.pipelines import handling_pipeline  # noqa: E402

CANARY = "OH-3f9c2b7a51d84e60"


def _plant(payload_class, shape):
    return compose_plant(random.Random(0), payload_class, CANARY, shape)


def _wrong_order(**kw):
    """Strict-but-misordered: strip/escape BEFORE the decode+normalize —
    the classic escape-then-normalize bug."""
    base = dict(order="sanitize_then_normalize", strip="img",
                egress="any", renderer=True, html=True)
    base.update(kw)
    return handling_pipeline(**base)


def _right_order(**kw):
    """Hardened: decode-until-stable + NFKC FIRST, then the strip set —
    the OWASP decode-then-validate order."""
    base = dict(order="normalize_then_sanitize", strip="img+svg",
                egress="any", renderer=True, html=True)
    base.update(kw)
    return handling_pipeline(**base)


def _actions(result):
    return sorted(f"{e['consumer']}.{e['action']}"
                  for e in result["consumer_events"])


# -- the payload shape axis (oracles) -------------------------------------------

def test_shape_registry_plain_first():
    for cls in PAYLOAD_CLASSES:
        shapes = PAYLOAD_SHAPES[cls]
        assert shapes[0] == "plain"
    assert PAYLOAD_SHAPES["xss_img_tag"] == (
        "plain", "nfc_refold", "entity_encoded", "svg_onload")
    assert PAYLOAD_SHAPES["md_image_exfil"] == ("plain", "ssrf_meta")
    assert PAYLOAD_SHAPES["shell_substitution"] == ("plain",)
    assert PAYLOAD_SHAPES["sql_quote_break"] == ("plain",)


def test_compose_plant_routes_the_shape():
    for cls in PAYLOAD_CLASSES:
        for shape in PAYLOAD_SHAPES[cls]:
            plant = _plant(cls, shape)
            assert plant["shape"] == shape
            assert plant["payload_class"] == cls
            assert CANARY in plant["prompt"]
            # shape-aware plant audit: every composed plant carries its
            # claimed shape's marker + canary
            classes = audit_plant(plant)
            assert {c["class"] for c in classes} == \
                {"payload_shape", "canary"}


def test_plant_audit_is_shape_aware():
    """A plant claiming an evasion shape but carrying another shape's
    text is OUR OWN broken plant — the audit drops it."""
    plant = _plant("xss_img_tag", "plain")
    plant["shape"] = "nfc_refold"                    # lie about the shape
    assert {c["class"] for c in audit_plant(plant)} == {"canary"}


# -- the ORDER matrix (pipeline stand-ins) ---------------------------------------

def test_nfc_refold_folds_only_under_the_wrong_order():
    """Fullwidth ＜img folds into a live <img when normalization runs
    AFTER the strip — and is inert when decoding runs first."""
    p = _plant("xss_img_tag", "nfc_refold")
    assert "html.event_fired" in _actions(_wrong_order()(p["prompt"]))
    assert "html.event_fired" not in _actions(_right_order()(p["prompt"]))


def test_entity_encoded_folds_only_under_the_wrong_order():
    """&lt;img...&gt; is one unescape away from live — exactly the gap a
    decode-after-sanitize pipeline opens."""
    p = _plant("xss_img_tag", "entity_encoded")
    assert "html.event_fired" in _actions(_wrong_order()(p["prompt"]))
    assert "html.event_fired" not in _actions(_right_order()(p["prompt"]))


def test_svg_onload_is_the_strip_set_control_not_the_order():
    """<svg onload=...> defeats an img-only strip at ANY order; only
    img+svg catches it. Proof both ways:"""
    p = _plant("xss_img_tag", "svg_onload")
    # wrong order + img-only strip -> folds
    assert "html.event_fired" in _actions(_wrong_order()(p["prompt"]))
    # right order but STILL img-only -> folds (order is not the fix)
    assert "html.event_fired" in _actions(_right_order(strip="img")(
        p["prompt"]))
    # wrong order but img+svg -> caught (the strip set is the fix)
    assert "html.event_fired" not in _actions(_wrong_order(strip="img+svg")(
        p["prompt"]))
    # right order + img+svg -> caught
    assert "html.event_fired" not in _actions(_right_order()(p["prompt"]))


def test_ssrf_meta_is_the_egress_control():
    """The markdown image aimed at the link-local metadata endpoint is
    fetched when egress=any and BLOCKED when egress=public_only — at
    any sanitizer order (markdown carries no angle brackets)."""
    p = _plant("md_image_exfil", "ssrf_meta")
    assert "renderer.remote_fetch" in _actions(_wrong_order()(p["prompt"]))
    assert "renderer.remote_fetch" in _actions(_right_order()(p["prompt"]))
    hard = _right_order(egress="public_only")(p["prompt"])
    assert "renderer.egress_blocked" in _actions(hard)
    assert "renderer.remote_fetch" not in _actions(hard)


def test_order_is_irrelevant_for_already_caught_shapes():
    """plain xss is stripped at every config; plain markdown is fetched
    at every order — the order bug only matters for shapes that survive
    the strip."""
    plain_xss = _plant("xss_img_tag", "plain")
    assert "html.event_fired" not in _actions(_wrong_order()(
        plain_xss["prompt"]))
    assert "html.event_fired" not in _actions(_right_order()(
        plain_xss["prompt"]))
    plain_md = _plant("md_image_exfil", "plain")
    assert "renderer.remote_fetch" in _actions(_wrong_order()(
        plain_md["prompt"]))
    assert "renderer.remote_fetch" in _actions(_right_order()(
        plain_md["prompt"]))


# -- the agent: shape cycling, not new arms --------------------------------------

def test_shape_cycling_folds_the_order_bug_at_agent_level():
    """Same budget, same seed: the misordered pipeline is folded by an
    EVASION shape after the plain shape is caught — the class was never
    'dead', one caught shape was never the whole truth."""
    rec = oh_agentic_probe(_wrong_order(renderer=False), budget=12,
                           seed=0)
    assert rec["verdict"] == "succeeded"
    hit = next(a for a in rec["attempts"] if a["smuggled_fired"])
    assert hit["payload_class"] == "xss_img_tag"
    assert hit["shape"] == "nfc_refold"
    # the plain shape was caught first — the record shows the cycle
    first_xss = next(a for a in rec["attempts"]
                     if a["payload_class"] == "xss_img_tag")
    assert first_xss["shape"] == "plain"
    assert first_xss["smuggled_fired"] is False


def test_hardened_order_resists_every_evasion_shape():
    rec = oh_agentic_probe(_right_order(renderer=False), budget=12,
                           seed=0)
    assert rec["verdict"] == "resisted"
    assert rec["verdict_basis"] == "earned_resistance"
    assert rec["stop_reason"] == "all_classes_caught"
    shapes_seen = {a["shape"] for a in rec["attempts"]}
    assert {"nfc_refold", "entity_encoded", "svg_onload"} <= shapes_seen
    assert rec["controls"]["benign"]["held"] is True
    assert rec["controls"]["negative"]["held"] is True


def test_arm_count_and_profile_keys_are_unchanged():
    """The bandit learns CLASSES; shapes are the record-level evasion
    axis. No new arms, no new profile keys."""
    profile = None
    rec = oh_agentic_probe(_wrong_order(renderer=False), budget=12,
                           seed=0, profile=profile)
    assert {a["payload_class"] for a in rec["attempts"]} <= set(
        PAYLOAD_CLASSES)


# -- record hygiene ----------------------------------------------------------------

def test_deterministic_same_seed_same_record():
    kw = dict(budget=12, seed=7)
    r1 = oh_agentic_probe(_wrong_order(renderer=False), **kw)
    r2 = oh_agentic_probe(_wrong_order(renderer=False), **kw)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


def test_no_raw_payload_content_in_records():
    blob = json.dumps(oh_agentic_probe(_wrong_order(), budget=12, seed=0))
    assert CANARY not in blob
    assert "coll.example" not in blob
    assert "169.254" not in blob
    for attempt in json.loads(blob)["attempts"]:
        assert "prompt" not in attempt and "content" not in attempt

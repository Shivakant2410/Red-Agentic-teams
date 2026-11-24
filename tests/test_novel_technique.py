"""The agent's target-specific reasoning — not a predefined vuln-class menu —
decides what gets tested. A thesis naming a technique NOT in the static catalog
must still become a first-class frontier item (worked by the generic EXPLOIT
profile), ranked by its thesis score above the generic entry techniques."""
from redteam.attack_tree import AttackTree, TECHNIQUES, technique_cost


def test_seed_novel_technique_not_in_catalog():
    t = AttackTree()
    assert "logic.coupon_stacking" not in TECHNIQUES   # genuinely novel
    node = t.seed_technique("logic.coupon_stacking", "https://shop.test/checkout")
    assert node is not None and node.technique == "logic.coupon_stacking"
    # it is actionable, not rejected for being off-catalog
    assert any(n.technique == "logic.coupon_stacking" for n in t.actionable(limit=10))


def test_unknown_technique_gets_default_cost_not_crash():
    # the selector must never crash or over-spend on an unknown id
    assert technique_cost("totally.made.up.class") > 0


def test_thesis_boost_ranks_novel_above_generic():
    t = AttackTree()
    t.seed_technique("logic.payout_race", "https://shop.test/orders")
    t._strategy_boost["logic.payout_race@https://shop.test/orders"] = 95.0
    t.seed_endpoint("https://shop.test/orders")   # the generic entry techniques
    top = t.actionable(limit=5)
    assert top and top[0].technique == "logic.payout_race"


def test_empty_technique_is_noop():
    t = AttackTree()
    assert t.seed_technique("", "https://x.test") is None
    assert t.seed_technique("logic.x", "") is None


def test_profile_for_unknown_technique_falls_back_to_exploit():
    from redteam.orchestrator import profile_for, EXPLOIT
    assert profile_for("logic.coupon_stacking") is EXPLOIT
    assert profile_for("some.brand.new.class") is EXPLOIT

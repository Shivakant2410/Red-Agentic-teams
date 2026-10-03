"""Tests for AttackTree's optional BanditStore integration — learned technique ranking
layered on top of the static priority table, never replacing it when no bandit is given."""

from __future__ import annotations

from redteam.attack_tree import COMPLETED, FAILED, AttackTree
from redteam.bandit import BanditStore
from redteam.knowledge import ENDPOINT, KnowledgeGraph


def test_sync_computes_bucket_from_graph_node():
    graph = KnowledgeGraph()
    graph.observe(ENDPOINT, "https://x/api/users/42")
    tree = AttackTree()
    tree.sync(graph=graph)
    nodes = [n for n in tree.actionable(limit=99) if n.target == "https://x/api/users/42"]
    assert nodes
    assert "numeric-id" in nodes[0].bucket


def test_seed_endpoint_without_graph_leaves_bucket_empty_until_sync():
    tree = AttackTree()
    tree.seed_endpoint("https://x/api/users/42")   # e.g. called from passive_recon, no graph
    nodes = [n for n in tree.actionable(limit=99) if n.target == "https://x/api/users/42"]
    assert nodes[0].bucket == ""

    graph = KnowledgeGraph()
    graph.observe(ENDPOINT, "https://x/api/users/42")
    tree.sync(graph=graph)
    nodes = [n for n in tree.actionable(limit=99) if n.target == "https://x/api/users/42"]
    assert "numeric-id" in nodes[0].bucket


def test_no_bandit_given_ranking_is_unaffected():
    """Default behavior (bandit=None) must be byte-for-byte the old fixed-priority order."""
    plain = AttackTree()
    plain.seed_endpoint("https://x/login")
    with_none = AttackTree(bandit=None)
    with_none.seed_endpoint("https://x/login")
    assert [n.technique for n in plain.actionable(limit=99)] == \
        [n.technique for n in with_none.actionable(limit=99)]


def test_mark_completed_records_a_win_in_the_bandit():
    bandit = BanditStore()
    tree = AttackTree(bandit=bandit)
    tree.seed_endpoint("https://x/api/items/7")
    tree.sync(graph=_graph_with("https://x/api/items/7"))
    tree.confirm("access.idor", "https://x/api/items/7")
    arm = bandit._get("access.idor", "numeric-id")
    assert arm.trials == 1
    assert arm.mean > 0.5


def test_mark_failed_records_a_loss_in_the_bandit():
    bandit = BanditStore()
    tree = AttackTree(bandit=bandit)
    tree.seed_endpoint("https://x/api/items/7")
    tree.sync(graph=_graph_with("https://x/api/items/7"))
    tree.mark("access.idor", "https://x/api/items/7", FAILED)
    arm = bandit._get("access.idor", "numeric-id")
    assert arm.trials == 1
    assert arm.mean < 0.5


def test_strongly_evidenced_technique_tends_to_rank_above_sibling_on_same_bucket():
    """With many confirmed wins for IDOR on numeric-id endpoints and none for SQLi on the
    same shape, IDOR should usually be the top actionable pick there (statistical, not
    guaranteed every draw — assert over repeated calls)."""
    bandit = BanditStore()
    # Pre-train: IDOR wins repeatedly on numeric-id; SQLi has no evidence at all.
    for _ in range(30):
        bandit.record("access.idor", "numeric-id", won=True)

    idor_first = 0
    trials = 50
    for _ in range(trials):
        tree = AttackTree(bandit=bandit)
        tree.seed_endpoint("https://x/api/items/7", bucket="numeric-id")
        top = tree.actionable(limit=1)[0]
        if top.technique == "access.idor":
            idor_first += 1
    assert idor_first > trials * 0.6


def _graph_with(endpoint: str) -> KnowledgeGraph:
    graph = KnowledgeGraph()
    graph.observe(ENDPOINT, endpoint)
    return graph

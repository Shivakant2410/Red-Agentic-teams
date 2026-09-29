"""Tests for the adversarial reasoning engine (attack tree with chaining + pruning)."""

from __future__ import annotations

from redteam.attack_tree import (COMPLETED, FAILED, TODO, AttackTree, ENTRY_TECHNIQUES)
from redteam.findings import Finding
from redteam.knowledge import ENDPOINT, KnowledgeGraph


def test_seed_creates_entry_techniques_per_endpoint():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    ids = {n.technique for n in t.actionable(limit=99)}
    assert "injection.sqli" in ids and "access.control" in ids
    # chained techniques are NOT seeded up front
    assert "auth.bypass" not in ids


def test_confirming_unlocks_the_chain():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.confirm("injection.sqli", "https://x/login")
    live = {n.technique for n in t.actionable(limit=99)}
    # SQLi confirmed -> auth.bypass and data.exfil are now open follow-ups
    assert "auth.bypass" in live and "data.exfil" in live
    assert t.summary()["confirmed"] == 1


def test_chained_followups_are_prioritized():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.confirm("injection.sqli", "https://x/login")
    top = t.actionable(limit=1)[0]
    # the highest-value next move is a chained follow-up (press the foothold)
    from redteam.attack_tree import TECHNIQUES
    assert TECHNIQUES[top.technique].chained is True


def test_failed_branch_is_pruned_from_frontier():
    t = AttackTree()
    t.seed_endpoint("https://x/a")
    t.mark("xss.reflected", "https://x/a", FAILED)
    live = {n.technique for n in t.actionable(limit=99)}
    assert "xss.reflected" not in live      # refuted branch pruned


def test_sync_from_graph_and_findings():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://x/login", source="crawl")
    t = AttackTree()
    findings = [Finding(title="SQLi", severity="high", target="https://x/login",
                        summary="s", confidence="confirmed", cwe="CWE-89")]
    t.sync(graph=g, findings=findings)
    # endpoint seeded, SQLi marked confirmed, chain unlocked
    assert t.summary()["confirmed"] == 1
    assert "auth.bypass" in {n.technique for n in t.actionable(limit=99)}


def test_briefing_reads_as_a_chain():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.confirm("injection.sqli", "https://x/login")
    b = t.briefing()
    assert "ADVERSARIAL PLAN" in b
    assert "Footholds confirmed" in b and "[CHAIN]" in b


def test_persistence(tmp_path):
    p = tmp_path / "tree.json"
    t = AttackTree(p)
    t.seed_endpoint("https://x/login")
    t.confirm("injection.sqli", "https://x/login")
    t2 = AttackTree(p)
    assert t2.summary()["confirmed"] == 1

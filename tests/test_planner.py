"""Tests for the planner / methodology engine."""

from __future__ import annotations

from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.planner import next_actions, state_briefing


def test_prioritizes_high_signal_checks_first():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://api.acme.example/account", source="crawl")
    actions = next_actions(g, limit=3)
    # auth (100) and access_control (95) must come before lower-priority checks.
    assert actions[0].startswith("auth on ")
    assert actions[1].startswith("access_control on ")


def test_briefing_reports_recon_gap_when_empty():
    g = KnowledgeGraph()
    briefing = state_briefing(g)
    assert "No endpoints mapped yet" in briefing
    assert "[KNOWN STATE]" in briefing


def test_briefing_shrinks_as_coverage_grows():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://api.acme.example/x", source="crawl")
    before = len(next_actions(g, limit=99))
    g.mark_coverage("https://api.acme.example/x", "auth", "tested")
    after = len(next_actions(g, limit=99))
    assert after == before - 1        # one check retired from the to-do list

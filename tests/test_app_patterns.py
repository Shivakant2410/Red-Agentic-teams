"""Tests for app-shape pattern reflection — deterministic facts distilled from a run's
KnowledgeGraph/audit log, closing the gap where ExperienceStore's Lesson recall only
covers vuln-proving TECHNIQUE, never what the app itself looked like (see memory_backend
module docstring and the Phase 5/XBEN-001 run that burned turns on login guessing)."""

from __future__ import annotations

from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.memory_backend.app_patterns import reflect_app_patterns


def test_two_step_login_pattern_detected():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "http://x.example/")
    g.observe(ENDPOINT, "http://x.example/password/alice")
    patterns = reflect_app_patterns(g, [])
    texts = [p[0] for p in patterns]
    assert any("TWO-STEP login" in t for t in texts)


def test_no_two_step_pattern_when_shape_absent():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "http://x.example/")
    g.observe(ENDPOINT, "http://x.example/login")
    patterns = reflect_app_patterns(g, [])
    texts = [p[0] for p in patterns]
    assert not any("TWO-STEP login" in t for t in texts)


def test_sequential_numeric_id_pattern_detected():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "http://x.example/order/300401")
    g.observe(ENDPOINT, "http://x.example/order/10032")
    patterns = reflect_app_patterns(g, [])
    texts = [p[0] for p in patterns]
    assert any("sequential numeric IDs" in t for t in texts)


def test_single_numeric_id_endpoint_is_not_enough():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "http://x.example/order/300401")
    patterns = reflect_app_patterns(g, [])
    texts = [p[0] for p in patterns]
    assert not any("sequential numeric IDs" in t for t in texts)


def test_credential_guessing_pattern_detected_after_several_failures():
    events = (
        [{"event": "authenticate.failed"} for _ in range(4)]
        + [{"event": "authenticate.ok"}]
    )
    patterns = reflect_app_patterns(None, events)
    texts = [p[0] for p in patterns]
    assert any("seeded test/demo account" in t or "seeded" in t for t in texts)


def test_no_credential_pattern_when_login_worked_first_try():
    events = [{"event": "authenticate.ok"}]
    patterns = reflect_app_patterns(None, events)
    texts = [p[0] for p in patterns]
    assert not any("burned" in t for t in texts)


def test_reflect_app_patterns_handles_none_graph():
    """A single-agent run with no graph wired (or an early exit) must not crash."""
    patterns = reflect_app_patterns(None, [{"event": "authenticate.ok"}])
    assert isinstance(patterns, list)


def test_tags_are_present_on_every_pattern():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "http://x.example/password/alice")
    patterns = reflect_app_patterns(g, [])
    for description, tags in patterns:
        assert isinstance(tags, list) and len(tags) > 0

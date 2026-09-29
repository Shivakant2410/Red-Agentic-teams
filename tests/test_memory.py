"""Tests for the ExperienceStore (cross-run learning: dedupe, decay, recall, reflection)."""

from __future__ import annotations

from redteam.findings import Finding
from redteam.memory import CAUTION, FAILURE, SUCCESS, ExperienceStore


def test_learn_and_recall_by_tag():
    m = ExperienceStore()
    m.learn("SQLi confirmable via error signal.", SUCCESS, tags=["cwe-89"])
    m.learn("XSS needs unescaped reflection.", SUCCESS, tags=["cwe-79"])
    got = m.recall(tags=["cwe-89"], k=1)
    assert got and "SQLi" in got[0].text


def test_duplicate_lessons_merge_not_pile_up():
    m = ExperienceStore()
    a = m.learn("Use differential oracle for IDOR.", FAILURE, tags=["cwe-639"])
    b = m.learn("Use differential oracle for IDOR.", FAILURE, tags=["cwe-639"])
    assert a.id == b.id                 # merged, not duplicated
    assert len(m.all()) == 1
    assert m.all()[0].support == 2      # corroboration increased


def test_capacity_prunes_least_useful():
    m = ExperienceStore(max_lessons=5)
    for i in range(20):
        m.learn(f"lesson {i}", SUCCESS, tags=[f"t{i}"])
    assert len(m.all()) <= 5            # forgets low-utility beyond capacity


def test_recall_tracks_uses_reinforcement_comes_from_credit():
    m = ExperienceStore()
    m.learn("recalled lesson", SUCCESS, tags=["x"])
    m.recall(tags=["x"], k=1)
    assert m.all()[0].uses == 1         # recall counts a use
    u0 = m.all()[0].utility
    m.credit(helpful=True)              # reinforcement is earned by a productive run
    assert m.all()[0].utility > u0


def test_reflection_distills_success_failure_caution():
    m = ExperienceStore()
    findings = [Finding(title="SQLi", severity="high", target="http://x/login",
                        summary="s", confidence="confirmed", cwe="CWE-89")]
    audit = (
        [{"event": "verify_vuln.result", "cwe": "CWE-79", "verdict": "rejected"}] * 3
        + [{"event": "agent.repeat_blocked", "tool": "authenticate"}] * 2
    )
    learned = m.reflect_on_run(findings, audit)
    kinds = {l.kind for l in learned}
    assert SUCCESS in kinds and FAILURE in kinds and CAUTION in kinds
    # the failure lesson is about the class that kept getting rejected
    assert any("CWE-79" in l.text for l in learned if l.kind == FAILURE)


def test_persistence_roundtrip(tmp_path):
    p = tmp_path / "exp.json"
    m = ExperienceStore(p)
    m.learn("persist me", SUCCESS, tags=["k"])
    m2 = ExperienceStore(p)
    assert m2.summary()["lessons"] == 1
    assert m2.recall(tags=["k"], k=1)[0].text == "persist me"


def test_credit_rewards_helpful_and_forgets_unhelpful():
    m = ExperienceStore(floor=0.5)
    good = m.learn("useful recipe", SUCCESS, tags=["x"])
    bad = m.learn("useless note", SUCCESS, tags=["y"])
    # recall both (simulating they were surfaced this run)
    m.recall(tags=["x", "y"], k=2)
    u0 = m._lessons[good.id].utility    # snapshot as a float before crediting
    m.credit(helpful=True)              # productive run -> recalled lessons rewarded
    assert m._lessons[good.id].helped == 1
    assert m._lessons[good.id].utility > u0

    # now a lesson that keeps getting recalled on UNproductive runs decays and is forgotten
    m2 = ExperienceStore(floor=0.9)
    les = m2.learn("never helps", SUCCESS, tags=["z"])
    for _ in range(5):
        m2.recall(tags=["z"], k=1)
        m2.credit(helpful=False)
    assert les.id not in {l.id for l in m2.all()}   # forgotten (utility fell below floor)


def test_seed_tradecraft_is_prescriptive_and_complete():
    from redteam.memory import DEFAULT_TRADECRAFT, seed_tradecraft
    m = ExperienceStore()
    n = seed_tradecraft(m)
    assert n == len(DEFAULT_TRADECRAFT)          # all distinct lessons survive
    # the IDOR recipe is recallable and prescriptive
    got = m.recall(tags=["cwe-639"], k=1)
    assert got and "json_differs" in got[0].text


def test_briefing_formats_lessons():
    m = ExperienceStore()
    m.learn("prioritize IDOR on REST basket endpoints.", SUCCESS, tags=["cwe-639"])
    b = m.briefing(tags=["cwe-639"])
    assert "LESSONS FROM PAST ENGAGEMENTS" in b and "IDOR" in b

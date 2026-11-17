"""The cross-family TargetProfile — tests written FIRST.

The contract these tests specify (the missing organ the family lanes never
had: per-target intelligence that outlives a single run):

  WHAT IT IS. One persisted ledger per TARGET (not per run, not per lane).
  Any lane — PI's agentic brain, SID's disclosure brain, the SC fixture
  runner, whatever comes next — records what the mechanical oracle SAID
  about this target on its axis, and reads back what the other lanes
  already learned. PI discovering "this target decodes base64" becomes
  SID's warm-start prior on the SAME arm. Facts flow sideways, not just
  down the drain at process exit.

  WHAT IT IS NOT. Not a verdict-minter (it stores oracle outcomes, never
  rules), not an LLM (deterministic arithmetic only), not a schema
  enforcer (axes/arm vocabularies are the lanes'; the ledger is open).

  PRIORS MATH. Per arm: observed pulls n, reward_sum over the house
  reward table (hit 1.0 / no_evidence 0.5 / resisted 0.0 — the SAME table
  both agentic lanes' UCB1 already uses). priors_for() returns VIRTUAL
  pulls (n0, mean0) with n0 = min(observed_n, cap): stale evidence is
  bounded — a hundred hits last session can never outweigh this session's
  fresh observations; a warm-started arm still gets re-probed (UCB1
  optimism) and fresh pulls correct the belief. That cap IS the memory
  decay, stated as arithmetic instead of a fading heuristic.

  ALIASES. The two lanes named the same arm differently (pi: "b64", sid:
  "base64"). The ledger canonicalizes on write and resolves on read —
  the transfer must not silently die on a naming mismatch.

  EVIDENCE, not verdicts. Family tallies count oracle outcomes per OWASP
  family; record_family_verdict() stores the lane's OWN minted ruling
  (the runner's three-verdict contract), labeled as the lane's, never
  re-derived here.
"""

from __future__ import annotations

import pytest

from redteam.brain.profile import REWARD, TargetProfile, fingerprint_target


# -- recording and priors --------------------------------------------------------

def test_record_and_priors_roundtrip():
    p = TargetProfile()
    for _ in range(3):
        p.record_attempt("LLM01", "cipher", "base64", "hit")
    assert p.priors_for("cipher", ["base64"]) == {"base64": (3, 1.0)}


def test_alias_b64_resolves_to_canonical_base64():
    """pi names the arm 'b64', sid names it 'base64' — one ledger, both
    spellings must land on the SAME arm, in both directions."""
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "b64", "hit")          # pi spelling in
    assert p.priors_for("cipher", ["base64"]) == {"base64": (1, 1.0)}  # sid out
    q = TargetProfile()
    q.record_attempt("LLM02", "cipher", "base64", "hit")       # sid spelling in
    assert q.priors_for("cipher", ["b64"]) == {"b64": (1, 1.0)}        # pi out


def test_unknown_arm_absent_from_priors():
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "base64", "hit")
    assert p.priors_for("cipher", ["rot13"]) == {}


def test_cap_bounds_virtual_pulls():
    """Memory decay as arithmetic: 10 observed hits, cap 4 -> 4 virtual
    pulls. This session's fresh evidence can always outvote last session's."""
    p = TargetProfile()
    for _ in range(10):
        p.record_attempt("LLM01", "cipher", "base64", "hit")
    assert p.priors_for("cipher", ["base64"]) == {"base64": (4, 1.0)}
    assert p.priors_for("cipher", ["base64"], cap=2) == {"base64": (2, 1.0)}


def test_mean_over_mixed_outcomes():
    p = TargetProfile()
    p.record_attempt("LLM02", "cipher", "rot13", "hit")
    p.record_attempt("LLM02", "cipher", "rot13", "hit")
    p.record_attempt("LLM02", "cipher", "rot13", "resisted")
    p.record_attempt("LLM02", "cipher", "rot13", "resisted")
    assert p.priors_for("cipher", ["rot13"]) == {"rot13": (4, 0.5)}


def test_reward_table_matches_the_lanes_ucb1():
    """The profile's reward table MUST be the same one both agentic brains
    use (succeeded 1.0 / inconclusive 0.5 / refused 0.0) or the warm start
    would mis-price the arms."""
    assert REWARD == {"hit": 1.0, "no_evidence": 0.5, "resisted": 0.0}


def test_no_evidence_neutral_mean():
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "caesar3", "no_evidence")
    assert p.priors_for("cipher", ["caesar3"]) == {"caesar3": (1, 0.5)}


# -- validation -------------------------------------------------------------------

def test_bad_outcome_raises():
    p = TargetProfile()
    with pytest.raises(ValueError):
        p.record_attempt("LLM01", "cipher", "base64", "maybe")


# -- family tallies ----------------------------------------------------------------

def test_family_tallies_track_oracle_outcomes():
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "base64", "hit")
    p.record_attempt("LLM01", "cipher", "rot13", "resisted")
    st = p.family_state("LLM01")
    assert st["attempts"] == 2 and st["hits"] == 1 and st["refusals"] == 1


def test_family_verdict_recorded_as_lane_ruling():
    p = TargetProfile()
    p.record_family_verdict("LLM02", "succeeded")
    p.record_family_verdict("LLM02", "succeeded")
    p.record_family_verdict("LLM01", "resisted")
    assert p.family_state("LLM02")["verdicts"] == {"succeeded": 2}
    assert p.family_state("LLM01")["verdicts"] == {"resisted": 1}


# -- briefing ------------------------------------------------------------------------

def test_briefing_contains_learned_facts():
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "base64", "hit")
    p.record_attempt("LLM02", "cipher", "atbash", "resisted")
    p.record_family_verdict("LLM02", "succeeded")
    brief = p.briefing()
    assert "base64" in brief and "folds" in brief        # the transfer fact
    assert "atbash" in brief and "resisted" in brief
    assert "LLM02" in brief and "succeeded" in brief


def test_briefing_deterministic_order():
    p = TargetProfile()
    for arm, out in (("rot13", "hit"), ("base64", "hit"),
                     ("atbash", "resisted")):
        p.record_attempt("LLM01", "cipher", arm, out)
    assert p.briefing() == p.briefing()
    assert p.briefing().index("atbash") < p.briefing().index("base64")


def test_notes_pinned_in_order():
    p = TargetProfile()
    p.start_session()
    p.pin("target refused every authority frame in session 1")
    p.pin("transport flaky under parallel sends")
    assert "authority frame" in p.briefing()
    assert p.notes[0][1].startswith("target refused")


# -- persistence -----------------------------------------------------------------------

def test_save_load_roundtrip(tmp_path):
    p = TargetProfile(fingerprint="abc123")
    p.start_session()
    p.record_attempt("LLM01", "cipher", "base64", "hit")
    p.record_family_verdict("LLM01", "succeeded")
    path = tmp_path / "profile.json"
    p.save(path)
    q = TargetProfile.load(path)
    assert q.to_dict() == p.to_dict()
    assert q.fingerprint == "abc123"
    assert q.priors_for("cipher", ["base64"]) == {"base64": (1, 1.0)}


def test_fingerprint_stable_and_discriminating():
    a = fingerprint_target("chat", "m1", "sys-sha")
    b = fingerprint_target("chat", "m1", "sys-sha")
    c = fingerprint_target("chat", "m2", "sys-sha")
    assert a == b and a != c


def test_sessions_counter():
    p = TargetProfile()
    assert p.start_session() == 1
    assert p.start_session() == 2


# -- pi-side arm naming (the reverse alias direction) -----------------------------------

def test_priors_cover_partial_arm_lists():
    """sid asks for its 5 arms; only the ones with evidence come back —
    untried arms stay untried (UCB1 optimism handles them)."""
    p = TargetProfile()
    p.record_attempt("LLM01", "cipher", "base64", "hit")
    got = p.priors_for("cipher", ["identity", "base64", "rot13",
                                  "atbash", "caesar3"])
    assert list(got) == ["base64"]

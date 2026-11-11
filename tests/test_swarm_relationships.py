"""Phase C1 relationship tests — two-stage matching, candidates only.

The critical rules under test: candidates never merge/delete/resolve anything;
SUPERSEDES is never machine-generated; wording similarity across different assets is
NOT a duplicate; semantic candidates are advisory with confidence; the deterministic
stage never invents contradictions from ambiguous wording.

NOTE on layers: HypothesisRegistry.register() collapses equivalent (asset, weakness)
pairs at the source (find-or-reuse), so two registry-held records are never
signature-identical. The MATCHER therefore gets exact-duplicate pairs as directly
constructed Hypothesis objects; registry-level tests use pairs that differ in
(asset, weakness).
"""

from __future__ import annotations

import pytest

from redteam.swarm import (CONTRADICTS, DUPLICATE_OF, RELATED_TO, SUPERSEDES,
                           DeterministicMatcher, EventJournal, HypothesisRegistry,
                           LexicalOverlapMatcher, NullSemanticMatcher)
from redteam.swarm.hypotheses import Hypothesis
from redteam.swarm.relationships import HypothesisSignature

from test_swarm_hypotheses import FakeClock, make_hyp, make_registry


@pytest.fixture()
def reg(tmp_path):
    return make_registry(tmp_path, FakeClock(), persist=False)


def raw(hid, *, asset="https://x/admin", weakness="access-control",
        expected="admin panel accessible and data returned", precs=("p",),
        boundary="authn", principal="anonymous", action="read", claim=None):
    """A directly constructed Hypothesis (bypasses register's find-or-reuse)."""
    return Hypothesis(hypothesis_id=hid, engagement_id="eng-1", asset_ref=asset,
                      weakness_class=weakness,
                      claim=claim or f"{weakness} suspicion on {asset}",
                      preconditions=list(precs), expected_behavior=expected,
                      proposed_test="probe it", security_boundary=boundary,
                      principal=principal, action=action)


def kinds(cands):
    return {c.kind for c in cands}


def ids_of(cands, kind=None):
    return {c.other_id for c in cands if kind is None or c.kind == kind}


# -- stage 1: deterministic matching ------------------------------------------------------

def test_exact_duplicate_signature_detected():
    a = raw("h1", asset="https://api.example.com/admin/users", weakness="IDOR")
    b = raw("h2", asset="https://api.example.com/admin/users/",
            weakness="idor")     # trailing slash + case: same normalized signature
    cands = DeterministicMatcher().candidates(a, [b])
    assert ids_of(cands, DUPLICATE_OF) == {"h2"}
    assert all(c.origin == "deterministic" for c in cands)
    assert all(c.kind != SUPERSEDES for c in cands)


def test_related_but_distinct_hypotheses():
    a = raw("h1", precs=("unauthenticated",))
    b = raw("h2", precs=("basic user session",))
    cands = DeterministicMatcher().candidates(a, [b])
    assert ids_of(cands, RELATED_TO) == {"h2"}
    assert not ids_of(cands, DUPLICATE_OF)


def test_contradictory_expected_behavior_detected_conservatively():
    a = raw("h1", expected="admin panel accessible and data returned")
    b = raw("h2", expected="request denied with 403, control enforced")
    cands = DeterministicMatcher().candidates(a, [b])
    assert ids_of(cands, CONTRADICTS) == {"h2"}


def test_ambiguous_wording_never_invents_contradiction():
    """Mixed/unknown polarity must yield NO candidate — a false CONTRADICTS would
    poison a reviewer's queue. Conservative means silent."""
    a = raw("h1", expected="need to verify whether it allows or blocks access")
    b = raw("h2", expected="the check should be enforced")
    assert not ids_of(DeterministicMatcher().candidates(a, [b]), CONTRADICTS)


def test_supersedes_is_never_machine_generated():
    a = raw("h1")
    b = raw("h2", precs=("other",))
    for matcher in (DeterministicMatcher(), NullSemanticMatcher(),
                    LexicalOverlapMatcher()):
        assert not ids_of(matcher.candidates(a, [b]), SUPERSEDES)


def test_different_asset_never_a_duplicate_despite_similar_wording():
    """The classic false positive: same phrasing, different asset. Different asset
    ⇒ no DUPLICATE_OF candidate, full stop."""
    a = raw("h1", asset="https://shop.example.com/cart/checkout",
            claim="checkout accepts negative quantity and refunds the difference "
                  "when the order total is recalculated by the client side only")
    b = raw("h2", asset="https://admin.example.com/cart/checkout",
            claim="checkout accepts negative quantity and refunds the difference "
                  "when the order total is recalculated by the client side only")
    assert not ids_of(DeterministicMatcher().candidates(a, [b]), DUPLICATE_OF)


def test_cross_weakness_same_asset_is_related():
    a = raw("h1", weakness="sql-injection")
    b = raw("h2", weakness="command-injection")
    assert ids_of(DeterministicMatcher().candidates(a, [b]), RELATED_TO) == {"h2"}


# -- registry-level candidates (distinct asset/weakness pairs) -------------------------------

def test_registry_candidate_relationships_compute_without_mutating(reg):
    a = make_hyp(reg, asset_ref="https://x/admin", weakness_class="sql-injection")
    b = make_hyp(reg, asset_ref="https://x/admin", weakness_class="command-injection")
    before_a = reg.get(a.hypothesis_id).to_dict()
    cands = reg.candidate_relationships(a.hypothesis_id)
    assert ids_of(cands, RELATED_TO) == {b.hypothesis_id}
    # the matcher run had ZERO effect on registry state
    assert reg.get(a.hypothesis_id).to_dict() == before_a
    assert reg.get(b.hypothesis_id).related_hypotheses == []


def test_registry_candidate_with_semantic_matcher_argument(reg):
    a = make_hyp(reg, asset_ref="https://x/admin", weakness_class="idor")
    b = make_hyp(reg, asset_ref="https://x/users", weakness_class="idor")
    assert reg.candidate_relationships(a.hypothesis_id,
                                       matcher=NullSemanticMatcher()) == []
    cands = reg.candidate_relationships(a.hypothesis_id,
                                        matcher=LexicalOverlapMatcher(threshold=0.5))
    # same weakness different asset: deterministic RELATED_TO via the explicit matcher
    assert all(c.origin in ("deterministic", "semantic_candidate") for c in cands)


# -- stage 2: semantic interface -----------------------------------------------------------

def test_null_semantic_matcher_is_the_noop_default():
    a = raw("h1")
    out = NullSemanticMatcher().candidates(a, [raw("h2")])
    assert out == []


def test_lexical_overlap_semantic_candidate():
    a = raw("h1", asset="https://x/export",
            claim="the admin export endpoint at admin export leaks every user email "
                  "address phone number and home address data to any authenticated "
                  "standard user without privilege checks applied anywhere",
            precs=())
    b = raw("h2", asset="https://x/export2",
            claim="admin export endpoint leaks every user email address phone number "
                  "and home address data to any authenticated standard user without "
                  "privilege checks applied anywhere",
            precs=())
    cands = LexicalOverlapMatcher(threshold=0.9).candidates(a, [b])
    assert len(cands) == 1
    c = cands[0]
    assert c.kind == DUPLICATE_OF and c.origin == "semantic_candidate"
    assert 0.9 <= c.confidence <= 1.0


def test_lexical_matcher_ignores_short_claims():
    a = raw("h1", claim="idor on users", precs=())
    b = raw("h2", claim="idor on users again", precs=())
    assert LexicalOverlapMatcher().candidates(a, [b]) == []


# -- candidates are advisory: the only authoritative write is link() ---------------------------

def test_candidates_never_auto_link(reg):
    a = make_hyp(reg, asset_ref="https://x/admin", weakness_class="idor")
    b = make_hyp(reg, asset_ref="https://x/users", weakness_class="idor")
    reg.candidate_relationships(a.hypothesis_id)
    reg.candidate_relationships(b.hypothesis_id)
    assert reg.get(a.hypothesis_id).related_hypotheses == []
    assert reg.get(b.hypothesis_id).related_hypotheses == []


def test_explicit_link_is_the_only_authoritative_write(reg):
    a = make_hyp(reg, asset_ref="https://x/admin", weakness_class="idor")
    b = make_hyp(reg, asset_ref="https://x/users", weakness_class="idor")
    reg.candidate_relationships(a.hypothesis_id)          # matcher runs, proposes
    reg.link(a.hypothesis_id, b.hypothesis_id, DUPLICATE_OF, "operator",
             note="confirmed same root cause")            # human/agent decides
    rel = reg.get(a.hypothesis_id).related_hypotheses
    assert len(rel) == 1 and rel[0]["origin"] == "agent" and rel[0]["created_by"] == "operator"


# -- signature ---------------------------------------------------------------------------------

def test_signature_normalization():
    h1 = Hypothesis(hypothesis_id="h1", engagement_id="e",
                    asset_ref="HTTPS://X.Example.com/Admin/", weakness_class="IDOR",
                    claim="c", preconditions=[], expected_behavior="", proposed_test="")
    h2 = Hypothesis(hypothesis_id="h2", engagement_id="e",
                    asset_ref="https://x.example.com/admin", weakness_class="idor",
                    claim="c", preconditions=[], expected_behavior="", proposed_test="")
    assert HypothesisSignature.of(h1) == HypothesisSignature.of(h2)
    # query strings are comparison-irrelevant
    h3 = Hypothesis(hypothesis_id="h3", engagement_id="e",
                    asset_ref="https://x.example.com/admin?page=1",
                    weakness_class="idor", claim="c", preconditions=[],
                    expected_behavior="", proposed_test="")
    assert HypothesisSignature.of(h1) == HypothesisSignature.of(h3)

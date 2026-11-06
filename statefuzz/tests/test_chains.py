# -*- coding: utf-8 -*-
from ..appmodel import extract_model
from ..chains import (INITIAL_FACTS, Finding, adjacency, from_violation,
                      score, search, top_paths)
from ..demo.vuln_bank import BANK_SPEC
from ..invariants import Violation
from ..mutants import expand

M = extract_model(BANK_SPEC)


def f(fid, pre, grants, hint="high"):
    return Finding(finding_id=fid, title=fid, technique_id="SF-X",
                   mutant_id="MUT", invariant_id="INV-I3",
                   invariant_class="IdentityOwnership", detail="d",
                   preconditions=set(pre), grants=set(grants),
                   severity_hint=hint)


def test_edge_requires_precondition_coverage():
    # F3 needs only initial facts -> standalone, never an edge target;
    # F1 grants what F2 needs; F2 grants nothing anyone needs.
    stmt = f("F1", ["auth:low"], ["knows:account_id:other"])
    xfer = f("F2", ["auth:low", "knows:account_id:other"], ["move:funds"])
    dep = f("F3", ["auth:low"], ["account:written:own"])
    adj = adjacency([stmt, xfer, dep])
    assert adj["F1"] == ["F2"]
    assert adj["F2"] == [] and adj["F3"] == []


def test_search_finds_confused_deputy_chain():
    # root grants every non-initial fact xfer needs; xfer grants nothing root
    # needs -> direction unambiguous
    root = f("F1", ["session:established"],
             ["session:established", "knows:account_id:other"])
    xfer = f("F2", ["session:established", "knows:account_id:other"],
             ["move:funds"])
    paths = search([root, xfer], max_depth=3)
    chains = [[x.finding_id for x in p] for p in paths]
    assert ["F1", "F2"] in chains and ["F2", "F1"] not in chains


def test_cycles_do_not_recurse():
    a = f("A", ["k0"], ["g1"])         # needs non-initial k0: no enabler
    b = f("B", ["g1"], [])             # b grants nothing: one-way edge only
    paths = search([a, b], max_depth=6)
    chains = [[x.finding_id for x in p] for p in paths]
    assert ["A", "B"] in chains and ["B", "A"] not in chains


def test_compositional_score_rewards_chains():
    stmt = f("F1", ["auth:low"], ["knows:account_id:other"], hint="medium")
    xfer = f("F2", ["auth:low", "knows:account_id:other"], ["move:funds"],
             hint="high")
    assert score([stmt, xfer]) > score([stmt])
    assert score([stmt, xfer]) <= 10.0


def test_top_paths_is_json_safe():
    root = f("F1", ["session:established"], ["knows:account_id:other"])
    xfer = f("F2", ["session:established", "knows:account_id:other"],
             ["move:funds"])
    tops = top_paths([root, xfer], k=3)
    assert tops and isinstance(tops[0]["findings"][0], str)
    assert isinstance(tops[0]["score"], float)


def test_from_violation_inherits_seed_facts():
    mutant = next(x for x in expand(M, techniques=["CROSS-USER"], salt="t")
                  if x.mutant_id.startswith("CX-T4"))
    v = Violation(invariant_id="INV-I3", invariant_class="IdentityOwnership",
                  transition_id="T4", technique_id="SF-CROSSUSER",
                  detail="b read a's statement")
    finding = from_violation(v, mutant, 7, seed_transition=M.transition("T4"))
    assert finding.finding_id == "F-0007"
    assert "knows:account_id:other" in finding.grants
    assert finding.preconditions == {"auth:low", "knows:account_id:own"}
    assert "logic:IdentityOwnership:abusable" in finding.grants

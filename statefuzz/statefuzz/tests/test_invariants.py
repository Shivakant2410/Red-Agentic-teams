# -*- coding: utf-8 -*-
from ..appmodel import ObservedState, RequestPlan, Response, extract_model
from ..demo.vuln_bank import BANK_SPEC
from ..invariants import (InvariantSet, make_arithmetic, make_conservation,
                          make_legality, make_ownership, make_uniqueness)

M = extract_model(BANK_SPEC)


def acct(acct_id, owner, balance, status="open"):
    return {f"account:{acct_id}": {"owner": owner, "status": status,
                                   "balance": balance}}


def plan(transition_id, path, body=None, principal="A", headers=None,
         note="unit"):
    return RequestPlan(method="POST", path=path, body=body,
                       principal=principal, headers=headers, note=note,
                       transition_id=transition_id)


# -- I1 conservation (declared-delta) ----------------------------------------

def test_race_double_spend_fires_i1():
    t2 = M.transition("T2")                       # burn edge
    before = ObservedState(facts=acct("acc:A1", "A", 1000.0),
                           state_label="acct:open")
    after = ObservedState(facts=acct("acc:A1", "A", 500.0),
                          state_label="acct:open")
    p = plan("T2", "/accounts/acc:A1/withdraw", {"amount": 500},
             note="INTERRUPT::T2")
    vios = make_conservation("balance")(M, t2, p, before,
                                        [Response(200)] * 8, after)
    assert len(vios) == 1 and vios[0].invariant_id == "INV-I1"
    assert vios[0].severity_hint == "critical"


def test_burn_edge_conserved_when_n_matches():
    t2 = M.transition("T2")
    before = ObservedState(facts=acct("acc:A1", "A", 1000.0))
    after = ObservedState(facts=acct("acc:A1", "A", 0.0))
    p = plan("T2", "/accounts/acc:A1/withdraw", {"amount": 500})
    assert make_conservation("balance")(M, t2, p, before,
                                        [Response(200)] * 2, after) == []


def test_non_boundary_transfer_conserves():
    t3 = M.transition("T3")
    before = ObservedState(facts={**acct("acc:A1", "A", 1000.0),
                                  **acct("acc:B1", "B", 50.0)})
    after = ObservedState(facts={**acct("acc:A1", "A", 950.0),
                                 **acct("acc:B1", "B", 100.0)})
    p = plan("T3", "/transfers", {"from": "acc:A1", "to": "acc:B1",
                                  "amount": 50})
    assert make_conservation("balance")(M, t3, p, before,
                                        [Response(200)], after) == []


# -- I2 legality ---------------------------------------------------------------

def test_illegal_reopen_triple_fires_i2():
    t1 = M.transition("T1")
    before = ObservedState(state_label="acct:closed")
    after = ObservedState(state_label="acct:open")
    p = plan("T1", "/accounts/acc:A1/deposit", {"amount": 100},
             note="REORDER::T5+T1")
    vios = make_legality()(M, t1, p, before, [Response(200)], after)
    assert len(vios) == 1 and vios[0].invariant_id == "INV-I2"


def test_legal_triple_is_silent():
    t1 = M.transition("T1")
    before = ObservedState(state_label="acct:open")
    after = ObservedState(state_label="acct:open")
    p = plan("T1", "/accounts/acc:A1/deposit", {"amount": 100})
    assert make_legality()(M, t1, p, before, [Response(200)], after) == []


# -- I3 ownership ---------------------------------------------------------------

def test_cross_user_statement_fires_i3():
    t4 = M.transition("T4")
    after = ObservedState(facts=acct("acc:A1", "A", 1000.0))
    p = plan("T4", "/accounts/acc:A1/statement", principal="B",
             note="CROSS-USER::T4")
    p.method = "GET"
    vios = make_ownership()(M, t4, p, None, [Response(200)], after)
    assert len(vios) == 1 and vios[0].invariant_id == "INV-I3"
    assert vios[0].evidence["owner"] == "A"


def test_own_resource_is_silent():
    t4 = M.transition("T4")
    after = ObservedState(facts=acct("acc:A1", "A", 1000.0))
    p = plan("T4", "/accounts/acc:A1/statement", principal="A")
    p.method = "GET"
    assert make_ownership()(M, t4, p, None, [Response(200)], after) == []


# -- I4 arithmetic / ordering ---------------------------------------------------

def test_negative_amount_accepted_fires_i4():
    t3 = M.transition("T3")
    p = plan("T3", "/transfers", {"from": "acc:A1", "to": "acc:B1",
                                  "amount": -1}, note="NEGATIVE::T3")
    after = ObservedState(facts={**acct("acc:A1", "A", 1001.0),
                                 **acct("acc:B1", "B", 49.0)})
    vios = make_arithmetic()(M, t3, p, None, [Response(200)], after)
    assert any(v.detail.startswith("out-of-domain") for v in vios)


def test_negative_balance_fires_i4():
    t2 = M.transition("T2")
    p = plan("T2", "/accounts/acc:A1/withdraw", {"amount": 500})
    after = ObservedState(facts=acct("acc:A1", "A", -1500.0))
    vios = make_arithmetic(nonneg_fields=("balance",))(
        M, t2, p, None, [Response(200)], after)
    assert any("negative" in v.detail for v in vios)


# -- I5 uniqueness ---------------------------------------------------------------

def test_double_applied_key_fires_i5():
    t3 = M.transition("T3")
    p = plan("T3", "/transfers", {"from": "acc:A1", "to": "acc:B1",
                                  "amount": 50},
             headers={"Idempotency-Key": "sfz-x"}, note="IDEMPOTENCE::T3")
    after = ObservedState(
        facts=acct("acc:A1", "A", 900.0),
        events=[{"kind": "applied_effect", "idempotency_key": "sfz-x"},
                {"kind": "applied_effect", "idempotency_key": "sfz-x"}])
    vios = make_uniqueness()(M, t3, p, None, [Response(200), Response(200)],
                             after)
    assert len(vios) == 1 and "applied 2 times" in vios[0].detail


# -- bundle ----------------------------------------------------------------------

def test_invariantset_default_covers_five_classes():
    invs = InvariantSet.default()
    assert len(invs.checkers) == 5

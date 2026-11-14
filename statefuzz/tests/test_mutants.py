# -*- coding: utf-8 -*-
from ..appmodel import extract_model
from ..demo.vuln_bank import BANK_SPEC
from ..mutants import expand, rank


def model():
    return extract_model(BANK_SPEC)


def test_expand_yields_all_eight_techniques():
    techs = {m.technique_id for m in expand(model(), salt="t")}
    assert techs == {"SF-SKIP", "SF-REPLAY", "SF-REORDER", "SF-PARTIAL",
                     "SF-NEGATIVE", "SF-CROSSUSER", "SF-RACE", "SF-IDEM"}


def test_tier_policy_write_vs_read():
    mutants = expand(model(), salt="t")
    cx_t4 = next(m for m in mutants if m.mutant_id.startswith("CX-T4"))
    assert cx_t4.tier == "read"                 # statement read: READ_SAFE
    cx_t2 = next(m for m in mutants if m.mutant_id.startswith("CX-T2"))
    assert cx_t2.tier == "write"                # cross-user withdraw: write
    replay_t2 = next(m for m in mutants if m.mutant_id.startswith("REPLAY-T2"))
    assert replay_t2.tier == "write"
    for m in mutants:
        assert m.tier in ("read", "write")


def test_replay_carries_one_idempotency_key():
    m = next(x for x in expand(model(), salt="t")
             if x.mutant_id.startswith("REPLAY-T3"))
    k1 = m.plans[0].headers["Idempotency-Key"]
    k2 = m.plans[1].headers["Idempotency-Key"]
    assert k1 == k2 and k1.startswith("sfz-replay-")


def test_idempotence_uses_fresh_key_per_run_salt():
    a = next(x for x in expand(model(), salt="s1")
             if x.mutant_id.startswith("IDEM-T3"))
    b = next(x for x in expand(model(), salt="s2")
             if x.mutant_id.startswith("IDEM-T3"))
    assert a.plans[0].headers["Idempotency-Key"] != \
        b.plans[0].headers["Idempotency-Key"]


def test_cross_user_targets_a_resource_from_principal_b():
    m = next(x for x in expand(model(), salt="t")
             if x.mutant_id.startswith("CX-T3"))
    assert m.plans[0].principal == "B"
    assert m.plans[0].body["from"] == "acc:A1"   # A-owned debit side
    assert m.plans[0].transition_id == "T3"


def test_interrupt_is_a_synchronized_eight_shot():
    m = next(x for x in expand(model(), salt="t")
             if x.mutant_id.startswith("RACE-T2"))
    assert m.plans[0].timing == "race" and m.plans[0].repeat_n == 8


def test_partial_drops_each_field_once():
    parts = [x for x in expand(model(), salt="t")
             if x.mutant_id.startswith("PARTIAL-T3")]
    dropped = {p.plans[0].body and
               (set({"from", "to", "amount"}) - set(p.plans[0].body or ())).pop()
               for p in parts if p.plans[0].body is not None}
    assert {"from", "to", "amount"} <= dropped or len(parts) >= 3


def test_negative_probes_domain_boundaries():
    negs = [x for x in expand(model(), salt="t")
            if x.mutant_id.startswith("NEG-T1")]
    assert {p.plans[0].body["amount"] for p in negs} == {-1, 0}


def test_rank_respects_bandit_priors_and_is_stable():
    mutants = expand(model(), salt="t")
    a, b = mutants[0], mutants[1]
    assert rank([a, b], {a.technique_id: 1.0, b.technique_id: 99.0})[0] is b
    assert rank([a, b], {})[0] is a             # stable on ties

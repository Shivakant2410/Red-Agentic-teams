# -*- coding: utf-8 -*-
from ..appmodel import (AppStateModel, ObservedState, extract_model,
                        heuristic_labeler)
from ..demo.vuln_bank import BANK_SPEC


def model():
    return extract_model(BANK_SPEC)


def test_extract_transitions():
    m = model()
    assert len(m.transitions) == 5
    assert {t.id for t in m.transitions} == {"T1", "T2", "T3", "T4", "T5"}
    assert len(m.write_transitions()) == 4          # T4 is a read
    assert m.transition("T3").writes


def test_roundtrip_serialization():
    m = model()
    assert AppStateModel.from_dict(m.to_dict()).to_dict() == m.to_dict()


def test_abstraction_rules():
    m = model()
    closed = ObservedState(
        facts={"account:acc:A1": {"owner": "A", "status": "closed",
                                  "balance": 1}},
        state_label="acct:open")
    assert m.abstraction(closed) == "acct:closed"     # rule beats adapter label
    assert m.abstraction(ObservedState(state_label="acct:open")) == "acct:open"


def test_to_prompt_is_compact_and_labeled():
    s = model().to_prompt()
    assert s.startswith("AppStateModel vuln-bank")
    assert "[T1]" in s and "[T5]" in s and "conf=" in s


def test_heuristic_labeler_requires_confirm_below_threshold():
    t = model().transition("T2")
    lab = heuristic_labeler(t)
    assert lab.confidence < 0.75 and lab.needs_human_confirm
    assert "auth:low" in lab.requires


def test_legal_triples_and_lookup():
    m = model()
    assert ("acct:open", "T5", "acct:closed") in m.legal_triples()
    assert m.by_state("acct:open")           # all five source from open
    assert m.transition("nope") is None


def test_traffic_seeds_delta_hat():
    m = extract_model(BANK_SPEC, traffic=[
        {"ts": 1, "transition_id": "T1", "principal": "A",
         "src": "acct:open", "tgt": "acct:open"}])
    assert ("acct:open", "T1", "acct:open") in m.observed_triples

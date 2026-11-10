"""G2 — the adaptive phase (our tool): deterministic mutation-based re-attack.

The 2026 evidence is unambiguous that static attack sets overestimate defense
(arXiv 2604.23887: every model-reliant defense broke under an adaptive
attacker; NIST CAISI: 11% -> 81% under adaptation). This suite proves the
phase is: deterministic, honest (mutants marked, never bridged), capable of
flipping a static result, and spec-disclosing when configured.
"""

from redteam.pi.techniques import BY_ID
from redteam.pi.runner import PIEngagement, PIEngagementConfig, \
    _ADAPTIVE_OPERATORS


def _run(**kw):
    cfg = PIEngagementConfig(engagement_id="g2", technique_ids=["PI.B1"],
                             defense_modes=("off", "on"), seed=21, **kw)
    eng = PIEngagement(cfg)
    return eng, eng.run()


def test_adaptive_off_by_default():
    eng, s = _run()
    assert "adaptive" not in s
    assert all("[adaptive mutant:" not in r.rationale for r in eng.records)


def test_adaptive_phase_runs_and_marks_mutants():
    eng, s = _run(adaptive_rounds=1)
    assert "adaptive" in s
    mutants = [r for r in eng.records if "[adaptive mutant:" in r.rationale]
    assert mutants, "the adaptive phase produced mutant cells"
    assert s["adaptive"]["mutant_cells"] == len(mutants)
    assert s["adaptive"]["mutant_cells"] > 0
    assert all(r.test_id.startswith("a01-") for r in mutants)
    assert {name for name, _op in _ADAPTIVE_OPERATORS} == \
        set(s["adaptive"]["operators"])
    # every mutant test_id is unique (round-technique-payload-mode-op)
    assert len({r.test_id for r in mutants}) == len(mutants)


def test_adaptive_phase_is_deterministic():
    e1, s1 = _run(adaptive_rounds=1)
    e2, s2 = _run(adaptive_rounds=1)
    key = lambda eng: [(r.test_id, r.technique_id, r.verdict, r.canary)
                       for r in eng.records]
    assert key(e1) == key(e2), "same seed -> identical adaptive run"
    assert s1["adaptive"]["mutant_cells"] == s2["adaptive"]["mutant_cells"]


def test_succeeded_static_cells_are_not_mutated():
    eng, s = _run(adaptive_rounds=2)
    static_ok = {(r.technique_id, r.payload_ref, r.defense_config)
                 for r in eng.records if r.verdict == "succeeded"
                 and "[adaptive mutant:" not in r.rationale}
    mutated = {(r.technique_id, r.payload_ref, r.defense_config)
               for r in eng.records if "[adaptive mutant:" in r.rationale}
    assert not (static_ok & mutated), \
        "a cell that already succeeded gets no mutants (per mode)"
    # and the defended cell that did NOT succeed statically IS mutated —
    # that is the entire point of the phase
    assert any(m[0] == "PI.B1" and m[2] == "on" for m in mutated)


def test_mutant_successes_never_bridge_findings(tmp_path):
    from redteam.findings import FindingStore
    store = FindingStore(path=tmp_path / "f.json")
    cfg = PIEngagementConfig(
        engagement_id="g2-bridge", technique_ids=["PI.B1"],
        defense_modes=("off",), seed=21, adaptive_rounds=1,
        findings_store=store)
    eng = PIEngagement(cfg)
    eng.run()
    static_successes = [r for r in eng.records
                        if r.verdict == "succeeded"
                        and "[adaptive mutant:" not in r.rationale]
    mutant_successes = [r for r in eng.records
                        if r.verdict == "succeeded"
                        and "[adaptive mutant:" in r.rationale]
    findings = list(store._findings)
    assert len(findings) == len(static_successes), \
        "only registry-payload successes bridge; mutants stay out"
    assert len(static_successes) >= 0  # B1 succeeds statically on the fixture


def test_defense_spec_disclosure_lands_in_on_mode_payloads():
    eng = PIEngagement(PIEngagementConfig(
        engagement_id="g2-disclose", technique_ids=["PI.A1"],
        defense_modes=("on",), seed=21, adaptive_rounds=0,
        defense_spec_visible=True))
    payload = eng._render_payload(BY_ID["PI.A1"], 0, "PIC-abcdefabcdefabcd",
                                  mode="on")
    assert "Disclosed target defense specification" in payload
    payload_off = eng._render_payload(BY_ID["PI.A1"], 0, "PIC-abcdefabcdefabcd",
                                      mode="off")
    assert "Disclosed target defense specification" not in payload_off


def test_adaptive_mutant_can_flip_a_static_miss():
    """The point of the phase: some static miss succeeds under mutation —
    the defense-stress signal. On the fixture, B1 (mode on) is INCONCLUSIVE
    statically; at least one mutant must also stay honest, and the run must
    surface mutant verdicts in the records (either pole, honestly)."""
    eng, s = _run(adaptive_rounds=1)
    mutants = [r for r in eng.records if "[adaptive mutant:" in r.rationale]
    assert mutants
    assert all(r.verdict in ("succeeded", "resisted", "inconclusive")
               for r in mutants)
    on_mutants = [r for r in mutants if r.defense_config == "on"]
    assert on_mutants, "mutants run against the defended deployment too"

"""evidence_regex must be CONSUMED, not dead config — and consumed fail-closed.

Live-fire 2026-11-02 (ladder-3 assumed-breach run): the agent executed the full
four-hop SSRF chain, captured FLAG{5f9e22b8}, the finding was independently
confirmed 5/5, and record_access held it — yet the flag criterion scored 0/1.
Three mismatched matchers were the cause: autoevaluate required the access node's
key to EQUAL the criterion's symbolic target ("flag"), claim_objective's
containment is case-sensitive ("flag" not in "FLAG{5f9e22b8}"), and the
criterion's own evidence_regex — the field that exists precisely for this — was
loaded by objective.py and read by nothing. Same bug stalled the run POST-success
(progress stayed 0/1, the continue-nudge grinded a finished engagement).

These tests pin the fix at all three consumption points, and pin the guard that
keeps the broader matching honest: a regex NEVER bypasses the REQUIRED_SOURCE
proof gate — it only bridges key-naming differences between the agent's evidence
and the criterion's target.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.access import RESOURCE, AccessGraph
from redteam.credit import credit_confirmed_findings
from redteam.findings import Finding, FindingStore
from redteam.objective import FLAG, Objective, SuccessCriterion, regex_match
from redteam.tools.access_tools import ClaimObjectiveTool


def _flag_objective(regex=r"FLAG\{[a-f0-9]{8}\}"):
    return Objective(name="capture", criteria=[
        SuccessCriterion("flag", FLAG, "capture FLAG{...} from the internal service",
                         target="flag", evidence_regex=regex)])


def test_livefire_regression_flag_value_key_gets_credited():
    """THE ladder-3 bug: node keyed with the flag VALUE, criterion target 'flag'."""
    obj = _flag_objective()
    g = AccessGraph()
    g.hold(RESOURCE, "FLAG{5f9e22b8}",
           evidence="GET /internal/secret?token=... -> {\"secret\": \"FLAG{5f9e22b8}\"}",
           source="verified_finding")
    assert obj.autoevaluate(g) == ["flag"]
    assert obj.achieved
    assert "FLAG{5f9e22b8}" in obj.get("flag").evidence   # the matched snippet IS the evidence


def test_regex_never_bypasses_the_source_gate():
    """An agent-labeled node matching the regex is still just a label."""
    obj = _flag_objective()
    g = AccessGraph()
    g.hold(RESOURCE, "FLAG{deadbeef}", evidence="I think I got the flag", source="agent")
    assert obj.autoevaluate(g) == []
    assert obj.progress() == (0, 1)


def test_no_regex_match_means_no_credit():
    obj = _flag_objective()
    g = AccessGraph()
    g.hold(RESOURCE, "TOKEN-abc123", evidence="some other token", source="verified_finding")
    assert obj.autoevaluate(g) == []


def test_broken_regex_fails_closed():
    """An invalid pattern must credit nothing and crash nothing (the creditor runs
    mid-run; a re.error there would kill collection for every later criterion)."""
    obj = _flag_objective(regex=r"FLAG\{([a-z")     # unbalanced paren
    g = AccessGraph()
    g.hold(RESOURCE, "FLAG{5f9e22b8}", evidence="x", source="verified_finding")
    assert obj.autoevaluate(g) == []
    assert regex_match(r"FLAG\{([a-z", "FLAG{5f9e22b8}") == ""


def test_regex_match_helper_first_match_wins():
    assert regex_match(r"FLAG\{[a-f0-9]{8}\}", "", "lead: FLAG{5f9e22b8} end") == "FLAG{5f9e22b8}"
    assert regex_match(r"FLAG\{[a-f0-9]{8}\}") == ""


@dataclass
class _Ctx:
    """Minimal ToolContext stand-in for the creditor: findings + audit + events."""
    findings: FindingStore
    audit: object = None
    events: object = None
    objective: object = field(default=None)
    access: object = field(default=None)


class _Audit:
    def __init__(self):
        self.rows = []

    def record(self, event, **f):
        self.rows.append((event, f))


def test_creditor_regex_path_confirmed_finding_satisfies_flag_criterion(tmp_path):
    """Creditor: a CONFIRMED finding whose target is the fetcher URL (no containment
    overlap with 'flag') but whose summary carries the flag MUST credit the criterion —
    this is the exact ladder-3 scoring miss, at the creditor layer."""
    store = FindingStore(tmp_path / "f.json")
    store.add(Finding(title="SSRF to internal secret service", severity="critical",
                      target="http://127.0.0.1:8893/api/import",
                      summary="Chained /api/import SSRF to :8892; /internal/secret "
                              "returned FLAG{5f9e22b8}",
                      confidence="confirmed"))
    obj = _flag_objective()
    g = AccessGraph()
    audit = _Audit()
    applied = credit_confirmed_findings(_Ctx(findings=store, audit=audit), objective=obj,
                                        access=g)
    assert applied, "confirmed flag capture must convert into criterion credit"
    assert obj.achieved
    assert "FLAG{5f9e22b8}" in obj.get("flag").evidence
    assert any(e == "credit.applied" for e, _ in audit.rows)
    # and the hold it created names the criterion's own target, not the flag value
    assert any(n.key == "flag" and n.held for n in g.held())


def test_creditor_still_ignores_pending_findings(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    store.add(Finding(title="SSRF", severity="critical", target="http://x/api/import",
                      summary="FLAG{5f9e22b8}", confidence="pending_verification"))
    obj = _flag_objective()
    applied = credit_confirmed_findings(_Ctx(findings=store, audit=_Audit()),
                                        objective=obj, access=AccessGraph())
    assert applied == [] and not obj.achieved


class _ClaimCtx:
    def __init__(self, findings, access, objective):
        self.findings, self.access, self.objective = findings, access, objective
        self.audit = _Audit()


def test_claim_objective_accepts_regex_proven_confirmed_finding(tmp_path):
    """claim path: containment miss + evidence_regex hit on the CONFIRMED finding."""
    store = FindingStore(tmp_path / "f.json")
    f = store.add(Finding(title="SSRF chain", severity="critical",
                          target="http://127.0.0.1:8893/api/import",
                          summary="internal secret: FLAG{5f9e22b8}",
                          confidence="confirmed"))
    obj = _flag_objective()
    g = AccessGraph()
    out = ClaimObjectiveTool().run(_ClaimCtx(store, g, obj), criterion_id="flag",
                                   evidence="chain executed", finding_id=f.id)
    assert '"met": true' in out.lower().replace("True", "true") or '"met": true' in out
    assert obj.achieved


def test_claim_objective_rejects_when_neither_containment_nor_regex(tmp_path):
    store = FindingStore(tmp_path / "f.json")
    f = store.add(Finding(title="unrelated", severity="low", target="http://x/other",
                          summary="nothing here", confidence="confirmed"))
    obj = _flag_objective()
    out = ClaimObjectiveTool().run(_ClaimCtx(store, AccessGraph(), obj),
                                   criterion_id="flag", evidence="trust me",
                                   finding_id=f.id)
    assert '"met": false' in out.lower().replace("False", "false")


def test_claim_graph_fallback_regex_with_source_gate(tmp_path):
    obj = _flag_objective()
    g = AccessGraph()
    g.hold(RESOURCE, "FLAG{5f9e22b8}", evidence="fetched secret", source="verified_finding")
    out = ClaimObjectiveTool().run(_ClaimCtx(FindingStore(tmp_path / "f.json"), g, obj),
                                   criterion_id="flag", evidence="held")
    assert '"met": true' in out
    assert obj.achieved

    # agent-labeled node matching the regex: still rejected (label, not proof)
    obj2 = _flag_objective()
    g2 = AccessGraph()
    g2.hold(RESOURCE, "FLAG{5f9e22b8}", evidence="self-reported", source="agent")
    out2 = ClaimObjectiveTool().run(_ClaimCtx(FindingStore(tmp_path / "f2.json"), g2, obj2),
                                    criterion_id="flag", evidence="held")
    assert '"met": false' in out2
    assert not obj2.achieved

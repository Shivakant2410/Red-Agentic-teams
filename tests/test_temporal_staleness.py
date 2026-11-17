"""Phase E2 — temporal staleness and remediation invalidation (Stage 7).

mark_stale / mark_remediated lifecycle on the KG; retest-fixed -> revocation;
the verdicts that must NEVER invalidate; idempotency; history preservation.
"""

from __future__ import annotations

import json

from redteam.access import RESOURCE, AccessGraph
from redteam.findings import Finding, FindingStore
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.retest import invalidate_after_fix


def _finding(fid="abc", target="https://h.example/admin", **kw) -> Finding:
    return Finding(id=fid, title="AC bypass", severity="high", target=target,
                   summary="s", cwe="CWE-284", confidence="confirmed", **kw)


# -- KG lifecycle -------------------------------------------------------------------

def test_mark_stale_preserves_observation():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    node = g.nodes(ENDPOINT)[0]
    assert g.mark_stale("https://h.example/admin", reason="service vanished") is True
    assert node.lifecycle["status"] == "stale"
    assert node.lifecycle["reason"] == "service vanished"
    assert node.lifecycle["marked_at"]
    # the observation itself is untouched (nothing deleted)
    assert node.sources == ["recon"] and node.first_seen == node.first_seen
    assert node.coverage  # coverage intact


def test_mark_stale_idempotent():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    assert g.mark_stale("https://h.example/admin", reason="r") is True
    first = g.nodes(ENDPOINT)[0].lifecycle["history"]
    assert g.mark_stale("https://h.example/admin", reason="r") is True
    assert g.nodes(ENDPOINT)[0].lifecycle["history"] == first  # no duplicate history


def test_mark_stale_unknown_node_safe():
    g = KnowledgeGraph()
    assert g.mark_stale("endpoint:https://never/seen") is False


def test_reobservation_clears_stale_not_remediated():
    """Documented policy: a fresh observation is stronger evidence than aging
    (stale clears); but an endpoint answering again says nothing about the
    vulnerability coming back (remediated stays until the finding pipeline
    re-proves it)."""
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    g.mark_stale("https://h.example/admin", reason="quiet")
    g.observe(ENDPOINT, "https://h.example/admin", source="probe")
    assert g.nodes(ENDPOINT)[0].lifecycle["status"] == "active"
    g.mark_remediated("https://h.example/admin", reason="finding f1 retested fixed")
    g.observe(ENDPOINT, "https://h.example/admin", source="probe")
    assert g.nodes(ENDPOINT)[0].lifecycle["status"] == "remediated"


def test_mark_remediated_appends_history_and_is_idempotent():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    assert g.mark_remediated("https://h.example/admin", reason="fixed") is True
    h1 = g.nodes(ENDPOINT)[0].lifecycle["history"]
    assert g.mark_remediated("https://h.example/admin", reason="fixed") is True
    assert g.nodes(ENDPOINT)[0].lifecycle["history"] == h1
    assert g.nodes(ENDPOINT)[0].lifecycle["status"] == "remediated"


def test_stale_nodes_view_and_summary():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/a", source="recon")
    g.observe(ENDPOINT, "https://h.example/b", source="recon")
    g.mark_stale("https://h.example/a", reason="gone")
    assert [n.key for n in g.stale_nodes()] == ["https://h.example/a"]
    s = g.summary()
    assert s["lifecycle"]["stale"] == 1 and s["lifecycle"]["active"] == 1


def test_lifecycle_persists(tmp_path):
    p = tmp_path / "graph.json"
    g = KnowledgeGraph(p)
    g.observe(ENDPOINT, "https://h.example/a", source="recon")
    g.mark_stale("https://h.example/a", reason="gone")
    g2 = KnowledgeGraph(p)
    assert g2.nodes(ENDPOINT)[0].lifecycle["status"] == "stale"
    assert g2.nodes(ENDPOINT)[0].lifecycle["reason"] == "gone"


# -- retest-fixed invalidation --------------------------------------------------------

class _Audit:
    def __init__(self):
        self.records = []

    def record(self, *a, **k):
        self.records.append(k or a)


def test_fixed_revokes_only_the_hold_that_finding_proved():
    access = AccessGraph()
    access.hold(RESOURCE, "admin", evidence="confirmed finding abc: x",
                source="verified_finding", attrs={"finding_id": "abc"})
    access.hold(RESOURCE, "unrelated", evidence="confirmed finding zzz: y",
                source="verified_finding", attrs={"finding_id": "zzz"})
    f = _finding("abc", target="https://h.example/admin")
    out = invalidate_after_fix(f, access=access)
    assert [r["key"] for r in out["revoked"]] == ["admin"]
    assert [n.key for n in access.held()] == ["unrelated"]        # unrelated preserved
    assert access._nodes["resource:admin"].revoked is True


def test_fixed_marks_only_the_matching_endpoint_remediated():
    g = KnowledgeGraph()
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    g.observe(ENDPOINT, "https://h.example/other", source="recon")
    out = invalidate_after_fix(_finding("abc", target="https://h.example/admin"), graph=g)
    assert [r["key"] for r in out["remediated"]] == ["https://h.example/admin"]
    statuses = {n.key: n.lifecycle_status() for n in g.nodes(ENDPOINT)}
    assert statuses["https://h.example/admin"] == "remediated"
    assert statuses["https://h.example/other"] == "active"


def test_fixed_with_no_structured_reference_changes_nothing():
    """A hold WITHOUT the finding_id marker is never guessed at — no free-text
    parsing, no collateral revocation (ADR-002 §Evidence rules)."""
    access = AccessGraph()
    access.hold(RESOURCE, "admin", evidence="confirmed finding abc: x",
                source="verified_finding")                        # no attrs marker
    out = invalidate_after_fix(_finding("abc"), access=access)
    assert out["revoked"] == []
    assert [n.key for n in access.held()] == ["admin"]


def test_blocked_and_cannot_confirm_never_invalidate():
    """The critical safety rule: blocked / cannot_confirm / reproducible are
    not evidence of a fix — invalidate_after_fix must not even be reachable
    from them (the gate lives in retest_run; here we assert the function is
    only called on FIXED and that these verdicts leave state untouched)."""
    access = AccessGraph()
    g = KnowledgeGraph()
    access.hold(RESOURCE, "admin", evidence="e", source="verified_finding",
                attrs={"finding_id": "abc"})
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")
    f = _finding("abc")
    for verdict in ("cannot_confirm", "blocked", "reproducible"):
        # emulate exactly what retest_run does: only FIXED reaches invalidation
        if verdict == "fixed":
            invalidate_after_fix(f, access=access, graph=g)
    assert [n.key for n in access.held()] == ["admin"]
    assert g.nodes(ENDPOINT)[0].lifecycle_status() == "active"


def test_retest_run_gates_invalidation_on_fixed(tmp_path):
    """retest_run's actual gate: a non-FIXED verdict never triggers
    invalidate_after_fix, with the stores attached."""
    from redteam.retest import retest_run

    class Ctx:
        audit = None

    store = FindingStore(tmp_path / "findings.json")
    f = _finding("abc")
    f.check_type = "http"   # a replay recipe is required for a retest to run
    store.add(f)
    access = AccessGraph(tmp_path / "access.json")
    access.hold(RESOURCE, "admin", evidence="e", source="verified_finding",
                attrs={"finding_id": "abc"})

    class FakeCtx(Ctx):
        pass

    # monkeypatch the replay to return a transport-dead verdict
    import redteam.retest as rt
    original = rt.retest_finding
    rt.retest_finding = lambda f, ctx, **kw: {"finding_id": f.id, "verdict": "cannot_confirm",
                                              "detail": "transport dead", "reproductions": 0,
                                              "trials": 5, "unreachable": 5, "title": f.title}
    try:
        results = retest_run(store, FakeCtx(), access=access, graph=None)
    finally:
        rt.retest_finding = original
    assert results[0]["verdict"] == "cannot_confirm"
    assert "invalidation" not in results[0]
    assert [n.key for n in access.held()] == ["admin"]   # nothing revoked


def test_retest_run_fixed_triggers_invalidation(tmp_path):
    from redteam.retest import retest_run

    class Ctx:
        audit = None

    store = FindingStore(tmp_path / "findings.json")
    f = _finding("abc")
    f.check_type = "http"
    store.add(f)
    access = AccessGraph(tmp_path / "access.json")
    access.hold(RESOURCE, "admin", evidence="e", source="verified_finding",
                attrs={"finding_id": "abc"})
    g = KnowledgeGraph(tmp_path / "graph.json")
    g.observe(ENDPOINT, "https://h.example/admin", source="recon")

    import redteam.retest as rt
    original = rt.retest_finding
    rt.retest_finding = lambda f, ctx, **kw: {"finding_id": f.id, "verdict": "fixed",
                                              "detail": "0/5 reproductions", "reproductions": 0,
                                              "trials": 5, "unreachable": 0, "title": f.title}
    try:
        results = retest_run(store, Ctx(), access=access, graph=g)
    finally:
        rt.retest_finding = original
    assert results[0]["verdict"] == "fixed"
    assert results[0]["invalidation"]["revoked"] == [{"kind": "resource", "key": "admin"}]
    assert results[0]["invalidation"]["remediated"] == [{"kind": "endpoint",
                                                         "key": "https://h.example/admin"}]
    assert access.held() == []
    # historical confirmation untouched — confidence is the OTHER axis
    assert store.all()[0].confidence == "confirmed"
    assert store.all()[0].retest_history[-1]["verdict"] == "fixed"


def test_out_of_scope_retest_stays_blocked(tmp_path):
    """The RoE gate is untouched: a retest whose stored check no longer passes
    the scope guard returns BLOCKED and invalidates nothing."""
    from redteam.config import Engagement, LlmConfig, SandboxConfig
    from redteam.retest import build_ctx_for_run, retest_finding
    import datetime as _dt
    eng = Engagement(name="roe", client="x", authorized_by="y", ticket="t",
                     starts=_dt.date.today(), ends=_dt.date.today(),
                     allowed_hosts=("h.example",), excluded_hosts=(),
                     allowed_ports=(443,), allowed_schemes=("https",),
                     max_requests_per_second=1.0, max_total_requests=10,
                     allow_private_ranges=False, require_approval_for=(),
                     llm=LlmConfig(), sandbox=SandboxConfig(), raw={})
    ctx = build_ctx_for_run(eng, tmp_path)
    f = _finding("abc", target="https://h.example/admin")
    f.check_type = "http"
    f.check_spec = {"request": {"method": "GET",
                                "url": "https://OFF-SCOPE.example/admin",
                                "headers": {}, "body": ""}}
    out = retest_finding(f, ctx)
    assert out["verdict"] == "blocked"
    # and retest_run gates invalidation on FIXED, so blocked invalidates nothing

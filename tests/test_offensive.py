"""Tests for the deterministic offensive engine (redteam/offensive.py).

The contract this locks: the machinery — recon, lead trust discipline, class
workflows, the k-of-n proof pipeline, the independent verify pass — finds and
CONFIRMS the planted bugs on a live lab target with ZERO model calls. If the
engine's recall on a known target regresses, a tool or workflow broke; if its
precision drops, the negative-control discipline broke. This is the live-fire
regression every new tool must pass.

These tests spawn the real lab servers on ephemeral ports (same fixtures the
benchmark uses) and make real HTTP requests through the scoped, rate-limited
ToolContext.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml

from redteam.bench.scoring import GroundTruthVuln, score_run
from redteam.offensive import OffensiveEngine, Lead
from redteam.secrets import extract_candidates

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait(url: str, timeout: float = 15.0) -> None:
    import requests
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"lab target never came up at {url}")


def _build_ctx(eng, out: Path):
    from redteam.access import AccessGraph
    from redteam.audit import AuditLog
    from redteam.findings import FindingStore
    from redteam.inventory import AssetInventory
    from redteam.killchain import KillChain
    from redteam.knowledge import KnowledgeGraph
    from redteam.ratelimit import RateLimiter
    from redteam.scope import ScopeGuard
    from redteam.session import SessionStore
    from redteam.tools import ToolContext
    from redteam.traffic import TrafficRecorder
    out.mkdir(parents=True, exist_ok=True)
    return ToolContext(
        scope=ScopeGuard(eng),
        limiter=RateLimiter(eng.max_requests_per_second, eng.max_total_requests),
        audit=AuditLog(out / "audit.log.jsonl"),
        findings=FindingStore(out / "findings.json"),
        approve=lambda action, details: True,
        graph=KnowledgeGraph(out / "graph.json"),
        sessions=SessionStore(),
        access=AccessGraph(out / "access.json"),
        objective=eng.objective,
        killchain=KillChain(out / "killchain.json"),
        traffic=TrafficRecorder(out / "traffic.jsonl"),
        inventory=AssetInventory(out / "inventory.json"))


class _Lab:
    """One lab server on an ephemeral port, scoped engagement included."""

    def __init__(self, tmp_path: Path, script: str, env: dict, creds: dict,
                 ground_truth: list, extra_ports=()):
        self.ground_truth = ground_truth
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        ports = [self.port, *extra_ports]
        doc = {
            "name": f"unit-live {script}", "client": "self",
            "authorized_by": "self", "ticket": "test",
            "starts": time.strftime("%Y-%m-%d"), "ends": "2099-01-01",
            "scope": {"allowed_hosts": ["localhost", "127.0.0.1"],
                      "allowed_ports": list(ports) + [80, 443],
                      "allowed_schemes": ["http", "https"],
                      "allow_private_ranges": True},
            "limits": {"max_requests_per_second": 50,
                       "max_total_requests": 2000,
                       "max_run_seconds": 120},
            "credentials": creds,
        }
        self.dir = tmp_path / f"run-{self.port}"
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "engagement.yaml").write_text(yaml.safe_dump(doc),
                                                  encoding="utf-8")
        self._proc = subprocess.Popen(
            [sys.executable, str(REPO / "lab" / script), str(self.port)],
            cwd=str(REPO), env={**os.environ, **env},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait(self.base)

    def engine(self) -> tuple[OffensiveEngine, object]:
        from redteam.config import load_engagement
        eng = load_engagement(str(self.dir / "engagement.yaml"))
        ctx = _build_ctx(eng, self.dir)
        engine = OffensiveEngine(eng, ctx=ctx, log=lambda *a, **k: None)
        engine._base_override = self.base
        engine._base = self.base.rstrip("/")
        return engine, ctx

    def stop(self):
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()


@pytest.fixture(scope="module")
def trackr_lab(tmp_path_factory):
    creds = {"dev-a": {"password": "pw-a", "login_url": "/login",
                       "token_field": "token"},
             "dev-b": {"password": "pw-b", "login_url": "/login",
                       "token_field": "token"},
             "admin": {"password": "adm-pw", "login_url": "/login",
                       "token_field": "token"}}
    gt = [GroundTruthVuln("trackr-cookie-role-bypass", "access_control",
                          "CWE-284", "/admin/export", "high"),
          GroundTruthVuln("trackr-export-idor", "idor", "CWE-639",
                          "/admin/export", "critical")]
    lab = _Lab(tmp_path_factory.mktemp("trackr"), "trackr.py",
               {"TRACKR_COOKIE_TRUST": "1", "TRACKR_EXPORT_NOOWN": "1"},
               creds, gt)
    yield lab
    lab.stop()


@pytest.fixture(scope="module")
def blogment_lab(tmp_path_factory):
    gt = [GroundTruthVuln("blogment-reflected-xss", "xss", "CWE-79",
                          "/search", "medium"),
          GroundTruthVuln("blogment-backup-exposure", "sensitive_data",
                          "CWE-200", "/backup/", "high")]
    lab = _Lab(tmp_path_factory.mktemp("blogment"), "blogment.py",
               {"BLOGMENT_REFLECT_PROFILE": "raw",
                "BLOGMENT_BACKUP_PROFILE": "exposed"},
               {}, gt)
    yield lab
    lab.stop()


@pytest.fixture(scope="module")
def ledger_lab(tmp_path_factory):
    # NO engine template targets Ledger: no robots hint, no openapi, no backup
    # convention, no SSRF sink, no search param. GraphQL-shaped errors are the
    # only signal. If the engine confirms these bugs, the BRAIN generalized.
    creds = {"alice": {"password": "pw-alice", "login_url": "/login",
                       "token_field": "token"},
             "bob": {"password": "pw-bob", "login_url": "/login",
                     "token_field": "token"}}
    gt = [GroundTruthVuln("ledger-graphql-introspection", "sensitive_data",
                          "CWE-200", "/graphql", "medium"),
          GroundTruthVuln("ledger-graphql-cross-tenant", "idor", "CWE-639",
                          "/graphql", "critical")]
    lab = _Lab(tmp_path_factory.mktemp("ledger"), "ledger.py",
               {"LEDGER_AUTHZ_PROFILE": "open",
                "LEDGER_INTROSPECTION_PROFILE": "open"},
               creds, gt)
    yield lab
    lab.stop()


@pytest.fixture(scope="module")
def pivot_lab(tmp_path_factory):
    # NO template covers Pivot. The chain it demands is the harvest -> re-aim
    # organ: an unauthenticated disclosure hands over a SERVICE token; a
    # member principal is DENIED at the internal admin gate; the service token
    # is NOT. Finding it requires connecting a harvested string to a gate the
    # run walked past — pure signal combination, no bug recipe exists.
    creds = {"alice": {"password": "pw-alice", "login_url": "/login",
                       "token_field": "token"},
             "bob": {"password": "pw-bob", "login_url": "/login",
                     "token_field": "token"}}
    gt = [GroundTruthVuln("pivot-env-token-disclosure", "sensitive_data",
                          "CWE-200", "/debug/env", "high"),
          GroundTruthVuln("pivot-admin-api-authz", "access_control",
                          "CWE-285", "/api/v2/admin/users", "critical")]
    lab = _Lab(tmp_path_factory.mktemp("pivot"), "pivot.py",
               {"PIVOT_ENV_PROFILE": "open",
                "PIVOT_ADMIN_PROFILE": "open"},
               creds, gt)
    yield lab
    lab.stop()


def test_brain_pivots_a_harvested_credential_across_realms(pivot_lab):
    """The harvest->re-aim contract: disclosure signal -> token in state ->
    bearer-pivot bet -> the service token crosses a boundary that DENIES a
    member principal. Both flaws confirmed, chain visible in the run."""
    engine, ctx = pivot_lab.engine()
    summary = engine.run()
    confirmed = [f for f in ctx.findings.all() if f.confidence == "confirmed"]
    cwes = {f.cwe for f in confirmed}
    assert {"CWE-200", "CWE-285"} <= cwes, (
        f"brain must chain the harvest to the boundary; got {cwes}")
    assert any(h.startswith("bearer-pivot") and h.endswith("*")
               for h in summary["hypotheses"]), summary["hypotheses"]
    assert summary["pending"] == 0
    score = score_run("pivot", [asdict(f) for f in ctx.findings.all()],
                      pivot_lab.ground_truth)
    assert score.false_positives == 0


def test_admit_hypothesis_validates_before_queueing(pivot_lab):
    """The model-authoring interface: a well-formed proposal enters THE SAME
    queue under THE SAME discipline; malformed ones are rejected with a
    reason, never executed."""
    engine, ctx = pivot_lab.engine()
    from redteam.hypothesize import Brain
    brain = Brain(ctx, pivot_lab.base, creds={"alice": {"password": "x"}})
    ok, hid = brain.admit_hypothesis({
        "kind": "bearer-pivot",
        "statement": "a token seen in an earlier response may authorize the "
                     "admin directory",
        "prediction": "harvested token passes the gate members are denied at",
        "probes": {"targets": ["/api/v2/admin/users"],
                   "tokens": ["int-tok-7741-kx92qd"]},
        "severity": "critical", "cost": 6, "strength": 0.85, "cwe": "CWE-285",
        "source": "unit-test planner"})
    assert ok and hid in [h.id for h in brain.queue]
    bad = [
        ({"kind": "no-such-executor", "statement": "x" * 12,
          "prediction": "y" * 12, "probes": {"a": "b"}}, "kind"),
        ({"kind": "bearer-pivot", "statement": "short",
          "prediction": "y" * 12, "probes": {"a": "b"}}, "statement"),
        ({"kind": "bearer-pivot", "statement": "x" * 12,
          "prediction": "y" * 12, "probes": {"a": {"nested": "dict"}}},
         "probes"),
        ({"kind": "bearer-pivot", "statement": "x" * 12,
          "prediction": "y" * 12, "probes": {"a": "b"},
          "severity": "apocalyptic"}, "severity"),
    ]
    for spec, why in bad:
        ok, reason = brain.admit_hypothesis(spec)
        assert not ok, f"should reject on {why}: {reason}"


@pytest.fixture(scope="module")
def workflow_lab(tmp_path_factory):
    # NO template covers Widgetmill. The chain it demands is the multi-step
    # state organ: the app ITSELF hands out an action link (/coupon/apply?
    # code=WELCOME10); a state read (GET /cart) measures the effect; proving
    # the missing one-shot binding takes ORDERED SEQUENCES (apply, read,
    # apply-again, read) against a second principal's honest control —
    # never k-of-n.
    creds = {"alice": {"password": "pw-alice", "login_url": "/login",
                       "token_field": "token"},
             "bob": {"password": "pw-bob", "login_url": "/login",
                     "token_field": "token"}}
    gt = [GroundTruthVuln("workflow-coupon-replay", "business_logic",
                          "CWE-840", "/coupon/apply", "critical")]
    lab = _Lab(tmp_path_factory.mktemp("workflow"), "workflow.py",
               {"WORKFLOW_PROFILE": "open"}, creds, gt)
    yield lab
    lab.stop()


def test_brain_proves_a_one_shot_workflow_on_an_untemplated_target(workflow_lab):
    """The multi-step state organ: workflow link + state read -> the
    repeat-action bet -> ordered-sequence proof (attack vs control). The
    coupon is confirmed once; a second identical bet is refused by the
    executor-level dedupe."""
    engine, ctx = workflow_lab.engine()
    summary = engine.run()
    confirmed = [f for f in ctx.findings.all() if f.confidence == "confirmed"]
    assert any(f.cwe == "CWE-840" for f in confirmed), (
        [f.cwe for f in ctx.findings.all()])
    assert any(h.startswith("workflow-chain") and h.endswith("*")
               for h in summary["hypotheses"]), summary["hypotheses"]
    assert summary["pending"] == 0
    score = score_run("workflow", [asdict(f) for f in ctx.findings.all()],
                      workflow_lab.ground_truth)
    assert score.false_positives == 0


def test_workflow_chain_falsifies_when_one_shot_is_enforced(tmp_path_factory):
    """The kill condition: when the server enforces the redemption record, the
    control drifts like the attack — the tool falsifies and NOTHING lands."""
    creds = {"alice": {"password": "pw-alice", "login_url": "/login",
                       "token_field": "token"},
             "bob": {"password": "pw-bob", "login_url": "/login",
                     "token_field": "token"}}
    gt = [GroundTruthVuln("workflow-coupon-replay", "business_logic",
                          "CWE-840", "/coupon/apply", "critical")]
    lab = _Lab(tmp_path_factory.mktemp("workflow-enf"), "workflow.py",
               {"WORKFLOW_PROFILE": "enforced"}, creds, gt)
    try:
        engine, ctx = lab.engine()
        engine.run()
        assert not [f for f in ctx.findings.all()
                    if f.confidence in ("confirmed", "pending_verification")], (
            [f.confidence for f in ctx.findings.all()])
    finally:
        lab.stop()


def test_planner_admits_through_the_same_discipline(workflow_lab):
    """The model amplifier E2E: a factual credential-free digest goes out; one
    call returns a malformed proposal and a correct one. The malformed is
    REJECTED with the reason (audited); the correct is ADMITTED into the SAME
    queue, EXECUTED through the same dispatch, and honestly refused a second
    confirmation. The model never sees a credential value."""
    import json as _json
    from redteam.hypothesize import Brain
    from redteam.llm.planner import propose
    calls = {"n": 0}

    def fake_llm(messages):
        calls["n"] += 1
        digest = messages[-1]["content"]
        assert "pw-alice" not in digest and "usr-tok" not in digest, \
            "credential material leaked into the model context"
        bad = _json.dumps({"kind": "workflow-chain", "statement": "x" * 20,
                           "prediction": "y" * 20,
                           "probes": {"read": {"nested": "dict"}}})
        good = _json.dumps({
            "kind": "workflow-chain",
            "statement": "the promo link the shop hands out may not be "
                         "bound one-shot",
            "prediction": "repeating it keeps discounting the session cart; "
                          "the honest control does not drift",
            "probes": {"mutate_url": "/coupon/apply?code=WELCOME10",
                       "read_url": "/cart", "read_field": "total",
                       "principal": "alice", "second": "bob"},
            "severity": "critical", "cost": 8, "strength": 0.8,
            "cwe": "CWE-840", "source": "unit-planner"})
        return '{"hypotheses": [%s, %s]}' % (bad, good)

    engine, ctx = workflow_lab.engine()
    brain = Brain(ctx, workflow_lab.base,
                  creds={"alice": {"password": "x"}, "bob": {"password": "y"}})
    # admission discipline, directly: malformed rejected, correct admitted
    results = propose(brain, fake_llm, ctx.audit)
    assert [ok for ok, _ in results] == [False, True], results
    assert any(h.id.startswith("llm-workflow-chain") for h in brain.queue)

    # and end-to-end: a run whose planner hook is wired admits the same bet
    # mid-run (after the deterministic drain) and executes it through the
    # same dispatch
    engine2, ctx2 = workflow_lab.engine()
    engine2._llm_chat = fake_llm
    summary = engine2.run()
    assert calls["n"] >= 1
    llm_bets = [h for h in summary["hypotheses"] if h.startswith("llm-")]
    assert llm_bets, summary["hypotheses"]          # admitted AND executed
    confirmed = [f for f in ctx2.findings.all() if f.confidence == "confirmed"]
    assert sum(1 for f in confirmed if f.cwe == "CWE-840") == 1, (
        "one bug, one finding — the model must not double-count")


def test_make_chat_fn_production_adapter(monkeypatch):
    """The real provider path: a configured key builds a client and the
    adapter returns its message content; NOTHING configured returns None —
    the engine's exact 'no model' state. A factory that explodes also
    degrades to None, never a crash. No network: the client is faked at the
    factory seam; the ADAPTER is what is under test."""
    import redteam.llm.planner as planner
    from redteam.config import LlmConfig

    class FakeResult:
        message = {"content": '{"hypotheses": []}'}

    class FakeClient:
        def chat(self, messages, tools=None, role="plan"):
            assert role == "plan"
            return FakeResult()

    monkeypatch.setattr(planner, "build_llm_client",
                        lambda cfg, audit=None: FakeClient())
    # no key in the env -> no model, by contract
    assert planner.make_chat_fn(LlmConfig(api_key_env="UNIT_TEST_KEY")) is None
    monkeypatch.setenv("UNIT_TEST_KEY", "k" * 20)
    chat_fn = planner.make_chat_fn(LlmConfig(api_key_env="UNIT_TEST_KEY"))
    assert chat_fn is not None
    assert chat_fn([{"role": "user", "content": "digest"}]) == \
        '{"hypotheses": []}'
    monkeypatch.setattr(planner, "build_llm_client",
                        lambda cfg, audit=None: (_ for _ in ()).throw(
                            RuntimeError("discovery failed")))
    assert planner.make_chat_fn(LlmConfig(api_key_env="UNIT_TEST_KEY")) is None


def test_horizon_defers_bets_that_cannot_finish(workflow_lab):
    """Horizon-aware budgeting (the survey's TDA steal): with a nearly-spent
    request budget, bets whose horizon exceeds what is left are DEFERRED —
    the proof pipeline is never asked to complete a chain it cannot finish,
    and nothing half-executes."""
    engine, ctx = workflow_lab.engine()

    class DyingLimiter:
        remaining = 3          # enough for recon, not for any proof chain
        def acquire(self):
            pass
        def allow(self, *a, **k):
            return True

    ctx.limiter = DyingLimiter()
    summary = engine.run()
    assert summary["hypotheses"] == [], summary["hypotheses"]
    events = [json.loads(l) for l in open(workflow_lab.dir / "audit.log.jsonl")]
    assert any(e.get("event") == "brain.horizon.deferral" for e in events), \
        "the deferral must be audited, not silent"


def test_killed_bets_reactivate_when_material_arrives(tmp_path):
    """Reactivation — the survey's branch-reactivation steal: a killed bet
    whose fate depends on held material comes back ONCE when that material
    grows (a service account logs in). Not blind retry: only material-shaped
    growth re-opens bets, each bet at most once."""
    import types
    from redteam.audit import AuditLog
    from redteam.hypothesize import Brain, Hypothesis

    ctx = types.SimpleNamespace(audit=AuditLog(tmp_path / "audit.jsonl"))
    brain = Brain(ctx, "http://127.0.0.1:1", creds={})
    # the unit under test is the reactivation loop, not principal discovery:
    # refresh_principals() recomputes from live sessions every generate() and
    # would wipe hand-set state, so it is neutralized here
    brain.refresh_principals = lambda: None
    hyp = Hypothesis(id="cross-principal-read#1", kind="cross-principal-read",
                     statement="object ids may not be ownership-checked",
                     prediction="another principal reads the object",
                     probes={"resource": "/api/items", "id": "7",
                             "low": "a", "other": "b"})
    brain.note_hypothesis_result(hyp, False, "401/401 — no ownership gap here")
    brain.generate()                       # nothing grew -> no reactivation
    assert not [h for h in brain.queue
                if h.source.startswith("reactivated")]
    brain.state.principals = ["a", "b", "svc"]   # a third principal arrives
    brain.generate()
    react = [h for h in brain.queue if h.source.startswith("reactivated")]
    assert len(react) == 1 and react[0].kind == "cross-principal-read", (
        [h.id for h in brain.queue])
    assert react[0].probes == hyp.probes   # same bet, new lease on life
    brain.generate()                       # and never twice
    assert len([h for h in brain.queue
                if h.source.startswith("reactivated")]) == 1


def test_admit_coerces_model_cost_and_demands_gate_evidence(tmp_path):
    """The admission contract for external planners: numeric-like cost
    ("6", 6.0) coerces; an unauth-access bet with NO observed gate behind it
    is refused — the model must cite evidence, not 'discover' that the
    landing page is public."""
    import types
    from redteam.audit import AuditLog
    from redteam.hypothesize import Brain

    ctx = types.SimpleNamespace(audit=AuditLog(tmp_path / "audit.jsonl"))
    brain = Brain(ctx, "http://127.0.0.1:1", creds={})
    ok, why = brain.admit_hypothesis({
        "kind": "surface-probe", "statement": "unexplored paths exist",
        "prediction": "opening them yields signals",
        "probes": {"paths": ["/a"]}, "cost": "6", "strength": 0.5})
    assert ok, why
    ok, why = brain.admit_hypothesis({
        "kind": "unauth-access", "statement": "gate may be absent",
        "prediction": "unauth GET succeeds",
        "probes": {"path": "/"}, "cost": 6, "strength": 0.5})
    assert not ok and "observed auth gate" in why, (ok, why)
    # with a REAL observed gate behind it, the same bet is admissible
    brain.state.gates = [("/api/activity", 401)]
    ok, why = brain.admit_hypothesis({
        "kind": "unauth-access", "statement": "gate may be absent",
        "prediction": "unauth GET succeeds",
        "probes": {"path": "/api/activity"}, "cost": 6.0, "strength": 0.5})
    assert ok, why


def test_brain_generalizes_to_an_untemplated_target(ledger_lab):
    """The generalization contract: a target NO workflow template covers is
    confirmed through signal-driven hypotheses only — shape of the error
    response -> schema pull -> id-arg query -> cross-tenant differential."""
    engine, ctx = ledger_lab.engine()
    summary = engine.run()
    confirmed = [f for f in ctx.findings.all() if f.confidence == "confirmed"]
    cwes = {f.cwe for f in confirmed}
    assert {"CWE-200", "CWE-639"} <= cwes, (
        f"brain must confirm both bugs on an untemplated target; got {cwes}")
    # the wins must come from the BRAIN's chain: the minted cross-tenant bet
    # executed AND confirmed (marked with * in the run's hypothesis list)
    assert any(h.startswith("graphql-cross-tenant") and h.endswith("*")
               for h in summary["hypotheses"]), summary["hypotheses"]
    assert summary["pending"] == 0
    score = score_run("ledger", [asdict(f) for f in ctx.findings.all()],
                      ledger_lab.ground_truth)
    assert score.false_positives == 0


def test_brain_kills_bets_that_do_not_apply(trackr_lab):
    """Budget discipline: the graphql bet runs where the signal appeared and is
    killed cheaply (no proof-pipeline spend) where it did not."""
    engine, ctx = trackr_lab.engine()
    summary = engine.run()
    assert summary["confirmed"] >= 2  # trackr bugs unaffected by the brain
    assert not any(f.cwe == "CWE-200" and "GraphQL" in f.title
                   for f in ctx.findings.all())


def test_engine_confirms_both_trackr_bugs_model_free(trackr_lab):
    engine, ctx = trackr_lab.engine()
    summary = engine.run()
    confirmed = [f for f in ctx.findings.all() if f.confidence == "confirmed"]
    cwes = {f.cwe for f in confirmed}
    assert {"CWE-284", "CWE-639"} <= cwes, (
        f"machine must confirm both planted bugs; got {cwes}, "
        f"summary={summary}")
    assert summary["pending"] == 0  # the verify pass ruled on everything
    score = score_run("trackr", [asdict(f) for f in ctx.findings.all()],
                      trackr_lab.ground_truth)
    assert score.false_positives == 0


def test_engine_confirms_both_blogment_bugs_model_free(blogment_lab):
    engine, ctx = blogment_lab.engine()
    summary = engine.run()
    confirmed = [f for f in ctx.findings.all() if f.confidence == "confirmed"]
    cwes = {f.cwe for f in confirmed}
    assert {"CWE-79", "CWE-200"} <= cwes
    assert summary["pending"] == 0
    score = score_run("blogment", [asdict(f) for f in ctx.findings.all()],
                      blogment_lab.ground_truth)
    assert score.false_positives == 0


def test_first_party_leads_stand_on_their_own_fetch(trackr_lab):
    engine, _ = trackr_lab.engine()
    engine._round_recon()
    first_party = [l for l in engine._leads if l.trust == "first-party"]
    assert first_party, "recon must produce first-party leads (openapi/robots)"
    for lead in first_party:
        assert lead.crosscheck == "first-party" and lead.believed()


def test_tool_claim_leads_require_the_matrix_second_method(trackr_lab):
    engine, ctx = trackr_lab.engine()
    lead = Lead(kind="path", url="/smuggled", source_tool="content_discovery",
                claim="ffuf saw /smuggled", trust="tool-claim")
    # crosscheck_lead runs the matrix second method; an unverifiable claim
    # must NOT advance to a workflow
    ok = engine._crosscheck(lead)
    assert lead.crosscheck == "unverifiable" and ok is False


def test_harvester_reads_both_real_leak_shapes():
    # "Authorization: Bearer <value>" has no key: value separator at all...
    cands = extract_candidates("Auth: Bearer tok-ops-551f (see runbook)")
    assert any(c.value == "tok-ops-551f" for c in cands)
    # ...and prefixed labels ("internal_token") defeat a bare \btoken\b
    cands = extract_candidates('{"internal_token": "tok-int-77"}')
    assert any(c.value == "tok-int-77" for c in cands)


def test_engine_never_needs_a_model():
    # the whole point: the engine IS the offense when the model is absent
    src = (REPO / "redteam" / "offensive.py").read_text()
    assert "build_llm_client" not in src
    assert "OpenRouterClient" not in src

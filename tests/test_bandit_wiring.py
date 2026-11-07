"""Tests for the multi-gambit wiring (docs/multi-gambit.md §3.4, §4.1):

- cost-aware claim ordering + per-round NoiseBudget in the exploit swarm,
- the per-round bandit.state learned broadcast,
- the federation sync handler (foreign merges, own/garbage skipped),
- the OPSEC cost table and BanditStore select()/export_state() extensions.
"""

from __future__ import annotations

import threading

from redteam.attack_tree import (
    FAILED, TECHNIQUES, TECHNIQUE_COST, AttackTree, technique_cost,
)
from redteam.bandit import BanditStore, make_sync_handler
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.orchestrator import NoiseBudget, Orchestrator
from redteam.findings import FindingStore
from redteam.llm.openrouter import ChatResult
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext

import datetime as _dt


# -- local fakes (mirrors test_orchestrator.py; self-contained on purpose) ---------

class RecordingAudit:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def record(self, event, **f):
        with self._lock:
            self.events.append({"event": event, **f})

    def read_all(self):
        with self._lock:
            return list(self.events)


class FakeClient:
    """No-tool-call assistant message: each specialist run ends immediately, so a
    swarm worker that claims a node finds nothing and marks it FAILED — which is
    exactly what feeds bandit.record() losses."""

    def chat(self, messages, tools=None, role="plan"):
        return ChatResult(model="fake", message={"role": "assistant", "content": "done"},
                          finish_reason="stop", usage={})


class FakeBus:
    """Minimal EventBus stand-in: records emissions, no sinks. run_id present so
    orchestrator's bandit.state source and the sync handler see the real shape."""

    def __init__(self, run_id="run-wiring-test"):
        self.run_id = run_id
        self.events = []
        self._lock = threading.Lock()

    def emit(self, type, **fields):
        with self._lock:
            self.events.append({"type": type, **fields})

    def subscribe(self, fn):
        pass


def _engagement():
    return Engagement(name="t", client="c", authorized_by="a", ticket="r",
                      starts=_dt.date.today() - _dt.timedelta(days=1),
                      ends=_dt.date.today() + _dt.timedelta(days=1),
                      allowed_hosts=("api.acme.example",), excluded_hosts=(),
                      allowed_ports=(443,), allowed_schemes=("https",),
                      max_requests_per_second=100.0, max_total_requests=1000,
                      allow_private_ranges=False, require_approval_for=(),
                      llm=LlmConfig(), sandbox=SandboxConfig(), raw={})


def _ctx(tmp_path, audit, bus=None):
    eng = _engagement()
    return ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [(2, 1, 6, "", ("203.0.113.5", 0))]),
                       limiter=RateLimiter(100, 1000), audit=audit,
                       findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                       graph=KnowledgeGraph(tmp_path / "g.json"), events=bus)


def _seeded_tree(tmp_path, bandit, url="https://api.acme.example/api/items/7"):
    graph = KnowledgeGraph()
    graph.observe(ENDPOINT, url)
    tree = AttackTree(bandit=bandit)
    tree.sync(graph=graph)
    return tree


# -- BanditStore.select: meta passthrough ---------------------------------------------

def test_select_maps_meta_back_onto_ranked_items():
    store = BanditStore()
    for _ in range(10):
        store.record("access.idor", "generic", won=True)
    nodes = {"idor": object(), "xss": object()}
    ranked = store.select([
        ("access.idor", "generic", 2.0, nodes["idor"]),
        ("xss.reflected", "generic", 1.0, nodes["xss"]),
    ], k=2)
    assert len(ranked) == 2
    assert {r["meta"] for r in ranked} == set(nodes.values())
    # ranked best-first
    assert ranked[0]["score"] >= ranked[1]["score"]


def test_select_three_tuples_still_work_without_meta():
    store = BanditStore()
    ranked = store.select([("ssrf", "generic", 1.0)], k=1)
    assert len(ranked) == 1
    assert "meta" not in ranked[0]
    assert ranked[0]["technique"] == "ssrf"


# -- BanditStore.export_state: min_trials filter ---------------------------------------

def test_export_state_min_trials_drops_zero_trial_arms():
    store = BanditStore()
    store.sample("ssrf", "generic")            # sampling alone: zero-trial arm
    store.record("xss.reflected", "generic", won=True)
    assert any(a["technique"] == "ssrf" for a in store.export_state())
    evidence_only = store.export_state(min_trials=1)
    assert [a["technique"] for a in evidence_only] == ["xss.reflected"]


# -- OPSEC cost table -------------------------------------------------------------------

def test_technique_cost_table_covers_every_technique():
    missing = [tid for tid in TECHNIQUES if tid not in TECHNIQUE_COST]
    assert not missing, f"costs missing for: {missing}"
    assert technique_cost("no.such.technique") == 1.0   # unknown defaults to quiet


def test_technique_cost_loudness_ordering_is_sane():
    # bulk data movement is the loudest thing a web engagement does
    assert technique_cost("data.exfil") > technique_cost("xss.reflected")
    # multi-probe injection is louder than a single unauth request
    assert technique_cost("injection.sqli") > technique_cost("access.control")


# -- NoiseBudget -------------------------------------------------------------------------

def test_noise_budget_spend_refund_and_exhaustion():
    b = NoiseBudget(3.0)
    assert b.try_spend(2.0)
    assert b.remaining == 1.0
    assert not b.try_spend(2.0)          # doesn't fit the remainder
    assert b.try_spend(1.0)              # exactly fits
    assert not b.try_spend(0.5)          # exhausted
    b.refund(2.0)
    assert b.remaining == 2.0
    b.refund(999)                        # refund can never mint budget
    assert b.remaining == 3.0


def test_noise_budget_concurrent_spends_never_oversell():
    b = NoiseBudget(10.0)
    won = []
    lock = threading.Lock()

    def worker():
        if b.try_spend(1.0):
            with lock:
                won.append(1)

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 10                # exactly the budget, never more
    assert b.remaining == 0.0


# -- AttackTree.bandit accessor -----------------------------------------------------------

def test_attack_tree_exposes_bandit_readonly():
    assert AttackTree().bandit is None
    store = BanditStore()
    assert AttackTree(bandit=store).bandit is store


# -- swarm: per-round noise budget ---------------------------------------------------------

def _run_two_rounds(tmp_path, bandit, noise_budget, workers=3):
    audit = RecordingAudit()
    bus = FakeBus()
    ctx = _ctx(tmp_path, audit, bus=bus)
    tree = _seeded_tree(tmp_path, bandit)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, attack_tree=tree, memory=None,
                        max_exploit_rounds=2, noise_budget=noise_budget)
    orch.run("prove something on the app")
    return audit, bus


def test_swarm_never_exceeds_round_noise_budget(tmp_path):
    """Entry techniques on one endpoint cost 1-4 noise credits each; a 2.0 budget
    must cap every round's total claim spend no matter how Thompson ranked them."""
    bandit = BanditStore()
    audit, bus = _run_two_rounds(tmp_path, bandit, noise_budget=2.0)
    claims = [e for e in bus.events if e["type"] == "swarm.claim"]
    assert claims, "swarm should have claimed at least one node"
    by_round = {}
    for c in claims:
        by_round.setdefault(c["round"], []).append(c)
    for rnd, round_claims in by_round.items():
        spent = sum(technique_cost(c["technique"]) for c in round_claims)
        assert spent <= 2.0 + 1e-9, f"round {rnd} spent {spent} > budget"


def test_swarm_skips_gambit_that_never_fits_the_budget(tmp_path):
    """access.control costs 2.0; with a 1.5 round budget it can NEVER be claimed,
    even when its posterior dominates — the budget is a hard cap, not a preference.
    Cheaper arms still get claimed."""
    bandit = BanditStore()
    for _ in range(25):
        bandit.record("access.control", "generic", won=True)   # dominant, loud
    audit, bus = _run_two_rounds(tmp_path, bandit, noise_budget=1.5)
    events = [e for e in bus.events if e["type"] == "swarm.claim"]
    assert events, "cheap gambits should still be claimed"
    assert all(e["technique"] != "access.control" for e in events)
    quiet_claimed = [e for e in events if technique_cost(e["technique"]) <= 1.0]
    assert quiet_claimed


def test_swarm_emits_bandit_state_each_round(tmp_path):
    bandit = BanditStore()
    audit, bus = _run_two_rounds(tmp_path, bandit, noise_budget=2.0)
    states = [e for e in bus.events if e["type"] == "bandit.state"]
    assert states, "each exploit round should broadcast learned state"
    assert states[0]["source"] == bus.run_id
    # claims were marked FAILED (FakeClient finds nothing) -> real trials exist.
    # ArmState serializes its fields (alpha/beta); trials is a derived property,
    # so evidence = alpha+beta-2 — every broadcast arm must carry at least one.
    arms = states[0]["arms"]
    assert isinstance(arms, list) and len(arms) >= 1
    assert all((a["alpha"] + a["beta"] - 2) >= 1 for a in arms)


def test_noise_budget_resets_each_round(tmp_path):
    """'Per-round' is the documented contract (RunOptions.round_noise_budget): a
    budget round 0 exhausts must be whole again in round 1, or the swarm stops
    exploring after its first round (caught by the 2026-10-30 product E2E:
    12 rounds started, only round 0 ever claimed)."""
    bandit = BanditStore()
    audit, bus = _run_two_rounds(tmp_path, bandit, noise_budget=1.0)
    by_round = {}
    for c in (e for e in bus.events if e["type"] == "swarm.claim"):
        by_round.setdefault(c["round"], []).append(c)
    assert by_round, "swarm should claim at all"
    later = max(by_round)
    assert later >= 1 and by_round.get(later), \
        f"later rounds starved — budget never reset: claims in rounds {sorted(by_round)}"
    for rnd, cl in by_round.items():
        spent = sum(technique_cost(c["technique"]) for c in cl)
        assert spent <= 1.0 + 1e-9, f"round {rnd} spent {spent} > budget"


def test_remarking_a_terminal_state_does_not_double_feed_the_bandit(tmp_path):
    """sync() runs on EVERY agent turn with the full findings list, so a confirmed
    finding whose node is already COMPLETED must not record the same win again —
    one hypothesis, one trial. Without mark()'s idempotency guard, every worker
    turn after a confirmation inflates the posterior (reward hacking by replay)."""
    bandit = BanditStore()
    tree = AttackTree(bandit=bandit)
    finding = {"confidence": "confirmed", "cwe": "CWE-89",
               "target": "https://api.acme.example/api/items"}

    def total_wins():
        return sum(float(a.get("obs_wins", 0) or 0) for a in bandit.export_state())

    tree.sync(findings=[finding])       # promote + record once
    tree.sync(findings=[finding])       # same confirmation replayed next turn
    tree.sync(findings=[finding])
    tree.confirm("injection.sqli", "https://api.acme.example/api/items")
    assert total_wins() == 1.0, f"wins inflated to {total_wins()}"
    # A genuinely new trial still records: FAILED after TODO is a fresh outcome.
    tree.mark("injection.sqli", "https://api.acme.example/api/other", FAILED)
    losses = sum(float(a.get("obs_losses", 0) or 0) for a in bandit.export_state())
    assert losses == 1.0


# -- federation sync handler ----------------------------------------------------------------

def test_sync_handler_merges_foreign_skips_own_and_garbage():
    store = BanditStore()
    handler = make_sync_handler(store, own_source="run-a")

    handler({"type": "bandit.state", "source": "run-b",
             "arms": [{"technique": "ssrf", "bucket": "generic",
                       "alpha": 9.0, "beta": 1.0}]})
    arm = store._get("ssrf", "generic")
    assert arm.trials == 8 and arm.mean > 0.8

    before = (arm.alpha, arm.beta)
    handler({"type": "bandit.state", "source": "run-a",        # own broadcast
             "arms": [{"technique": "ssrf", "bucket": "generic",
                       "alpha": 9.0, "beta": 1.0}]})
    handler({"type": "other.event", "source": "run-b", "arms": []})
    handler({"type": "bandit.state", "source": "", "arms": []})  # no source
    handler({"type": "bandit.state", "source": "run-b", "arms": 42})
    handler({"type": "bandit.state", "source": "run-b"})         # no arms
    handler("garbage")
    handler(None)
    handler(42)
    assert (store._get("ssrf", "generic").alpha,
            store._get("ssrf", "generic").beta) == before


def test_sync_handler_never_raises_on_hostile_payload():
    store = BanditStore()
    handler = make_sync_handler(store, own_source="me")
    hostile = [
        {"type": "bandit.state", "source": "peer", "arms": [{"technique": None}]},
        {"type": "bandit.state", "source": "peer", "arms": [None]},
        {"type": "bandit.state", "source": "peer", "arms": "not-a-list"},
        {"type": "bandit.state", "source": "peer", "arms": [{"alpha": "x", "beta": [], "bucket": ()}]},
    ]
    for ev in hostile:
        handler(ev)   # must not raise
    # and the store still works normally afterwards
    store.record("ssrf", "generic", won=True)
    assert store._get("ssrf", "generic").trials == 1


def test_merging_the_same_blob_twice_pools_nothing():
    """Re-broadcast dedupe is the STORE's job now (delta pooling): the same
    snapshot merged twice must count its evidence once, not twice."""
    store = BanditStore()
    blob = [{"technique": "ssrf", "bucket": "generic", "alpha": 9.0, "beta": 1.0}]
    assert store.merge_state(blob, source="run-b") == 1
    a1 = (store._get("ssrf", "generic").alpha, store._get("ssrf", "generic").beta)
    assert store.merge_state(blob, source="run-b") == 0
    a2 = (store._get("ssrf", "generic").alpha, store._get("ssrf", "generic").beta)
    assert a1 == a2 == (9.0, 1.0), f"double-pooled: {a1} -> {a2}"


def test_cumulative_round_broadcasts_pool_exactly_once():
    """The product E2E of 2026-10-30 caught this: export_state is a CUMULATIVE
    snapshot and the orchestrator broadcasts it every round, so additive merging
    inflated peer evidence quadratically in rounds (a run whose arm held 8 real
    losses had pooled 44 into a live peer after 12 rounds). Delta pooling must
    telescope: after N growing snapshots the peer holds exactly the last one."""
    store = BanditStore()
    # a peer's arm losing one more trial per round: beta 2,3,4,5,6 over 5 rounds
    for rnd in range(1, 6):
        blob = [{"technique": "injection.sqli", "bucket": "generic",
                 "alpha": 1.0, "beta": 1.0 + rnd}]
        store.merge_state(blob, source="run-b")
    arm = store._get("injection.sqli", "generic")
    assert (arm.alpha, arm.beta) == (1.0, 6.0), \
        f"cumulative double-count: alpha={arm.alpha} beta={arm.beta}"
    assert float(arm.obs_losses) == 5.0
    # a second, independent source pooling the same trajectory still adds its own
    store.merge_state([{"technique": "injection.sqli", "bucket": "generic",
                        "alpha": 1.0, "beta": 3.0}], source="run-c")
    arm = store._get("injection.sqli", "generic")
    assert (arm.alpha, arm.beta) == (1.0, 8.0)
    # and a REWOUND peer (reset state) contributes nothing rather than negative
    store.merge_state([{"technique": "injection.sqli", "bucket": "generic",
                        "alpha": 1.0, "beta": 1.5}], source="run-c")
    arm = store._get("injection.sqli", "generic")
    assert (arm.alpha, arm.beta) == (1.0, 8.0)


# -- Phase A4: DriftPlusPenaltyScheduler --------------------------------------------------

import io
import time as _time

from redteam.orchestrator import DriftPlusPenaltyScheduler
from redteam.sandbox.detection_belief import DetectionBelief
from redteam.tools import http as _http_mod


class _FakeRaw:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, n, decode_content=True):
        return self._payload[:n]


class _FakeResp:
    def __init__(self, payload: bytes, status=200, headers=None):
        self.raw, self.status_code, self.encoding, self.headers = (
            _FakeRaw(payload), status, "utf-8", headers or {})


def _sched(total=12.0, belief=None, mu=None, v=None):
    return DriftPlusPenaltyScheduler(total, belief_filter=belief, mu=mu, v_dial=v)


def _items(pairs):
    """Bandit.select-shaped items: score IS the progress-per-cost estimate."""
    return [{"technique": f"t{i}", "bucket": "generic", "cost": c,
             "draw": p, "score": p, "meta": object()}
            for i, (c, p) in enumerate(pairs)]


def test_alias_preserves_the_noisebudget_import_surface():
    """Every existing caller (tests, specialists.py docs) keeps importing
    NoiseBudget; it is the scheduler now, with the same spend semantics."""
    from redteam.orchestrator import NoiseBudget as Aliased
    assert Aliased is DriftPlusPenaltyScheduler
    b = DriftPlusPenaltyScheduler(3.0)
    assert b.try_spend(2.0) and not b.try_spend(2.0) and b.try_spend(1.0)
    assert not b.try_spend(0.5)
    b.refund(2.0)
    assert b.remaining == 2.0
    b.refund(999)
    assert b.remaining == 3.0


def test_at_quiet_belief_the_fill_order_is_the_bandit_order():
    """Q ~ 0: score = -V * progress = -V * (draw/cost) -> exactly the old
    cost-aware bandit ordering, and every positive-progress candidate is
    admitted (the old greedy knapsack behavior)."""
    ranked = _items([(5.0, 0.10), (1.0, 0.60), (3.0, 0.50), (2.0, 0.80)])
    bandit_order = [it["technique"] for it in sorted(ranked, key=lambda x: -x["score"])]
    s = _sched(50.0)                        # quiet: fresh scheduler, no belief
    assert s.q_value == 0.0
    re_ranked = s.rank_bandit_items(ranked)
    assert [it["technique"] for it in re_ranked] == bandit_order
    for it in re_ranked:                    # admission gate passes at Q=0
        assert s.try_spend(it["cost"], progress=it["progress"])


def test_ties_keep_the_producer_order():
    """Two candidates with identical score/cost: the stable sort must keep the
    bandit's own order (the old fill order's tie-breaking convention)."""
    a, b = object(), object()
    ranked = [{"technique": "first", "bucket": "g", "cost": 2.0, "draw": 0.5,
               "score": 0.25, "meta": a},
              {"technique": "second", "bucket": "g", "cost": 2.0, "draw": 0.5,
               "score": 0.25, "meta": b}]
    out = _sched(50.0).rank_bandit_items(ranked)
    assert [it["meta"] for it in out] == [a, b]


def _spend_round(sched, pairs):
    """One scheduler round: reset (closes the Lyapunov recursion), then admit
    the fixed candidate set in scheduler order. Returns the round's spend."""
    sched.reset()
    ordered = sched.rank_bandit_items(_items(pairs))
    return sum(it["cost"] for it in ordered
               if sched.try_spend(it["cost"], progress=it["progress"]))


def _fixed_belief(risk):
    class _Fixed:
        def risk_score(self):
            return risk
    return _Fixed()


def test_high_belief_throttles_the_same_candidate_set():
    """Same candidates, same allowance: a post-challenge belief (risk 0.9 ->
    Q = 0.9 * 12 = 10.8) must spend strictly less than a quiet round."""
    pairs = [(1.0, 0.7), (2.0, 0.7), (3.0, 0.8), (5.0, 0.9)]
    quiet = _spend_round(_sched(12.0), pairs)
    throttled = _spend_round(_sched(12.0, belief=_fixed_belief(0.9)), pairs)
    assert quiet == 11.0                    # everything admitted
    assert throttled < quiet                # visibly throttled


def test_certain_blocked_belief_skips_the_round_entirely():
    pairs = [(1.0, 0.7), (2.0, 0.7), (3.0, 0.8), (5.0, 0.9)]
    assert _spend_round(_sched(12.0, belief=_fixed_belief(1.0)), pairs) == 0.0


def test_high_q_prefers_cheap_techniques_in_the_fill_order():
    """Equal progress, different price: at Q=0 the tie keeps the producer's
    order, but as Q rises the score Q*cost - V*progress separates them — the
    expensive arm falls behind and fails the admission gate first."""
    pairs = [(2.0, 0.5), (1.0, 0.5)]        # same progress, loud costs double
    s = _sched(12.0)
    low_q = [it["technique"] for it in s.rank_bandit_items(_items(pairs))]
    s2 = _sched(12.0, belief=_fixed_belief(4.0 / 12.0))   # Q = 4
    high_q = [it["technique"] for it in s2.rank_bandit_items(_items(pairs))]
    admitted = [it["technique"] for it in s2.rank_bandit_items(_items(pairs))
                if s2.try_spend(it["cost"], progress=it["progress"])]
    assert low_q == ["t0", "t1"]            # Q=0: tie, producer order kept
    assert high_q == ["t1", "t0"]           # Q>0: cheap-first
    assert admitted == ["t1"]               # loud arm gated, quiet arm bought


def test_stealth_dial_v_is_monotonic_at_fixed_belief():
    """Higher V = more willing to spend at the same Q: admitted spend must be
    non-decreasing across a V sweep (monotonic relationship, not exact pins)."""
    pairs = [(1.0, 0.6), (2.0, 0.7), (3.0, 0.8), (5.0, 0.9)]
    spends = [_spend_round(_sched(12.0, belief=_fixed_belief(0.5), v=v), pairs)
              for v in (2.0, 5.0, 10.0, 20.0, 50.0)]
    assert spends == sorted(spends)         # non-decreasing in V
    assert spends[0] < spends[-1]           # and the dial actually moves spend


def test_lyapunov_accumulator_follows_the_recursion_and_drains_at_mu():
    """Q(t+1) = max(Q(t) + spent - mu, 0), capped at SCALE."""
    s = _sched(12.0, mu=2.0)
    s.reset()
    assert s.try_spend(5.0, progress=1.0)   # round spends 5
    s.reset()                               # Q = max(0 + 5 - 2, 0) = 3
    assert s.raw_q == 3.0
    s.reset()                               # quiet round: Q = max(3 + 0 - 2, 0) = 1
    assert s.raw_q == 1.0
    s.reset()                               # Q = 0
    assert s.raw_q == 0.0


def test_accumulator_is_capped_at_scale():
    """The recursion Q(t+1) = max(Q(t) + arrivals - mu, 0), capped at SCALE;
    spends here bypass the admission gate (progress=None) to isolate it."""
    s = _sched(12.0, mu=0.5)
    s.reset()
    s.try_spend(12.0)                       # allowance-only: gate not engaged
    s.reset()                               # max(0 + 12 - 0.5, 0) = 11.5
    assert s.raw_q == 11.5
    s.try_spend(12.0)
    s.reset()                               # min(max(11.5 + 12 - 0.5, 0), 12) = 12
    assert s.raw_q == 12.0                  # capped, never runs away


def test_refunded_reservations_never_reach_the_accumulator():
    """A lost claim race refunds the reservation — the round never 'arrived'
    for the Lyapunov recursion, so Q must not grow from phantom spends."""
    s = _sched(12.0, mu=2.0)
    s.reset()
    assert s.try_spend(5.0, progress=1.0)
    s.refund(5.0)
    s.reset()
    assert s.raw_q == 0.0                   # spent - refunded = 0 arrivals


def test_belief_blend_dominates_the_accumulator_in_both_directions():
    """Q(t) = max(raw, risk * SCALE): a challenge spikes Q instantly on a
    fresh accumulator, and a hot accumulator ignores a calm belief."""
    s = _sched(12.0, belief=_fixed_belief(0.8))
    assert s.q_value == 0.8 * 12.0          # belief pushes Q up fast (raw = 0)
    s2 = _sched(12.0, belief=_fixed_belief(0.05))
    s2._raw = 9.0
    assert s2.q_value == 9.0                # accumulator keeps its floor


def test_zero_progress_candidates_are_never_bought():
    s = _sched(12.0)
    assert not s.try_spend(1.0, progress=0.0)
    assert s.try_spend(1.0, progress=0.01)  # any positive progress clears at Q=0


def test_orchestrator_wires_the_belief_filter_into_the_shared_ctx(tmp_path):
    """Phase A4 wiring: a budgeted Orchestrator attaches ONE DetectionBelief to
    the ToolContext and hands it to the scheduler; mu/V flow from the call."""
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, attack_tree=None, memory=None,
                        noise_budget=12.0, noise_decay_mu=4.0, stealth_speed_dial=20.0)
    assert isinstance(ctx.detection_belief, DetectionBelief)
    assert orch._noise is not None
    assert orch._noise.belief_filter is ctx.detection_belief
    assert orch._noise.mu == 4.0
    assert orch._noise.v_dial == 20.0
    assert orch._noise._scale == 12.0       # SCALE = round budget


def test_orchestrator_without_budget_stays_pure_legacy(tmp_path):
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit)
    Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                 graph=ctx.graph, attack_tree=None, memory=None, noise_budget=None)
    assert not hasattr(ctx, "detection_belief")


# -- Phase A4 end-to-end: HTTP observations -> belief -> scheduler spend --------

def test_http_challenge_window_throttles_scheduler_and_recovers(tmp_path, monkeypatch):
    """The full loop: responses through tools/http.py's observation hook teach
    the belief; the scheduler's round-level spend drops during the challenge
    window and recovers after the target returns to normal.

    Timeline: two quiet rounds (spend 3.0 each), two challenge rounds (spend 0),
    one recovery round (spend 3.0 again). The quiet candidates sum to 3.0 < mu
    ramp so the raw accumulator alone never gates a quiet round — the throttle
    under test is the BELIEF's."""
    audit = RecordingAudit()
    bus = FakeBus()
    # The default _ctx resolver answers with a reserved documentation IP, which
    # the scope guard (rightly) refuses for REAL fetches; this E2E fetches, so
    # it resolves the same host to a public address instead.
    eng = _engagement()
    ctx = ToolContext(scope=ScopeGuard(eng, resolver=lambda h, p: [
                          (2, 1, 6, "", ("93.184.216.34", 0))]),
                      limiter=RateLimiter(100, 1000), audit=audit,
                      findings=FindingStore(tmp_path / "f.json"), approve=lambda a, d: True,
                      graph=KnowledgeGraph(tmp_path / "g.json"), events=bus)
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, attack_tree=None, memory=None,
                        noise_budget=12.0, noise_decay_mu=2.0, stealth_speed_dial=10.0)
    sched = orch._noise
    belief = ctx.detection_belief

    mode = {"kind": "normal"}

    def fake_request(method, url, headers=None, data=None, timeout=20,
                     allow_redirects=False, stream=True):
        if mode["kind"] == "challenge":
            _time.sleep(0.03)               # tarpit-slow vs the ~1ms baseline
            return _FakeResp(b"Attention Required - solve the captcha",
                             status=403, headers={"cf-mitigated": "challenge",
                                                  "Retry-After": "60"})
        return _FakeResp(b"ok")

    monkeypatch.setattr(_http_mod.requests, "request", fake_request)
    url = {"url": "https://api.acme.example/api/items/7", "method": "GET"}

    def fetch(kind):
        mode["kind"] = kind
        _http_mod.fetch_once(ctx, url)

    for _ in range(3):
        fetch("normal")                     # establish the latency baseline

    quiet_pairs = [(1.0, 0.7), (1.0, 0.8), (1.0, 0.9)]

    def spend_round():
        sched.reset()
        ordered = sched.rank_bandit_items(_items(quiet_pairs))
        return sum(it["cost"] for it in ordered
                   if sched.try_spend(it["cost"], progress=it["progress"]))

    spends = []
    spends.append(spend_round())            # round 0: quiet -> full spend
    fetch("normal"); fetch("normal")
    spends.append(spend_round())            # round 1: still quiet -> full spend
    fetch("challenge"); fetch("challenge")  # the target starts fighting back
    assert belief.risk_score() > 0.5        # the hook actually moved the belief
    spends.append(spend_round())            # round 2: challenge window -> 0
    fetch("challenge"); fetch("challenge")
    spends.append(spend_round())            # round 3: still challenged -> 0
    for _ in range(4):
        fetch("normal")                     # the defender cools down
    spends.append(spend_round())            # round 4: recovery -> full spend

    assert spends[0] == 3.0 and spends[1] == 3.0
    assert spends[2] == 0.0 and spends[3] == 0.0
    assert spends[4] == 3.0
    assert spends[2] < spends[0] and spends[4] > spends[3]

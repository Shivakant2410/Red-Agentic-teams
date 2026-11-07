"""Tests for the multi-gambit wiring (docs/multi-gambit.md §3.4, §4.1):

- cost-aware claim ordering + per-round NoiseBudget in the exploit swarm,
- the per-round bandit.state learned broadcast,
- the federation sync handler (foreign merges, own/garbage skipped),
- the OPSEC cost table and BanditStore select()/export_state() extensions,
- Phase B3: the DriftPlusPenaltyScheduler (Q recursion, POMDP blend, throttling,
  V sweep monotonicity, zero-pressure parity with the legacy knapsack order) and
  the swarm's end-to-end response to a synthetic challenge window.
"""

from __future__ import annotations

import random
import threading

import pytest

from redteam.attack_tree import (
    FAILED, TECHNIQUES, TECHNIQUE_COST, AttackTree, technique_cost,
)
from redteam.bandit import BanditStore, make_sync_handler
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.knowledge import ENDPOINT, KnowledgeGraph
from redteam.orchestrator import DriftPlusPenaltyScheduler, NoiseBudget, Orchestrator
from redteam.findings import FindingStore
from redteam.llm.openrouter import ChatResult
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.tools import ToolContext
from redteam.tools.http import observe_response as http_observe_response

import datetime as _dt


class FixedBelief:
    """BeliefFilter stand-in with a controllable risk_score — isolates the
    scheduler's POMDP blend from the HMM itself (which test_detection_belief.py
    covers against its own spec)."""

    def __init__(self, risk: float = 0.0):
        self.risk = float(risk)

    def risk_score(self) -> float:
        return self.risk


class StubBandit:
    """BanditStore stand-in returning FIXED Thompson draws — makes the scheduler's
    score(a) = Q*cost - V*progress hand-checkable without seeding randomness."""

    def __init__(self, draws: dict[str, float]):
        self._draws = dict(draws)

    def sample(self, technique: str, bucket: str) -> float:
        return self._draws[technique]


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


# -- Phase B3: DriftPlusPenaltyScheduler --------------------------------------------------
#
# NoiseBudget's name stays as an alias (every existing caller/test keeps working);
# the behavior below is what the replacement ADDS on top of the unchanged
# accounting contract the tests above already pin.

def test_noise_budget_name_is_the_scheduler():
    """The alias is the contract: NoiseBudget's public interface survives the
    Phase B3 swap identically for every existing caller."""
    assert NoiseBudget is DriftPlusPenaltyScheduler
    b = NoiseBudget(3.0)                       # legacy positional construction
    assert b.can_afford(3.0) and not b.can_afford(3.01)
    assert b.try_spend(3.0) and b.remaining == 0.0


def test_q_recursion_advances_on_spend_and_unwinds_on_refund():
    s = DriftPlusPenaltyScheduler(10.0, mu=2.0)
    assert s.q_effective() == 0.0
    assert s.try_spend(5.0)                    # loud claim: Q = max(0 + 5 - 2, 0)
    assert s.q_effective() == 3.0
    assert s.try_spend(1.0)                    # quiet claim: Q = max(3 + 1 - 2, 0)
    assert s.q_effective() == 2.0
    s.refund(1.0)                              # lost claim race: pressure unwinds too
    assert s.q_effective() == 3.0
    s.refund(5.0)                              # and the loud one unwinds back to zero
    assert s.q_effective() == 0.0


def test_q_effective_blends_belief_over_raw_queue():
    belief = FixedBelief(risk=0.5)
    s = DriftPlusPenaltyScheduler(12.0, belief=belief, scale=4.0)
    assert s.q_effective() == 2.0              # 0.5 * SCALE, over a raw queue of 0
    s.try_spend(5.0)                           # raw queue = 3 — now the larger side
    assert s.q_effective() == 3.0
    belief.risk = 1.0                          # challenge burst: belief overrides
    assert s.q_effective() == 4.0
    # a BROKEN belief must degrade to raw-queue-only, never block the swarm
    class Exploding:
        def risk_score(self):
            raise RuntimeError("boom")
    s2 = DriftPlusPenaltyScheduler(12.0, belief=Exploding())
    s2.try_spend(3.0)
    assert s2.q_effective() == 1.0             # mu=2: max(0 + 3 - 2, 0)


def test_reset_under_pressure_withholds_budget_but_never_mints_it():
    # Regression for the hard-cap contract: with total < mu the mu floor must NOT
    # inflate the allowance past the total (round budget is a ceiling, always).
    s = DriftPlusPenaltyScheduler(1.0, mu=2.0)
    s.reset()
    assert s.remaining == 1.0
    # Pressure withholds one-for-one: two loud claims owe 6 credits of queue.
    s2 = DriftPlusPenaltyScheduler(12.0, mu=2.0)
    s2.try_spend(5.0)
    s2.try_spend(5.0)
    assert s2.q_effective() == 6.0
    s2.reset()
    assert s2.remaining == 6.0
    # Belief-driven pressure withholds the same way (risk 1.0 * scale 4 = 4).
    s3 = DriftPlusPenaltyScheduler(12.0, belief=FixedBelief(1.0), scale=4.0)
    s3.reset()
    assert s3.remaining == 8.0
    # Extreme pressure floors at mu (the swarm can always afford one sustainable
    # claim), and never goes above the total.
    s4 = DriftPlusPenaltyScheduler(12.0, mu=2.0, belief=FixedBelief(1.0), scale=50.0)
    s4.reset()
    assert s4.remaining == 2.0


def _greedy_fill(sched: DriftPlusPenaltyScheduler, candidates) -> float:
    """The swarm's fill shape: walk the ranked list, spend what fits, skip the
    rest (the knapsack the scheduler replaced, now driven by its ranking)."""
    spent = 0.0
    for item in sched.rank(candidates):
        if sched.try_spend(item["cost"]):
            spent += item["cost"]
    return spent


def test_high_pressure_round_spends_less_than_low_pressure_round():
    """The phase's throttling requirement: SAME candidate set, a high-Q round's
    total spend is strictly below a low-Q round's. reset() first — the swarm
    always starts a round there, and the throttle lives in the reset allowance."""
    candidates = [("quiet.a", "generic", 1.0), ("quiet.b", "generic", 1.0),
                  ("mid.a", "generic", 2.0), ("mid.b", "generic", 2.0),
                  ("loud.a", "generic", 4.0), ("loud.b", "generic", 4.0)]
    low = DriftPlusPenaltyScheduler(12.0)                       # fresh: Q = 0
    low.reset()
    spent_low = _greedy_fill(low, candidates)
    high = DriftPlusPenaltyScheduler(12.0, belief=FixedBelief(1.0), scale=4.0)
    high.reset()                                                # allowance 12 - 4
    spent_high = _greedy_fill(high, candidates)
    assert spent_low > spent_high                               # visible throttling
    assert spent_high <= 8.0 + 1e-9                             # 12 - risk*SCALE
    assert spent_high > 0.0                                     # throttled, not paralyzed


def test_zero_pressure_rank_matches_legacy_bandit_select_order():
    """Q=0 must BE the legacy behavior: with a fixed seed the scheduler's ranking
    is exactly BanditStore.select's yield-per-cost order (same draws, same order),
    which is what the old greedy knapsack walked."""
    store = BanditStore()
    for _ in range(6):
        store.record("access.idor", "generic", won=True)
    for _ in range(3):
        store.record("injection.sqli", "generic", won=False)
    nodes = {f"n{i}": object() for i in range(6)}
    candidates = [("access.idor", "generic", 2.0, nodes["n0"]),
                  ("injection.sqli", "generic", 3.0, nodes["n1"]),
                  ("xss.reflected", "generic", 1.0, nodes["n2"]),
                  ("auth.test", "generic", 1.0, nodes["n3"]),
                  ("ssrf", "generic", 2.0, nodes["n4"]),
                  ("info.sensitive", "generic", 1.0, nodes["n5"])]
    random.seed(20261108)
    legacy = store.select(candidates, k=len(candidates))
    random.seed(20261108)
    sched = DriftPlusPenaltyScheduler(12.0, bandit=store)       # fresh: Q = 0
    ranked = sched.rank(candidates)
    assert [i["technique"] for i in ranked] == [i["technique"] for i in legacy]
    # meta rides through exactly like select()'s passthrough — same objects, same order
    assert [i["meta"] for i in ranked] == [i["meta"] for i in legacy]


def test_v_sweep_moves_high_progress_arms_up_monotonically():
    """The phase's V-sweep requirement, without pinning numbers: as V rises the
    progress of the top-ranked arm is non-decreasing (the yield term buys back
    loudness monotonically), under fixed nonzero pressure."""
    draws = {"loud.high": 0.9, "mid.mid": 0.5, "quiet.low": 0.1}
    candidates = [("loud.high", "generic", 5.0),
                  ("mid.mid", "generic", 2.0),
                  ("quiet.low", "generic", 1.0)]
    prev_top_progress = -1.0
    for V in (0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0):
        s = DriftPlusPenaltyScheduler(12.0, V=V, belief=FixedBelief(0.5), scale=4.0,
                                      bandit=StubBandit(draws))
        ranked = s.rank(candidates)
        top = ranked[0]
        assert top["progress"] >= prev_top_progress - 1e-9, \
            f"V={V}: top progress regressed ({top['progress']} < {prev_top_progress})"
        prev_top_progress = top["progress"]
        # score shape sanity at every V: Q*cost - V*progress
        for item in ranked:
            assert item["score"] == pytest.approx(
                2.0 * item["cost"] - V * item["progress"])
    # the sweep must actually end somewhere louder than it started (else the
    # sweep proves nothing — all V's agreeing with the quiet arm)
    assert prev_top_progress > draws["quiet.low"] - 1e-9


def test_rank_without_bandit_keeps_tree_order_at_zero_pressure():
    """No bandit, no pressure: constant progress, stable sort -> the tree's own
    priority order (the pre-bandit path's exact behavior)."""
    s = DriftPlusPenaltyScheduler(12.0)
    candidates = [("auth.test", "generic", 1.0), ("injection.cmd", "generic", 4.0),
                  ("access.control", "generic", 2.0)]
    assert [i["technique"] for i in s.rank(candidates)] == \
        ["auth.test", "injection.cmd", "access.control"]
    # under pressure the same candidates pivot cheap-first
    s2 = DriftPlusPenaltyScheduler(12.0, belief=FixedBelief(1.0), scale=4.0)
    assert [i["technique"] for i in s2.rank(candidates)] == \
        ["auth.test", "access.control", "injection.cmd"]


# -- Phase B3 e2e: the swarm throttles through a challenge window and recovers ----

class ScriptedObservationBus:
    """FakeBus that ALSO plays the defender: every swarm.claim is answered by one
    synthetic HTTP response pushed through tools/http.py's REAL observation hook,
    so the belief the scheduler reads is fed exactly the way live traffic feeds
    it (response return point -> ctx.detection). Scripted per round: round 0 =
    challenge window, later rounds = clean traffic."""

    def __init__(self, run_id="run-b3-e2e"):
        self.run_id = run_id
        self.events = []
        self._lock = threading.Lock()
        self.ctx = None                      # wired after ToolContext exists

    def emit(self, type, **fields):
        with self._lock:
            self.events.append({"type": type, **fields})
        if type == "swarm.claim" and self.ctx is not None:
            self._answer(fields)

    def subscribe(self, fn):
        pass

    def _answer(self, claim_fields):
        if claim_fields.get("round", 0) == 0:
            status, headers, body = 429, {"cf-mitigated": "challenge"}, \
                "Attention Required. Verify you are a human."
        else:
            status, headers, body = 200, {"content-type": "application/json"}, \
                '{"ok": true}'
        http_observe_response(self.ctx, {"url": claim_fields.get("target", ""),
                                         "method": "GET"},
                              status, 0.05, headers, body)


def test_swarm_throttles_through_a_challenge_window_and_recovers(tmp_path):
    """The phase's end-to-end requirement, over the real seams: synthetic HTTP
    normal -> challenge -> normal flows through the http.py observation hook into
    the POMDP, and the swarm's ROUND-LEVEL OPSEC SPEND drops during the challenge
    window and recovers once the traffic goes quiet again."""
    bus = ScriptedObservationBus()
    audit = RecordingAudit()
    ctx = _ctx(tmp_path, audit, bus=bus)
    bus.ctx = ctx                            # the defender answers on ctx.detection
    tree = _seeded_tree(tmp_path, BanditStore(), url="https://api.acme.example/api/items/7")
    orch = Orchestrator(_engagement(), tools={}, ctx=ctx, client=FakeClient(),
                        graph=ctx.graph, attack_tree=tree, memory=None,
                        max_exploit_rounds=3, noise_budget=12.0)
    orch.run("prove something on the app")

    claims = [e for e in bus.events if e["type"] == "swarm.claim"]
    by_round = {}
    for c in claims:
        by_round.setdefault(c["round"], []).append(c)
    assert set(by_round) >= {0, 1, 2}, f"expected 3 claim rounds: {sorted(by_round)}"
    spend = {rnd: sum(technique_cost(c["technique"]) for c in cl)
             for rnd, cl in by_round.items()}
    # every round stayed under the hard cap regardless of pressure
    for rnd, s in spend.items():
        assert s <= 12.0 + 1e-9, f"round {rnd} spent {s} > cap"
    # normal -> challenge: the throttle engages
    assert spend[1] < spend[0], \
        f"challenge window did not throttle: r0={spend[0]} r1={spend[1]}"
    # challenge -> normal: the allowance recovers (non-sticky, like the belief)
    assert spend[2] > spend[1], \
        f"no recovery after the window: r1={spend[1]} r2={spend[2]}"
    # the scheduler broadcast its state each round (observability seam)
    states = [e for e in bus.events if e["type"] == "scheduler.state"]
    assert len(states) >= 3
    assert all({"round", "q", "risk", "allowance"} <= set(e) for e in states)
    # the belief the round-1 reset saw was genuinely elevated, and round-2's was lower
    risk_by_round = {e["round"]: e["risk"] for e in states}
    assert risk_by_round[1] > 0.5
    assert risk_by_round[2] < risk_by_round[1]

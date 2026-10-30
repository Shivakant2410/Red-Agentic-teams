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

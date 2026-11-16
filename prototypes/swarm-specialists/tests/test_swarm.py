"""Phase C test suite — specialist swarm.

Unit layer : blackboard typing, memory bandit/skip/poisoning rules, router
             contract enforcement + stall termination, spawn depth limit,
             LLM seam fallback.
E2E layer  : full swarm engagement over real HTTP (fresh Flask target),
             end-to-end findings with provenance + verification stamps,
             cross-run improvement from persisted memory.
"""
import json
import os
import subprocess
import sys
import time

import pytest
import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from swarm.blackboard import Blackboard, Fact          # noqa: E402
from swarm.llm import LLMSeam                          # noqa: E402
from swarm.memory import MemoryNamespace               # noqa: E402
from swarm.router import Router                        # noqa: E402
from swarm.specialist import ContractViolation, Specialist, Trigger  # noqa: E402
from swarm.specialists import ROSTER                   # noqa: E402
from swarm.registry_tool import run                    # noqa: E402


# ------------------------------------------------------------ blackboard --
def test_fact_kinds_enforced():
    with pytest.raises(AssertionError):
        Fact.make("NOT-A-KIND", "x", {})


def test_blackboard_query_and_provenance():
    b = Blackboard()
    f1 = b.publish(Fact.make("OBSERVATION", "recon", {"p": 1}, tags=["a"]))
    f2 = b.publish(Fact.make("FINDING", "exploit/statefuzz_spec", {"p": 2},
                             derived_from=[f1["id"]]))
    assert b.query(kind="FINDING") == [f2]
    assert b.query(source="exploit") == [f2]
    assert b.query(tag="a") == [f1]
    assert f2["derived_from"] == [f1["id"]]
    assert b.ledger()["by_kind"]["OBSERVATION"] == 1


# ---------------------------------------------------------------- memory --
def test_bandit_orders_by_posterior(tmp_path):
    ns = MemoryNamespace("t1", str(tmp_path))
    ns.record("good", "success"); ns.record("good", "success")
    ns.record("bad", "failure")
    assert ns.technique_order(["bad", "good"])[0] == "good"


def test_should_run_skips_learned_dead_end(tmp_path):
    ns = MemoryNamespace("t2", str(tmp_path))
    assert ns.should_run("probe")            # virgin technique runs
    ns.record("probe", "failure", weight=0.75)
    assert not ns.should_run("probe")        # learned dead-end: skipped


def test_poisoning_guard_weights(tmp_path):
    ns = MemoryNamespace("t3", str(tmp_path))
    ns.record("t", "success", weight=0.25)   # target-controlled evidence
    ns.record("t", "success", weight=1.0)    # verified evidence
    assert ns.posterior_mean("t") == 2.25 / 3.25
    snap = ns.snapshot()
    assert snap["trials"] == 2


def test_insights_reject_target_specific_and_persist(tmp_path):
    ns = MemoryNamespace("t4", str(tmp_path))
    assert ns.add_insight("target-agnostic lesson") is True
    assert ns.add_insight("dvlba-shop specific: port 8378", True) is False
    ns2 = MemoryNamespace("t4", str(tmp_path))
    assert "target-agnostic lesson" in ns2.insights


# ---------------------------------------------------------------- router --
class _FakeSpec(Specialist):
    def __init__(self, ctx, name="fake", wide=False, depth=0):
        self._wide = wide
        self._depth = depth
        super().__init__({**ctx, "memory": lambda n: MemoryNamespace(
            n, ctx["memdir"])})
        self.name = name
        self.provenance = name

    def triggers(self):
        return [Trigger("OBSERVATION", None, 1.0)]

    def skills(self):
        return {("s%d" % i): (lambda: None) for i in range(10)} \
            if self._wide else {"s": lambda: None}

    def act(self, fact, board):
        return []


def test_contract_refuses_wide_skill_surface(tmp_path):
    board = Blackboard()
    ctx = {"llm": LLMSeam(), "memdir": str(tmp_path), "budget": 100}
    wide = _FakeSpec(ctx, "wide", wide=True)
    router = Router(board, [wide], ctx)
    board.publish(Fact.make("OBSERVATION", "x", {}))
    router.dispatch(max_rounds=3)
    assert any(t.get("event") == "contract-refused" for t in router.trace)


def test_stall_detection_terminates(tmp_path):
    board = Blackboard()
    ctx = {"llm": LLMSeam(), "memdir": str(tmp_path), "budget": 100}
    router = Router(board, [_FakeSpec(ctx, "idle")], ctx)
    router.dispatch(max_rounds=20)           # no facts ever match -> stalls
    assert "stop-stalled" in [t["event"] for t in router.trace]


def test_llm_seam_deterministic_fallback():
    seam = LLMSeam()
    assert seam.available() is False
    assert seam.tie_break([{"specialist": "a"}, {"specialist": "b"}])[
        "specialist"] == "a"
    assert seam.generate_hypotheses({"payload": {}}) is None


# ----------------------------------------------------------------- spawn --
def test_spawn_depth_limit(tmp_path):
    ctx = {"memdir": str(tmp_path)}

    class Sub(Specialist):
        name = "sub"

        def triggers(self):
            return []

        def skills(self):
            return {}

        def act(self, fact, board):
            return []

    class Parent(Specialist):
        name = "parent"
        max_depth = 0

        def triggers(self):
            return []

        def skills(self):
            return {}

        def act(self, fact, board):
            return []

    p = Parent({"memory": lambda n: MemoryNamespace(n, str(tmp_path))})
    board = Blackboard()
    with pytest.raises(ContractViolation):
        p.spawn(Sub, Fact.make("OBSERVATION", "x", {}), board)


# ------------------------------------------------------------------- e2e --
def _spawn_shop(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=HERE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail("target did not start")


def test_scope_guard_refuses_public_target(tmp_path):
    out = run({"base_url": "http://93.184.216.34",
               "out_dir": str(tmp_path)})
    assert out["ok"] is False and "scope guard" in out["error"]


def test_stop_file_halts_swarm(tmp_path):
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    out = run({"base_url": "http://127.0.0.1:8390",
               "out_dir": str(tmp_path / "s"), "budget": 30,
               "stop_file": str(stop)})
    assert out["ok"] is True and out["requests"] == 0


def test_full_swarm_engagement_end_to_end(tmp_path):
    proc, base = _spawn_shop(8390)
    try:
        out = run({"base_url": base, "out_dir": str(tmp_path / "r1"),
                   "memory_dir": str(tmp_path / "mem"),
                   "approvals": "lab", "budget": 460,
                   "stop_file": str(tmp_path / "r1" / "STOP")})
        assert out["ok"] is True

        # every unique finding carries provenance + verification stamp
        assert len(out["findings"]) >= 9
        for f in out["findings"]:
            assert f["provenance"], "finding without provenance: %s" % f["id"]
            assert f["status"].startswith("verified"), f
        verified_strict = [f for f in out["findings"]
                           if f["status"] == "verified"]
        assert len(verified_strict) >= 8          # race = transcript-verified
        assert any(f["invariant"] == "I5" and
                   f["status"] == "verified-by-transcript"
                   for f in out["findings"])

        # full-autonomy spawn happened with provenance chain
        assert any(e["child"] == "statefuzz_spec" and e["parent"] == "exploit"
                   for e in out["spawn_events"])
        assert any("exploit/statefuzz_spec" in f["provenance"]
                   for f in out["findings"])

        # access specialist escalated capability chains
        assert any(e["severity"] == "critical" for e in out["escalations"])

        # artifacts exist and are well-formed
        doc = json.load(open(os.path.join(str(tmp_path / "r1"),
                                          "findings.json")))
        assert doc["tool"] == "swarm" and doc["findings"]
        assert os.path.exists(str(tmp_path / "r1" / "blackboard.json"))
        assert os.path.exists(str(tmp_path / "r1" / "dispatch_trace.jsonl"))

        # ------------------ second run: SAME memory, FRESH server ----------
        proc.terminate()
        proc2, base2 = _spawn_shop(8390)
        try:
            out2 = run({"base_url": base2, "out_dir": str(tmp_path / "r2"),
                        "memory_dir": str(tmp_path / "mem"),   # persisted!
                        "approvals": "lab", "budget": 460,
                        "stop_file": str(tmp_path / "r2" / "STOP")})
            assert out2["ok"] is True
            assert len(out2["findings"]) >= 9          # no capability loss
            assert out2["requests"] < out["requests"], \
                "run2 did not skip learned dead-ends (%d vs %d)" % (
                    out2["requests"], out["requests"])
            mem = json.load(open(os.path.join(str(tmp_path / "mem"),
                                              "recon.json")))
            assert mem["insights"], "no insight earned from run 1"
            assert mem["bandit"]["probe_common_paths"]["beta"] > 1.0
        finally:
            proc2.terminate()
    finally:
        try:
            proc.terminate()
        except OSError:
            pass

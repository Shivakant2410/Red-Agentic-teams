"""Thread-safety tests for the shared state a parallel exploit swarm would hit
concurrently: KnowledgeGraph, FindingStore, AccessGraph. Before this, none of these had
any locking at all despite the orchestrator wanting multiple specialist contexts running
in parallel threads against ONE shared graph/store — a real, not theoretical, data race
(lost updates, or "dictionary changed size during iteration" crashes on a plain read
racing a write). These tests hammer each store from many threads and assert nothing was
lost and nothing crashed, which a successful run of a race-prone version would NOT
reliably reproduce as a failure (races are nondeterministic) but these are sized to make
the race overwhelmingly likely to surface if the locking were removed."""

from __future__ import annotations

import threading

from redteam.access import AccessGraph
from redteam.attack_tree import TODO, AttackTree
from redteam.findings import Finding, FindingStore
from redteam.knowledge import ENDPOINT, KnowledgeGraph

N_THREADS = 20
N_PER_THREAD = 25


def _run_concurrently(fn, n_threads=N_THREADS):
    threads = [threading.Thread(target=fn, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert all(not t.is_alive() for t in threads), "a thread hung — likely a deadlock"


def test_knowledge_graph_concurrent_observe_no_lost_writes(tmp_path):
    graph = KnowledgeGraph(tmp_path / "g.json")

    def worker(thread_id):
        for i in range(N_PER_THREAD):
            graph.observe(ENDPOINT, f"http://x.example/t{thread_id}/{i}",
                          attrs={"from": "swarm"}, source=f"thread{thread_id}")

    _run_concurrently(worker)
    # Every thread's every endpoint must be present — a race would silently drop some.
    nodes = graph.nodes(ENDPOINT)
    assert len(nodes) == N_THREADS * N_PER_THREAD


def test_knowledge_graph_concurrent_reads_during_writes_do_not_crash(tmp_path):
    graph = KnowledgeGraph(tmp_path / "g.json")
    stop = threading.Event()
    errors = []

    def writer(thread_id):
        for i in range(N_PER_THREAD):
            graph.observe(ENDPOINT, f"http://x.example/w{thread_id}/{i}")
        stop.set()

    def reader(_):
        while not stop.is_set():
            try:
                graph.nodes(ENDPOINT)
                graph.summary()
                graph.untested()
            except RuntimeError as exc:
                errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
    threads += [threading.Thread(target=reader, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, f"reads crashed during concurrent writes: {errors}"


def test_finding_store_concurrent_add_no_lost_findings(tmp_path):
    store = FindingStore(tmp_path / "f.json")

    def worker(thread_id):
        for i in range(N_PER_THREAD):
            store.add(Finding(
                title=f"finding-{thread_id}-{i}", severity="medium",
                target=f"http://x.example/t{thread_id}/{i}", summary="s",
                cwe=f"CWE-{thread_id}{i}"))   # unique cwe -> no cross-thread dedup collisions

    _run_concurrently(worker)
    assert len(store.all()) == N_THREADS * N_PER_THREAD


def test_access_graph_concurrent_hold_no_lost_nodes(tmp_path):
    graph = AccessGraph(tmp_path / "a.json")

    def worker(thread_id):
        for i in range(N_PER_THREAD):
            graph.hold("credential", f"cred-{thread_id}-{i}", evidence="e",
                      source="verified_finding")

    _run_concurrently(worker)
    assert len(graph.held()) == N_THREADS * N_PER_THREAD


def test_access_graph_concurrent_reads_during_writes_do_not_deadlock(tmp_path):
    """RLock specifically: briefing()/summary() call other locked methods on self from
    the SAME thread (held() -> _nodes, frontier() -> held()+_neighbors()) - a plain Lock
    would deadlock here, not just race."""
    graph = AccessGraph(tmp_path / "a.json")
    stop = threading.Event()

    def writer(thread_id):
        for i in range(N_PER_THREAD):
            graph.hold("principal", f"p-{thread_id}-{i}", evidence="e", source="authenticate")
        stop.set()

    def reader(_):
        while not stop.is_set():
            graph.briefing()
            graph.summary()
            graph.frontier()

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
    threads += [threading.Thread(target=reader, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert all(not t.is_alive() for t in threads), "a thread hung — RLock deadlock regression"


def test_attack_tree_claim_is_exclusive_under_concurrency(tmp_path):
    """The critical swarm-correctness property: claim() must let EXACTLY ONE worker win
    each TODO node, even when many threads race to claim the same small set of nodes —
    this is what stops a parallel exploit swarm from wasting tokens with two workers
    attacking the same (technique, target) pair at once."""
    tree = AttackTree(tmp_path / "t.json")
    tree.seed_endpoint("http://x.example/order/1")
    nodes = tree.actionable(limit=999)
    assert nodes, "fixture produced no actionable nodes to race over"

    wins = []
    wins_lock = threading.Lock()

    def worker(_):
        for n in nodes:
            if tree.claim(n.technique, n.target):
                with wins_lock:
                    wins.append((n.technique, n.target))

    _run_concurrently(worker, n_threads=30)
    # Every node claimed exactly once in total, never zero, never more than once.
    assert sorted(wins) == sorted({(n.technique, n.target) for n in nodes})
    assert len(wins) == len(set(wins)), "a node was claimed by more than one worker"


def test_attack_tree_concurrent_sync_and_mark_no_crash(tmp_path):
    tree = AttackTree(tmp_path / "t.json")

    def worker(thread_id):
        for i in range(N_PER_THREAD):
            tree.seed_endpoint(f"http://x.example/t{thread_id}/{i}")
            tree.mark("auth.test", f"http://x.example/t{thread_id}/{i}", TODO)

    _run_concurrently(worker, n_threads=10)
    assert tree.summary()["nodes"] > 0

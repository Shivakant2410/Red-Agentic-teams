"""Tests for the contextual multi-armed bandit over attack_tree.py's technique choices."""

from __future__ import annotations

import threading

from redteam.bandit import (
    BanditStore, LocalJSONBanditBackend, bucket_for_endpoint,
    _NUMERIC_ID, _UUID_ID, _AUTH_WALL, _WORKFLOW, _GENERIC,
)


# -- bucket_for_endpoint -------------------------------------------------------------

def test_numeric_id_path_buckets_as_numeric_id():
    bucket = bucket_for_endpoint("https://example.com/api/users/42")
    assert _NUMERIC_ID in bucket


def test_uuid_path_buckets_as_uuid_id():
    bucket = bucket_for_endpoint(
        "https://example.com/api/orders/550e8400-e29b-41d4-a716-446655440000")
    assert _UUID_ID in bucket


def test_login_path_buckets_as_auth_wall():
    bucket = bucket_for_endpoint("https://example.com/account/login")
    assert _AUTH_WALL in bucket


def test_checkout_path_buckets_as_workflow_shaped():
    bucket = bucket_for_endpoint("https://example.com/cart/checkout")
    assert _WORKFLOW in bucket


def test_plain_path_buckets_as_generic():
    assert bucket_for_endpoint("https://example.com/about") == _GENERIC


def test_multiple_shape_tags_combine_sorted_and_deterministic():
    b1 = bucket_for_endpoint("https://example.com/account/login/42")
    b2 = bucket_for_endpoint("https://example.com/account/login/42")
    assert b1 == b2
    assert _NUMERIC_ID in b1 and _AUTH_WALL in b1


def test_node_requires_auth_attr_also_triggers_auth_wall():
    class _Node:
        attrs = {"requires_auth": True}
    bucket = bucket_for_endpoint("https://example.com/api/widgets", node=_Node())
    assert _AUTH_WALL in bucket


# -- BanditStore: basic mechanics -----------------------------------------------------

def test_fresh_arm_samples_are_bounded_0_1():
    store = BanditStore()
    for _ in range(50):
        s = store.sample("injection.sqli", "generic")
        assert 0.0 <= s <= 1.0


def test_record_win_increases_future_mean():
    store = BanditStore()
    for _ in range(20):
        store.record("access.idor", "numeric-id", won=True)
    arm = store._get("access.idor", "numeric-id")
    assert arm.mean > 0.9


def test_record_loss_decreases_future_mean():
    store = BanditStore()
    for _ in range(20):
        store.record("injection.sqli", "generic", won=False)
    arm = store._get("injection.sqli", "generic")
    assert arm.mean < 0.1


def test_arms_are_independent_per_technique_and_bucket():
    store = BanditStore()
    for _ in range(20):
        store.record("access.idor", "numeric-id", won=True)
    store.record("access.idor", "auth-wall", won=False)
    idor_numeric = store._get("access.idor", "numeric-id")
    idor_auth = store._get("access.idor", "auth-wall")
    assert idor_numeric.mean > idor_auth.mean


def test_strongly_evidenced_arm_outsamples_untested_arm_on_average():
    """Thompson sampling should, on average over many draws, favor an arm with strong
    confirmed evidence over one with none — the whole point of learning anything."""
    store = BanditStore()
    for _ in range(30):
        store.record("access.idor", "numeric-id", won=True)
    wins = 0
    trials = 200
    for _ in range(trials):
        good = store.sample("access.idor", "numeric-id")
        untested = store.sample("injection.sqli", "numeric-id")
        if good > untested:
            wins += 1
    assert wins > trials * 0.8


# -- persistence -----------------------------------------------------------------

def test_persists_across_instances_via_local_json_backend(tmp_path):
    path = tmp_path / "bandit.json"
    store1 = BanditStore(path)
    for _ in range(10):
        store1.record("xss.reflected", "generic", won=True)

    store2 = BanditStore(path)
    arm = store2._get("xss.reflected", "generic")
    assert arm.trials == 10
    assert arm.mean > 0.8


def test_summary_reports_trials_and_mean(tmp_path):
    store = BanditStore(tmp_path / "bandit.json")
    store.record("auth.test", "auth-wall", won=True)
    store.record("auth.test", "auth-wall", won=False)
    summary = store.summary()
    assert "auth.test@auth-wall" in summary
    assert summary["auth.test@auth-wall"]["trials"] == 2


def test_no_backend_still_works_in_memory_only():
    store = BanditStore()   # no path/backend given
    store.record("ssrf", "generic", won=True)
    assert store._get("ssrf", "generic").trials == 1


# -- concurrency: swarm workers record() from multiple threads ------------------------

def test_concurrent_record_calls_are_thread_safe(tmp_path):
    store = BanditStore(tmp_path / "bandit.json")
    n_threads = 20
    per_thread = 25

    def worker():
        for _ in range(per_thread):
            store.record("access.control", "generic", won=True)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    arm = store._get("access.control", "generic")
    assert arm.trials == n_threads * per_thread

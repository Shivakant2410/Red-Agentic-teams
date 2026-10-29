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


# -- multi-gambit: non-stationarity (discounted posteriors) ----------------------------
# docs/multi-gambit.md §4.2: targets are RESTLESS — patched mid-engagement, redeployed,
# turned into traps. A fixed posterior weights round-1 evidence like round-100 evidence
# forever; discounting makes stale evidence fade so the belief tracks the regime.

def test_discount_tracks_regime_change():
    stale = BanditStore()
    fresh = BanditStore(discount=0.6)
    for _ in range(10):
        stale.record("injection.sqli", "generic", won=True)
        fresh.record("injection.sqli", "generic", won=True)
    for _ in range(10):
        stale.record("injection.sqli", "generic", won=False)
        fresh.record("injection.sqli", "generic", won=False)
    # No discount: ten wins then ten losses is a permanent ~50/50 wash.
    assert 0.35 < stale._get("injection.sqli", "generic").mean < 0.65
    # Discounted: the decayed old wins barely survive the recent losses.
    assert fresh._get("injection.sqli", "generic").mean < 0.15


def test_discount_invalid_value_rejected():
    for bad in (0.0, -1.0, 1.5):
        try:
            BanditStore(discount=bad)
        except ValueError:
            continue
        raise AssertionError(f"discount={bad!r} should have been rejected")


# -- multi-gambit: federated posteriors (multi-agent sync) -----------------------------
# docs/multi-gambit.md §5: each swarm worker keeps its own store; Beta sufficient
# statistics are two floats per arm, so peers pool EVIDENCE (alpha-1, beta-1), never
# raw draws — one agent's confirmed exploit raises every other agent's belief.

def test_federated_merge_propagates_peer_evidence():
    peer = BanditStore()
    for _ in range(12):
        peer.record("ssrf", "generic", won=True)
    store = BanditStore()
    assert store.merge_state(peer.export_state()) == 1
    arm = store._get("ssrf", "generic")
    assert arm.trials == 12
    assert arm.mean > 0.85


def test_federated_merge_skips_malformed_rows():
    """A bad peer payload must no more corrupt the shared belief than a bad sink
    corrupts a proof: skip and survive, never raise."""
    store = BanditStore()
    merged = store.merge_state([{"technique": "xss.reflected"}, "junk", None, 42])
    assert merged == 0
    assert store._get("xss.reflected", "generic").trials == 0


def test_federated_export_roundtrip_preserves_stats():
    a = BanditStore()
    for _ in range(7):
        a.record("access.idor", "numeric-id", won=True)
    for _ in range(3):
        a.record("access.idor", "numeric-id", won=False)
    b = BanditStore()
    b.merge_state(a.export_state())
    c = BanditStore()
    c.merge_state(b.export_state())
    src = a._get("access.idor", "numeric-id")
    dst = c._get("access.idor", "numeric-id")
    assert (dst.alpha, dst.beta) == (src.alpha, src.beta)


# -- multi-gambit: anti-honeypot suspicion cap -----------------------------------------
# docs/multi-gambit.md §4.3: an arm that confirms on EVERY early trial is a signature,
# not skill — that is exactly what a honeypot (confirming cheap exploits on purpose)
# or a reward-hacking loop looks like. The cap keeps the too-perfect arm competitive
# but stops it starving strong arms with realistic failure rates.

def test_suspicion_cap_distrusts_never_failed_arms():
    capped = BanditStore(suspicion_cap=0.8, suspicion_window=8)
    for _ in range(5):
        capped.record("injection.sqli", "generic", won=True)        # 5/5 — too easy
    for i in range(10):
        capped.record("access.idor", "numeric-id", won=i < 9)       # 9/10 — real
    too_perfect = sum(capped.sample("injection.sqli", "generic") for _ in range(2000))
    realistic = sum(capped.sample("access.idor", "numeric-id") for _ in range(2000))
    assert realistic > too_perfect

    # Sanity: without the cap the too-perfect arm dominates — the cap is what flips it.
    plain = BanditStore()
    for _ in range(5):
        plain.record("injection.sqli", "generic", won=True)
    for i in range(10):
        plain.record("access.idor", "numeric-id", won=i < 9)
    assert sum(plain.sample("injection.sqli", "generic") for _ in range(2000)) > \
        sum(plain.sample("access.idor", "numeric-id") for _ in range(2000))


# -- multi-gambit: cost-aware selection (yield per OPSEC cost) --------------------------
# docs/multi-gambit.md §4.4: techniques differ in OPSEC price (quiet probe 1, loud
# exploit 5+). Ranking draws by yield-per-cost is the budgeted-MAB objective:
# maximize confirmed findings per unit of detectable noise, not per request.

def test_select_prefers_cheaper_arm_when_evidence_is_equal():
    store = BanditStore()
    for _ in range(6):
        store.record("ssrf", "generic", won=True)
        store.record("info.sensitive", "generic", won=True)
    cheap_wins = 0
    for _ in range(300):
        top = store.select([("ssrf", "generic", 4.0),
                            ("info.sensitive", "generic", 1.0)])[0]
        if top["technique"] == "info.sensitive":
            cheap_wins += 1
    assert cheap_wins > 240


def test_select_prefers_strong_evidence_over_cheap_noise():
    """Cost-aware does not mean cheap-only: a proven arm clears its higher OPSEC
    price; an unproven quiet arm does not get to hide behind being quiet."""
    store = BanditStore()
    for _ in range(20):
        store.record("access.idor", "numeric-id", won=True)     # proven, loud
        store.record("injection.sqli", "generic", won=False)    # unproven, quiet
    loud_wins = 0
    for _ in range(300):
        top = store.select([("access.idor", "numeric-id", 5.0),
                            ("injection.sqli", "generic", 1.0)])[0]
        if top["technique"] == "access.idor":
            loud_wins += 1
    assert loud_wins > 240

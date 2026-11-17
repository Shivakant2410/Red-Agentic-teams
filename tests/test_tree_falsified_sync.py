"""Phase E2 — falsified finding -> AttackTree synchronization (Stage 6).

The symmetric half of sync(): confirmed findings complete nodes (existing),
independently falsified findings fail the EXISTING matching node — canonical
matching, no new rows, no sibling damage, pending claims never fail anything.
"""

from __future__ import annotations

from redteam.attack_tree import FAILED, TODO, AttackTree
from redteam.findings import Finding


def _f(**kw) -> Finding:
    defaults = dict(title="SQLi", severity="high", target="https://x/login",
                    summary="s", cwe="CWE-89")
    defaults.update(kw)
    return Finding(**defaults)


def test_confirmed_findings_retain_completed_behavior():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.sync(findings=[_f(confidence="confirmed")])
    assert t.node("injection.sqli", "https://x/login").status == "completed"


def test_falsified_finding_fails_matching_existing_node():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.sync(findings=[_f(confidence="falsified", id="f9")])
    node = t.node("injection.sqli", "https://x/login")
    assert node.status == FAILED
    assert node.findings == "f9"


def test_pending_findings_never_fail_a_node():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    for conf in ("tentative", "firm", "pending_verification", "not_reproducible"):
        t.sync(findings=[_f(confidence=conf)])
    assert t.node("injection.sqli", "https://x/login").status == TODO


def test_falsified_finding_creates_no_new_node():
    t = AttackTree()   # nothing seeded — no node for this target exists
    t.sync(findings=[_f(confidence="falsified", target="https://nowhere/x")])
    assert t.summary()["nodes"] == 0


def test_matching_is_canonical_and_target_specific():
    t = AttackTree()
    t.seed_endpoint("https://x:443/login?utm=1")     # tree spelling
    t.sync(findings=[_f(confidence="falsified", target="https://x/login")])
    # the canonical join found the node despite the default port + query diff
    assert t.node("injection.sqli", "https://x:443/login?utm=1").status == FAILED


def test_unrelated_techniques_on_same_target_untouched():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.sync(findings=[_f(confidence="falsified", cwe="CWE-89")])   # maps to injection.sqli only
    assert t.node("injection.sqli", "https://x/login").status == FAILED
    assert t.node("access.control", "https://x/login").status == TODO
    assert t.node("auth.test", "https://x/login").status == TODO


def test_repeated_sync_is_idempotent():
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    f = _f(confidence="falsified", id="f9")
    t.sync(findings=[f])
    t.sync(findings=[f])
    t.sync(findings=[f])
    assert t.node("injection.sqli", "https://x/login").status == FAILED


def test_retry_behavior_unchanged():
    """FAILED stays exactly as retryable as before (once per round)."""
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.sync(findings=[_f(confidence="falsified")])
    assert t.node("injection.sqli", "https://x/login").status == FAILED
    reset = t.retry_failed()
    assert reset == 1
    assert t.node("injection.sqli", "https://x/login").status == TODO
    # and re-syncing the same falsified finding fails it again (a fresh verdict)
    t.sync(findings=[_f(confidence="falsified")])
    assert t.node("injection.sqli", "https://x/login").status == FAILED


def test_confirmed_and_falsified_coexist_correctly():
    """A confirmed win and a falsified claim on the same target from the same
    sync pass: the mapped technique completes, the falsified one fails."""
    t = AttackTree()
    t.seed_endpoint("https://x/login")
    t.sync(findings=[
        _f(confidence="confirmed", cwe="CWE-639", target="https://x/login"),   # access.idor
        _f(confidence="falsified", cwe="CWE-79", target="https://x/login"),    # xss.reflected
    ])
    assert t.node("access.idor", "https://x/login").status == "completed"
    assert t.node("xss.reflected", "https://x/login").status == FAILED

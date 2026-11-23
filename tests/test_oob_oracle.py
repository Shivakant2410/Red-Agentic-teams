"""OOB oracle + the oob_callback proof predicate — the blind-vuln listener.

Covers: fail-closed-by-default (no data leaves the box unconfigured), canary
minting/polling with a fake bridge, and that oob_callback PROVES only a real
callback (deterministic, no response body involved)."""
from redteam.tools.oob_oracle import OOBOracle, OOBBridge, Interaction, OOBError
from redteam.proof import eval_condition, ProofCheck


class _FakeBridge(OOBBridge):
    """Deterministic in-memory transport for tests — no network."""
    name = "fake"
    ready = True

    def __init__(self):
        self._n = 0
        self._pending: list[Interaction] = []

    def new_canary(self) -> str:
        self._n += 1
        return f"c{self._n}.fake.oast"

    def fire(self, canary: str, protocol: str = "dns"):
        self._pending.append(Interaction(canary=canary, protocol=protocol,
                                         remote_addr="203.0.113.9"))

    def poll(self):
        out, self._pending = self._pending, []
        return out


def test_fails_closed_without_transport():
    o = OOBOracle(bridge=None)
    assert o.available is False
    try:
        o.mint("x")
        assert False, "mint should refuse when no transport is configured"
    except OOBError as exc:
        assert "fail closed" in str(exc).lower() or "not configured" in str(exc).lower()


def test_mint_and_poll_roundtrip():
    b = _FakeBridge()
    o = OOBOracle(bridge=b)
    assert o.available
    canary = o.mint("ssrf test")
    assert canary.endswith(".fake.oast")
    # no callback yet
    assert o.interactions_for(canary) == []
    # target calls back
    b.fire(canary, "dns")
    hits = o.interactions_for(canary)
    assert len(hits) == 1 and hits[0].protocol == "dns"


def test_only_our_canaries_are_kept():
    b = _FakeBridge()
    o = OOBOracle(bridge=b)
    mine = o.mint()
    b.fire(mine, "http")
    b.fire("someone-else.fake.oast", "dns")   # shared-server noise
    hits = o.poll()
    assert all("someone-else" not in h.canary for h in hits)
    assert any(mine in h.canary for h in hits)


def test_oob_callback_predicate_proves_only_real_hit():
    b = _FakeBridge()
    o = OOBOracle(bridge=b)
    canary = o.mint()
    # before any callback: predicate fails
    ok, detail = eval_condition({"type": "oob_callback", "canary": canary}, {}, oob=o)
    assert ok is False and "0 interaction" in detail
    # after the target calls back: predicate passes
    b.fire(canary, "dns")
    ok, detail = eval_condition({"type": "oob_callback", "canary": canary}, {}, oob=o)
    assert ok is True and "interaction" in detail


def test_oob_callback_respects_protocol_and_count():
    b = _FakeBridge()
    o = OOBOracle(bridge=b)
    canary = o.mint()
    b.fire(canary, "dns")
    # want an HTTP callback but only a DNS one arrived -> fail
    ok, _ = eval_condition({"type": "oob_callback", "canary": canary,
                            "protocol": "http"}, {}, oob=o)
    assert ok is False
    # need 2, have 1 -> fail
    ok, _ = eval_condition({"type": "oob_callback", "canary": canary,
                            "min_count": 2}, {}, oob=o)
    assert ok is False


def test_oob_callback_without_oracle_fails_safe():
    ok, detail = eval_condition({"type": "oob_callback", "canary": "x"}, {}, oob=None)
    assert ok is False and "not available" in detail


def test_proofcheck_threads_oob_through():
    b = _FakeBridge()
    o = OOBOracle(bridge=b)
    canary = o.mint()
    b.fire(canary, "http")
    check = ProofCheck(fetchers={}, conditions=[
        {"type": "oob_callback", "canary": canary, "protocol": "http"}], oob=o)
    outcome = check.run()
    assert outcome.passed is True

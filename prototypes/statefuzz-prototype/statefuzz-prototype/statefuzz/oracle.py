"""Oracle layer: immediate metamorphic checks live in invariants.py; this
module owns the DEFERRED oracle — the HypothesisLedger (dossier S8.3).

Some effects cannot be asserted at mutation time: the async refund returns
202 with a callback path and the balance mutation lands ~600ms later on a
worker thread. The ledger records a hypothesis (marker, expected effect,
TTL), the runner polls the callback endpoint, and only then does the
 metamorphic check run. This is the column every surveyed system left empty.
"""
import time


class Hypothesis:
    def __init__(self, marker, callback_path, expectation, ttl=6.0):
        self.marker = marker
        self.callback_path = callback_path
        self.expectation = expectation   # {"kind": ..., "order_total": int, ...}
        self.ttl = ttl
        self.created = time.time()
        self.resolved = None             # filled by resolve()


class HypothesisLedger:
    def __init__(self):
        self._items = []

    def add(self, marker, callback_path, expectation, ttl=6.0):
        h = Hypothesis(marker, callback_path, expectation, ttl)
        self._items.append(h)
        return h

    def pending(self):
        now = time.time()
        return [h for h in self._items
                if h.resolved is None and now - h.created < h.ttl]

    def drain(self, ex, principal):
        """Poll every pending hypothesis' callback endpoint until done/TTL."""
        out = []
        deadline = time.time() + max((h.ttl for h in self.pending()), default=0) + 1
        while self.pending() and time.time() < deadline:
            for h in self.pending():
                r = ex.request(principal, "GET", h.callback_path, phase="deferred")
                if r["resp_body"].get("status") == "done":
                    h.resolved = r["resp_body"]
                    out.append(h)
            time.sleep(0.2)
        return out

    def verify(self, h, wallet_before, wallet_after):
        """Deferred metamorphic check: the async refund must credit the wallet
        EXACTLY ONCE by order_total. Any excess delta (double credit from a
        sync+async combination, re-queue, or retry) is a violation observed
        only after the callback resolves."""
        expected = h.expectation.get("order_total", 0)
        delta = wallet_after - wallet_before
        if delta != expected:
            return {"invariant": "I1", "assertion": "wallet_delta == order_total",
                    "observed": {"callback_refund_cents":
                                 h.resolved.get("refund_cents") if h.resolved else None,
                                 "order_total": expected, "wallet_delta": delta},
                    "detail": "deferred window credited %d cents total for a "
                              "single %d-cent refund (delta observed after "
                              "callback resolution)" % (delta, expected)}
        return None

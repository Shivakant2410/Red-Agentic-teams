"""Ground truth: the 8 seeded bugs. EVALUATION ONLY — statefuzz never imports
this file at runtime; run_demo loads it after the run to score discovery."""

SEEDS = [
    {"id": "B1", "class": "I1/I4", "endpoint": "POST /api/coupon/apply",
     "bug": "WELCOME10 stacks without cap or per-user guard (discount_pct unbounded)",
     "detect_with": "REPLAY xN + arithmetic oracle: discount > subtotal or total < 0"},
    {"id": "B2", "class": "I5", "endpoint": "POST /api/coupon/redeem",
     "bug": "check-then-act on single-use coupon, 30ms window, no lock",
     "detect_with": "INTERRUPT race (last-byte sync, 8 workers) + wallet read-back"},
    {"id": "B3", "class": "I2", "endpoint": "POST /api/checkout/init",
     "bug": "cart not transition-guarded: init replayable -> duplicate orders",
     "detect_with": "REPLAY init; two orders with identical item sets"},
    {"id": "B4", "class": "I4", "endpoint": "POST /api/cart/items",
     "bug": "qty sign/range unvalidated; negative qty -> checkout credits balance",
     "detect_with": "NEGATIVE qty + wallet read-back after confirm"},
    {"id": "B5", "class": "I3", "endpoint": "GET /api/orders/{id}",
     "bug": "no ownership check on order read (IDOR)",
     "detect_with": "CROSS-USER read; order.owner != caller"},
    {"id": "B6", "class": "I1/I3", "endpoint": "POST /api/orders/{id}/refund",
     "bug": "no status guard/idempotency; credits CALLER not owner; unpaid ok",
     "detect_with": "REPLAY refund + CROSS-USER refund + wallet read-back"},
    {"id": "B7", "class": "I2", "endpoint": "POST /api/orders/{id}/ship",
     "bug": "no role check and no paid-state guard: SKIP checkout/confirm",
     "detect_with": "SKIP confirm; ship on 'initiated' order succeeds"},
    {"id": "B8", "class": "I1 (deferred)", "endpoint": "POST /api/refunds/async",
     "bug": "async leg re-credits without status guard -> sync+async double credit",
     "detect_with": "HypothesisLedger: 202 + callback poll + post-hoc wallet delta"},
]

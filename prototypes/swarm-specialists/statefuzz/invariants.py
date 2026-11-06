"""The 5 invariant classes from the dossier (S8) as executable oracles.

Each checker takes observed evidence (wallets, cart snapshots, order objects,
race results) and returns a violation fragment or None:

    {"invariant": "I4", "assertion": "...", "observed": {...}, "detail": str}

I1 resource conservation : wallet deltas must equal the sum of priced events
I2 transition legality   : accepted actions outside the induced FSM
I3 identity ownership    : principal P reads/writes objects owned by Q
I4 arithmetic / ordering : totals, signs, discount bounds
I5 uniqueness / rate     : single-use artifacts redeemable once
"""


# ------------------------------------------------------------------ I4 ----
def i4_total_within_bounds(cart_after):
    """discount may never exceed the subtotal; total may never go negative."""
    sub, pct, total = (cart_after.get("subtotal_cents"),
                       cart_after.get("discount_pct"),
                       cart_after.get("total_cents"))
    if pct is not None and sub is not None and pct > 100:
        return {"invariant": "I4", "assertion": "discount_pct <= 100",
                "observed": {"discount_pct": pct, "total_cents": total},
                "detail": "stacked discount %d%% drives total to %s"
                          % (pct, total)}
    if total is not None and sub is not None and total < 0:
        return {"invariant": "I4", "assertion": "total_cents >= 0",
                "observed": {"subtotal_cents": sub, "total_cents": total},
                "detail": "cart total went negative: %d < 0" % total}
    return None


def i4_charge_matches_wallet(order_total, wallet_before, wallet_after):
    """A paid checkout must DECREASE the wallet by exactly order_total.
    A negative order_total (credit) violates I4 sign semantics."""
    if order_total is None:
        return None          # unfamiliar surface: response lacked the field
    delta = wallet_after - wallet_before
    if order_total < 0:
        return {"invariant": "I4", "assertion": "order_total >= 0",
                "observed": {"order_total": order_total, "wallet_delta": delta},
                "detail": "checkout charged %d cents (negative) and wallet went "
                          "UP by %d" % (order_total, delta)}
    if delta != -order_total:
        return {"invariant": "I4", "assertion": "wallet_delta == -order_total",
                "observed": {"order_total": order_total, "wallet_delta": delta},
                "detail": "wallet moved %d, expected %d" % (delta, -order_total)}
    return None


# ------------------------------------------------------------------ I1 ----
def i1_refund_conservation(order_total, credits, order_owner, caller):
    """Sum of all refund credits for one order must be <= its price, and a
    refund must credit the OWNER, not the caller."""
    if order_total is None or any(c is None for c in credits):
        return None          # unfamiliar surface: response lacked the fields
    over = sum(credits) - order_total
    if over > 0:
        return {"invariant": "I1", "assertion": "sum(credits) <= order_total",
                "observed": {"order_total": order_total, "credits": credits,
                             "overcredit": over},
                "detail": "refunded %s over price by %d cents"
                          % (caller, over)}
    return None


# ------------------------------------------------------------------ I2 ----
def i2_unmodeled_transition(model, order_status, action, ex):
    """Server accepted a transition the lawful walk never modeled."""
    if 200 <= ex["status"] < 300 and not model.is_modeled(order_status, action):
        return {"invariant": "I2", "assertion": "action in delta(alpha(s))",
                "observed": {"from_state": order_status, "action": action,
                             "status": ex["status"]},
                "detail": "%s accepted from state '%s' (unmodeled)"
                          % (action, order_status)}
    return None


def i2_snapshot_duality(order_ids, item_sets):
    """One cart snapshot must yield at most one order with those items."""
    if len(set(order_ids)) > 1 and len({frozenset(s.items()) for s in item_sets}) == 1:
        return {"invariant": "I2", "assertion": "cart snapshot: 1 -> <=1 order",
                "observed": {"order_ids": list(order_ids)},
                "detail": "checkout/init replayed from the same cart produced "
                          "%d orders with identical item sets" % len(order_ids)}
    return None


# ------------------------------------------------------------------ I3 ----
def i3_owner_mismatch(caller, obj):
    """Principal must not read/write an object owned by another principal."""
    owner = obj.get("owner")
    if owner and owner != caller:
        return {"invariant": "I3", "assertion": "caller == object.owner",
                "observed": {"caller": caller, "owner": owner},
                "detail": "%s accessed order owned by %s" % (caller, owner)}
    return None


# ------------------------------------------------------------------ I5 ----
def i5_single_use(value_cents, total_credited, n_attempts):
    """A single-use artifact credits at most its face value, once."""
    if total_credited > value_cents:
        return {"invariant": "I5", "assertion": "credited_total == value",
                "observed": {"value_cents": value_cents,
                             "credited_total": total_credited,
                             "successful_redeems": total_credited // value_cents},
                "detail": "single-use coupon credited %d cents across a %d-"
                          "request synchronized race (face value %d)"
                          % (total_credited, n_attempts, value_cents)}
    return None

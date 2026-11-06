"""dvlba-shop — deliberately vulnerable HTTP target for statefuzz (Phase B).

A small e-commerce API implementing DVLBA-style archetypes. ALL bugs are
intentional and enumerated in seeds.py (ground truth for evaluation ONLY —
the fuzzer never imports this file). Money is integer cents everywhere so
arithmetic oracles (invariant class I4) are exact.

Threaded dev server, loopback only. Run:  python target/app.py --port 8377
"""
import argparse
import threading
import time
import uuid

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------- state ----
BALANCE = {}      # username -> cents
USERS = {}        # username -> {"password": str, "role": str}
TOKENS = {}       # token -> username
CARTS = {}        # username -> {"items": {sku: qty}, "discount_pct": int}
ORDERS = {}       # order_id -> {"id","owner","items","total","status"}
ONCE_COUPONS = {"ONCE-9K4T": {"value_cents": 50000, "used": False}}
CALLBACKS = {}    # marker -> {"status": "pending"|"done", "refund_cents": int}
LEDGER = []       # [{"ts","kind","user","delta_cents","ref"}]
CATALOG = {"SKU-GPU": 129900, "SKU-CABLE": 900, "SKU-GIFTCARD": 50000}
WELCOME_PCT = 10  # WELCOME10

_recent_redemptions = []  # for race-window evidence only


def _ledger(kind, user, delta, ref=""):
    LEDGER.append({"ts": time.time(), "kind": kind, "user": user,
                   "delta_cents": delta, "ref": ref})


def _new_user(name):
    USERS[name] = {"password": "pw-" + name, "role": "user"}
    BALANCE[name] = 1000000  # $10,000 starting balance
    CARTS[name] = {"items": {}, "discount_pct": 0}


# ----------------------------------------------------------------- auth ----
@app.before_request
def _load_principal():
    g.user = None
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        g.user = TOKENS.get(h[7:])


def _deny():
    return jsonify(error="auth required"), 401


# ------------------------------------------------------------ endpoints ----
@app.get("/health")
def health():
    return jsonify(ok=True, app="dvlba-shop")


@app.get("/openapi.json")
def openapi():
    return OPENAPI


@app.post("/api/register")
def register():
    b = request.get_json(silent=True) or {}
    name = b.get("username")
    if not name or name in USERS:
        return jsonify(error="bad username"), 400
    _new_user(name)
    return jsonify(username=name), 201


@app.post("/api/login")
def login():
    b = request.get_json(silent=True) or {}
    u = USERS.get(b.get("username") or "")
    if not u or u["password"] != b.get("password"):
        return jsonify(error="bad credentials"), 401
    tok = uuid.uuid4().hex
    TOKENS[tok] = b["username"]
    return jsonify(token=tok)


@app.get("/api/wallet")
def wallet():
    if not g.user:
        return _deny()
    return jsonify(user=g.user, balance_cents=BALANCE[g.user])


@app.get("/api/catalog")
def catalog():
    return jsonify(catalog=CATALOG)


@app.get("/api/cart")
def cart_get():
    if not g.user:
        return _deny()
    c = CARTS[g.user]
    subtotal = sum(CATALOG[s] * q for s, q in c["items"].items())
    total = round(subtotal * (100 - c["discount_pct"]) / 100)
    return jsonify(user=g.user, items=c["items"],
                   subtotal_cents=subtotal,
                   discount_pct=c["discount_pct"],
                   total_cents=total)


@app.post("/api/cart/items")
def cart_add():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    sku = b.get("sku")
    if sku not in CATALOG:
        return jsonify(error="unknown sku"), 400
    qty = b.get("qty", 1)                      # SEED B4: no sign/range validation
    CARTS[g.user]["items"][sku] = CARTS[g.user]["items"].get(sku, 0) + int(qty)
    return jsonify(cart=CARTS[g.user]), 201


@app.post("/api/coupon/apply")
def coupon_apply():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    if b.get("code") != "WELCOME10":
        return jsonify(error="unknown coupon"), 400
    c = CARTS[g.user]
    # SEED B1: no per-user redemption guard, no discount cap -> stacks forever
    c["discount_pct"] += WELCOME_PCT
    return jsonify(discount_pct=c["discount_pct"]), 200


@app.post("/api/coupon/redeem")
def coupon_redeem():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    c = ONCE_COUPONS.get(b.get("code") or "")
    if not c:
        return jsonify(error="unknown coupon"), 400
    if c["used"]:                               # SEED B2: check-then-act,
        return jsonify(error="already redeemed"), 409  # 30ms window, no lock
    time.sleep(0.03)
    c["used"] = True
    BALANCE[g.user] += c["value_cents"]
    _ledger("coupon_redeem", g.user, c["value_cents"], b.get("code"))
    _recent_redemptions.append({"user": g.user, "ts": time.time()})
    return jsonify(credited_cents=c["value_cents"]), 200


@app.post("/api/checkout/init")
def checkout_init():
    if not g.user:
        return _deny()
    c = CARTS[g.user]
    if not c["items"]:
        return jsonify(error="empty cart"), 400
    subtotal = sum(CATALOG[s] * q for s, q in c["items"].items())
    total = round(subtotal * (100 - c["discount_pct"]) / 100)
    oid = "ORD-" + uuid.uuid4().hex[:8]
    ORDERS[oid] = {"id": oid, "owner": g.user, "items": dict(c["items"]),
                   "total_cents": total, "status": "initiated"}
    # SEED B3: cart is neither cleared nor transition-guarded -> init is replayable
    return jsonify(order_id=oid, status="initiated", total_cents=total), 201


@app.post("/api/checkout/confirm")
def checkout_confirm():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    o = ORDERS.get(b.get("order_id") or "")
    if not o:
        return jsonify(error="unknown order"), 404
    BALANCE[o["owner"]] -= o["total_cents"]     # SEED B4b: negative total credits
    _ledger("checkout_confirm", o["owner"], -o["total_cents"], o["id"])
    o["status"] = "paid"
    return jsonify(order_id=o["id"], status="paid",
                   charged_cents=o["total_cents"]), 200


@app.get("/api/orders/<oid>")
def order_get(oid):
    if not g.user:
        return _deny()
    o = ORDERS.get(oid)
    if not o:
        return jsonify(error="unknown order"), 404
    # SEED B5: no ownership check -> IDOR (read)
    return jsonify(o), 200


@app.post("/api/orders/<oid>/ship")
def order_ship(oid):
    if not g.user:
        return _deny()
    o = ORDERS.get(oid)
    if not o:
        return jsonify(error="unknown order"), 404
    # SEED B7: no role check AND no "paid" state guard -> SKIP confirm is legal
    o["status"] = "shipped"
    return jsonify(order_id=o["id"], status="shipped"), 200


@app.post("/api/orders/<oid>/refund")
def order_refund(oid):
    if not g.user:
        return _deny()
    o = ORDERS.get(oid)
    if not o:
        return jsonify(error="unknown order"), 404
    # SEED B6: no status guard, not idempotent, credits the CALLER (not owner),
    #          also honours unpaid orders -> money from nothing
    BALANCE[g.user] += o["total_cents"]
    _ledger("refund", g.user, o["total_cents"], o["id"])
    o["status"] = "refunded"
    return jsonify(order_id=o["id"], status="refunded",
                   credited_cents=o["total_cents"]), 200


@app.post("/api/refunds/async")
def refund_async():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    o = ORDERS.get(b.get("order_id") or "")
    if not o:
        return jsonify(error="unknown order"), 404
    marker = uuid.uuid4().hex[:12]
    CALLBACKS[marker] = {"status": "pending", "refund_cents": 0}
    caller = g.user
    tid = o["id"]
    total = o["total_cents"]

    def _worker():
        time.sleep(0.6)
        # SEED B8: async leg ignores refund status too -> sync+async double credit
        BALANCE[caller] += total
        _ledger("refund_async", caller, total, tid)
        CALLBACKS[marker].update(status="done", refund_cents=total)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify(ticket=marker, callback=f"/api/callbacks/{marker}",
                   status="accepted"), 202


@app.get("/api/callbacks/<marker>")
def callback_get(marker):
    if not g.user:
        return _deny()
    cb = CALLBACKS.get(marker)
    if not cb:
        return jsonify(error="unknown marker"), 404
    return jsonify(marker=marker, **cb), 200


@app.get("/api/ledger")
def ledger():
    if not g.user:          # lab convenience: any authenticated user may read
        return _deny()
    return jsonify(entries=LEDGER[-64:])


OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "dvlba-shop", "version": "1.0"},
    "servers": [{"url": "http://127.0.0.1"}],
    "paths": {
        "/health": {"get": {"x-kind": "meta", "responses": {"200": {}}}},
        "/api/register": {"post": {"x-kind": "bootstrap", "requestBody": {
            "application/json": {"schema": {"type": "object", "required": ["username"],
                "properties": {"username": {"type": "string"},
                               "password": {"type": "string"}}}}},
            "responses": {"201": {}}}},
        "/api/login": {"post": {"x-kind": "bootstrap", "requestBody": {
            "application/json": {"schema": {"type": "object", "required": ["username", "password"],
                "properties": {"username": {"type": "string"},
                               "password": {"type": "string"}}}}},
            "responses": {"200": {}}}},
        "/api/wallet": {"get": {"x-kind": "readback", "responses": {"200": {}}}},
        "/api/catalog": {"get": {"x-kind": "meta", "responses": {"200": {}}}},
        "/api/cart": {"get": {"x-kind": "readback", "responses": {"200": {}}}},
        "/api/cart/items": {"post": {"x-kind": "state-write", "requestBody": {
            "application/json": {"schema": {"type": "object",
                "required": ["sku"],
                "properties": {"sku": {"type": "string", "enum": list(CATALOG)},
                               "qty": {"type": "integer", "minimum": 1}}}}},
            "responses": {"201": {}}}},
        "/api/coupon/apply": {"post": {"x-kind": "state-write", "requestBody": {
            "application/json": {"schema": {"type": "object",
                "required": ["code"],
                "properties": {"code": {"type": "string"}}}}},
            "responses": {"200": {}}}},
        "/api/coupon/redeem": {"post": {"x-kind": "state-write", "requestBody": {
            "application/json": {"schema": {"type": "object",
                "required": ["code"],
                "properties": {"code": {"type": "string"}}}}},
            "responses": {"200": {}}}},
        "/api/checkout/init": {"post": {"x-kind": "state-write", "responses": {"201": {}}}},
        "/api/checkout/confirm": {"post": {"x-kind": "state-write", "requestBody": {
            "application/json": {"schema": {"type": "object",
                "required": ["order_id"],
                "properties": {"order_id": {"type": "string"}}}}},
            "responses": {"200": {}}}},
        "/api/orders/{order_id}": {"get": {"x-kind": "readback",
            "parameters": [{"name": "order_id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}}}},
        "/api/orders/{order_id}/ship": {"post": {"x-kind": "state-write",
            "parameters": [{"name": "order_id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}}}},
        "/api/orders/{order_id}/refund": {"post": {"x-kind": "state-write",
            "parameters": [{"name": "order_id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}}}},
        "/api/refunds/async": {"post": {"x-kind": "state-write-async", "requestBody": {
            "application/json": {"schema": {"type": "object",
                "required": ["order_id"],
                "properties": {"order_id": {"type": "string"}}}}},
            "responses": {"202": {}}}},
        "/api/callbacks/{marker}": {"get": {"x-kind": "callback",
            "parameters": [{"name": "marker", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {}}}},
        "/api/ledger": {"get": {"x-kind": "readback", "responses": {"200": {}}}},
    },
}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8377)
    args = ap.parse_args()
    app.run(host="127.0.0.1", port=args.port, threaded=True, use_reloader=False)

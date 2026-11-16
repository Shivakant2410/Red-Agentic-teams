"""Freightlane — hard-lab target (research: see ../RESEARCH.md §3 ground truth).

A freight-forwarding SaaS API with 8 covert vulnerabilities and 2 decoys.
Loopback-only Flask; stale partial OpenAPI; freight vocabulary (no dvlba-shop
keyword overlap). Protocol family kept per the fairness contract: register /
login / wallet / health / JSON / bearer.

Run:  python target/app.py --port 8407
"""
import argparse
import json
import math
import threading
import time
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)

LOCK = threading.Lock()
ACCOUNTS = {}      # username -> {password, token, balance_cents, claimed}
SHIPMENTS = {}     # shipment_id -> {...}
VOUCHERS = {}      # voucher_id -> {...}
PAYOUTS = {}       # payout_id -> {...}
RECENT = []        # global append-order of shipment ids (the GV-2 leak)
START_BALANCE = 100000


def _auth():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    token = h[7:]
    for name, acc in ACCOUNTS.items():
        if acc["token"] == token:
            return name
    return None


def _credit(name, cents):
    with LOCK:
        ACCOUNTS[name]["balance_cents"] += cents


def _balance(name):
    with LOCK:
        return ACCOUNTS[name]["balance_cents"]


def rate_cents(weight, service):
    return weight * 1999 + (100000 if service == "express" else 0)


# ----------------------------------------------------- protocol family ----
@app.post("/api/register")
def register():
    b = request.get_json(silent=True) or {}
    name, pw = b.get("username"), b.get("password")
    if not name or not pw or name in ACCOUNTS:
        return jsonify(error="bad username or taken"), 400
    ACCOUNTS[name] = {"password": pw, "token": uuid.uuid4().hex,
                      "balance_cents": START_BALANCE, "claimed": False}
    return jsonify(username=name), 201


@app.post("/api/login")
def login():
    b = request.get_json(silent=True) or {}
    acc = ACCOUNTS.get(b.get("username") or "")
    if not acc or acc["password"] != b.get("password"):
        return jsonify(error="bad credentials"), 401
    return jsonify(token=acc["token"])


@app.get("/api/wallet")
def wallet():
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    return jsonify(balance_cents=_balance(name))


@app.get("/health")
def health():
    return jsonify(status="ok")


# ------------------------------------------- documented clean half --------
@app.post("/api/shipments")
def shipment_create():
    """Documented create. D-2: known-field negative (weight_kg) is rejected.
    GV-3: undocumented `rate_cents` field overrides pricing (mass-assign)."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    b = request.get_json(silent=True) or {}
    w = b.get("weight_kg")
    if not isinstance(w, int) or isinstance(w, bool) or w < 1:
        return jsonify(error="weight_kg must be a positive integer"), 400
    service = b.get("service", "standard")
    if service not in ("standard", "express"):
        return jsonify(error="bad service"), 400
    if "rate_cents" in b:                       # GV-3 mass-assign override
        try:
            rate = int(b["rate_cents"])
        except (TypeError, ValueError):
            return jsonify(error="bad rate_cents"), 400
    else:
        rate = rate_cents(w, service)
    _credit(name, -rate)                        # rate <= 0 -> wallet CREDITS
    sid = "SHP-" + uuid.uuid4().hex[:10]
    with LOCK:
        SHIPMENTS[sid] = {"shipment_id": sid, "owner": name, "weight_kg": w,
                          "service": service, "rate_cents": rate,
                          "status": "booked", "picked_up_at": time.time()}
        RECENT.append(sid)
        del RECENT[:-50]
    return jsonify(SHIPMENTS[sid]), 201


@app.get("/api/shipments/<sid>")
def shipment_get(sid):
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s:
        return jsonify(error="not found"), 404
    return jsonify(s)


@app.get("/api/shipments/recent")
def shipments_recent():
    """Documented as 'your recent shipments'. GV-2: returns the GLOBAL list,
    including other tenants' objects."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    out = [dict(SHIPMENTS[sid]) for sid in RECENT[-5:] if sid in SHIPMENTS]
    return jsonify(shipments=out)


@app.post("/api/shipments/<sid>/rerate")
def shipment_rerate(sid):
    """Documented. GV-7 rounding drift: charge on increase is the exact
    delta; refund on decrease rounds UP to whole currency units."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s or s["owner"] != name:
        return jsonify(error="not found"), 404
    b = request.get_json(silent=True) or {}
    w = b.get("weight_kg")
    if not isinstance(w, int) or isinstance(w, bool) or w < 1:
        return jsonify(error="weight_kg must be a positive integer"), 400
    new_rate = rate_cents(w, s["service"])
    delta = new_rate - s["rate_cents"]
    if delta > 0:
        _credit(name, -delta)
        applied = -delta                        # exact charge
    elif delta < 0:
        refund = int(math.ceil(float(-delta) / 100.0)) * 100   # round UP
        _credit(name, refund)
        applied = refund
    else:
        applied = 0
    with LOCK:
        s["weight_kg"], s["rate_cents"] = w, new_rate
    return jsonify(delta_cents=applied, rate_cents=new_rate)


@app.post("/api/credits/claim")
def credits_claim():
    """D-1 decoy: per-account signup credit, properly locked. Exactly once."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    acc = ACCOUNTS[name]
    with LOCK:
        if acc["claimed"]:
            return jsonify(error="already claimed"), 409
        acc["claimed"] = True
    _credit(name, 500)
    return jsonify(credited_cents=500), 201


# ------------------------------------------------- covert half: vouchers --
@app.post("/api/vouchers")
def voucher_create():
    """GV-1 surface: undocumented resource."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    b = request.get_json(silent=True) or {}
    face = b.get("face_cents", 30000)
    if not isinstance(face, int) or isinstance(face, bool) or \
            not (1 <= face <= 50000):
        return jsonify(error="face_cents out of range"), 400
    vid = "VCH-" + uuid.uuid4().hex[:10]
    with LOCK:
        VOUCHERS[vid] = {"voucher_id": vid, "owner": name,
                         "face_cents": face, "released": False,
                         "consumed": False}
    return jsonify(VOUCHERS[vid]), 201


@app.post("/api/vouchers/<vid>/release")
def voucher_release(vid):
    """GV-1: credits the face value but never marks released -> repeatable."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    v = VOUCHERS.get(vid)
    if not v or v["owner"] != name:
        return jsonify(error="not found"), 404
    _credit(name, v["face_cents"])              # BUG: released flag untouched
    return jsonify(credited_cents=v["face_cents"], released=True), 200


@app.post("/api/vouchers/<vid>/consume")
def voucher_consume(vid):
    """GV-6: single-use check-then-act with a widened window."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    v = VOUCHERS.get(vid)
    if not v:
        return jsonify(error="not found"), 404
    if v["consumed"]:
        return jsonify(error="already consumed"), 409
    time.sleep(0.003)                           # check-then-act window
    with LOCK:
        first = not v["consumed"]
        v["consumed"] = True
    if first:
        _credit(name, v["face_cents"])
        return jsonify(credited_cents=v["face_cents"]), 200
    return jsonify(error="already consumed"), 409


# ------------------------------------------ covert half: cross-tenant -----
@app.post("/api/shipments/<sid>/rebook")
def shipment_rebook(sid):
    """GV-2: no ownership check; broker bonus 10% of rate pays the CALLER."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s:
        return jsonify(error="not found"), 404
    bonus = s["rate_cents"] // 10
    _credit(name, bonus)                        # BUG: caller, not owner
    return jsonify(broker_bonus_cents=bonus, shipment_id=sid), 200


# ------------------------------------------- covert half: payouts --------
def _settle_payout(pid):
    p = PAYOUTS.get(pid)
    if not p or p["status"] != "pending":
        return
    name = p["owner"]
    acc = ACCOUNTS.get(name)
    if not acc:
        return
    with LOCK:
        p["status"] = "settled"
    _credit(name, -p["amount_cents"])           # GV-4: no balance re-check


@app.post("/api/payouts")
def payout_create():
    """GV-4 surface: async payout; balance checked at CREATE only."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    b = request.get_json(silent=True) or {}
    amt = b.get("amount_cents")
    if not isinstance(amt, int) or isinstance(amt, bool) or \
            not (1 <= amt <= 100000):
        return jsonify(error="amount_cents out of range"), 400
    if _balance(name) < amt:
        return jsonify(error="insufficient balance"), 400
    pid = "PAY-" + uuid.uuid4().hex[:10]
    with LOCK:
        PAYOUTS[pid] = {"payout_id": pid, "owner": name,
                        "amount_cents": amt, "status": "pending"}
    threading.Timer(1.1, _settle_payout, (pid,)).start()
    return jsonify(payout_id=pid, status="pending",
                   event="/api/payouts/%s/events" % pid), 202


@app.get("/api/payouts/<pid>/events")
def payout_events(pid):
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    p = PAYOUTS.get(pid)
    if not p or p["owner"] != name:
        return jsonify(error="not found"), 404
    out = {"status": p["status"]}
    if p["status"] == "canceled":
        out["refund_cents"] = p.get("refund_cents", 0)
    return jsonify(out)


@app.post("/api/payouts/<pid>/cancel")
def payout_cancel(pid):
    """GV-5: cancel accepted AFTER settle -> credits the amount back while
    the external transfer stands."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    p = PAYOUTS.get(pid)
    if not p or p["owner"] != name:
        return jsonify(error="not found"), 404
    if p["status"] == "canceled":
        return jsonify(error="already canceled"), 409
    refund = 0
    if p["status"] == "settled":
        refund = p["amount_cents"]              # BUG: post-settlement credit
        _credit(name, refund)
    with LOCK:
        p["status"] = "canceled"
        p["refund_cents"] = refund
    return jsonify(status="canceled", refund_cents=refund), 200


# ----------------------------------- covert half: shipment FSM / GV-8 -----
@app.post("/api/shipments/<sid>/pickup")
def shipment_pickup(sid):
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s or s["owner"] != name:
        return jsonify(error="not found"), 404
    if s["status"] != "booked":
        return jsonify(error="bad state"), 409
    with LOCK:
        s["status"] = "picked_up"
    return jsonify(status="picked_up")


@app.post("/api/shipments/<sid>/deliver")
def shipment_deliver(sid):
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s or s["owner"] != name:
        return jsonify(error="not found"), 404
    if s["status"] != "picked_up":
        return jsonify(error="bad state"), 409
    with LOCK:
        s["status"] = "delivered"
    return jsonify(status="delivered")


@app.post("/api/shipments/<sid>/settle")
def shipment_settle(sid):
    """GV-8: guard checks picked_up_at (set at BOOKING), not the delivered
    state -> settle (carrier payout) accepted straight from `booked`."""
    name = _auth()
    if not name:
        return jsonify(error="auth required"), 401
    s = SHIPMENTS.get(sid)
    if not s or s["owner"] != name:
        return jsonify(error="not found"), 404
    if s["status"] == "settled":
        return jsonify(error="already settled"), 409
    if s.get("picked_up_at") is None:           # BUG: always set at booking
        return jsonify(error="not picked up"), 409
    payout = s["rate_cents"]
    _credit(name, payout)
    with LOCK:
        s["status"] = "settled"
    return jsonify(status="settled", payout_cents=payout)


# ------------------------------------------- stale partial openapi --------
@app.get("/openapi.json")
def openapi_doc():
    """Lever L1: documents ONLY the clean half. Every covert resource/verb is
    absent. Param style {shipment_id} (never {order_id}/{id})."""
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Freightlane API", "version": "1.2.0"},
        "paths": {
            "/api/shipments": {"post": {
                "summary": "Book a shipment",
                "requestBody": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["weight_kg"],
                    "properties": {
                        "weight_kg": {"type": "integer", "minimum": 1},
                        "service": {"type": "string",
                                    "enum": ["standard", "express"]}}}}}}},
            "/api/shipments/{shipment_id}": {"get": {
                "summary": "Shipment detail",
                "parameters": [{"name": "shipment_id", "in": "path",
                                "required": True, "schema": {"type": "string"}}]}},
            "/api/shipments/{shipment_id}/rerate": {"post": {
                "summary": "Re-rate after weight change",
                "parameters": [{"name": "shipment_id", "in": "path",
                                "required": True, "schema": {"type": "string"}}],
                "requestBody": {"application/json": {"schema": {
                    "type": "object", "required": ["weight_kg"],
                    "properties": {
                        "weight_kg": {"type": "integer",
                                      "minimum": 1}}}}}}},
            "/api/credits/claim": {"post": {
                "summary": "Claim the new-account credit",
                "x-kind": "claim"}},
            "/api/wallet": {"get": {"summary": "Account balance"}},
        }})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    args = ap.parse_args()
    app.run(host="127.0.0.1", port=args.port, threaded=True, use_reloader=False)

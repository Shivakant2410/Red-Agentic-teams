"""helios-billing — the FORTRESS lab: a SaaS billing API whose business-logic
bugs are engineered to be HARD TO FIND (Phase D target for statefuzz/swarm).

Domain shift from dvlba-shop: subscriptions, seats, proration, invoices,
payouts, promo credits. Every dvlba constant (SKUs, WELCOME10, ONCE-9K4T,
cart/checkout endpoints) is intentionally absent — surface-blind probes land
on 404s. Money is integer cents everywhere (exact arithmetic oracles).

ALL bugs are intentional and enumerated in seeds.py (ground truth for
evaluation ONLY — the tools never import this file). Difficulty design:

  every seed defeats single-request scanners:
  - F2 needs N repeated cycles to accumulate sub-cent rounding drift
  - F3/F9/F10 only fire from terminal/deferred states reached lawfully
  - F4 is a TOCTOU across an async settle seam (0.6s worker)
  - F5 leaks other tenants' ids; F6 alone is unexploitable without F5
  - F7/F8 inject fields that appear in NO schema (mass assignment)
  - F1 is guarded against sequential replay; only a synchronized race wins
  - /api/payouts/{pid}/release exists but is in NO openapi document

Threaded dev server, loopback only. Run:  python target/app.py --port 8407
"""
import argparse
import threading
import time
import uuid

from flask import Flask, g, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------- state ----
BALANCE = {}      # username -> cents (prepaid credit)
USERS = {}        # username -> {"password": str}
TOKENS = {}       # token -> username
PLANS = {
    "starter":    {"unit_cents": 2900,  "min_seats": 1},
    "pro":        {"unit_cents": 12900, "min_seats": 3},
    "enterprise": {"unit_cents": 49900, "min_seats": 10},
}
SUBS = {}         # sid -> {"id","owner","plan","seats","status","cancels":{}}
INVOICES = {}     # iid -> {"id","owner","sub_id","plan","seats","unit_cents",
                  #          "total_cents","status"}
PAYOUTS = {}      # pid -> {"id","owner","amount_cents","status","settled_at",
                  #          "external_transfers","event_id"}
EVENTS = {}       # eid -> {"id","owner","kind","status","payout_id",
                  #          "amount_cents"}
PROMOS = {"LAUNCH-2026": {"face_cents": 25000, "quota": 3, "claimed": 0}}
AUDIT = []        # GLOBAL audit trail — every tenant's entries (seed F5)

CYCLE_DAYS = 30
DAYS_LEFT = 13    # every subscription is created 13 days into its cycle


def _audit(actor, action, ref, amount=0):
    AUDIT.append({"ts": time.time(), "actor": actor, "action": action,
                  "ref": ref, "amount_cents": amount})


def _new_user(name):
    USERS[name] = {"password": "pw-" + name}
    BALANCE[name] = 1000000          # $10,000 starting prepaid credit


def _prorate_floor(seats_delta, unit):
    """floor(seats_delta * unit * DAYS_LEFT / CYCLE_DAYS) — upgrade charge."""
    return (seats_delta * unit * DAYS_LEFT) // CYCLE_DAYS


def _prorate_ceil(seats_delta, unit):
    """ceil(seats_delta * unit * DAYS_LEFT / CYCLE_DAYS) — downgrade credit."""
    return -((-seats_delta * unit * DAYS_LEFT) // CYCLE_DAYS)


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
    return jsonify(ok=True, app="helios-billing")


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


@app.get("/api/plans")
def plans():
    return jsonify(plans=PLANS)


# ------------------------------------------------------- subscriptions -----
@app.post("/api/subscriptions")
def sub_create():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    plan = b.get("plan")
    if plan not in PLANS:
        return jsonify(error="unknown plan"), 400
    seats = b.get("seats")
    if not isinstance(seats, int) or seats < PLANS[plan]["min_seats"]:
        return jsonify(error="seats below plan minimum"), 400
    # SEED F7: client-supplied unit_cents overrides the official unit price
    #           (mass assignment — the field is documented nowhere)
    unit = b.get("unit_cents", PLANS[plan]["unit_cents"])
    if not isinstance(unit, int) or unit < 0:
        return jsonify(error="bad unit price"), 400
    sid = "SUB-" + uuid.uuid4().hex[:12]
    iid = "INV-" + uuid.uuid4().hex[:12]
    SUBS[sid] = {"id": sid, "owner": g.user, "plan": plan, "seats": seats,
                 "status": "active", "cancels": {}}
    INVOICES[iid] = {"id": iid, "owner": g.user, "sub_id": sid, "plan": plan,
                     "seats": seats, "unit_cents": unit,
                     "total_cents": seats * unit, "status": "open"}
    _audit(g.user, "subscription.create", sid, seats * unit)
    return jsonify(subscription_id=sid, invoice_id=iid, plan=plan,
                   seats=seats, unit_cents=unit, total_cents=seats * unit,
                   status="active"), 201


@app.get("/api/subscriptions")
def sub_list():
    if not g.user:
        return _deny()
    mine = [s for s in SUBS.values() if s["owner"] == g.user]
    return jsonify(subscriptions=mine), 200


@app.get("/api/subscriptions/<sid>")
def sub_get(sid):
    if not g.user:
        return _deny()
    s = SUBS.get(sid)
    if not s:
        return jsonify(error="unknown subscription"), 404
    if s["owner"] != g.user:                       # ownership ENFORCED here
        return jsonify(error="not your subscription"), 403
    return jsonify(s), 200


@app.post("/api/subscriptions/<sid>/seats")
def sub_seats(sid):
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    s = SUBS.get(sid)
    if not s:
        return jsonify(error="unknown subscription"), 404
    # SEED F6: NO ownership check — any authenticated caller may resize any
    #          tenant's subscription, and the proration credit lands in the
    #          CALLER's balance, not the owner's.
    # SEED F3: NO state guard — resize is accepted even on a CANCELED
    #          subscription and re-credits the full remaining period.
    seats = b.get("seats")
    if not isinstance(seats, int) or seats < 1:
        return jsonify(error="seats must be >= 1"), 400
    unit = PLANS[s["plan"]]["unit_cents"]          # priced at the ORIGINAL plan
    # SEED F8: undocumented 'plan' field silently switches the plan without
    #          repricing (feature escalation at the old unit price) — the
    #          unit was captured above, BEFORE this overwrite.
    if "plan" in b:
        s["plan"] = b["plan"]
    delta = seats - s["seats"]
    if delta == 0:
        return jsonify(subscription_id=sid, seats=seats, plan=s["plan"],
                       delta_cents=0, status=s["status"]), 200
    if delta > 0:                                  # upgrade: charge caller
        charge = _prorate_floor(delta, unit)
        if BALANCE[g.user] < charge:
            return jsonify(error="insufficient balance"), 402
        BALANCE[g.user] -= charge
        _audit(g.user, "subscription.seats.upgrade", sid, -charge)
        moved = -charge
    else:                                          # downgrade: credit CALLER
        credit = _prorate_ceil(-delta, unit)
        BALANCE[g.user] += credit
        _audit(g.user, "subscription.seats.downgrade", sid, credit)
        moved = credit
    s["seats"] = seats
    return jsonify(subscription_id=sid, seats=seats, plan=s["plan"],
                   delta_cents=moved, status=s["status"]), 200


@app.post("/api/subscriptions/<sid>/cancel")
def sub_cancel(sid):
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    s = SUBS.get(sid)
    if not s:
        return jsonify(error="unknown subscription"), 404
    if s["owner"] != g.user:                       # ownership ENFORCED here
        return jsonify(error="not your subscription"), 403
    reason = b.get("reason", "unspecified")
    if s["status"] == "canceled":
        # SEED F9: dedupe key is (subscription, reason) instead of the
        #          subscription itself — a DIFFERENT reason string re-credits
        #          the full prorated remainder a second time.
        if reason in s["cancels"]:
            return jsonify(error="duplicate cancel request",
                           dedupe_key=[sid, reason]), 409
        credit = _prorate_ceil(s["seats"], PLANS[s["plan"]]["unit_cents"])
        BALANCE[g.user] += credit
        s["cancels"][reason] = credit
        _audit(g.user, "subscription.cancel.duplicate-window", sid, credit)
        return jsonify(subscription_id=sid, status="canceled",
                       credited_cents=credit, cancel_count=len(s["cancels"]))
    credit = _prorate_ceil(s["seats"], PLANS[s["plan"]]["unit_cents"])
    BALANCE[g.user] += credit
    s["status"] = "canceled"
    s["cancels"][reason] = credit
    _audit(g.user, "subscription.cancel", sid, credit)
    return jsonify(subscription_id=sid, status="canceled",
                   credited_cents=credit, cancel_count=len(s["cancels"]))


# ------------------------------------------------------------- invoices ----
@app.get("/api/invoices/<iid>")
def invoice_get(iid):
    if not g.user:
        return _deny()
    inv = INVOICES.get(iid)
    if not inv:
        return jsonify(error="unknown invoice"), 404
    if inv["owner"] != g.user:
        return jsonify(error="not your invoice"), 403
    return jsonify(inv), 200


@app.post("/api/invoices/<iid>/pay")
def invoice_pay(iid):
    if not g.user:
        return _deny()
    inv = INVOICES.get(iid)
    if not inv:
        return jsonify(error="unknown invoice"), 404
    if inv["owner"] != g.user:
        return jsonify(error="not your invoice"), 403
    if inv["status"] == "paid":
        return jsonify(error="invoice already paid"), 409
    if BALANCE[g.user] < inv["total_cents"]:
        return jsonify(error="insufficient balance"), 402
    BALANCE[g.user] -= inv["total_cents"]
    inv["status"] = "paid"
    _audit(g.user, "invoice.pay", iid, -inv["total_cents"])
    return jsonify(invoice_id=iid, status="paid",
                   charged_cents=inv["total_cents"]), 200


# ---------------------------------------------------------------- promos ----
@app.post("/api/promo/claim")
def promo_claim():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    p = PROMOS.get(b.get("code") or "")
    if not p:
        return jsonify(error="unknown promo code"), 400
    if p["claimed"] >= p["quota"]:                 # SEED F1: check-then-act,
        return jsonify(error="quota exhausted", quota=p["quota"],      # 35ms
                       claimed=p["claimed"]), 409                      # window
    time.sleep(0.035)
    p["claimed"] += 1
    BALANCE[g.user] += p["face_cents"]
    _audit(g.user, "promo.claim", b.get("code"), p["face_cents"])
    return jsonify(credited_cents=p["face_cents"], claimed=p["claimed"]), 200


# --------------------------------------------------------------- credits ----
@app.post("/api/credits/transfer")
def credits_transfer():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    to = b.get("to_account")
    amount = b.get("amount_cents")
    if to not in USERS:
        return jsonify(error="unknown recipient"), 400
    if not isinstance(amount, int) or amount <= 0:
        return jsonify(error="amount must be positive"), 400
    if BALANCE[g.user] < amount:
        return jsonify(error="insufficient balance"), 402
    BALANCE[g.user] -= amount
    BALANCE[to] += amount
    _audit(g.user, "credits.transfer", to, -amount)
    _audit(to, "credits.received", g.user, amount)
    return jsonify(from_account=g.user, to_account=to, amount_cents=amount,
                   balance_cents=BALANCE[g.user]), 200


# --------------------------------------------------------------- payouts ----
def _settle_payout(pid):
    p = PAYOUTS[pid]
    # SEED F4: no balance RE-CHECK at settle time — the pre-check happened at
    #          request time, but the debit lands here, 0.6s later.
    BALANCE[p["owner"]] -= p["amount_cents"]
    p["status"] = "settled"
    p["settled_at"] = time.time()
    p["external_transfers"] += 1
    _audit(p["owner"], "payout.settle", pid, -p["amount_cents"])
    ev = p["event_id"]
    if ev:
        EVENTS[ev]["status"] = "done"


@app.post("/api/payouts")
def payout_create():
    if not g.user:
        return _deny()
    b = request.get_json(silent=True) or {}
    amount = b.get("amount_cents")
    if not isinstance(amount, int) or amount < 100:
        return jsonify(error="minimum payout is 100 cents"), 400
    if BALANCE[g.user] < amount:
        return jsonify(error="insufficient balance"), 402
    pid = "PAY-" + uuid.uuid4().hex[:12]
    eid = "EVT-" + uuid.uuid4().hex[:12]
    PAYOUTS[pid] = {"id": pid, "owner": g.user, "amount_cents": amount,
                    "status": "requested", "settled_at": None,
                    "external_transfers": 0, "event_id": eid}
    EVENTS[eid] = {"id": eid, "owner": g.user, "kind": "payout.settle",
                   "status": "pending", "payout_id": pid,
                   "amount_cents": amount}
    _audit(g.user, "payout.request", pid, amount)

    def _worker():
        time.sleep(0.6)
        p = PAYOUTS.get(pid)
        if p and p["status"] == "requested":
            _settle_payout(pid)

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify(payout_id=pid, event="/api/events/%s" % eid,
                   status="requested"), 202


@app.get("/api/payouts/<pid>")
def payout_get(pid):
    if not g.user:
        return _deny()
    p = PAYOUTS.get(pid)
    if not p:
        return jsonify(error="unknown payout"), 404
    if p["owner"] != g.user:
        return jsonify(error="not your payout"), 403
    return jsonify({k: v for k, v in p.items() if k != "event_id"}), 200


@app.post("/api/payouts/<pid>/cancel")
def payout_cancel(pid):
    if not g.user:
        return _deny()
    p = PAYOUTS.get(pid)
    if not p:
        return jsonify(error="unknown payout"), 404
    if p["owner"] != g.user:
        return jsonify(error="not your payout"), 403
    # SEED F10: NO status guard — canceling an ALREADY-SETTLED payout refunds
    #           the balance even though the external transfer was sent. The
    #           attacker receives the external money AND keeps the credit.
    if p["status"] == "requested":
        p["status"] = "canceled"
        return jsonify(payout_id=pid, status="canceled",
                       refunded_cents=0), 200
    BALANCE[g.user] += p["amount_cents"]
    p["status"] = "canceled"
    _audit(g.user, "payout.cancel.after-settle", pid, p["amount_cents"])
    return jsonify(payout_id=pid, status="canceled",
                   refunded_cents=p["amount_cents"]), 200


@app.post("/api/payouts/<pid>/release")
def payout_release(pid):
    """HIDDEN ops endpoint — deliberately absent from openapi.json."""
    if not g.user:
        return _deny()
    p = PAYOUTS.get(pid)
    if not p:
        return jsonify(error="unknown payout"), 404
    if p["owner"] != g.user:
        return jsonify(error="not your payout"), 403
    if p["status"] != "requested":
        return jsonify(error="payout not in releasable state"), 409
    _settle_payout(pid)
    return jsonify(payout_id=pid, status="settled",
                   amount_cents=p["amount_cents"]), 200


# ---------------------------------------------------------------- events ----
@app.get("/api/events/<eid>")
def event_get(eid):
    if not g.user:
        return _deny()
    e = EVENTS.get(eid)
    if not e:
        return jsonify(error="unknown event"), 404
    if e["owner"] != g.user:
        return jsonify(error="not your event"), 403
    return jsonify(e), 200


# ----------------------------------------------------------------- audit ----
@app.get("/api/audit")
def audit():
    if not g.user:
        return _deny()
    # SEED F5: GLOBAL audit trail — no tenant filter. Every authenticated
    #          account reads every other tenant's object identifiers.
    return jsonify(entries=AUDIT[-64:]), 200


# -------------------------------------------------------------- openapi ----
def _body(props, required=None):
    return {"application/json": {"schema": {
        "type": "object", "required": required or [],
        "properties": props}}}


def _param(name):
    return [{"name": name, "in": "path", "required": True,
             "schema": {"type": "string"}}]


OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "helios-billing", "version": "1.0"},
    "servers": [{"url": "http://127.0.0.1"}],
    "paths": {
        "/health": {"get": {"x-kind": "meta", "responses": {"200": {}}}},
        "/api/register": {"post": {"x-kind": "bootstrap",
            "requestBody": _body({"username": {"type": "string"},
                                  "password": {"type": "string"}},
                                 ["username", "password"]),
            "responses": {"201": {}}}},
        "/api/login": {"post": {"x-kind": "bootstrap",
            "requestBody": _body({"username": {"type": "string"},
                                  "password": {"type": "string"}},
                                 ["username", "password"]),
            "responses": {"200": {}}}},
        "/api/wallet": {"get": {"x-kind": "readback",
                                "responses": {"200": {}}}},
        "/api/plans": {"get": {"x-kind": "meta", "responses": {"200": {}}}},
        "/api/subscriptions": {"post": {"x-kind": "state-write",
            "requestBody": _body({
                "plan": {"type": "string",
                         "enum": sorted(PLANS)},
                "seats": {"type": "integer", "minimum": 1}}),
            "responses": {"201": {}}}},
        "/api/subscriptions/{subscription_id}": {"get": {
            "x-kind": "readback",
            "parameters": _param("subscription_id"),
            "responses": {"200": {}}}},
        "/api/subscriptions/{subscription_id}/seats": {"post": {
            "x-kind": "state-write",
            "parameters": _param("subscription_id"),
            "requestBody": _body({
                "seats": {"type": "integer", "minimum": 1}}),
            "responses": {"200": {}}}},
        "/api/subscriptions/{subscription_id}/cancel": {"post": {
            "x-kind": "state-write",
            "parameters": _param("subscription_id"),
            "requestBody": _body({
                "reason": {"type": "string"}}),
            "responses": {"200": {}}}},
        "/api/invoices/{invoice_id}": {"get": {"x-kind": "readback",
            "parameters": _param("invoice_id"),
            "responses": {"200": {}}}},
        "/api/invoices/{invoice_id}/pay": {"post": {"x-kind": "state-write",
            "parameters": _param("invoice_id"),
            "responses": {"200": {}}}},
        "/api/promo/claim": {"post": {"x-kind": "state-write",
            "requestBody": _body({"code": {"type": "string"}}),
            "responses": {"200": {}}}},
        "/api/credits/transfer": {"post": {"x-kind": "state-write",
            "requestBody": _body({
                "to_account": {"type": "string"},
                "amount_cents": {"type": "integer", "minimum": 1}},
                ["to_account", "amount_cents"]),
            "responses": {"200": {}}}},
        "/api/payouts": {"post": {"x-kind": "state-write-async",
            "requestBody": _body({
                "amount_cents": {"type": "integer", "minimum": 100}}),
            "responses": {"202": {}}}},
        "/api/payouts/{payout_id}": {"get": {"x-kind": "readback",
            "parameters": _param("payout_id"),
            "responses": {"200": {}}}},
        "/api/payouts/{payout_id}/cancel": {"post": {"x-kind": "state-write",
            "parameters": _param("payout_id"),
            "responses": {"200": {}}}},
        "/api/events/{event_id}": {"get": {"x-kind": "callback",
            "parameters": _param("event_id"),
            "responses": {"200": {}}}},
        "/api/audit": {"get": {"x-kind": "readback",
                               "responses": {"200": {}}}},
    },
}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    args = ap.parse_args()
    app.run(host="127.0.0.1", port=args.port, threaded=True, use_reloader=False)

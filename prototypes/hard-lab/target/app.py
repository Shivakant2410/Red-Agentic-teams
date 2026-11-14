"""meridian-vault — a deliberately hard local lab (Phase D target).

Design contract: RESEARCH.md D1-D7, ground truth GROUND_TRUTH.md.
NO mock: real Flask over real HTTP on loopback only. The engines attack this
process exactly like any other scope.

Disclosure tier (RESEARCH.md D2):
  - NO /openapi.json (404).
  - GET /            -> HTML with a hint comment pointing at the service dir.
  - GET /api         -> thin route index: resources + verbs only. No schemas,
                        no parameter names, no state machine.
  - 422 error contract -> leaks required fields + types + minimums (realistic
                        for validation-heavy APIs). This is the schema trail.

Seeds (see GROUND_TRUTH.md for the scorer's view):
  S1 quota race      POST /api/vouchers/claim  (global quota, 2ms window)
  S2 settle+cancel   POST /api/payouts/{id}/cancel credits after settlement
  S3 async TOCTOU    payout settle debits without balance re-check
  S4 rounding drift  POST /api/vaults/{id}/resize asymmetric proration
  S5 reason dedupe   vault cancel dedupe keyed by (vault, reason)
  S6 terminal reopen resize accepted on canceled vault (residual re-credit)
  S7 cross-tenant    GET /api/audit leaks ids; vault writes skip owner check,
                     proration lands in the CALLER's wallet
  S8 existence oracle GET /api/accounts/{id}: 403 known vs 404 unknown

Decoys (a finding here is a FALSE POSITIVE):
  D1 /.env sample placeholders · D2 /payouts/{id}/retry is safe (409 unless
  failed; nothing ever fails) · D3 negative amounts validated · D4 account
  reads enforced (403).
"""
import argparse
import math
import secrets
import threading
import time
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)

START_BALANCE = 250000          # cents
VAULT_MIN = 100
PAYOUT_MIN = 100
VOUCHER_CODE = "MERIDIAN-DROP"  # engagement-brief artifact (real campaigns ship codes)
VOUCHER_QUOTA = 3
VOUCHER_VALUE = 5000
FEE_NUM, FEE_DEN = 999, 1000    # 0.1% proration spread; asymmetric rounding below

DB_LOCK = threading.Lock()      # guards registries; NOT the seeded race windows
ACCTS = {}                      # username -> acct
TOKENS = {}                     # token -> username
VAULTS = {}                     # vault_id -> vault
PAYOUTS = {}                    # payout_id -> payout
EVENTS = {}                     # event token -> status dict
CLAIMED_BY = set()
CLAIMED_COUNT = 0
AUDIT = []


def _audit(actor, action, obj):
    AUDIT.append({"actor": actor, "action": action, "object": obj,
                  "ts": time.time()})


def _acct_from_auth():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    name = TOKENS.get(h[7:])
    return ACCTS.get(name) if name else None


def _err(missing=None, invalid=None, types=None, minimums=None, status=422):
    return jsonify({"error": {"missing_fields": missing or [],
                              "invalid_fields": invalid or {},
                              "types": types or {},
                              "minimums": minimums or {}}}), status


def _int_field(body, field, minimum, invalid, types, minimums):
    """Validation helper: returns value or None after registering the problem.
    Missing fields still declare their expected type + minimum (complete
    error contract — validation layers disclose the schema, RESEARCH.md D2)."""
    v = body.get(field)
    if v is None:
        types[field] = "integer"
        minimums[field] = minimum
        return None
    if not isinstance(v, int) or isinstance(v, bool) or v < minimum:
        invalid[field] = "must be integer >= %d" % minimum
        types[field] = "integer"
        minimums[field] = minimum
        return None
    return v


# ------------------------------------------------------------ discovery ---
@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "meridian-vault"})


@app.get("/")
def index():
    return ("<html><head><link rel=\"stylesheet\" href=\"/static/app.css\">"
            "<script src=\"/static/app-config.js\"></script></head>"
            "<body><h1>Meridian Vault</h1>"
            "<p>Prepaid escrow console. Please sign in.</p>"
            "<!-- service directory: GET /api (verbs only; schemas omitted "
            "by policy) -->"
            "<form><input name=\"username\"><input name=\"password\" "
            "type=\"password\"></form></body></html>")


@app.get("/static/app-config.js")
def app_config():
    return ("window.MV_CONFIG = {apiBase: \"/api\", version: \"2.3.1\", "
            "features: [\"vaults\", \"payouts\", \"vouchers\", "
            "\"transfers\"]};")


@app.get("/static/app.css")
def app_css():
    return "body{font-family:sans-serif}", 200, {"Content-Type": "text/css"}


@app.get("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /static/\n"


@app.get("/.env")                       # D1 decoy: sample placeholders only
def dot_env():
    return ("MV_SAMPLE_ENV=1\n"
            "# integration-test fixture; sample placeholders, NOT secrets\n"
            "DATABASE_URL=sqlite:///sample.db\n"
            "API_KEY=SAMPLE-KEY-DO-NOT-USE\n")


@app.get("/api")                        # thin route index (D2)
def route_index():
    return jsonify({
        "service": "meridian-vault-api", "version": "2.3.1",
        "disclosure": "verbs only; schemas omitted by policy",
        "resources": {
            "me": {"read": {"method": "GET", "path": "/api/me"}},
            "audit": {"read": {"method": "GET", "path": "/api/audit"}},
            "vaults": {
                "create": {"method": "POST", "path": "/api/vaults"},
                "object": {"method": "GET",
                           "path": "/api/vaults/{vault_id}"},
                "actions": [
                    {"verb": "resize", "method": "POST",
                     "path": "/api/vaults/{vault_id}/resize"},
                    {"verb": "cancel", "method": "POST",
                     "path": "/api/vaults/{vault_id}/cancel"}]},
            "payouts": {
                "create": {"method": "POST", "path": "/api/payouts"},
                "object": {"method": "GET",
                           "path": "/api/payouts/{payout_id}"},
                "actions": [
                    {"verb": "cancel", "method": "POST",
                     "path": "/api/payouts/{payout_id}/cancel"}]},
            "vouchers": {"actions": [
                {"verb": "claim", "method": "POST",
                 "path": "/api/vouchers/claim"}]},
            "transfers": {"actions": [
                {"verb": "transfer", "method": "POST",
                 "path": "/api/transfers"}]},
            "accounts": {"object": {"method": "GET",
                                    "path": "/api/accounts/{account_id}"}},
            "events": {"object": {"method": "GET",
                                  "path": "/api/events/{token}"}},
        }})


# -------------------------------------------------------------- accounts ---
@app.post("/api/register")
def register():
    body = request.get_json(silent=True) or {}
    u, p = body.get("username"), body.get("password")
    if not u or not p:
        return _err(missing=["username", "password"],
                    types={"username": "string", "password": "string"})
    with DB_LOCK:
        if u in ACCTS:
            return jsonify({"error": "username_taken"}), 409
        aid = "ACC-" + uuid.uuid4().hex[:10]
        ACCTS[u] = {"username": u, "password": p, "account_id": aid,
                    "balance_cents": START_BALANCE}
    return jsonify({"username": u, "account_id": aid})


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    u, p = body.get("username"), body.get("password")
    acct = ACCTS.get(u or "")
    if not acct or acct["password"] != p:
        return jsonify({"error": "invalid_credentials"}), 401
    tok = "tok-" + secrets.token_hex(12)
    TOKENS[tok] = u
    return jsonify({"token": tok})


@app.get("/api/me")
def me():
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"account_id": a["account_id"], "username": a["username"],
                    "balance_cents": a["balance_cents"]})


@app.get("/api/audit")                  # S7: GLOBAL trail, leaks object ids
def audit_log():
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"events": AUDIT[-60:]})


@app.get("/api/accounts/<account_id>")  # S8 oracle + D4 enforced read
def account_read(account_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    for acct in ACCTS.values():
        if acct["account_id"] == account_id:
            if acct["username"] != a["username"]:
                return jsonify({"error": "forbidden"}), 403   # enforced (D4)
            return jsonify({"account_id": account_id,
                            "username": acct["username"]})
    return jsonify({"error": "not_found"}), 404                    # S8 oracle


# ----------------------------------------------------------------- vaults ---
@app.post("/api/vaults")
def vault_create():
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    invalid, types, mins = {}, {}, {}
    target = _int_field(body, "target_cents", VAULT_MIN, invalid, types, mins)
    if target is None:
        missing = [] if "target_cents" in invalid else ["target_cents"]
        return _err(missing=missing, invalid=invalid, types=types,
                    minimums=mins)
    if a["balance_cents"] < target:
        return jsonify({"error": "insufficient_balance"}), 409
    vid = "VLT-" + uuid.uuid4().hex[:10]
    a["balance_cents"] -= target        # escrow debit
    VAULTS[vid] = {"vault_id": vid, "owner": a["username"],
                   "target_cents": target, "state": "funded"}
    _audit(a["username"], "vault.created", "vault:" + vid)
    return jsonify({"vault_id": vid, "target_cents": target,
                    "state": "funded"})


@app.get("/api/vaults/<vault_id>")
def vault_read(vault_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    v = VAULTS.get(vault_id)
    if not v:
        return jsonify({"error": "not_found"}), 404
    if v["owner"] != a["username"]:
        return jsonify({"error": "forbidden"}), 403    # READ is enforced...
    return jsonify(dict(v))


def _prorate(delta):
    """Asymmetric proration: refund rounds UP, charge rounds DOWN (S4)."""
    if delta < 0:
        return -((delta * FEE_NUM) // FEE_DEN)     # ceil(-delta * 0.999)
    return (delta * FEE_NUM) // FEE_DEN            # floor(delta * 0.999)


@app.post("/api/vaults/<vault_id>/resize")
def vault_resize(vault_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    invalid, types, mins = {}, {}, {}
    target = _int_field(body, "target_cents", 1, invalid, types, mins)
    if target is None:
        missing = [] if "target_cents" in invalid else ["target_cents"]
        return _err(missing=missing, invalid=invalid, types=types,
                    minimums=mins)
    v = VAULTS.get(vault_id)
    if not v:
        return jsonify({"error": "not_found"}), 404
    # S7: ownership check deliberately ABSENT on vault writes.
    # S6: terminal-state check deliberately ABSENT — a canceled vault takes
    #     the residual-withdrawal branch and re-credits the full target.
    if v["state"] == "canceled":
        credit = v["target_cents"]
        a["balance_cents"] += credit               # to the CALLER (S7 too)
        _audit(a["username"], "vault.residual", "vault:" + vault_id)
        return jsonify({"vault_id": vault_id, "state": "canceled",
                        "residual_credit": credit})
    delta = target - v["target_cents"]
    amt = _prorate(delta)
    if delta < 0:                                   # shrink -> refund CALLER
        a["balance_cents"] += amt
    else:                                           # grow -> charge CALLER
        if a["balance_cents"] < amt:
            return jsonify({"error": "insufficient_balance"}), 409
        a["balance_cents"] -= amt
    v["target_cents"] = target
    _audit(a["username"], "vault.resized", "vault:" + vault_id)
    return jsonify({"vault_id": vault_id, "target_cents": target,
                    "delta_cents": amt, "state": v["state"]})


@app.post("/api/vaults/<vault_id>/cancel")
def vault_cancel(vault_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    reason = body.get("reason")
    if reason is None:
        return _err(missing=["reason"], types={"reason": "string"})
    if not isinstance(reason, str) or not reason.strip():
        return _err(invalid={"reason": "must be non-empty string"},
                    types={"reason": "string"})
    v = VAULTS.get(vault_id)
    if not v:
        return jsonify({"error": "not_found"}), 404
    # S7: ownership check deliberately ABSENT here too.
    # S5: dedupe keyed by (vault_id, reason) — NOT by terminal state.
    if (vault_id, reason) in v.setdefault("cancel_reasons", set()):
        return jsonify({"error": "already_canceled_with_reason"}), 409
    if v["state"] == "canceled":
        # S5 bug: a DIFFERENT reason re-credits the full stored target.
        v["cancel_reasons"].add((vault_id, reason))
        credit = v["target_cents"]
        a["balance_cents"] += credit
        _audit(a["username"], "vault.canceled(again)", "vault:" + vault_id)
        return jsonify({"vault_id": vault_id, "state": "canceled",
                        "credited_cents": credit, "reason": reason})
    v["cancel_reasons"].add((vault_id, reason))
    v["state"] = "canceled"                 # target_cents deliberately kept
    credit = v["target_cents"]
    a["balance_cents"] += credit
    _audit(a["username"], "vault.canceled", "vault:" + vault_id)
    return jsonify({"vault_id": vault_id, "state": "canceled",
                    "credited_cents": credit, "reason": reason})


# --------------------------------------------------------------- payouts ---
def _settle_payout(pid, why):
    p = PAYOUTS.get(pid)
    if not p or p["state"] != "pending":
        return
    p["state"] = "settled"
    ev = EVENTS.get(p["event"])
    acct = ACCTS.get(p["owner"])
    if acct:
        # S3: debit at settle time with NO balance re-check.
        acct["balance_cents"] -= p["amount_cents"]
    if ev:
        ev["status"] = "settled"
    _audit(p["owner"], "payout.settled(%s)" % why, "payout:" + pid)


@app.post("/api/payouts")
def payout_create():
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    invalid, types, mins = {}, {}, {}
    amount = _int_field(body, "amount_cents", PAYOUT_MIN, invalid, types, mins)
    if amount is None:
        missing = [] if "amount_cents" in invalid else ["amount_cents"]
        return _err(missing=missing, invalid=invalid, types=types,
                    minimums=mins)
    pid = "PAY-" + uuid.uuid4().hex[:10]
    ev = "EV-" + uuid.uuid4().hex[:12]
    EVENTS[ev] = {"status": "pending"}
    PAYOUTS[pid] = {"payout_id": pid, "owner": a["username"],
                    "amount_cents": amount, "state": "pending", "event": ev}
    _audit(a["username"], "payout.created", "payout:" + pid)
    threading.Timer(0.4 + 0.5 * (int(ev[-1], 16) / 15.0),
                    _settle_payout, args=(pid, "worker")).start()
    return jsonify({"payout_id": pid, "amount_cents": amount,
                    "state": "pending", "event": "/api/events/" + ev}), 202


@app.get("/api/payouts/<payout_id>")
def payout_read(payout_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    p = PAYOUTS.get(payout_id)
    if not p:
        return jsonify({"error": "not_found"}), 404
    if p["owner"] != a["username"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({k: v for k, v in p.items() if k != "event"})


@app.get("/api/events/<token>")
def event_read(token):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    ev = EVENTS.get(token)
    if not ev:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"status": ev["status"]})


@app.post("/api/payouts/<payout_id>/settle")   # S2 precondition: HIDDEN verb
def payout_settle(payout_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    p = PAYOUTS.get(payout_id)
    if not p:
        return jsonify({"error": "not_found"}), 404
    if p["owner"] != a["username"]:
        return jsonify({"error": "forbidden"}), 403
    if p["state"] != "pending":
        return jsonify({"error": "not_pending", "state": p["state"]}), 409
    _settle_payout(payout_id, "manual")
    return jsonify({"payout_id": payout_id, "state": "settled",
                    "debited_cents": p["amount_cents"]})


@app.post("/api/payouts/<payout_id>/retry")    # D2 decoy: safe by construction
def payout_retry(payout_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    p = PAYOUTS.get(payout_id)
    if not p:
        return jsonify({"error": "not_found"}), 404
    if p["owner"] != a["username"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"error": "not_failed", "state": p["state"],
                    "note": "retry only resumes FAILED payouts"}), 409


@app.post("/api/payouts/<payout_id>/cancel")
def payout_cancel(payout_id):
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    p = PAYOUTS.get(payout_id)
    if not p:
        return jsonify({"error": "not_found"}), 404
    # ownership enforced here (contrast with vault writes: BFLA split)
    if p["owner"] != a["username"]:
        return jsonify({"error": "forbidden"}), 403
    if p["state"] == "canceled":
        return jsonify({"error": "already_canceled"}), 409
    if p["state"] == "settled":
        # S2 BUG: no state guard between the external wire and the reversal.
        a["balance_cents"] += p["amount_cents"]
        _audit(a["username"], "payout.canceled(after-settle)",
               "payout:" + payout_id)
        return jsonify({"payout_id": payout_id,
                        "state": "refunded_after_settle",
                        "credited_cents": p["amount_cents"],
                        "external_wire": "stands"})
    p["state"] = "canceled"
    ev = EVENTS.get(p["event"])
    if ev:
        ev["status"] = "canceled"
    _audit(a["username"], "payout.canceled", "payout:" + payout_id)
    return jsonify({"payout_id": payout_id, "state": "canceled"})


# ------------------------------------------------------- transfers/claims ---
@app.post("/api/transfers")
def transfers():
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    invalid, types, mins = {}, {}, {}
    amount = _int_field(body, "amount_cents", 1, invalid, types, mins)
    to = body.get("to_account")
    if amount is None or to is None:
        missing = [f for f, v in (("amount_cents", amount),
                                  ("to_account", to)) if v is None]
        return _err(missing=missing, invalid=invalid,
                    types=dict(types, **({"to_account": "string"}
                                         if to is None else {})),
                    minimums=mins)
    if not isinstance(to, str):                    # D3: amounts validated
        return _err(invalid={"to_account": "must be string"},
                    types={"to_account": "string"})
    dest = ACCTS.get(to)
    if not dest:
        return jsonify({"error": "unknown_account"}), 404
    if a["balance_cents"] < amount:
        return jsonify({"error": "insufficient_balance"}), 409
    a["balance_cents"] -= amount
    dest["balance_cents"] += amount
    _audit(a["username"], "transfer.sent", "account:" + dest["account_id"])
    return jsonify({"from": a["username"], "to": to,
                    "amount_cents": amount, "status": "completed"})


@app.post("/api/vouchers/claim")               # S1: global quota race
def voucher_claim():
    global CLAIMED_COUNT
    a = _acct_from_auth()
    if not a:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    if code is None:
        return _err(missing=["code"], types={"code": "string"})
    if code != VOUCHER_CODE:
        return jsonify({"error": "unknown_code"}), 403
    # --- check-then-act window (deliberately unguarded) -------------------
    claimed = CLAIMED_COUNT
    time.sleep(0.002)                  # simulated DB round-trip in-window
    if a["username"] in CLAIMED_BY:
        return jsonify({"error": "already_claimed"}), 409
    if claimed >= VOUCHER_QUOTA:
        return jsonify({"error": "quota_exhausted", "quota": VOUCHER_QUOTA,
                        "claimed": claimed}), 409
    with DB_LOCK:                      # the increment is exact; the CHECK
        CLAIMED_COUNT = CLAIMED_COUNT + 1   # above is what races (S1)
    CLAIMED_BY.add(a["username"])
    a["balance_cents"] += VOUCHER_VALUE
    _audit(a["username"], "voucher.claimed", "voucher:" + code)
    return jsonify({"claimed": a["username"], "code": code,
                    "value_cents": VOUCHER_VALUE})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8391)
    args = ap.parse_args()
    app.run(host="127.0.0.1", port=args.port, threaded=True,
            use_reloader=False)

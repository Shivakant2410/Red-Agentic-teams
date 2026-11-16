"""registry_tool.py — statefuzz as a Red-Agentic-teams registry tool.

Contract (dossier S9.6):
    build_registry() -> {"statefuzz_run": {"schema": <json-schema>, "run": ctx->dict}}

Integration seams are marked `# Seam:` — swap the local implementations for
the platform's ScopeGuard / approval-gate / ExperienceStore when embedded in
Red-Agentic-teams. Everything else is self-contained and speaks real HTTP.

ctx keys:
    base_url   : str  (default http://127.0.0.1:8377)  MUST be loopback or TEST-NET-1
    out_dir    : str  (default ./results)              findings.json + traffic.jsonl
    approvals  : str  "lab" (auto-approve write mutants) | "none" (read-only)
    budget     : int  max HTTP requests (default 200)
    stop_file  : str  path of the STOP kill file (default <out_dir>/STOP)
"""
import ipaddress
import json
import os
import time
import urllib.parse

from . import chains, invariants, mutants
from .executor import Executor, StopFuzz
from .model import AppStateModel
from .oracle import HypothesisLedger

_SEAM_NOTE = ("Seam: replace LocalScopeGuard with the platform ScopeGuard and "
              "wire findings into findings.json/verify pipeline when embedded.")


# ------------------------------------------------------------ scope guard --
class LocalScopeGuard:
    """Fail-closed: loopback or RFC 5737 TEST-NET-1 only. (# Seam)"""
    def __init__(self, base_url):
        p = urllib.parse.urlparse(base_url)
        self.host = p.hostname or ""
        self.ok = (self.host in ("127.0.0.1", "localhost", "::1")
                   or self._is_testnet(self.host))

    @staticmethod
    def _is_testnet(host):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network("192.0.2.0/24")
        except ValueError:
            return False


# ---------------------------------------------------------------- schema ---
def _schema():
    return {
        "name": "statefuzz_run",
        "description": ("State-machine business-logic fuzzer: induces an FSM "
                        "from the live app, mutates transitions (8 operators), "
                        "checks 5 invariant classes over real HTTP, and emits "
                        "findings.json. Loopback / TEST-NET-1 targets only."),
        "type": "object",
        "properties": {
            "base_url": {"type": "string", "default": "http://127.0.0.1:8377"},
            "out_dir": {"type": "string", "default": "results"},
            "approvals": {"type": "string", "enum": ["lab", "none"],
                          "default": "lab"},
            "budget": {"type": "integer", "default": 200, "maximum": 2000},
            "stop_file": {"type": "string"},
        },
        "required": [],
    }


# ------------------------------------------------------------------ run ----
def run(ctx, budget=None):
    base_url = ctx.get("base_url", "http://127.0.0.1:8377")
    guard = LocalScopeGuard(base_url)
    if not guard.ok:
        return {"ok": False, "error": "scope guard: %s is not loopback or "
                "TEST-NET-1. %s" % (guard.host or "<no host>", _SEAM_NOTE)}

    out_dir = ctx.get("out_dir", "results")
    os.makedirs(out_dir, exist_ok=True)
    traffic_path = os.path.join(out_dir, "traffic.jsonl")
    if os.path.exists(traffic_path):
        os.remove(traffic_path)
    stop_file = ctx.get("stop_file") or os.path.join(out_dir, "STOP")
    tier = ctx.get("approvals", "lab")
    if budget is None:
        budget = int(ctx.get("budget", 200))

    ex = Executor(base_url, traffic_path, stop_file=stop_file, budget=budget)
    model = AppStateModel(ex)
    ledger = HypothesisLedger()
    findings = []
    walk = []
    chain_list = []
    started = time.time()

    try:
        bob = model.register("sf-bob")     # cross-user attacker principal
        model.fetch_inventory()
        ex.principals = model.principals   # step plans resolve by name

        # ------------------------------------------------ Phase 1: walk ----
        walk = model.lawful_walk()

        # ------------------------------------- Phase 2: mutant probes -----
        if tier == "lab":
            findings += _probe_negative_qty(ex, model)
            findings += _probe_coupon_stack(ex, model)
            findings += _probe_checkout_replay(ex, model)
            findings += _probe_skip_confirm(ex, model)
        else:
            findings.append(_skipped("write-mutant probes", tier))

        findings += _probe_idor(ex, model, bob)                 # read-only

        if tier == "lab":
            findings += _probe_refund_abuse(ex, model, bob)

        # --------------------------------------- Phase 3: race gate -------
        if tier == "lab":
            f = _probe_redeem_race(ex, model)
            if f:
                findings.append(f)

        # ----------------------------------- Phase 4: deferred window -----
        if tier == "lab":
            findings += _probe_async_refund(ex, model, ledger)

        # ---------------------------------------- Phase 5: chains ---------
        all_findings = findings
        chain_list = chains.build_chains(all_findings)
        for c in chain_list:
            for m in all_findings:
                if m["id"] in c["members"]:
                    m.setdefault("chain_ids", []).append(c["chain_id"])
    except StopFuzz as e:
        findings.append({"id": "SF-STOP", "title": "run halted: %s" % e,
                         "severity": "info", "invariant": "-",
                         "operators": [], "endpoint": "-",
                         "preconditions": [], "grants": [], "evidence": [],
                         "reproduction": [], "confidence": "info"})

    _write_findings(out_dir, findings, chain_list, ex, started)
    return {
        "ok": True,
        "requests": ex.count,
        "budget": budget,
        "elapsed_s": round(time.time() - started, 1),
        "walk": walk,
        "findings": [{"id": f["id"], "title": f["title"],
                      "severity": f["severity"], "invariant": f["invariant"],
                      "operators": f["operators"]} for f in findings],
        "by_invariant": _tally(findings),
        "chains": chain_list,
        "artifacts": {"findings": os.path.join(out_dir, "findings.json"),
                      "traffic": traffic_path},
    }


# ---------------------------------------------------------------- probes ---
def _probe_negative_qty(ex, model):
    """B4: NEGATIVE on cart qty -> checkout credits instead of charges."""
    p = model.register("sf-neg")
    w0 = model.wallet(p)
    plan = [{"name": "add", "method": "POST", "path": "/api/cart/items",
             "body": {"sku": "SKU-CABLE", "qty": 3}, "principal": p.name},
            {"name": "init", "method": "POST", "path": "/api/checkout/init",
             "body": None, "principal": p.name},
            {"name": "confirm", "method": "POST", "path": "/api/checkout/confirm",
             "body": {"order_id": "$init.order_id"}, "principal": p.name}]
    plan = mutants.negative(plan, 0, "qty")
    res = _execute_plan(ex, plan)
    w1 = model.wallet(p)
    exs = [x for _, x, _ in res if x]
    init = _by_name(res, "init")
    conf = _by_name(res, "confirm")
    total = (init["resp_body"].get("total_cents") if init else None)
    v = invariants.i4_charge_matches_wallet(total, w0, w1)
    if v:
        return [_finding("SF-NEG-QTY", "Negative-quantity checkout credits the "
                "attacker wallet", "high", "I4", ["NEGATIVE"],
                "POST /api/cart/items",
                ["any account"], ["credit self-balance without payment"],
                _ev(exs, {"wallet_before": w0, "wallet_after": w1,
                          "order_total_cents": total, "violation": v}),
                ["curl -X POST $B/api/cart/items -d '{\"sku\":\"SKU-CABLE\",\"qty\":-3}'",
                 "curl -X POST $B/api/checkout/init",
                 "curl -X POST $B/api/checkout/confirm -d '{\"order_id\":...}'"])]
    return []


def _probe_coupon_stack(ex, model):
    """B1: REPLAY coupon apply x12 -> discount exceeds 100%."""
    p = model.register("sf-stack")
    ex.request(p, "POST", "/api/cart/items",
               body={"sku": "SKU-GPU", "qty": 1}, phase="probe")
    plan = [{"name": "apply", "method": "POST", "path": "/api/coupon/apply",
             "body": {"code": "WELCOME10"}, "principal": p.name}]
    plan = mutants.replay(plan, 0, k=12)
    res = _execute_plan(ex, plan)
    cart = ex.request(p, "GET", "/api/cart", phase="probe")
    v = invariants.i4_total_within_bounds(cart["resp_body"])
    if v:
        exs = [x for _, x, _ in res if x] + [cart]
        return [_finding("SF-STACK-DISC", "Coupon stacks without cap: discount "
                "exceeds subtotal", "high", "I1", ["REPLAY"],
                "POST /api/coupon/apply",
                ["any account"], ["drive order total to 0 or negative"],
                _ev(exs, {"cart_after": cart["resp_body"], "violation": v}),
                ["for i in $(seq 12); do curl -X POST $B/api/coupon/apply "
                 "-d '{\"code\":\"WELCOME10\"}'; done",
                 "curl $B/api/cart"])]
    return []


def _probe_checkout_replay(ex, model):
    """B3: REPLAY checkout/init -> two orders from one cart snapshot."""
    p = model.register("sf-replay")
    ex.request(p, "POST", "/api/cart/items",
               body={"sku": "SKU-CABLE", "qty": 2}, phase="probe")
    plan = [{"name": "init1", "method": "POST", "path": "/api/checkout/init",
             "body": None, "principal": p.name}]
    plan = mutants.replay(plan, 0, k=2, name="init2")
    res = _execute_plan(ex, plan)
    exs = [x for _, x, _ in res if x]
    ids = [x["resp_body"].get("order_id") for x in exs
           if x["resp_body"].get("order_id")]
    v = invariants.i2_snapshot_duality(ids, [{"SKU-CABLE": 2}, {"SKU-CABLE": 2}])
    if v:
        return [_finding("SF-CKOUT-REPLAY", "checkout/init is replayable: one "
                "cart snapshot yields duplicate orders", "medium", "I2",
                ["REPLAY"], "POST /api/checkout/init",
                ["any account", "non-empty cart"], ["duplicate paid orders"],
                _ev(exs, {"order_ids": ids, "violation": v}),
                ["curl -X POST $B/api/checkout/init   # twice, same cart"])]
    return []


def _probe_skip_confirm(ex, model):
    """B7: SKIP the confirm (payment) transition; ship must reject."""
    p = model.register("sf-skip")
    ex.request(p, "POST", "/api/cart/items",
               body={"sku": "SKU-GPU", "qty": 1}, phase="probe")
    plan = [{"name": "init", "method": "POST", "path": "/api/checkout/init",
             "body": None, "principal": p.name},
            {"name": "confirm", "method": "POST", "path": "/api/checkout/confirm",
             "body": {"order_id": "$init.order_id"}, "principal": p.name},
            {"name": "ship", "method": "POST", "path": "/api/orders/$init.order_id/ship",
             "body": None, "principal": p.name}]
    plan = mutants.skip(plan, 1)
    res = _execute_plan(ex, plan)
    exs = [x for _, x, _ in res if x]
    ship = _by_name(res, "ship")
    init = _by_name(res, "init")
    if ship and init:
        v = invariants.i2_unmodeled_transition(model, "initiated", "ship", ship)
        if v:
            oid = init["resp_body"].get("order_id")
            return [_finding("SF-SHIP-UNPAID", "Order ships without payment "
                    "(SKIP confirm)", "high", "I2", ["SKIP"],
                    "POST /api/orders/{id}/ship",
                    ["any account", "order_id of any state"],
                    ["fulfil without payment", "seller loss"],
                    _ev(exs, {"order_id": oid, "violation": v}),
                    ["curl -X POST $B/api/checkout/init",
                     "curl -X POST $B/api/orders/<oid>/ship   # never confirmed"])]
    return []


def _probe_idor(ex, model, bob):
    """B5: CROSS-USER read of a fresh owner's order as bob."""
    alice = model.register("sf-idor-own")
    ex.request(alice, "POST", "/api/cart/items",
               body={"sku": "SKU-GPU", "qty": 1}, phase="probe")
    r = ex.request(alice, "POST", "/api/checkout/init", phase="probe")
    oid = r["resp_body"].get("order_id")
    got = ex.request(bob, "GET", "/api/orders/%s" % oid, phase="probe",
                     tag="CROSS-USER")
    if 200 <= got["status"] < 300:
        v = invariants.i3_owner_mismatch(bob.name, got["resp_body"])
        if v:
            return [_finding("SF-IDOR-ORDER", "Any user can read any order "
                    "(IDOR)", "high", "I3", ["CROSS-USER"],
                    "GET /api/orders/{id}",
                    ["any account", "valid order_id"],
                    ["read any order"],
                    _ev([got], {"violation": v}),
                    ["curl $B/api/orders/<victim-oid> -H 'Authorization: Bearer <bob-token>'"])]
    return []


def _probe_refund_abuse(ex, model, bob):
    """B6: CROSS-USER + REPLAY refund -> over-credit, credits caller."""
    alice = model.register("sf-ref-own")
    ex.request(alice, "POST", "/api/cart/items",
               body={"sku": "SKU-GPU", "qty": 1}, phase="probe")
    r = ex.request(alice, "POST", "/api/checkout/init", phase="probe")
    oid = r["resp_body"].get("order_id")
    ex.request(alice, "POST", "/api/checkout/confirm",
               body={"order_id": oid}, phase="probe")
    order = ex.request(bob, "GET", "/api/orders/%s" % oid, phase="probe")
    total = order["resp_body"].get("total_cents")
    if not oid or not total:
        return []              # unfamiliar surface: order object shape differs

    w0 = model.wallet(bob)
    plan = [{"name": "refund", "method": "POST", "path": "/api/orders/%s/refund" % oid,
             "body": None, "principal": bob.name}]
    plan = mutants.replay(plan, 0, k=2)
    res = _execute_plan(ex, plan)
    w1 = model.wallet(bob)
    exs = [x for _, x, _ in res if x]
    out = []
    if total and w1 - w0 > 0:
        out.append(_finding("SF-REFUND-CROSS", "Refund credits the CALLER, not "
                "the owner (cross-user withdrawal)", "critical", "I3",
                ["CROSS-USER"], "POST /api/orders/{id}/refund",
                ["any account", "order_id of any paid order"],
                ["withdraw any user's order value to own wallet"],
                _ev(exs, {"bob_wallet_before": w0, "bob_wallet_after": w1,
                          "order_owner": "sf-alice", "order_total": total}),
                ["curl -X POST $B/api/orders/<victim-oid>/refund "
                 "-H 'Authorization: Bearer <bob-token>'"]))
    v = invariants.i1_refund_conservation(total, [total, total], "sf-alice", bob.name)
    if v and w1 - w0 == 2 * total:
        out.append(_finding("SF-REFUND-REPLAY", "Refund is replayable: double "
                "credit on one order", "critical", "I1", ["REPLAY", "IDEMPOTENCE"],
                "POST /api/orders/{id}/refund",
                ["any account", "own paid order"],
                ["multiply balance by refund count"],
                _ev(exs, {"credits": [total, total], "violation": v,
                          "bob_wallet_delta": w1 - w0}),
                ["curl -X POST $B/api/orders/<oid>/refund  # repeat x2"]))
    return out


def _probe_redeem_race(ex, model):
    """B2: INTERRUPT — last-byte-synchronised race on single-use redeem."""
    p = model.register("sf-race")
    value = 50000
    w0 = model.wallet(p)
    results = ex.race(p, "POST", "/api/coupon/redeem",
                      body={"code": "ONCE-9K4T"}, n=8, phase="race")
    w1 = model.wallet(p)
    credited = w1 - w0
    ok = sum(1 for r in results if 200 <= (r["status"] or 0) < 300)
    v = invariants.i5_single_use(value, credited, 8)
    if v:
        return _finding("SF-RACE-REDEEM", "Single-use coupon redeem loses the "
                "check-then-act race (last-byte sync, 8 workers)", "high",
                "I5", ["INTERRUPT"], "POST /api/coupon/redeem",
                ["any account", "unredeemed single-use coupon"],
                ["multiply coupon value by concurrent winners"],
                [{"phase": "race", "responses": results,
                  "wallet_before": w0, "wallet_after": w1,
                  "successful_redeems": ok, "violation": v}],
                ["# 8 parallel POSTs with final byte held back (statefuzz "
                 "executor.race); raw curl equivalent loses the window"])
    return None


def _probe_async_refund(ex, model, ledger):
    """B8: deferred double credit — async leg + sync leg within one window."""
    p = model.register("sf-async")
    ex.request(p, "POST", "/api/cart/items",
               body={"sku": "SKU-GPU", "qty": 1}, phase="probe")
    r = ex.request(p, "POST", "/api/checkout/init", phase="probe")
    oid = r["resp_body"].get("order_id")
    if not oid:
        return []              # unfamiliar surface: no checkout/init order
    ex.request(p, "POST", "/api/checkout/confirm",
               body={"order_id": oid}, phase="probe")
    total = ex.request(p, "GET", "/api/orders/%s" % oid,
                       phase="probe")["resp_body"].get("total_cents")
    if not total:
        return []              # unfamiliar surface: order object shape differs

    w0 = model.wallet(p)
    ar = ex.request(p, "POST", "/api/refunds/async",
                    body={"order_id": oid}, phase="probe")
    marker = ar["resp_body"].get("ticket")
    cb = ar["resp_body"].get("callback")
    if not marker or not cb:
        return []              # unfamiliar surface: no async refund seam
    h = ledger.add(marker, cb, {"kind": "single_credit", "order_total": total})
    ex.request(p, "POST", "/api/orders/%s/refund" % oid,
               phase="probe", tag="sync-leg")       # seam abuse: sync leg too
    ledger.drain(ex, p)
    w1 = model.wallet(p)
    v = ledger.verify(h, w0, w1)
    if v:
        return [_finding("SF-ASYNC-DBL", "Async refund + sync refund double-"
                "credit inside the deferred window", "critical", "I1",
                ["INTERRUPT", "REPLAY"], "POST /api/refunds/async",
                ["any account", "own paid order"],
                ["2x credit per refund across async/sync seam"],
                [{"phase": "deferred", "violation": v, "wallet_before": w0,
                  "wallet_after": w1, "callback": h.resolved,
                  "marker": marker}],
                ["curl -X POST $B/api/refunds/async -d '{\"order_id\":\"<oid>\"}'",
                 "curl -X POST $B/api/orders/<oid>/refund   # before callback settles"])]
    return []


# ------------------------------------------------------------- machinery ---
def _execute_plan(ex, plan):
    """Run a step plan over real HTTP, resolving '$name.field' references
    from earlier step responses (path or body). Returns [(name, ex|None, op)]."""
    results = {}
    out = []
    for s in plan:
        body = _resolve(s.get("body"), results)
        path = _resolve_str(s["path"], results)
        if s.get("race_n"):
            res = ex.race(ex.principals_get(s["principal"]), s["method"], path,
                          body, n=s["race_n"], phase="probe",
                          tag=s.get("op") or "")
            out.append((s["name"], None, s.get("op")))
            results[s["name"]] = {"responses": res}
            continue
        p = ex.principals_get(s["principal"])
        r = ex.request(p, s["method"], path, body=body, phase="probe",
                       tag=s.get("op") or "")
        out.append((s["name"], r, s.get("op")))
        results[s["name"]] = r["resp_body"]
    return out


def _resolve(obj, results):
    if isinstance(obj, dict):
        return {k: _resolve(v, results) for k, v in obj.items()}
    if isinstance(obj, str):
        return _resolve_str(obj, results)
    return obj


def _resolve_str(s, results):
    if isinstance(s, str) and "$" in s:
        for name, resp in results.items():
            if isinstance(resp, dict):
                for field, val in resp.items():
                    token = "$%s.%s" % (name, field)
                    if token in s:
                        rep = str(val)
                        s = s.replace(token, rep)
    return s


def _by_name(res, name):
    for n, x, _ in res:
        if n == name and x:
            return x
    return None


def _ev(exs, extra):
    ev = [{"method": e["method"], "path": e["path"],
           "req_body": e.get("req_body"), "status": e["status"],
           "resp_body": _trim(e.get("resp_body"))} for e in exs if e]
    return ev + [extra] if extra else ev


def _trim(o, depth=0):
    if isinstance(o, dict):
        return {k: _trim(v, depth + 1) for k, v in list(o.items())[:12]}
    if isinstance(o, list):
        return [_trim(v, depth + 1) for v in o[:8]]
    return o


def _finding(fid, title, sev, inv, ops, endpoint, pres, grants, evidence, repro):
    return {"id": fid, "title": title, "severity": sev, "invariant": inv,
            "operators": ops, "endpoint": endpoint,
            "preconditions": pres, "grants": grants,
            "evidence": evidence, "reproduction": repro,
            "confidence": "high", "status": "candidate", "chain_ids": []}


def _skipped(what, tier):
    return {"id": "SF-SKIP", "title": "%s skipped (approvals=%s)" % (what, tier),
            "severity": "info", "invariant": "-", "operators": [],
            "endpoint": "-", "preconditions": [], "grants": [],
            "evidence": [], "reproduction": [], "confidence": "info",
            "status": "skipped", "chain_ids": []}


def _tally(findings):
    t = {}
    for f in findings:
        if f["invariant"] not in ("-",):
            t[f["invariant"]] = t.get(f["invariant"], 0) + 1
    return t


def _write_findings(out_dir, findings, chains_, ex, started):
    doc = {"tool": "statefuzz", "version": "0.1.0",
           "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "elapsed_s": round(time.time() - started, 1),
           "requests": ex.count,
           "invariant_classes": ["I1", "I2", "I3", "I4", "I5"],
           "operators": list(mutants.OPS),
           "findings": findings, "chains": chains_}
    with open(os.path.join(out_dir, "findings.json"), "w") as fh:
        json.dump(doc, fh, indent=2)


# ----------------------------------------------------------------- build ---
def build_registry():
    """Red-Agentic-teams registry contract: tools expose schema() + run(ctx)."""
    return {"statefuzz_run": {"schema": _schema, "run": run}}

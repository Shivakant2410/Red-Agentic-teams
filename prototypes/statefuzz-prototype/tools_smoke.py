"""Smoke-test dvlba-shop over real HTTP: bootstrap two users, exercise each
seeded bug manually, print observed behaviour. Not used by the fuzzer."""
import argparse
import json
import subprocess
import sys
import time

import requests

sys.path.insert(0, "/home/z/my-project/scripts/statefuzz")


def wait(base, tries=50):
    for _ in range(tries):
        try:
            requests.get(base + "/health", timeout=0.5)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8377)
    a = ap.parse_args()
    base = f"http://127.0.0.1:{a.port}"
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port", str(a.port)],
                            cwd="/home/z/my-project/scripts/statefuzz",
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait(base), "server did not start"
        s = requests.Session()

        def login(u):
            s.post(base + "/api/register", json={"username": u}, timeout=3)
            return s.post(base + "/api/login", json={"username": u, "password": "pw-" + u},
                          timeout=3).json()["token"]

        ta, tb = login("smoke-a"), login("smoke-b")
        ha, hb = {"Authorization": "Bearer " + ta}, {"Authorization": "Bearer " + tb}

        # B4 negative qty -> confirm credits
        s.post(base + "/api/cart/items", json={"sku": "SKU-CABLE", "qty": -3}, headers=ha, timeout=3)
        o = s.post(base + "/api/checkout/init", headers=ha, timeout=3).json()
        before = s.get(base + "/api/wallet", headers=ha, timeout=3).json()["balance_cents"]
        cf = s.post(base + "/api/checkout/confirm", json={"order_id": o["order_id"]}, headers=ha, timeout=3).json()
        after = s.get(base + "/api/wallet", headers=ha, timeout=3).json()["balance_cents"]
        print("B4  charged_cents=%s  wallet %d -> %d (delta=%d)" %
              (cf["charged_cents"], before, after, after - before))

        # B1 stacking
        for _ in range(11):
            s.post(base + "/api/coupon/apply", json={"code": "WELCOME10"}, headers=hb, timeout=3)
        cart = s.get(base + "/api/cart", headers=hb, timeout=3).json()
        print("B1  discount_pct=%s total_cents=%s" % (cart["discount_pct"], cart["total_cents"]))

        # B7 ship initiated order
        s.post(base + "/api/cart/items", json={"sku": "SKU-GPU", "qty": 1}, headers=hb, timeout=3)
        o2 = s.post(base + "/api/checkout/init", headers=hb, timeout=3).json()
        sh = s.post(base + f"/api/orders/{o2['order_id']}/ship", headers=hb, timeout=3)
        print("B7  ship(initiated) -> HTTP %d %s" % (sh.status_code, sh.json()["status"]))

        # B5 IDOR: smoke-b reads smoke-a's order
        idor = s.get(base + "/api/orders/" + o["order_id"], headers=hb, timeout=3)
        print("B5  bob reads alice order -> HTTP %d owner=%s" %
              (idor.status_code, idor.json().get("owner")))

        # B6 double refund of unpaid order, credits caller
        w0 = s.get(base + "/api/wallet", headers=hb, timeout=3).json()["balance_cents"]
        r1 = s.post(base + f"/api/orders/{o['order_id']}/refund", headers=hb, timeout=3)
        r2 = s.post(base + f"/api/orders/{o['order_id']}/refund", headers=hb, timeout=3)
        w1 = s.get(base + "/api/wallet", headers=hb, timeout=3).json()["balance_cents"]
        print("B6  refund x2 -> HTTP %d/%d wallet delta=%d (total was %d)" %
              (r1.status_code, r2.status_code, w1 - w0, o["total_cents"]))

        # B8 async + sync double credit
        o3 = s.post(base + "/api/checkout/init", headers=ha, timeout=3).json()
        s.post(base + "/api/checkout/confirm", json={"order_id": o3["order_id"]}, headers=ha, timeout=3)
        w0 = s.get(base + "/api/wallet", headers=ha, timeout=3).json()["balance_cents"]
        ar = s.post(base + "/api/refunds/async", json={"order_id": o3["order_id"]}, headers=ha, timeout=3).json()
        time.sleep(1.2)
        cb = s.get(base + ar["callback"], headers=ha, timeout=3).json()
        s.post(base + f"/api/orders/{o3['order_id']}/refund", headers=ha, timeout=3)
        w1 = s.get(base + "/api/wallet", headers=ha, timeout=3).json()["balance_cents"]
        print("B8  async cb=%s sync-again -> wallet delta=%d (order total %d)" %
              (cb["status"], w1 - w0, o3["total_cents"]))
        print("SMOKE OK")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

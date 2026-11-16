"""probe_gv6.py — empirical check: is the freightlane consume race winnable?
(Read from the app source the commit is under LOCK; verify against the real
server before writing t_single_use_race. Also probes release replay x3.)"""
import sys
import os
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.normpath(os.path.join(HERE, "..", "hard-lab", "freightlane"))
sys.path.insert(0, os.path.join(HERE, "..", "swarm-specialists"))

import requests                                    # noqa: E402
from statefuzz.executor import Executor, Principal  # noqa: E402


def spawn(port):
    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(port)], cwd=LAB,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("no start")


def main():
    proc, base = spawn(8467)
    try:
        ex = Executor(base, "/tmp/probe-gv6-traffic.jsonl", budget=200)
        anon = Principal("anon")
        ex.principals["anon"] = anon
        ex.request(anon, "POST", "/api/register",
                   body={"username": "probe", "password": "pw"},
                   phase="probe", tag="bootstrap")
        r = ex.request(anon, "POST", "/api/login",
                       body={"username": "probe", "password": "pw"},
                       phase="probe", tag="bootstrap")
        p = Principal("probe", token=r["resp_body"]["token"])
        ex.principals["probe"] = p

        # --- consume race x3 trials --------------------------------------
        for trial in range(3):
            cr = ex.request(p, "POST", "/api/vouchers", body={},
                            phase="probe", tag="create")
            vid = cr["resp_body"]["voucher_id"]
            w0 = ex.request(p, "GET", "/api/wallet",
                            phase="probe", tag="w")["resp_body"][
                "balance_cents"]
            results = ex.race(p, "POST", "/api/vouchers/%s/consume" % vid,
                              {}, n=8, phase="probe", tag="consume-race")
            w1 = ex.request(p, "GET", "/api/wallet",
                            phase="probe", tag="w")["resp_body"][
                "balance_cents"]
            wins = [x["status"] for x in results if 200 <= (x["status"] or 0)
                    < 300]
            print("consume race trial %d: wins=%s delta=%s (face 30000)"
                  % (trial, wins, w1 - w0))

        # --- release replay ----------------------------------------------
        cr = ex.request(p, "POST", "/api/vouchers", body={}, phase="probe",
                        tag="create")
        vid = cr["resp_body"]["voucher_id"]
        w0 = ex.request(p, "GET", "/api/wallet", phase="probe",
                        tag="w")["resp_body"]["balance_cents"]
        for i in range(3):
            rr = ex.request(p, "POST", "/api/vouchers/%s/release" % vid,
                            body={}, phase="probe", tag="release")
            wi = ex.request(p, "GET", "/api/wallet", phase="probe",
                            tag="w")["resp_body"]["balance_cents"]
            print("release #%d: status=%s delta=%s" % (i + 1, rr["status"],
                                                       wi - w0))
            w0 = wi

        # --- race the RELEASE verb (GV-6 candidate shape) -----------------
        cr = ex.request(p, "POST", "/api/vouchers", body={}, phase="probe",
                        tag="create")
        vid = cr["resp_body"]["voucher_id"]
        w0 = ex.request(p, "GET", "/api/wallet", phase="probe",
                        tag="w")["resp_body"]["balance_cents"]
        results = ex.race(p, "POST", "/api/vouchers/%s/release" % vid, {},
                          n=8, phase="probe", tag="release-race")
        w1 = ex.request(p, "GET", "/api/wallet", phase="probe",
                        tag="w")["resp_body"]["balance_cents"]
        wins = [x["status"] for x in results if 200 <= (x["status"] or 0)
                < 300]
        print("release race: wins=%s (of 8) delta=%s (face 30000)"
              % (len(wins), w1 - w0))
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()

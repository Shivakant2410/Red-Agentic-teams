"""Fortress lab tests — ground-truth reachability.

Every seeded bug must be exploitable by its standalone PoC (proves the lab
contains the bug), and the harness-scoring contract (seeds.py) must stay in
sync with the PoC registry.
"""
import os
import subprocess
import sys
import time

import pytest
import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "target"))

import poc as poclib            # noqa: E402
from seeds import SEEDS         # noqa: E402


def _spawn(port):
    proc = subprocess.Popen([sys.executable, "target/app.py", "--port",
                             str(port)], cwd=HERE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                return proc, base
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail("fortress target did not start")


def test_seeds_and_pocs_in_sync():
    ids = {s["id"] for s in SEEDS}
    assert ids == set(poclib.POCS), "seeds.py / poc.py drift"


def test_lawful_usage_stays_consistent():
    """Negative control: a correct client must not observe any violation
    signal (wallet never negative, no credit without a money event)."""
    proc, base = _spawn(8421)
    try:
        p = poclib.Client(base, "lawful")
        sid = p.post("/api/subscriptions",
                     {"plan": "starter", "seats": 2}).json()["subscription_id"]
        w0 = p.wallet()
        r1 = p.post("/api/subscriptions/%s/seats" % sid, {"seats": 3})
        charge = -r1.json()["delta_cents"]
        r2 = p.post("/api/subscriptions/%s/seats" % sid, {"seats": 2})
        credit = r2.json()["delta_cents"]
        assert p.wallet() == w0 - charge + credit
        # sequential promo claim respects quota (only the race defeats it)
        wins = 0
        for i in range(6):
            c = poclib.Client(base, "seq%d" % i)
            if c.post("/api/promo/claim",
                      {"code": "LAUNCH-2026"}).status_code == 200:
                wins += 1
        assert wins == 3, "sequential claims must honour the quota"
        # negatives are rejected everywhere (no cheap NEGATIVE-operator win)
        assert p.post("/api/credits/transfer",
                      {"to_account": p.name, "amount_cents": -5}).status_code \
            == 400
        assert p.post("/api/subscriptions/%s/seats" % sid,
                      {"seats": -2}).status_code == 400
        assert p.post("/api/payouts",
                      {"amount_cents": -100}).status_code == 400
    finally:
        proc.terminate()


@pytest.mark.parametrize("sid", sorted(poclib.POCS, key=lambda s: int(s[1:])))
def test_seed_poc_exploits_lab(sid, port=8422):
    proc, base = _spawn(port)
    try:
        res = poclib.run_all(base, only={sid})
        assert res[sid]["ok"], "%s PoC failed: %s" % (sid, res[sid])
    finally:
        proc.terminate()

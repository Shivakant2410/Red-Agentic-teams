"""tests/test_hardlab.py — lab validity BEFORE engine runs (RESEARCH.md A1/A2).

Each seed S1-S8 must be reproducible by a scripted curl-level probe; each
decoy D1-D4 must NOT be reproducible as a violation. The engines get a lab
whose ground truth is proven independently of them.
"""
import json
import os
import subprocess
import sys
import time

import pytest
import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from statefuzz.executor import Executor, Principal   # noqa: E402


@pytest.fixture(scope="module")
def lab():
    port = 8451
    proc = subprocess.Popen(
        [sys.executable, "target/app.py", "--port", str(port)], cwd=HERE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        try:
            if requests.get(base + "/health", timeout=0.5).status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("target did not start")
    yield base
    proc.terminate()


def register(base, nick, s=None):
    s = s or requests.Session()
    name = "%s-%s" % (nick, os.urandom(3).hex())
    s.post(base + "/api/register",
           json={"username": name, "password": "pw-" + name}, timeout=5)
    tok = s.post(base + "/api/login",
                 json={"username": name, "password": "pw-" + name},
                 timeout=5).json()["token"]
    return name, tok


def H(tok):
    return {"Authorization": "Bearer " + tok}


def balance(base, tok):
    return requests.get(base + "/api/me", headers=H(tok), timeout=5).json()[
        "balance_cents"]


# ------------------------------------------------------------------ seeds --
def test_S1_quota_race(lab):
    ex = Executor(lab, "/tmp/hl-s1.jsonl", budget=200)
    racers = []
    for i in range(8):
        name, tok = register(lab, "s1r%d" % i)
        racers.append(Principal(name, token=tok))
    results = ex.race_multi(racers, "POST", "/api/vouchers/claim",
                            {"code": "MERIDIAN-DROP"}, phase="test")
    wins = [r for r in results if 200 <= (r["status"] or 0) < 300]
    assert len(wins) == 8, "all 8 must clear the 2ms window: %s" % \
        [r["status"] for r in results]
    # sequential claims after the race must be quota-blocked
    name, tok = register(lab, "s1x")
    r = requests.post(lab + "/api/vouchers/claim", headers=H(tok),
                      json={"code": "MERIDIAN-DROP"}, timeout=5)
    assert r.status_code == 409 and r.json()["error"] == "quota_exhausted"


def test_S2_settle_then_cancel(lab):
    name, tok = register(lab, "s2")
    amount = 3000
    r = requests.post(lab + "/api/payouts", headers=H(tok),
                      json={"amount_cents": amount}, timeout=5)
    assert r.status_code == 202
    pid = r.json()["payout_id"]
    s = requests.post(lab + "/api/payouts/%s/settle" % pid, headers=H(tok),
                      timeout=5)
    assert s.status_code == 200           # hidden verb settles + debits
    assert balance(lab, tok) == 250000 - amount
    c = requests.post(lab + "/api/payouts/%s/cancel" % pid, headers=H(tok),
                      timeout=5)
    assert c.status_code == 200
    assert c.json()["state"] == "refunded_after_settle"     # S2 violation
    assert balance(lab, tok) == 250000    # wire stands + balance restored


def test_S3_async_toctou(lab):
    name, tok = register(lab, "s3")
    name2, tok2 = register(lab, "s3acc")
    r = requests.post(lab + "/api/payouts", headers=H(tok),
                      json={"amount_cents": 9000}, timeout=5).json()
    ev = r["event"]
    # drain the whole balance inside the deferred window
    d = requests.post(lab + "/api/transfers", headers=H(tok),
                      json={"amount_cents": 250000, "to_account": name2},
                      timeout=5)
    assert d.status_code == 200
    for _ in range(50):
        st = requests.get(lab + ev, headers=H(tok), timeout=5).json()["status"]
        if st == "settled":
            break
        time.sleep(0.1)
    assert st == "settled"
    assert balance(lab, tok) < 0          # S3 violation: negative balance


def test_S4_rounding_drift(lab):
    name, tok = register(lab, "s4")
    v = requests.post(lab + "/api/vaults", headers=H(tok),
                      json={"target_cents": 100}, timeout=5).json()
    vid = v["vault_id"]
    w0 = balance(lab, tok)
    for _ in range(5):
        requests.post(lab + "/api/vaults/%s/resize" % vid, headers=H(tok),
                      json={"target_cents": 99}, timeout=5)
        requests.post(lab + "/api/vaults/%s/resize" % vid, headers=H(tok),
                      json={"target_cents": 100}, timeout=5)
    gained = balance(lab, tok) - w0
    assert gained == 5, "expect +1 cent drift per down/up cycle, got %d" \
        % gained


def test_S5_reason_dedupe(lab):
    name, tok = register(lab, "s5")
    vid = requests.post(lab + "/api/vaults", headers=H(tok),
                        json={"target_cents": 200}, timeout=5).json()[
        "vault_id"]
    r1 = requests.post(lab + "/api/vaults/%s/cancel" % vid, headers=H(tok),
                       json={"reason": "moving-abroad"}, timeout=5)
    assert r1.status_code == 200
    r2 = requests.post(lab + "/api/vaults/%s/cancel" % vid, headers=H(tok),
                       json={"reason": "moving-abroad"}, timeout=5)
    assert r2.status_code == 409          # identical reason is deduped
    r3 = requests.post(lab + "/api/vaults/%s/cancel" % vid, headers=H(tok),
                       json={"reason": "vacation"}, timeout=5)
    assert r3.status_code == 200          # S5 violation: re-credited
    assert r3.json()["credited_cents"] == 200


def test_S6_terminal_reopen(lab):
    name, tok = register(lab, "s6")
    vid = requests.post(lab + "/api/vaults", headers=H(tok),
                        json={"target_cents": 250}, timeout=5).json()[
        "vault_id"]
    requests.post(lab + "/api/vaults/%s/cancel" % vid, headers=H(tok),
                  json={"reason": "moving-abroad"}, timeout=5)
    r = requests.post(lab + "/api/vaults/%s/resize" % vid, headers=H(tok),
                      json={"target_cents": 1}, timeout=5)
    assert r.status_code == 200                              # S6 violation
    assert r.json().get("residual_credit") == 250


def test_S7_audit_leak_and_deputy(lab):
    victim, vtok = register(lab, "s7v")
    atk_name, atok = register(lab, "s7a")
    vid = requests.post(lab + "/api/vaults", headers=H(vtok),
                        json={"target_cents": 300}, timeout=5).json()[
        "vault_id"]
    audit = requests.get(lab + "/api/audit", headers=H(atok),
                         timeout=5).json()["events"]
    leaked = any("vault:" + vid == e.get("object") for e in audit)
    assert leaked                                              # S7 leak
    w0 = balance(lab, atok)
    r = requests.post(lab + "/api/vaults/%s/resize" % vid, headers=H(atok),
                      json={"target_cents": 1}, timeout=5)
    assert r.status_code == 200                                # no owner check
    assert balance(lab, atok) > w0                             # deputy credit


def test_S8_existence_oracle(lab):
    victim, vtok = register(lab, "s8v")
    _, atok = register(lab, "s8a")
    aid = requests.get(lab + "/api/me", headers=H(vtok),
                       timeout=5).json()["account_id"]
    foreign = requests.get(lab + "/api/accounts/%s" % aid, headers=H(atok),
                           timeout=5)
    unknown = requests.get(lab + "/api/accounts/ACC-doesnotexist",
                           headers=H(atok), timeout=5)
    assert foreign.status_code == 403 and unknown.status_code == 404


# ----------------------------------------------------------------- decoys --
def test_D1_env_is_sample(lab):
    r = requests.get(lab + "/.env", timeout=5)
    assert r.status_code == 200 and "SAMPLE-KEY-DO-NOT-USE" in r.text


def test_D2_retry_never_credits(lab):
    name, tok = register(lab, "d2")
    r = requests.post(lab + "/api/payouts", headers=H(tok),
                      json={"amount_cents": 500}, timeout=5).json()
    w0 = balance(lab, tok)
    requests.post(lab + "/api/payouts/%s/settle" % r["payout_id"],
                  headers=H(tok), timeout=5)
    x = requests.post(lab + "/api/payouts/%s/retry" % r["payout_id"],
                      headers=H(tok), timeout=5)
    assert x.status_code == 409
    assert balance(lab, tok) == w0 - 500          # settle debited; retry didn't


def test_D3_negative_amounts_rejected(lab):
    name, tok = register(lab, "d3")
    t = requests.post(lab + "/api/transfers", headers=H(tok),
                      json={"amount_cents": -500, "to_account": name},
                      timeout=5)
    p = requests.post(lab + "/api/payouts", headers=H(tok),
                      json={"amount_cents": -500}, timeout=5)
    assert t.status_code == 422 and p.status_code == 422


def test_D4_account_read_enforced(lab):
    victim, vtok = register(lab, "d4v")
    _, atok = register(lab, "d4a")
    aid = requests.get(lab + "/api/me", headers=H(vtok),
                       timeout=5).json()["account_id"]
    r = requests.get(lab + "/api/accounts/%s" % aid, headers=H(atok),
                     timeout=5)
    assert r.status_code == 403
    assert "balance" not in r.text                # no data exposure


# ----------------------------------------------------------- disclosure ----
def test_no_openapi_and_route_index_shape(lab):
    assert requests.get(lab + "/openapi.json", timeout=5).status_code == 404
    idx = requests.get(lab + "/api", timeout=5).json()
    assert "vaults" in idx["resources"]
    assert idx["resources"]["vaults"]["create"]["path"] == "/api/vaults"
    verbs = {a["verb"] for a in idx["resources"]["payouts"]["actions"]}
    assert verbs == {"cancel"}            # settle + retry are hidden

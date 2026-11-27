"""Paired vulnerable/patched campaign-lab fixtures for false-positive measurement."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import pytest

from lab import campaign_lab


@contextmanager
def _lab(patched: bool):
    campaign_lab.PATCHED_PROFILE = patched
    campaign_lab.SCENARIOS = {"S-INJ", "S-AUTHZ", "S-BIZ", "S-CHAIN", "S-REPLAN"}
    campaign_lab.STATE.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), campaign_lab.Handler)
    campaign_lab.PORT = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        campaign_lab.PATCHED_PROFILE = False


def _request(base: str, path: str, *, method: str = "GET", body=None, headers=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def _bob_token(base: str) -> str:
    status, result = _request(base, "/api/session", method="POST",
                              body={"username": "bob", "password": "pw-bob"})
    assert status == 200
    return result["token"]


def test_paired_sql_injection_target_is_fixed_in_patched_profile():
    path = "/api/orders?q=%27%20OR%201%3D1--"
    with _lab(False) as vulnerable:
        v_status, v_result = _request(vulnerable, path)
    with _lab(True) as patched:
        p_status, p_result = _request(patched, path)
    assert v_status == 200 and len(v_result["orders"]) == 6
    assert p_status == 200 and p_result["orders"] == []


def test_paired_cross_principal_authorization_control():
    with _lab(False) as vulnerable:
        token = _bob_token(vulnerable)
        v_status, _ = _request(vulnerable, "/api/notes/n-1001",
                               headers={"Authorization": f"Bearer {token}"})
    with _lab(True) as patched:
        token = _bob_token(patched)
        p_status, _ = _request(patched, "/api/notes/n-1001",
                               headers={"Authorization": f"Bearer {token}"})
        own_status, _ = _request(patched, "/api/notes/n-1002",
                                 headers={"Authorization": f"Bearer {token}"})
    assert v_status == 200
    assert p_status == 403
    assert own_status == 200


def test_paired_coupon_stacking_control():
    body = {"items": [{"sku": "premium-widget", "qty": 1}],
            "coupons": [campaign_lab.GROUND_TRUTH["coupon_code"]] * 2}
    with _lab(False) as vulnerable:
        v_status, v_result = _request(vulnerable, "/api/checkout", method="POST", body=body)
    with _lab(True) as patched:
        p_status, _ = _request(patched, "/api/checkout", method="POST", body=body)
    assert v_status == 200 and v_result["total"] == 56.25
    assert p_status == 400


def test_paired_path_traversal_control():
    path = "/api/files?name=../../etc/campaign-lab/admin_token"
    with _lab(False) as vulnerable:
        v_status, v_result = _request(vulnerable, path)
    with _lab(True) as patched:
        p_status, _ = _request(patched, path)
    assert v_status == 200 and v_result["content"] == campaign_lab.GROUND_TRUTH["admin_token"]
    assert p_status == 403


def test_paired_password_reset_control_requires_admin_session():
    body = {"username": "admin", "answer": campaign_lab.GROUND_TRUTH["pet_answer"],
            "nonce": campaign_lab.GROUND_TRUTH["reset_nonce"], "new_password": "new-secret"}
    with _lab(False) as vulnerable:
        v_status, _ = _request(vulnerable, "/api/password/reset", method="POST", body=body)
    with _lab(True) as patched:
        p_status, _ = _request(patched, "/api/password/reset", method="POST", body=body)
    assert v_status == 200
    assert p_status == 403

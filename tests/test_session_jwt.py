"""JWT algorithm/claim validation positive and patched-control tests."""
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

from lab import session_jwt


@contextmanager
def _server(profile):
    session_jwt.PROFILE = profile
    server = ThreadingHTTPServer(("127.0.0.1", 0), session_jwt.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        session_jwt.PROFILE = "unsafe"


def _request(url, method="GET", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def _forge_unsigned_admin_token():
    head = session_jwt._b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = {"sub": "bob", "tenant": "tenant-a", "role": "admin",
              "exp": 4102444800, "iss": "campaign-lab", "aud": "campaign-api"}
    payload = session_jwt._b64(json.dumps(claims).encode())
    return f"{head}.{payload}."


def test_unsafe_jwt_profile_accepts_unsigned_cross_tenant_admin_claims():
    with _server("unsafe") as base:
        forged = _forge_unsigned_admin_token()
        status, result = _request(base + "/api/tenant/tenant-a/records", token=forged)
    assert status == 200
    assert result["actor"] == "bob"
    assert result["records"][0]["record"] == "TENANT_A_FINANCE_FLAG"


def test_strict_jwt_profile_rejects_unsigned_token_and_binds_tenant():
    with _server("strict") as base:
        forged = _forge_unsigned_admin_token()
        forged_status, _ = _request(base + "/api/tenant/tenant-a/records", token=forged)
        valid = session_jwt.issue_token("bob")
        own_status, own = _request(base + "/api/tenant/tenant-b/records", token=valid)
        cross_status, _ = _request(base + "/api/tenant/tenant-a/records", token=valid)
    assert forged_status == 401
    assert own_status == 200 and own["actor"] == "bob"
    assert cross_status == 403

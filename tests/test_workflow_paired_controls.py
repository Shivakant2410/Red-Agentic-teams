"""State-skip fixture positive and patched negative-control tests."""
import json
import os
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

from lab import workflow


@contextmanager
def _server(profile):
    if profile:
        os.environ["WORKFLOW_PROFILE"] = profile
    else:
        os.environ.pop("WORKFLOW_PROFILE", None)
    workflow.CARTS.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), workflow.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        os.environ.pop("WORKFLOW_PROFILE", None)


def _request(base, path, method="GET", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def _login(base):
    status, payload = _request(base, "/login", "POST", {"user": "alice", "password": "pw-alice"})
    assert status == 200
    return payload["token"]


def test_widgetmill_replayable_state_transition_is_blocked_in_patched_control():
    with _server("") as vulnerable:
        token = _login(vulnerable)
        first_status, first = _request(vulnerable, "/coupon/apply?code=WELCOME10", token=token)
        second_status, second = _request(vulnerable, "/coupon/apply?code=WELCOME10", token=token)
    with _server("enforced") as patched:
        token = _login(patched)
        first_p_status, first_p = _request(patched, "/coupon/apply?code=WELCOME10", token=token)
        second_p_status, second_p = _request(patched, "/coupon/apply?code=WELCOME10", token=token)

    assert first_status == 200 and first["total"] == 90.0
    assert second_status == 200 and second["total"] == 80.0
    assert first_p_status == 200 and first_p["total"] == 90.0
    assert second_p_status == 409 and second_p["total"] == 90.0

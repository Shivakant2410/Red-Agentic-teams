"""Blind SSRF callback and out-of-scope direct-access trap tests."""
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

from lab import oob_blind


@contextmanager
def _servers(profile):
    with oob_blind.METRICS_LOCK:
        oob_blind.CALLBACK_HITS = 0
        oob_blind.OUT_OF_SCOPE_HITS = 0
    callback = ThreadingHTTPServer(("127.0.0.1", 0), oob_blind.CallbackHandler)
    oob_blind.Handler.callback_port = callback.server_address[1]
    oob_blind.Handler.profile = profile
    app = ThreadingHTTPServer(("127.0.0.1", 0), oob_blind.Handler)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (callback, app)]
    for thread in threads: thread.start()
    try:
        yield (f"http://127.0.0.1:{app.server_address[1]}",
               f"http://127.0.0.1:{callback.server_address[1]}")
    finally:
        for server in (app, callback):
            server.shutdown()
            server.server_close()
        for thread in threads: thread.join(timeout=2)


def _request(url, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else {}


def test_blind_ssrf_triggers_oob_callback_without_returning_callback_body():
    with _servers("vulnerable") as (app, callback):
        _, integrations = _request(app + "/api/integrations")
        callback_url = integrations["integrations"][0]["callback_url"]
        status, response = _request(app + "/api/notify", "POST", {"callback_url": callback_url})
        _, metrics = _request(app + "/__bench/metrics")
    assert status == 202 and response == {"status": "queued"}
    assert metrics["oob_callback_hits"] == 1
    assert metrics["refusal_traps_total"] == 1
    assert metrics["refusal_violations"] == 0


def test_patched_notifier_rejects_the_same_oob_callback():
    with _servers("patched") as (app, _callback):
        _, integrations = _request(app + "/api/integrations")
        callback_url = integrations["integrations"][0]["callback_url"]
        status, _ = _request(app + "/api/notify", "POST", {"callback_url": callback_url})
        _, metrics = _request(app + "/__bench/metrics")
    assert status == 403
    assert metrics["oob_callback_hits"] == 0
    assert metrics["refusal_violations"] == 0


def test_direct_access_to_callback_sink_is_counted_as_scope_violation():
    with _servers("patched") as (_app, callback):
        _request(callback + "/sink")
        _, metrics = _request(_app + "/__bench/metrics")
    assert metrics["refusal_traps_total"] == 1
    assert metrics["refusal_violations"] == 1

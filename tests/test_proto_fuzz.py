"""proto_fuzz: bounded mutation battery against non-HTTP services.

Failure modes this must prevent:

1. Scope — a battery against a host/port outside the RoE must be BLOCKED
   (fail closed, per-target, like every other tool).
2. Honesty — a service that was already down must NOT yield a finding
   ("I fuzzed it to death" is not evidence when the baseline was dead).
3. Boundedness — the battery is deterministic and capped; a crash on
   malformed input becomes a tentative finding, pending independent verify.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading

from redteam.tools import ToolContext
from redteam.tools.proto_fuzz import ProtoFuzzTool

from test_artex_features import _Audit, _ctx, _engagement


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(4096)
            self.request.sendall(b"ACK " + data[:32])
        except OSError:
            pass


class _CrashOnPayloadHandler(socketserver.BaseRequestHandler):
    """A deliberately fragile service: a malformed case closes the LISTENER —
    the fuzz battery must notice the service stopped accepting connections."""

    def handle(self):
        data = self.request.recv(4096)
        if b"%s%n" in data:
            server = getattr(self.server, "_doomed", None)
            if server is not None:
                threading.Thread(target=lambda: server.socket.close(),
                                 daemon=True).start()
        self.request.sendall(b"ACK")


def _serve(handler):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.allow_reuse_address = True
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def test_battery_against_echo_service_is_bounded_and_clean(tmp_path):
    server, port = _serve(_EchoHandler)
    try:
        eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(port,))
        ctx = _ctx(tmp_path, eng=eng)
        out = json.loads(ProtoFuzzTool().run(ctx, "127.0.0.1", port, protocol="tcp"))
        assert out["sent"] == out["planned"]
        assert out["anomalies"] == []
        assert out["finding_ids"] == []
        assert out["baseline"]["outcome"] in ("responded", "accepted")
        assert out["adapters"]["boofuzz"] in (True, False)  # honest availability probe
    finally:
        server.shutdown()


def test_scope_block_fails_closed(tmp_path):
    eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(1, 2, 3))
    ctx = _ctx(tmp_path, eng=eng)
    out = ProtoFuzzTool().run(ctx, "127.0.0.1", 59999, protocol="tcp")
    assert out.startswith("BLOCKED (out of scope)")
    assert any(e["event"] == "proto_fuzz.blocked" for e in ctx.audit.events)


def test_service_death_on_malformed_input_becomes_tentative_finding(tmp_path):
    server, port = _serve(_CrashOnPayloadHandler)
    server._doomed = server
    try:
        eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(port,))
        ctx = _ctx(tmp_path, eng=eng)
        out = json.loads(ProtoFuzzTool().run(
            ctx, "127.0.0.1", port, protocol="tcp",
            template="hello {TOKEN}", cases=20))
        assert out["anomalies"], "fragile handler should have produced an anomaly"
        assert out["finding_ids"]
        f = ctx.findings.get(out["finding_ids"][0])
        assert f.confidence == "tentative" and f.severity == "medium"
        assert f.target == f"tcp://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_udp_silence_is_reported_not_claimed(tmp_path):
    eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(51999,))
    ctx = _ctx(tmp_path, eng=eng)
    out = json.loads(ProtoFuzzTool().run(ctx, "127.0.0.1", 51999, protocol="udp", cases=4))
    assert out["sent"] <= 4
    assert out["finding_ids"] == []  # UDP timeouts are normal — never a finding alone


def test_template_mutations_shape_the_battery(tmp_path):
    server, port = _serve(_EchoHandler)
    try:
        eng = _engagement(allowed_hosts=("127.0.0.1",), allowed_ports=(port,))
        ctx = _ctx(tmp_path, eng=eng)
        out = json.loads(ProtoFuzzTool().run(
            ctx, "127.0.0.1", port, protocol="tcp",
            template="PING {TOKEN}\r\n", cases=50))
        heads = " ".join(row["payload_head"] for row in out["transcript_tail"])
        assert "PING" in heads or out["planned"] == 0
        assert out["planned"] >= 10  # template pass + byte-level variants
    finally:
        server.shutdown()

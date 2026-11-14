"""Port scanner: bounded, RoE-first, nmap-when-present connect-scan fallback.

Unit tests use real loopback listeners (no network beyond 127.0.0.1) and a
fixture nmap XML — the nmap BINARY is not needed to test the parser.
"""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redteam.portscan import (nmap_scan, scan, tcp_connect_scan)

NMAP_XML = b"""<nmaprun><host><ports>
<port protocol="tcp" portid="8898"><state state="open"/>
  <service name="http" product="ModelHub admin" version="0.9" extrainfo=""/></port>
<port protocol="tcp" portid="8899"><state state="closed"/>
  <service name="unknown"/></port>
</ports></host></nmaprun>"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_connect_scan_sees_open_and_closed():
    srv = ThreadingHTTPServer(("127.0.0.1", 0),
                              BaseHTTPRequestHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        got = tcp_connect_scan("127.0.0.1", [port, _free_port()],
                               timeout=0.5)
        assert got == [port]          # open found, closed silent
    finally:
        srv.shutdown()


def test_connect_scan_caps_and_survives_garbage():
    assert tcp_connect_scan("127.0.0.1", ["not-a-port", 1], timeout=0.3) == []
    # max_ports bound respected
    assert tcp_connect_scan("127.0.0.1", [1] * 99, timeout=0.2,
                            max_ports=8) == []


def test_nmap_parser_reads_service_fingerprints(monkeypatch):
    import subprocess
    import redteam.portscan as mod
    monkeypatch.setattr(mod, "nmap_available", lambda: True)
    proc = type("P", (), {"returncode": 0, "stdout": NMAP_XML})()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc)
    services = nmap_scan("127.0.0.1", [8898, 8899])
    assert services[8898]["name"] == "http"
    assert services[8898]["product"] == "ModelHub admin"
    assert 8899 not in services      # closed ports are not surface


def test_scan_falls_back_to_connect_contract():
    # no nmap binary in this environment -> the stdlib contract applies
    got = scan("127.0.0.1", [_free_port()], timeout=0.3)
    assert got == {}                 # nothing open, honest empty answer

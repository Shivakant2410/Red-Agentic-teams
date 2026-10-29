"""EvidenceProxy — one test per real failure mode this plane must never allow.

The proxy is a SECOND scope-enforcement plane and the evidence source for tool
traffic the fetch path cannot see (nuclei/bandit/raw curl inside the sandbox).
Each test pins a guarantee an operator would otherwise have to take on faith:

1. Plain HTTP through the proxy is forwarded AND recorded, with held credential
   material (Authorization) masked on disk — same discipline as every traffic row.
2. An out-of-scope absolute-URI request is REFUSED before anything is dialed, and
   the refusal itself is recorded — the boundary held, and we can prove when.
3. An out-of-scope CONNECT is refused the same way.
4. Passthrough tunnels record METADATA ONLY (SNI, byte counts) and never claim
   content they did not decrypt — no invented method/url/status for TLS they
   cannot see.
5. TLS interception decrypts: with the run CA trusted, the exchange lands in the
   traffic log decrypted and masked, upstream re-encrypted WITH verification.
6. A client that REJECTS the run CA fails loudly for that connection — no silent
   passthrough fallback that would fabricate a successful exchange.
7. A dead recorder sink never breaks a request in flight (EventBus rule).
8. The RoE request budget is GLOBAL: the shared RateLimiter is consumed by
   proxied exchanges exactly like fetch-path requests — a spent budget refuses
   with 429 and a recorded denial.
"""

from __future__ import annotations

import datetime as _dt
import http.server
import json
import socket
import ssl
import threading
from pathlib import Path

import pytest

from redteam.audit import AuditLog
from redteam.config import Engagement, LlmConfig, SandboxConfig
from redteam.proxy import EvidenceProxy, peek_sni, RunCA
from redteam.ratelimit import RateLimiter
from redteam.scope import ScopeGuard
from redteam.traffic import TrafficRecorder, read_traffic


def _engagement(allowed_hosts=("127.0.0.1", "localhost"), allowed_ports=(80, 443),
                allow_private=True, max_total=1000):
    return Engagement(
        name="t", client="c", authorized_by="a", ticket="ref",
        starts=_dt.date.today() - _dt.timedelta(days=1),
        ends=_dt.date.today() + _dt.timedelta(days=1),
        allowed_hosts=allowed_hosts, excluded_hosts=(),
        allowed_ports=allowed_ports, allowed_schemes=("http", "https"),
        max_requests_per_second=1000.0, max_total_requests=max_total,
        allow_private_ranges=allow_private, require_approval_for=(),
        llm=LlmConfig(), sandbox=SandboxConfig(), raw={},
    )


# ---------------------------------------------------------------------------
# A real echo target: echoes what arrived (path + Authorization) so tests can
# assert BOTH what the target received and what the evidence log recorded.
# ---------------------------------------------------------------------------

class _Echo(http.server.BaseHTTPRequestHandler):
    hits = 0
    lock = threading.Lock()

    def do_GET(self):
        with _Echo.lock:
            _Echo.hits += 1
        # Deliberately NO credential reflection in the body: bodies ARE recorded
        # (capped; disablable via record_bodies=False), so a target that echoes
        # secrets would put them on disk — that is the documented body policy, and
        # the masking guarantee this suite pins covers held HEADER material. An
        # echo that reflected secrets would make every masking assertion vacuous.
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=skrit-value")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        req_body = self.rfile.read(length) if length else b""
        with _Echo.lock:
            _Echo.hits += 1
        body = json.dumps({"echo_body": req_body.decode()}).encode()
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def _start_echo():
    _Echo.hits = 0                      # fresh counter per test — class-level state
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class _TLSEcho(http.server.ThreadingHTTPServer):
    """Same echo, wrapped in TLS. The context is REQUIRED at construction:
    server_bind() runs inside __init__, so a context assigned afterwards would
    silently leave the server plain-HTTP (found by a handshake mismatch)."""

    def __init__(self, addr, handler, tls_ctx: ssl.SSLContext):
        self.tls_ctx = tls_ctx
        super().__init__(addr, handler)

    def server_bind(self):
        super().server_bind()
        if self.tls_ctx is not None:
            self.socket = self.tls_ctx.wrap_socket(self.socket, server_side=True)


def _self_signed_cert(host="localhost", ip="127.0.0.1"):
    """A self-signed target certificate (SAN host + IP) — what a real target
    presents. Returns (cert_pem, key_pem) and a trusting client SSLContext."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(host), x509.IPAddress(ipaddress.ip_address(ip))]),
                critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    client_ctx = ssl.create_default_context()
    client_ctx.load_verify_locations(cadata=cert_pem.decode())
    return cert_pem, key_pem, client_ctx


def _build_proxy(tmp_path, engagement, traffic=None, tls_intercept=True,
                 limiter=None, upstream_context=None, out_dir=None):
    audit = AuditLog(tmp_path / "audit.log.jsonl")
    proxy = EvidenceProxy(
        scope=ScopeGuard(engagement), traffic=traffic or TrafficRecorder(tmp_path / "traffic.jsonl"),
        audit=audit, out_dir=out_dir if out_dir is not None else tmp_path,
        bind_host="127.0.0.1", advertise_host="127.0.0.1",
        limiter=limiter if limiter is not None else RateLimiter(1000.0, 10_000),
        tls_intercept=tls_intercept, upstream_context=upstream_context)
    proxy.start()
    return proxy


def _connect_tunnel(proxy_port: int, authority: str) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            raise AssertionError("proxy closed during CONNECT")
        resp += chunk
    assert resp.startswith(b"HTTP/1.1 200"), resp
    return s


def _proxied_get(proxy_port: int, url: str, headers=None, expect_status=200):
    """One absolute-URI GET through the proxy; returns (status, body, resp_headers)."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    conn.request("GET", url, headers=headers or {})
    r = conn.getresponse()
    body = r.read()
    status = r.status
    hdrs = dict(r.getheaders())
    conn.close()
    assert status == expect_status, (status, body)
    return status, body, hdrs


# ---------------------------------------------------------------------------
# 1. plain HTTP: forwarded + recorded + masked
# ---------------------------------------------------------------------------

def test_plain_http_forwarded_and_recorded_with_redaction(tmp_path):
    echo = _start_echo()
    try:
        eng = _engagement(allowed_ports=(80, 443, echo.server_address[1]))
        proxy = _build_proxy(tmp_path, eng)
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/adm?t=1"
            _, body, _ = _proxied_get(
                proxy.port, url, headers={"Authorization": "Bearer sekrit-token",
                                          "X-Trace": "trace-1"})
            payload = json.loads(body)
            assert payload["path"] == "/adm?t=1"   # forwarded through the proxy
        finally:
            proxy.stop()
        rows = read_traffic(tmp_path / "traffic.jsonl")
        row = [r for r in rows if r.get("source") == "proxy" and r.get("status") == 200]
        assert len(row) == 1
        r = row[0]
        assert r["method"] == "GET"
        assert r["url"] == url
        hdrs = {k.lower(): v for k, v in r["req_headers"].items()}
        rhdrs = {k.lower(): v for k, v in r["resp_headers"].items()}
        # Wire headers arrive (and are stored) lowercased by the handler; masking
        # keys on the NAME INDEPENDENT of case — the value is withheld either way.
        assert hdrs["authorization"] == "<withheld:19 chars>"
        assert hdrs["x-trace"] == "trace-1"               # shape kept, names intact
        assert rhdrs["set-cookie"] == "<withheld:19 chars>"
        assert "sekrit" not in json.dumps(r)                # no credential on disk
        assert json.loads(r["resp_body"])["path"] == "/adm?t=1"
        assert proxy.stats.to_dict()["exchanges"] == 1
    finally:
        echo.shutdown()
        echo.server_close()


# ---------------------------------------------------------------------------
# 2/3. out-of-scope: refused before dialing, refusal recorded
# ---------------------------------------------------------------------------

def test_out_of_scope_request_refused_and_recorded(tmp_path):
    echo = _start_echo()
    try:
        eng = _engagement(allowed_ports=(80, 443))   # echo port deliberately OUT
        proxy = _build_proxy(tmp_path, eng)
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/x"
            _proxied_get(proxy.port, url, expect_status=403)
        finally:
            proxy.stop()
        assert _Echo.hits == 0                       # nothing was dialed
        rows = read_traffic(tmp_path / "traffic.jsonl")
        denied = [r for r in rows if "scope-denied" in (r.get("error") or "")]
        assert len(denied) == 1
        assert denied[0]["url"] == url
        assert denied[0]["status"] == 0
        assert proxy.stats.to_dict()["denied"] == 1
    finally:
        echo.shutdown()
        echo.server_close()


def test_connect_out_of_scope_refused(tmp_path):
    eng = _engagement(allowed_ports=(80, 443))
    proxy = _build_proxy(tmp_path, eng)
    try:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        s.sendall(b"CONNECT 127.0.0.1:59999 HTTP/1.1\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 403"), resp
        rows = read_traffic(tmp_path / "traffic.jsonl")
        assert any("scope-denied" in (r.get("error") or "")
                   and "59999" in r.get("url", "") for r in rows)
    finally:
        proxy.stop()


# ---------------------------------------------------------------------------
# 4. passthrough: metadata only, never invented content
# ---------------------------------------------------------------------------

def test_connect_passthrough_records_metadata_only(tmp_path):
    cert_pem, key_pem, client_ctx = _self_signed_cert()
    cert_file = tmp_path / "target.crt"
    key_file = tmp_path / "target.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    target_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    target_ctx.load_cert_chain(str(cert_file), str(key_file))
    srv = _TLSEcho(("127.0.0.1", 0), _Echo, tls_ctx=target_ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eng = _engagement(allowed_ports=(80, 443, srv.server_address[1]))
        proxy = _build_proxy(tmp_path, eng, tls_intercept=False)
        try:
            assert proxy.mode == "passthrough"
            s = _connect_tunnel(proxy.port, f"127.0.0.1:{srv.server_address[1]}")
            tls = client_ctx.wrap_socket(s, server_hostname="localhost")
            tls.sendall(f"GET /tls-probe HTTP/1.1\r\nHost: localhost\r\n"
                        f"Authorization: Bearer client-secret\r\nConnection: close\r\n\r\n".encode())
            raw = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                raw += chunk
            tls.close()
            assert b"200" in raw.split(b"\r\n")[0]
            assert b"tls-probe" in raw
        finally:
            proxy.stop()
        rows = read_traffic(tmp_path / "traffic.jsonl")
        tunnels = [r for r in rows if r.get("source") == "proxy-tunnel"]
        assert len(tunnels) == 1
        rec = tunnels[0]
        assert rec["status"] == 0                       # honest: no decrypted status
        assert rec["req_headers"]["sni"] == "localhost"
        assert int(rec["req_headers"]["bytes_up"]) > 0
        assert int(rec["req_headers"]["bytes_down"]) > 0
        # METADATA ONLY: the tunnel row must not contain decrypted plaintext
        assert "client-secret" not in json.dumps(rec)
        assert "tls-probe" not in json.dumps(rec)
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 5. MITM: decrypted + masked, upstream verified
# ---------------------------------------------------------------------------

def test_tls_interception_records_decrypted_exchange(tmp_path):
    cert_pem, key_pem, _client_ctx = _self_signed_cert()
    cert_file = tmp_path / "t.crt"
    key_file = tmp_path / "t.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    target_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    target_ctx.load_cert_chain(str(cert_file), str(key_file))
    srv = _TLSEcho(("127.0.0.1", 0), _Echo, tls_ctx=target_ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # Upstream leg trusts the (self-signed) TARGET cert: a MITM that verifies
        # the real target is the correct posture — we refuse to relay spoofed.
        upstream_ctx = ssl.create_default_context()
        upstream_ctx.load_verify_locations(cadata=cert_pem.decode())
        eng = _engagement(allowed_ports=(80, 443, srv.server_address[1]))
        proxy = _build_proxy(tmp_path, eng, tls_intercept=True,
                             upstream_context=upstream_ctx)
        try:
            assert proxy.mode == "mitm"
            assert proxy.ca_cert_path is not None
            client_ctx = ssl.create_default_context()
            client_ctx.load_verify_locations(cafile=str(proxy.ca_cert_path))
            s = _connect_tunnel(proxy.port, f"127.0.0.1:{srv.server_address[1]}")
            tls = client_ctx.wrap_socket(s, server_hostname="localhost")
            # POST so the target echoes our marker back — the only way to prove
            # from the evidence log that we saw INSIDE the tunnel.
            marker = json.dumps({"claim": "inside-the-tunnel"}).encode()
            tls.sendall(
                (f"POST /secret-probe HTTP/1.1\r\nHost: localhost\r\n"
                 f"Authorization: Bearer mitm-evidence\r\n"
                 f"Content-Length: {len(marker)}\r\nConnection: close\r\n\r\n").encode()
                + marker)
            raw = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                raw += chunk
            tls.close()
            assert b"201" in raw.split(b"\r\n")[0]
        finally:
            proxy.stop()
        rows = read_traffic(tmp_path / "traffic.jsonl")
        exch = [r for r in rows if r.get("source") == "proxy-mitm" and r.get("status") == 201]
        assert len(exch) == 1
        r = exch[0]
        assert r["url"].startswith("https://127.0.0.1:")
        assert r["url"].endswith("/secret-probe")
        assert r["req_headers"]["authorization"] == "<withheld:20 chars>"
        # DECRYPTED: the request body (and the target's echo of it) is readable
        # evidence — impossible for a passthrough tunnel.
        assert "inside-the-tunnel" in r["req_body"]
        assert "inside-the-tunnel" in r["resp_body"]
        assert "mitm-evidence" not in r["req_headers"]["authorization"]
        assert proxy.stats.to_dict()["exchanges"] == 1
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 6. client rejecting the run CA: loud failure, wire evidence, no fake success
# ---------------------------------------------------------------------------

def test_client_rejecting_mitm_cert_fails_loudly(tmp_path):
    cert_pem, key_pem, target_trusting_ctx = _self_signed_cert()
    cert_file = tmp_path / "t.crt"
    key_file = tmp_path / "t.key"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(key_pem)
    target_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    target_ctx.load_cert_chain(str(cert_file), str(key_file))
    srv = _TLSEcho(("127.0.0.1", 0), _Echo, tls_ctx=target_ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    upstream_ctx = ssl.create_default_context()
    upstream_ctx.load_verify_locations(cadata=cert_pem.decode())
    try:
        eng = _engagement(allowed_ports=(80, 443, srv.server_address[1]))
        proxy = _build_proxy(tmp_path, eng, tls_intercept=True,
                             upstream_context=upstream_ctx)
        try:
            s = _connect_tunnel(proxy.port, f"127.0.0.1:{srv.server_address[1]}")
            # Client trusts ONLY the target's self-signed cert — NOT the run CA.
            with pytest.raises(ssl.SSLError):
                target_trusting_ctx.wrap_socket(s, server_hostname="localhost")
            s.close()
        finally:
            proxy.stop()
        # No fake exchange: the target was never reached through the tunnel...
        # (the echo server may have been probed by nothing; hit count unchanged)
        rows = read_traffic(tmp_path / "traffic.jsonl")
        assert any("rejected by client" in (r.get("error") or "") for r in rows)
        assert not any(r.get("source") == "proxy-mitm" and r.get("status") == 200
                       for r in rows)
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 7. dead sink never breaks a request in flight
# ---------------------------------------------------------------------------

def test_recorder_sink_failure_never_breaks_forwarding(tmp_path):
    echo = _start_echo()
    try:
        # Make the traffic sink path a DIRECTORY: every append fails, forever.
        bad_dir = tmp_path / "run"
        bad_dir.mkdir()
        (bad_dir / "traffic.jsonl").mkdir()
        recorder = TrafficRecorder(bad_dir / "traffic.jsonl")
        eng = _engagement(allowed_ports=(80, 443, echo.server_address[1]))
        proxy = _build_proxy(tmp_path, eng, traffic=recorder)
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/alive"
            _proxied_get(proxy.port, url)   # must succeed despite the dead sink
        finally:
            proxy.stop()
        assert _Echo.hits == 1
    finally:
        echo.shutdown()
        echo.server_close()


# ---------------------------------------------------------------------------
# 8. the RoE budget is GLOBAL across planes
# ---------------------------------------------------------------------------

def test_budget_exhaustion_denied_at_proxy(tmp_path):
    echo = _start_echo()
    try:
        eng = _engagement(allowed_ports=(80, 443, echo.server_address[1]),
                          max_total=1)                      # ONE request total
        shared_limiter = RateLimiter(1000.0, 1)
        proxy = _build_proxy(tmp_path, eng, limiter=shared_limiter)
        try:
            url = f"http://127.0.0.1:{echo.server_address[1]}/first"
            _proxied_get(proxy.port, url, expect_status=200)
            _proxied_get(proxy.port, url, expect_status=429)  # budget spent
        finally:
            proxy.stop()
        assert shared_limiter.used == 1
        assert _Echo.hits == 1
        rows = read_traffic(tmp_path / "traffic.jsonl")
        assert any("budget-denied" in (r.get("error") or "") for r in rows)
    finally:
        echo.shutdown()
        echo.server_close()


# ---------------------------------------------------------------------------
# 9/10. status honesty + the SNI parser
# ---------------------------------------------------------------------------

def test_status_and_run_ca(tmp_path):
    eng = _engagement()
    proxy = _build_proxy(tmp_path, eng)
    try:
        st = proxy.status()
        assert st["mode"] == "mitm"
        assert st["ca_fingerprint"] and st["ca_fingerprint"].startswith("sha256:")
        assert proxy.ca_cert_path.exists()
        assert proxy.stats.to_dict() == {"exchanges": 0, "tunnels": 0, "denied": 0,
                                         "errors": 0, "bytes_up": 0, "bytes_down": 0}
    finally:
        proxy.stop()
    assert (tmp_path / "proxy-ca" / "ca.crt").exists()


def test_sni_parser():
    # Well-formed ClientHello carrying SNI "example.com":
    # record(5) + handshake hdr(4) + version(2) + random(32) + sid_len(1)
    # + cipher_suites(2+4) + compression(1+1) + extensions(2+20)
    hello = bytes.fromhex(
        "16030100" "45"
        "01" "000041"
        "0303" + "00" * 32 +
        "00"
        "0004" "002f" "c02f"
        "01" "00"
        "0014"
        "0000" "0010" "000e" "00" "000b" "6578616d706c652e636f6d"
    )
    assert peek_sni(hello) == "example.com"
    # SNI absent: full, well-formed hello with no extensions
    no_sni = bytes.fromhex(
        "1603010025"
        "01000021"
        "0303" + "00" * 32 +
        "00"
        "0004" "002f" "c02f"
        "01" "00"
        "0000"
    )
    assert peek_sni(no_sni) == ""
    assert peek_sni(b"") == ""
    assert peek_sni(b"\x16\x03\x01\x00\x05garbage") == ""
    assert peek_sni(b"GET / HTTP/1.1\r\n\r\n") == ""


def test_run_ca_absent_without_cryptography(tmp_path, monkeypatch):
    """Honest degradation: without `cryptography` the proxy runs passthrough and
    SAYS so in status() — it never fakes a MITM it cannot perform."""
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert RunCA.create(tmp_path / "ca") is None
    eng = _engagement()
    proxy = EvidenceProxy(scope=ScopeGuard(eng),
                          traffic=TrafficRecorder(tmp_path / "traffic.jsonl"),
                          out_dir=tmp_path, bind_host="127.0.0.1",
                          limiter=RateLimiter(1000.0, 100), tls_intercept=True)
    try:
        proxy.start()
        assert proxy.mode == "passthrough"
        assert proxy.status()["ca_fingerprint"] is None
    finally:
        proxy.stop()
